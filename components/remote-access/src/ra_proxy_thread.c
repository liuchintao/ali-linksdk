/*
 * remote_access_proxy_thread.c
 *
 *  Created on: 2019年6月27日
 *      Author: weixia.lw
 */

#include "core_stdinc.h"
#include "aiot_ra_private.h"
#include "ra_buffer_mgr.h"
#include "ra_proxy_channel.h"
#include "ra_proxy_protocol.h"
#include "ra_proxy_thread.h"
#include "ra_proxy_trans.h"
#include "ra_session_mgr.h"
#include "aiot_mqtt_api.h"

#include "nopoll.h"
#include "core_log.h"

static const char* FMT_TOPIC_SWITCH = "/sys/%s/%s/edge/debug/switch";
#define CLOUD_CHANNEL_HANDSHAKE_TIMEOUT 3
#define CLOUD_CHANNEL_KEEPALIVE_CNT_MAX 3
//#define CLOUD_CHANNEL_FD_SET

#define UPDATE_PROXY_THREAD_RUNNING_CNT(a) do{a->thread_running_cnt = (a->thread_running_cnt + 1) % 0xFFFF; }while(0)
/*********************************************************
 * 接口名称：init_cloud_channel_params
 * 描       述：初始化连接云端的通道参数
 * 输入参数：void* params
 * 输出参数：
 * 返  回 值：
 * 说       明：接口可重入
 *********************************************************/
static int init_cloud_channel_params(CLOUD_CHANNEL_PARAMS_S* cloud_channel_params, ra_handle_t *ra_handle)
{
    cloud_channel_params->host = ra_handle->cloud_host;
    cloud_channel_params->port = ra_handle->cloud_port;
    cloud_channel_params->private_key = NULL;

    cloud_channel_params->pk = ra_handle->pk;
    cloud_channel_params->dn = ra_handle->dn;
    cloud_channel_params->ds = ra_handle->ds;
    cloud_channel_params->local_services = &ra_handle->local_services;
    cloud_channel_params->cred = ra_handle->cred;

    return STATE_SUCCESS;
}

#define FORMAT_SERVICE_INFO "{\"service_type\":\"%s\",\"service_name\":\"%s\",\"service_ip\":\"%s\",\"service_port\":%d}"
static char *splice_local_service_info_content(LOCAL_SERVICES_S *local_services)
{
    int buf_len = 0;
    int service_count = local_services->service_count > 0 ? local_services->service_count : 1;
    char *buf = NULL;
    int i = 0;

    //format lenght: [{},{},{}]
    buf_len = sizeof("[]") + service_count * (strlen(FORMAT_SERVICE_INFO) + DEFAULT_LEN_SERVICE_NAME + DEFAULT_LEN_SERVICE_TYPE + DEFAULT_LEN_IP + DEFAULT_LEN_PORT + sizeof(",")) + 1;
    buf = malloc(buf_len);
    if (!buf)
    {
        return NULL;
    }

    memset(buf, 0, buf_len);

    buf[0] = '[';

    if (local_services->service_count > 0)
    {
        LOCAL_SERVICE_NODE_S *item = NULL, *next = NULL;
        core_list_for_each_entry_safe(item, next, &local_services->service_list, node, LOCAL_SERVICE_NODE_S)
        {
            if(strlen(buf) >= buf_len)
            {
                core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "splice content of local service list error!\r\n");
                free(buf);
                return NULL;
            }

            snprintf(buf + strlen(buf), buf_len - strlen(buf), FORMAT_SERVICE_INFO, item->type, item->name, item->ip, item->port);
            i++;
            if (i != local_services->service_count)
            {
                strncat(buf, ",", 1);
            }
        }
    }
    else
    {
        //default service info.
        snprintf(buf + strlen(buf), buf_len - strlen(buf), FORMAT_SERVICE_INFO, "SSH", "ssh_localhost", "127.0.0.1", 22);
    }


    buf[strlen(buf)] = ']';

    return buf;
}

/*********************************************************
 * 接口名称：update_retry_params
 * 描       述：更新重连参数
 * 输入参数：REMOTE_PROXY_INFO_S *remote_proxy_info
 * 输出参数：
 * 返  回 值：
 * 说       明：
 *********************************************************/
static void update_retry_params(REMOTE_PROXY_INFO_S *remote_proxy_info)
{
    remote_proxy_info->retry_info.retry_times++;
    aiot_sysdep_portfile_t *sysdep = aiot_sysdep_get_portfile();
    remote_proxy_info->retry_info.connect_time = sysdep->core_sysdep_time();
    return ;
}


/*********************************************************
 * 接口名称：clean_retry_params
 * 描       述：清除重连参数
 * 输入参数：REMOTE_PROXY_INFO_S *remote_proxy_info
 * 输出参数：
 * 返  回 值：
 * 说       明：
 *********************************************************/
static void clean_retry_params(REMOTE_PROXY_INFO_S *remote_proxy_info)
{
    remote_proxy_info->retry_info.retry_times = 0;
    remote_proxy_info->retry_info.connect_time = 0;
    return ;
}


/*********************************************************
 * 接口名称：create_remote_proxy
 * 描       述：创建北向连接云端的通道资源
 * 输入参数：void* params
 * 输出参数：
 * 返  回 值：
 * 说       明：
 *********************************************************/
static int create_remote_proxy(REMOTE_PROXY_INFO_S *remote_proxy_info)
{
    CLOUD_CHANNEL_PARAMS_S *cloud_channel_params = &remote_proxy_info->cloud_channel_params;
    aiot_sysdep_portfile_t *sysdep = aiot_sysdep_get_portfile();
    void *cloud_connection = NULL;
    int ret_code = STATE_REMOTE_ACCESS_FAILED;

    //如果资源已经建立，则返回成功
    if (CLOUD_CHANNEL_CLOSED != remote_proxy_info->cloud_channel_state)
    {
        ret_code = STATE_SUCCESS;
        goto end_label;
    }

    core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "start to create cloud channel\r\n");

    //创建云端通道连接资源 
    cloud_connection = open_cloud_proxy_channel(cloud_channel_params->host, cloud_channel_params->port, cloud_channel_params->cred);
    if (NULL == cloud_connection)
    {
        //连接失败则1s后重连接
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "cloud channel open failed");
        goto end_label;
    }
    cloud_channel_params->cloud_connection = cloud_connection;

    //创建资源后赋值通道资源
    cloud_channel_params->origin = nopoll_conn_get_origin(cloud_connection);
    cloud_channel_params->get_uRL = nopoll_conn_get_requested_url(cloud_connection);

    // 发送握手请求
    ret_code = send_cloud_channel_hand_shake_request(remote_proxy_info,remote_proxy_info->cloud_channel_params.services_list);
    if (STATE_SUCCESS != ret_code)
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "send cloud channel Hand_shake request error!\r\n");
        goto end_label;
    }

    //创建成功则清除buffer
    reset_ra_buffer(&remote_proxy_info->cloud_write_buffer);
    reset_ra_buffer(&remote_proxy_info->cloud_read_buffer);
    remote_proxy_info->cloud_channel_state = CLOUD_CHANNEL_CONNECTED;
    remote_proxy_info->hand_shake_time = sysdep->core_sysdep_time();

end_label:

    if (STATE_SUCCESS != ret_code)
    {
        close_cloud_proxy_channel(cloud_connection);
        release_all_session_from_list(&remote_proxy_info->session_list);
        reset_ra_buffer(&remote_proxy_info->cloud_write_buffer);
        reset_ra_buffer(&remote_proxy_info->cloud_read_buffer);
    }

    return ret_code;
}

static LOCAL_SERVICE_NODE_S *get_service_node(LOCAL_SERVICES_S *services, PROXY_PROT_SESSION_PARAMS_S *session_params)
{
    LOCAL_SERVICE_NODE_S *item = NULL, *next = NULL;

    core_list_for_each_entry_safe(item, next, &services->service_list, node, LOCAL_SERVICE_NODE_S)
    {
        if (strcmp(session_params->type, item->type) == 0 && strcmp(session_params->name, item->name) == 0 && strcmp(session_params->ip, item->ip) == 0 && session_params->port == item->port)
            return item;
    }

    return NULL;
}
//
//static int is_service_availibe(LOCAL_SERVICES_S *services, PROXY_PROT_SESSION_PARAMS_S *session_params)
//{
//    LOCAL_SERVICE_NODE_S *service_node = get_service_node(services, session_params);
//
//    if(NULL == service_node)
//        return STATE_REMOTE_ACCESS_FAILED;
//
//    return STATE_SUCCESS;
//}

static void *connect2Local_service(char *host_addr, int port)
{
    void* network_handle = NULL;
    aiot_sysdep_portfile_t *sysdep = aiot_sysdep_get_portfile();
    if (NULL == sysdep) {
        return NULL;
    }
    network_handle = sysdep->core_sysdep_network_init();
    if (network_handle == NULL) {
        return NULL;
    }

    int socket_type = CORE_SYSDEP_SOCKET_TCP_CLIENT;
    uint16_t tmp_port = port;
    uint32_t timeout_ms = 5 * 1000;
    int32_t res = STATE_SUCCESS;
    if ((res = sysdep->core_sysdep_network_setopt(network_handle, CORE_SYSDEP_NETWORK_SOCKET_TYPE,
               &socket_type)) < STATE_SUCCESS ||
        (res = sysdep->core_sysdep_network_setopt(network_handle, CORE_SYSDEP_NETWORK_HOST,
                host_addr)) < STATE_SUCCESS ||
        (res = sysdep->core_sysdep_network_setopt(network_handle, CORE_SYSDEP_NETWORK_PORT,
                &tmp_port)) < STATE_SUCCESS ||
        (res = sysdep->core_sysdep_network_setopt(network_handle,
                CORE_SYSDEP_NETWORK_CONNECT_TIMEOUT_MS,
                &timeout_ms)) < STATE_SUCCESS) {
        sysdep->core_sysdep_network_deinit(&network_handle);
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "core_sysdep_network_setopt error\r\n");
        return NULL;
    }

    if((res = sysdep->core_sysdep_network_establish(network_handle)) < STATE_SUCCESS)
    {
        return NULL;
    }

    return network_handle;
}

static int verify_account(PROXY_PROT_ACCOUNT_S *account)
{
	/*由service自行对账号密码进行判断*/
	return STATE_REMOTE_ACCESS_FAILED;
}

/*********************************************************
 * 接口名称：new_session
 * 描       述：创建南向的本地服务的会话
 * 输入参数：void* params
 * 输出参数：
 * 返  回 值：
 * 说       明：
 *********************************************************/
static void new_session(REMOTE_PROXY_INFO_S *remote_proxy_info, PROXY_PROT_HEADER_S *head_info)
{
    if(CLOUD_CHANNEL_HANDSHAKE != remote_proxy_info->cloud_channel_state)
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "cloud channel does not finish handshake!\r\n");
        return;
    }

    //云端指令是创建一个新的session
    void *network_handle = NULL;
    char *session_id = rand_string_static();
    LOCAL_SERVICES_S *local_services = remote_proxy_info->cloud_channel_params.local_services;
    PROXY_PROT_SESSION_PARAMS_S session_params;
    memset(&session_params, 0, sizeof(PROXY_PROT_SESSION_PARAMS_S));

    RA_BUFFER_INFO_S *channel_buffer = &remote_proxy_info->cloud_read_buffer;
    char *buffer = get_ra_buffer_read_pointer(channel_buffer);
    int len = get_ra_buffer_read_len(channel_buffer);
    parse_proxy_protocol_new_session_payload(buffer, len + 4, &session_params);

    //判断session List 是否已经上限
    if (get_session_num_from_list(&remote_proxy_info->session_list) >= DEFAULT_SESSION_COUNT)
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "session List is limited\r\n");
        cloud_channel_response_with_error(remote_proxy_info, ERR_SESSION_CREATE_FAILED, "socketfd insert error", head_info->msgID, NULL);
        return;
    }

    //根据session的信息链接本地服务
    network_handle = connect2Local_service(session_params.ip, session_params.port);
    if (network_handle == NULL)
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "failed to connect to local service\r\n");
        cloud_channel_response_with_error(remote_proxy_info, ERR_BACKEND_SERVICE_UNAVALIBE, "LE local service is not available", head_info->msgID, NULL);
        return;
    }

    if (STATE_SUCCESS != add_one_session_to_list(&remote_proxy_info->session_list, session_id, network_handle, get_service_node(local_services, &session_params)))
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "failed to alloc new session\r\n");
        cloud_channel_response_with_error(remote_proxy_info, ERR_SESSION_CREATE_FAILED, "memory error", head_info->msgID, NULL);
        return;
    }

    if(0 != cloud_channel_response_new_session(remote_proxy_info, head_info->msgID, session_id))
    {
        core_log2(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "cloud channel response to new session error!session_id:%s, msgID:%s",session_id,head_info->msgID);
        return;
    }
}

/*********************************************************
 * 接口名称：release_session
 * 描       述：释放南向的本地服务的会话
 * 输入参数：void* params
 * 输出参数：
 * 返  回 值：
 * 说       明：
 *********************************************************/
static void release_session(REMOTE_PROXY_INFO_S *remote_proxy_info, PROXY_PROT_HEADER_S *head_info)
{
    if(CLOUD_CHANNEL_HANDSHAKE != remote_proxy_info->cloud_channel_state)
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "cloud channel does not finish handshake!\r\n");
        return;
    }

    (void)release_one_session_from_list(&remote_proxy_info->session_list, head_info->token);
    if(0 != cloud_channel_response_release_session(remote_proxy_info, head_info->msgID, head_info->token))
    {
        core_log1(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "release the session failed! sessionID:%s", head_info->token);
    }
    else
    {
        core_log1(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "release the session: %s", head_info->token);
    }

    return;
}

/*********************************************************
 * 接口名称：send_raw_data2Local_service
 * 描       述：转发数据到本地服务
 * 输入参数：void* params
 * 输出参数：
 * 返  回 值：
 * 说       明：
 *********************************************************/
static int send_raw_data2Local_service(RA_BUFFER_INFO_S  *channel_buffer,SESSION_INFO_NODE_S *session_node)
{
    int total_len = get_ra_buffer_read_len(channel_buffer);
    char *buffer = get_ra_buffer_read_pointer(channel_buffer);
    int res = STATE_SUCCESS;
    aiot_sysdep_portfile_t *sysdep = aiot_sysdep_get_portfile();
    if (NULL == sysdep) {
        return STATE_REMOTE_ACCESS_FAILED;
    }
    if( (res = sysdep->core_sysdep_network_send(session_node->network_handle, (uint8_t *)buffer, total_len, 500, NULL)) < STATE_SUCCESS)
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "core_sysdep_network_send error\r\n");
        return STATE_REMOTE_ACCESS_FAILED;
    }

    return STATE_SUCCESS;
}

/*********************************************************
 * 接口名称：proc_cloud_channel_data
 * 描       述：云端下行数据的处理
 * 输入参数：REMOTE_PROXY_INFO_S *remote_proxy_info
 *           PROXY_PROT_HEADER_S *head_info
 * 输出参数：
 * 返  回 值：
 * 说       明：
 *********************************************************/
static void proc_cloud_channel_data(REMOTE_PROXY_INFO_S *remote_proxy_info, PROXY_PROT_HEADER_S *head_info)
{
    RA_BUFFER_INFO_S *cloud_read_buffer = &remote_proxy_info->cloud_read_buffer;

    if(CLOUD_CHANNEL_HANDSHAKE != remote_proxy_info->cloud_channel_state)
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "cloud channel does not finish handshake!\r\n");
        return;
    }

    //数据：则转发到本地相应的服务中，保证发送数据的完整性
    SESSION_INFO_NODE_S *session_node = get_one_session_from_list(&remote_proxy_info->session_list, head_info->token);
    if (NULL == session_node)
    {
        //session异常则退出
        core_log1(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "session id invalid: %s", head_info->token);
        reset_ra_buffer(cloud_read_buffer);
        return;
    }

    if(0 != send_raw_data2Local_service(cloud_read_buffer, session_node))
    {
        //session异常则退出
        core_log1(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "release the session: %s", head_info->token);
        send_cloud_channel_release_session_request(remote_proxy_info, head_info->msgID, head_info->token);
        release_one_session_from_list(&remote_proxy_info->session_list, head_info->token);
        reset_ra_buffer(cloud_read_buffer);
        return;
    }
    return;
}

/*********************************************************
 * 接口名称：proc_cloud_channel_hand_shake_response
 * 描       述：处理云端握手响应
 * 输入参数：void* params
 * 输出参数：
 * 返  回 值：
 * 说       明：
 *********************************************************/
static int proc_cloud_channel_hand_shake_response(REMOTE_PROXY_INFO_S *remote_proxy_info, PROXY_PROT_HEADER_S *head_info)
{
    if(CLOUD_CHANNEL_CONNECTED != remote_proxy_info->cloud_channel_state)
    {
        return STATE_REMOTE_ACCESS_FAILED;
    }

    char *buffer = get_ra_buffer_read_pointer(&remote_proxy_info->cloud_read_buffer);
    int len = get_ra_buffer_read_len(&remote_proxy_info->cloud_read_buffer);
    int code = 0;

    //解析握手响应报文
    if(0 != parse_proxy_protocol_hand_shake_response(buffer,len,&code))
    {
        return STATE_REMOTE_ACCESS_FAILED;
    }

    if(code==0)
    {
        remote_proxy_info->cloud_channel_state = CLOUD_CHANNEL_HANDSHAKE;
        aiot_sysdep_portfile_t *sysdep = aiot_sysdep_get_portfile();
        remote_proxy_info->hand_shake_time = sysdep->core_sysdep_time();
        //握手成功则清除重连计数
        clean_retry_params(remote_proxy_info);
    }

    return STATE_SUCCESS;
}

/*********************************************************
 * 接口名称：proc_cloud_channel_response
 * 描       述：处理云端响应
 * 输入参数：void* params
 * 输出参数：
 * 返  回 值：
 * 说       明：
 *********************************************************/
static int proc_cloud_channel_response(REMOTE_PROXY_INFO_S *remote_proxy_info, PROXY_PROT_HEADER_S *head_info)
{
    if(0 != strcmp(head_info->msgID, DEFAULT_MSG_ID_HDSK))
    {
        char *buffer = get_ra_buffer_read_pointer(&remote_proxy_info->cloud_read_buffer);
        core_log1(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "recv release session response.payload:%s",buffer);
        return STATE_SUCCESS;
    }

    proc_cloud_channel_hand_shake_response(remote_proxy_info,head_info);
    return STATE_SUCCESS;
}

/*********************************************************
 * 接口名称：proc_verify_account
 * 描       述：处理云端请求账号校验请求
 * 输入参数：void* params
 * 输出参数：
 * 返  回 值：
 * 说       明：
 *********************************************************/
static void proc_verify_account(REMOTE_PROXY_INFO_S *remote_proxy_info, PROXY_PROT_HEADER_S *head_info)
{
    if(CLOUD_CHANNEL_HANDSHAKE != remote_proxy_info->cloud_channel_state)
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "cloud channel does not finish handshake!\r\n");
        return;
    }

    char *buffer = get_ra_buffer_read_pointer(&remote_proxy_info->cloud_read_buffer);
    int len = get_ra_buffer_read_len(&remote_proxy_info->cloud_read_buffer);
    PROXY_PROT_ACCOUNT_S account;
    int ret = 0;

    ret = parse_proxy_protocol_verify_account(buffer, len, &account);
    if(STATE_REMOTE_ACCESS_FAILED == ret)
    {
        cloud_channel_response_with_error(remote_proxy_info, ERR_PARAM_INVALID, "parse Verify_account failed", head_info->msgID, NULL);
        return;
    }

    ret = verify_account(&account);
    if(STATE_REMOTE_ACCESS_FAILED == ret)
    {
        cloud_channel_response_with_error(remote_proxy_info, ERR_VERIFY_ACCOUT, "verify account failed", head_info->msgID, NULL);
        return;
    }
    
    if(0 != cloud_channel_response_verify_account(remote_proxy_info, head_info->msgID, NULL))
    {
        core_log2(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "cloud channel response to verify_account error!session_id:%s, msgID:%s",NULL,head_info->msgID);
        return;
    }
}

static void proc_keepalive_response(REMOTE_PROXY_INFO_S *remote_proxy_info, PROXY_PROT_HEADER_S *head_info)
{
    if(CLOUD_CHANNEL_HANDSHAKE != remote_proxy_info->cloud_channel_state)
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "recv keepalive pong, but cloud channel does not finish handshake!\r\n");
        return;
    }

    remote_proxy_info->keepalive_cnt=0;
    core_log1(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "recv keepalive pong,messagID=%s",head_info->msgID);

    return;
}

/*********************************************************
 * 接口名称：release_cloud_channel_resource
 * 描       述：释放北向连接云端的通道资源
 * 输入参数：void* params
 * 输出参数：
 * 返  回 值：
 * 说       明：接口可重入
 *********************************************************/
static int release_cloud_channel_resource(CLOUD_CHANNEL_PARAMS_S* cloud_channel_params)
{
    void *cloud_connection = cloud_channel_params->cloud_connection;

    //释放云端连接资源
    if(cloud_connection != NULL)
    {
        close_cloud_proxy_channel(cloud_connection);
        cloud_channel_params->cloud_connection = NULL;
    }

    return STATE_SUCCESS;
}

/*********************************************************
 * 接口名称：release_remote_proxy
 * 描       述：释放远程代理通道的所有资源
 * 输入参数：REMOTE_PROXY_INFO_S *remote_proxy_info
 * 输出参数：
 * 返  回 值：
 * 说       明：此接口释放所有连接资源。
 *          包括：北向的云端连接资源，南向的本地服务的链接资源
 *********************************************************/
static int release_remote_proxy(REMOTE_PROXY_INFO_S *remote_proxy_info)
{
    if(CLOUD_CHANNEL_CLOSED == remote_proxy_info->cloud_channel_state)
    {
        return STATE_SUCCESS;
    }

    core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "end the cloud channel.\r\n");

    //释放云端websocket连接资源
    release_cloud_channel_resource(&remote_proxy_info->cloud_channel_params);
    release_all_session_from_list(&remote_proxy_info->session_list);

    //清理其它相关资源
    reset_ra_buffer(&remote_proxy_info->cloud_write_buffer);
    reset_ra_buffer(&remote_proxy_info->cloud_read_buffer);
    remote_proxy_info->cloud_channel_state = CLOUD_CHANNEL_CLOSED;
    remote_proxy_info->keepalive_cnt = 0;

    return STATE_SUCCESS;
}

/*********************************************************
 * 接口名称：cloud_data_proc
 * 描       述：云端数据的处理
 * 输入参数：REMOTE_PROXY_INFO_S *remote_proxy_info
 * 输出参数：
 * 返  回 值：
 * 说       明：cloud_data有一个接收buffer，确保接收数据的完整性
 *          每一个本地服务有一个sendbuff，确保发送给本地服务的数据完整性
 *********************************************************/
static void cloud_data_proc(REMOTE_PROXY_INFO_S *remote_proxy_info)
{
    void *cloud_connection = remote_proxy_info->cloud_channel_params.cloud_connection;
    RA_BUFFER_INFO_S *cloud_read_buffer = &remote_proxy_info->cloud_read_buffer;
    int ret_code = STATE_SUCCESS;
    int is_fin = 0;

    //nopoll尽力处理完所有已经接收的数据（数据已经从socket缓存放入nopoll的缓存中）
    for(;;)
    {
        //取到一个_fin==1的包（之后需要清除接收buffer）
        //取到一个_fin==0的包
        //取不到完整的包
        //取到一个错误包（之后需要清除buffer）
        ret_code = read_cloud_proxy_channel(cloud_connection, cloud_read_buffer, &is_fin);
        if(ret_code == STATE_REMOTE_ACCESS_FAILED)
        {
            //异常退出，需要清理buffer,一般是buffer开辟的不够大
            reset_ra_buffer(cloud_read_buffer);
            return;
        }
        else if(ret_code == STATE_REMOTE_ACCESS_TIMEOUT)
        {
            //确认已经无包可取时退出
            break;
        }

        //不是一个完整的包,则等待下次接收,保证数据完整性
        if (is_fin == 0)
        {
            core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "this websocket message not have Fin flag!\r\n");
            continue;
        }

        //读取自定义的proxy协议的数据头，判断数据类型，分别如下：
        PROXY_PROT_HEADER_S header_info;
        memset(&header_info, 0, sizeof(PROXY_PROT_HEADER_S));
        ret_code = get_remote_access_protocol_header(cloud_read_buffer, &header_info);
        if (STATE_SUCCESS != ret_code)
        {
            //数据包异常，则丢弃，处理下一个包
            reset_ra_buffer(cloud_read_buffer);
            continue;
        }
        
        move_ra_buffer_read_pointer(cloud_read_buffer,header_info.hdr_len);

        //如果协议头中描述的负载长度不等于得到的完整包的负载长度，则作为异常包丢弃
        if(header_info.payload_len != get_ra_buffer_read_len(cloud_read_buffer))
        {
            //数据包异常，则丢弃，处理下一个包
            core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "payload length info is error!\r\n");
            reset_ra_buffer(cloud_read_buffer);
            continue;
        }

        //云端下行数据和命令的处理
        if (header_info.msg_type == MSG_SERVICE_CONSUMER_NEW_SESSION)
        {
            //命令：本地服务session的开启
            new_session(remote_proxy_info, &header_info);
        }
        else if (header_info.msg_type == MSG_SERVICE_CONSUMER_RELEASE_SESSION)
        {
            //命令：则做本地服务session的关闭
            release_session(remote_proxy_info, &header_info);
        }
        else if (header_info.msg_type == MSG_SERVICE_CONSUMER_RAW_PROTOCOL)
        {
            //数据：云端传输给本地服务的数据
            proc_cloud_channel_data(remote_proxy_info, &header_info);
        }
        else if (header_info.msg_type == MSG_RESP_OK)
        {
            //命令：云通道上线后握手协议的response
            proc_cloud_channel_response(remote_proxy_info, &header_info);
        }
        else if (header_info.msg_type ==  MSG_SERVICE_VERIFY_ACCOUNT)
        {
            proc_verify_account(remote_proxy_info, &header_info);
        }
        else if(header_info.msg_type ==  MSG_KEEPALIVE_PONG)
        {
            proc_keepalive_response(remote_proxy_info, &header_info);
        }
        else
        {
            //error
            core_log2(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "recv error websocket package! header %.*s ", &header_info.hdr_len, cloud_read_buffer);
        }

        //处理成功则清除缓存
        reset_ra_buffer(cloud_read_buffer);
    }
}

/*********************************************************
 * 接口名称：local_service_data_proc
 * 描       述：本地服务的数据的处理
 * 输入参数：REMOTE_PROXY_INFO_S *remote_proxy_info
 *          SESSION_INFO_NODE_S  *session_info
 * 输出参数：
 * 返  回 值：
 * 说       明：发送给云通道的数据完整性通过检测nopoll_conn_send_ping完成
 *********************************************************/
static int local_service_data_proc(SESSION_INFO_NODE_S *session_info, void *remote_proxy_info_in)
{
    int recv_len = 0;
    REMOTE_PROXY_INFO_S *remote_proxy_info = (REMOTE_PROXY_INFO_S *)remote_proxy_info_in;
    void *cloud_connection = remote_proxy_info->cloud_channel_params.cloud_connection;
    char common_buffer[DEFAULT_MSG_HDR_LEN] = {0};
    //重置writebuffer
    RA_BUFFER_INFO_S *channel_buffer = &remote_proxy_info->cloud_write_buffer;
    reset_ra_buffer(channel_buffer);

    char *buffer = get_ra_buffer_write_pointer(channel_buffer);
    aiot_sysdep_portfile_t *sysdep = aiot_sysdep_get_portfile();
    if (NULL == sysdep) {
        return STATE_REMOTE_ACCESS_FAILED;
    }
    recv_len = sysdep->core_sysdep_network_recv(session_info->network_handle, (uint8_t *)buffer, (channel_buffer->size - DEFAULT_MSG_HDR_LEN - 4), 10, NULL);
    //接收本地服务的数据
    if (recv_len < 0)
    {
        //接收异常退出
        if((errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN))
        {
            //重试
            return STATE_REMOTE_ACCESS_FAILED;
        }
        else
        {
            core_log2(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "system error:%s. local service exit, release session: %s", strerror(errno),session_info->sessionID);

            send_cloud_channel_release_session_request(remote_proxy_info,NULL,session_info->sessionID);
            release_one_session_from_list(&remote_proxy_info->session_list, session_info->sessionID);
            return STATE_REMOTE_ACCESS_FAILED;
        }
    }
    else if (recv_len == 0)
    {
        return STATE_REMOTE_ACCESS_FAILED;
    }
    if(-1 == move_ra_buffer_write_pointer(channel_buffer, recv_len))
    {
        return STATE_REMOTE_ACCESS_FAILED;
    }
    //获取报文头
    int header_len = splice_proxy_protocol_header(common_buffer,DEFAULT_MSG_HDR_LEN,MSG_SERVICE_PROVIDER_RAW_PROTOCOL, recv_len, NULL, session_info->sessionID);
    if(header_len <= 0)
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "splice local services packets header error!\r\n");
        return STATE_REMOTE_ACCESS_FAILED;
    }

    //拼接报文
    if( 0 != join_content_before_ra_buffer(common_buffer,header_len,channel_buffer))
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "join content before buffer error\r\n");
        return STATE_REMOTE_ACCESS_FAILED;
    }

    /*core_log_hexdump(-0X2,2,(uint8_t *)(channel_buffer->buffer+header_len),(uint32_t)recv_len);*/
    /*发送至云端，如果消息阻塞，则整包丢弃*/
    int writen_len = write_cloud_proxy_channel(cloud_connection, channel_buffer->buffer, get_ra_buffer_read_len(channel_buffer),remote_proxy_info->cloud_channel_params.trans_timeout);
    if (writen_len != get_ra_buffer_read_len(channel_buffer))
    {
        return STATE_REMOTE_ACCESS_FAILED;
    }

    return STATE_SUCCESS;
}

#ifdef  CLOUD_CHANNEL_FD_SET

#include <sys/select.h>
typedef struct
{
    fd_set               *rfds;                                      //可读fd数组，用于记录可读的所有fds
    int                   fd_num;                                     //可读的fds的数目
    SESSION_INFO_NODE_S  *session_array[DEFAULT_SESSION_COUNT];       //可读的fd对应的session，所有session按顺序放入此数组
} ACTIVE_FD_CALLBACK_PARAMS;

typedef struct
{
    fd_set        *rfds;                                      //可读fd数组，用于记录可读的所有fds
    int            max_fd;                                     //最大的fd
} SET_FD_CALLBACK_PARAMS;

/*********************************************************
 * 接口名称：set_local_service_sockets_to_rfds
 * 描       述：记录本地服务中发生可读事件的socket
 * 输入参数：SESSION_INFO_NODE_S *session_info
 *           void *data
 * 输出参数：
 * 返  回 值：
 * 说       明：
 *********************************************************/
static int set_local_service_sockets_to_rfds(SESSION_INFO_NODE_S *session_info, void *data)
{
    SET_FD_CALLBACK_PARAMS *param = (SET_FD_CALLBACK_PARAMS*) data;
    int fd = -1;
    memcpy((void *)&fd, session_info->network_handle, sizeof(fd));
    if (fd > 0)
    {
        FD_SET(fd, param->rfds);

        if (fd > param->max_fd)
        {
            param->max_fd = fd;
        }
    }

    return 0;
}

/*********************************************************
 * 接口名称：init_select_io_array
 * 描       述：初始化多路复用的IO列表
 * 输入参数：REMOTE_PROXY_INFO_S *remote_proxy_info
 * 输出参数：int *maxfd
 * 返  回 值：
 * 说       明：返回最大的fd
 *********************************************************/
static inline int init_select_io_array(REMOTE_PROXY_INFO_S *remote_proxy_info, fd_set *rfds_obj, int *maxfd)
{
    int cloudfd = (int)nopoll_conn_socket(remote_proxy_info->cloud_channel_params.cloud_connection);
    SESSION_LIST_S *session_list = &remote_proxy_info->session_list;

    FD_ZERO(rfds_obj);

    if (cloudfd >= 0)
    {
        FD_SET(cloudfd, rfds_obj);
    }
    else
    {
        //云端通道socket异常需要释放
        return STATE_REMOTE_ACCESS_RESET;
    }

    SET_FD_CALLBACK_PARAMS params;
    memset(&params, 0x0, sizeof(SET_FD_CALLBACK_PARAMS));
    params.max_fd = cloudfd;
    params.rfds = rfds_obj;

    iterate_each_session(session_list, set_local_service_sockets_to_rfds, &params);

    *maxfd = params.max_fd;

    return STATE_SUCCESS;
}

/*********************************************************
 * 接口名称：record_active_local_service_sockets
 * 描       述：记录本地服务中发生可读事件的socket
 * 输入参数：SESSION_INFO_NODE_S *session_info
 *           void *data
 * 输出参数：
 * 返  回 值：
 * 说       明：
 *********************************************************/
static int record_active_local_service_sockets(SESSION_INFO_NODE_S *session_info, void *data)
{
    ACTIVE_FD_CALLBACK_PARAMS *param = (ACTIVE_FD_CALLBACK_PARAMS*) data;
    int fd = -1;
    memcpy((void *)&fd, session_info->network_handle, sizeof(fd));
    if (FD_ISSET(fd, param->rfds) > 0)
    {
        param->session_array[param->fd_num] = session_info;
        param->fd_num++;
    }
    return 0;
}

/*********************************************************
 * 接口名称：proxy_data_proc
 * 描       述：代理的南北向数据的处理
 * 输入参数：void* params
 * 输出参数：
 * 返  回 值：
 * 说       明：接收南北向数据，并向对端进行转发，所有网络IO非阻塞
 *********************************************************/
static int proxy_data_proc(REMOTE_PROXY_INFO_S *remote_proxy_info)
{
    SESSION_LIST_S *session_list = &remote_proxy_info->session_list;
    int maxfd = 0;
    int ret = 0;
    fd_set rfds;
    ACTIVE_FD_CALLBACK_PARAMS params;
    memset(&params, 0x0, sizeof(ACTIVE_FD_CALLBACK_PARAMS));
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    FD_ZERO(&rfds);

    do
    {
        //初始化多路复用的IO列表
        if(STATE_REMOTE_ACCESS_RESET == init_select_io_array(remote_proxy_info, &rfds, &maxfd))
        {
            return STATE_REMOTE_ACCESS_RESET;
        }

        //判断多路复用IO是否有可读数据
        ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (0 == ret)
        {
            //超时没有任何可读事件
            break;
        }
        else if (ret < 0)
        {
            //系统error, 由以下本地和云端通道处理对通道异常进行判断，根据情况对资源进行释放回收
            core_log1(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "failed to select: %s", strerror(errno));
        }

        //ret > 0的处理部分
        //判断fd是否有可读状态
        //判断是否是本地服务可读
        params.rfds = &rfds;
        iterate_each_session(session_list, record_active_local_service_sockets, &params);
        if (params.fd_num > 0)
        {
            //依次读取可读的本地服务socket
            int j = 0;
            for (j = 0; j < params.fd_num; j++)
            {
                local_service_data_proc(params.session_array[j], remote_proxy_info);
            }
        }

        //判断是否是云端服务可读
        if (FD_ISSET(nopoll_conn_socket(remote_proxy_info->cloud_channel_params.cloud_connection), &rfds) > 0)
        {
            //接收处理云端数据
            cloud_data_proc(remote_proxy_info);
        }

        // 更新ping 的超时时间
        aiot_sysdep_portfile_t *sysdep = aiot_sysdep_get_portfile();
        remote_proxy_info->hand_shake_time = sysdep->core_sysdep_time();

    } while (0);

    return STATE_SUCCESS;
}

#else
typedef struct
{
    int                   fd_num;                                     //可读的fds的数目
    SESSION_INFO_NODE_S  *session_array[DEFAULT_SESSION_COUNT];       //可读的fd对应的session，所有session按顺序放入此数组
} ACTIVE_FD_CALLBACK_PARAMS;

static int record_active_local_service_sockets(SESSION_INFO_NODE_S *session_info, void *data)
{
    ACTIVE_FD_CALLBACK_PARAMS *param = (ACTIVE_FD_CALLBACK_PARAMS*) data;
    param->session_array[param->fd_num] = session_info;
    param->fd_num++;
    return 0;
}

static int proxy_data_proc(REMOTE_PROXY_INFO_S *remote_proxy_info)
{
    SESSION_LIST_S *session_list = &remote_proxy_info->session_list;
    ACTIVE_FD_CALLBACK_PARAMS params = { .fd_num = 0 };
    iterate_each_session(session_list, record_active_local_service_sockets, &params);
    if (params.fd_num > 0)
    {
        //依次读取可读的本地服务socket
        int j = 0;
        for (j = 0; j < params.fd_num; j++)
        {
            local_service_data_proc(params.session_array[j], remote_proxy_info);
        }
    }
    cloud_data_proc(remote_proxy_info);
    return STATE_SUCCESS;
}
#endif

int init_remote_proxy_resource(REMOTE_PROXY_INFO_S *remote_proxy_info,ra_handle_t *ra_handle)
{
    //初始化资源
    if (0 != create_ra_buffer(&remote_proxy_info->cloud_read_buffer,DEFAULT_MSG_BUFFER_LEN))
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "cloud channel buffer malloc failed\r\n");
        return STATE_REMOTE_ACCESS_FAILED;
    }

    if (0 != create_ra_buffer(&remote_proxy_info->cloud_write_buffer,DEFAULT_SEND_MSG_BUFFER_LEN))
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "cloud channel buffer malloc failed\r\n");
        return STATE_REMOTE_ACCESS_FAILED;
    }

    init_session_list(&remote_proxy_info->session_list);

    //服务列表初始化
    remote_proxy_info->cloud_channel_params.services_list = splice_local_service_info_content(&ra_handle->local_services);
    if (NULL == remote_proxy_info->cloud_channel_params.services_list)
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "generate local services info string failed\r\n");
        return STATE_REMOTE_ACCESS_FAILED;
    }

    //初始化连接参数
    init_cloud_channel_params(&remote_proxy_info->cloud_channel_params, ra_handle);

    return STATE_SUCCESS;
}

void update_cloud_channel_params(REMOTE_PROXY_INFO_S *remote_proxy_info, ra_handle_t *ra_handle)
{
    //用户开关事件发生,且用户操作的是开操作，即用户触发开关时立即发起重连
    if(0 != ra_handle->has_switch_event && 0 != ra_handle->remote_proxy_channel_switch)
    {
        clean_retry_params(remote_proxy_info);
    }

    //清除事件标记
    ra_handle->has_switch_event = 0;
}

#define RETRY_TIMES_CYCLE 5

/*********************************************************
 * 接口名称：get_wait_time_exp
 * 描       述：获取等待时间的指数
 * 输入参数：int retry_times 重连次数
 * 输出参数：
 * 返  回 值：0~6
 * 说       明：
 *********************************************************/
int get_wait_time_exp(int retry_times)
{
    int exp = retry_times/RETRY_TIMES_CYCLE;
    if(exp > 6)
    {
        exp = 6;
    }
    return exp;
}

/*********************************************************
 * 接口名称：get_wait_time_period
 * 描       述：获取等待时间周期
 * 输入参数：int exp 重连次数
 * 输出参数：
 * 返  回 值：等待周期时间s
 * 说       明：
 *********************************************************/
int get_wait_time_period(int exp)
{
    int i= 1;
    i = i << exp;
    return i;
}

int whether_connect_time_up(REMOTE_PROXY_INFO_S *remote_proxy_info)
{
    uint64_t timeout = get_wait_time_period(get_wait_time_exp(remote_proxy_info->retry_info.retry_times));

    uint64_t tp_now;
    aiot_sysdep_portfile_t *sysdep = aiot_sysdep_get_portfile();
    tp_now = sysdep->core_sysdep_time();
    if(tp_now - remote_proxy_info->retry_info.connect_time >= timeout * 1000)
    {
        return STATE_SUCCESS;
    }
    else
    {
        return STATE_REMOTE_ACCESS_FAILED;
    }
}

static int whether_connected_state_timeout(REMOTE_PROXY_INFO_S *remote_proxy_info)
{
    uint64_t tp_now;
    aiot_sysdep_portfile_t *sysdep = aiot_sysdep_get_portfile();
    tp_now = sysdep->core_sysdep_time();
    if(tp_now - remote_proxy_info->hand_shake_time >= CLOUD_CHANNEL_HANDSHAKE_TIMEOUT * 1000)
    {
        return STATE_SUCCESS;
    }
    return STATE_REMOTE_ACCESS_FAILED;
}

static int cloud_channel_keepalive(REMOTE_PROXY_INFO_S *remote_proxy_info)
{
    if(remote_proxy_info->keepalive_cnt > CLOUD_CHANNEL_KEEPALIVE_CNT_MAX)
    {
        return STATE_REMOTE_ACCESS_FAILED;
    }

    uint64_t tp_now;
    aiot_sysdep_portfile_t *sysdep = aiot_sysdep_get_portfile();
    tp_now = sysdep->core_sysdep_time();
    if(tp_now - remote_proxy_info->hand_shake_time >= 20 * 1000)
    {
        //发送通道保活信号
        send_cloud_channel_keepalive_ping(remote_proxy_info);
        aiot_sysdep_portfile_t *sysdep = aiot_sysdep_get_portfile();
        remote_proxy_info->hand_shake_time = sysdep->core_sysdep_time();
    }
    return STATE_SUCCESS;
}

static void cloud_channel_error_state_proc(REMOTE_PROXY_INFO_S *remote_proxy_info, int remote_proxy_channel_switch)
{
    //错误状态
    core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "cloud channel state error! state\r\n");
    release_remote_proxy(remote_proxy_info);

    //用户关闭时，主动清除重连参数
    clean_retry_params(remote_proxy_info);
}

static void cloud_channel_closed_state_proc(REMOTE_PROXY_INFO_S *remote_proxy_info, int remote_proxy_channel_switch)
{
    static int num = 0;
    if(0 != remote_proxy_channel_switch)
    {
        //判断是否连接时间到
        if(0 != whether_connect_time_up(remote_proxy_info))
        {
            //不到连接时间则退出
            usleep(300000); //300ms
            return;
        }

        //开关标记为开，则创建云端连接
        if(STATE_SUCCESS != create_remote_proxy(remote_proxy_info))
        {
            //更新连接时间和连接次数,等待下次重连
            update_retry_params(remote_proxy_info);
            num++;
            usleep(300000); //300ms

            if(num > 5)
            {
                //如果长时间无法连接运维通道需要重启服务进程
                core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "=======retry to connect remote debug channel error! service exit!=======\r\n");
            }
        }
        else
        {
            num = 0;
        }
    }
    else
    {
        //开关标记为关，则睡眠等待
        usleep(300000); //300ms
        num = 0;
    }

    return;
}

static void cloud_channel_connected_state_proc(REMOTE_PROXY_INFO_S *remote_proxy_info, int remote_proxy_channel_switch)
{
    if(0 != remote_proxy_channel_switch)
    {
        //开关标记为开，则做数据的处理
        if(STATE_REMOTE_ACCESS_RESET == proxy_data_proc(remote_proxy_info))
        {
            //云通道连接异常，释放资源，状态转移到closed状态
            release_remote_proxy(remote_proxy_info);

            //更新参数，等待下次重新发起连接
            update_retry_params(remote_proxy_info);
        }

        //判断connected状态下是否超时，次状态下应该发起handshake鉴权，超时无鉴权则释放连接
        if(0 == whether_connected_state_timeout(remote_proxy_info))
        {
            release_remote_proxy(remote_proxy_info);

            //更新参数，等待下次重新发起连接
            update_retry_params(remote_proxy_info);
        }
    }
    else
    {
        //开关标记为关，释放资源，状态转移到closed状态
        release_remote_proxy(remote_proxy_info);

        //用户关闭时，主动清除重连参数
        clean_retry_params(remote_proxy_info);
    }

    return;
}

static void cloud_channel_hand_shake_state_proc(REMOTE_PROXY_INFO_S *remote_proxy_info, int remote_proxy_channel_switch)
{
    if(0 != remote_proxy_channel_switch)
    {
        //开关标记为开，则做数据的处理
        if(STATE_REMOTE_ACCESS_RESET == proxy_data_proc(remote_proxy_info))
        {
            //释放资源，状态转移到closed状态
            release_remote_proxy(remote_proxy_info);

            //云通道连接异常，主动释放资源
            clean_retry_params(remote_proxy_info);
            usleep(500000);
        }
        else
        {
            //通道保活
            if(0 != cloud_channel_keepalive(remote_proxy_info))
            {
                //开关标记为关，释放资源，状态转移到closed状态
                release_remote_proxy(remote_proxy_info);

                //用户关闭时，主动清除重连参数
                clean_retry_params(remote_proxy_info);
            }
        }
    }
    else
    {
        //开关标记为关，释放资源，状态转移到closed状态
        release_remote_proxy(remote_proxy_info);

        //用户关闭时，主动清除重连参数
        clean_retry_params(remote_proxy_info);
    }

    return;
}


static void _switch_topic_handler(void *handle, const aiot_mqtt_recv_t *packet, void *userdata)
{
    char *status_str = NULL;
    uint32_t status_strlen = 0, status = 0;
    int32_t res;
    ra_handle_t *ra_handle = (ra_handle_t *)userdata;
    if(packet->type == AIOT_MQTTRECV_PUB)
    {
	int32_t payload_len = packet->data.pub.payload_len;
	core_log2(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "_switch_topic_handler payload:%.*s", &payload_len, packet->data.pub.payload);
        res = core_json_value((const char *)packet->data.pub.payload, packet->data.pub.payload_len, "status", strlen("status"), &status_str,
                              &status_strlen);
        if (res < STATE_SUCCESS) {
            return;
        }

        res = core_str2uint(status_str, status_strlen, &status);
        if (res < STATE_SUCCESS) {
            return;
        }

        if(status == 0)
        {
            ra_handle->remote_proxy_channel_switch = 0;
            ra_handle->has_switch_event = 1;
            remote_proxy_event_handle(ra_handle, AIOT_RA_EVT_CLOSE_WEBSOCKET);
        }
        else if(status == 1)
        {
            ra_handle->remote_proxy_channel_switch = 1;
            ra_handle->has_switch_event = 1;
            remote_proxy_event_handle(ra_handle, AIOT_RA_EVT_OPEN_WEBSOCKET);
        }
    }
}
static int32_t _unsub_switch_topic(void *handle)
{
    int32_t res = STATE_SUCCESS;
    ra_handle_t *ra_handle = (ra_handle_t*)handle;
    char cloud_switch_commond_topic[CLOUD_TOPIC_LEN_MAX];

    snprintf(cloud_switch_commond_topic,CLOUD_TOPIC_LEN_MAX,FMT_TOPIC_SWITCH,ra_handle->pk,ra_handle->dn);
    res = aiot_mqtt_unsub(ra_handle->mqtt_handle,cloud_switch_commond_topic);
    if (res < 0) {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "aiot_mqtt_unsub failed\r\n");
        return -1;
    }

    return res;
}

static int32_t _sub_switch_topic(void *handle)
{
    int32_t res = STATE_SUCCESS;
    ra_handle_t *ra_handle = (ra_handle_t*)handle;
    char cloud_switch_commond_topic[CLOUD_TOPIC_LEN_MAX];

    snprintf(cloud_switch_commond_topic,CLOUD_TOPIC_LEN_MAX,FMT_TOPIC_SWITCH,ra_handle->pk,ra_handle->dn);
    res = aiot_mqtt_sub(ra_handle->mqtt_handle,cloud_switch_commond_topic, _switch_topic_handler, 1, handle);
    if (res < 0) {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "aiot_mqtt_sub failed\r\n");
        return -1;
    }

    return res;
}


/*******************************************************************************************
 * 接口名称：remote_proxy_thread
 * 描       述：远程访问的云边代理线程
 * 输入参数：void* params
 * 输出参数：
 * 返  回 值：
 * 说       明：其北向连接云端，南向连接本地服务; 其作为南北数据的转发代理
 *           其中状态机如下所示:
 *                                     +------+    switch==0                 ||
 *                                     |      |    not time to connect cloud ||
 *                                     |      v    create cloud channel fail
 *                                  +--+------+-+
 *                                  |           |
 *                   +--------------+   closed  + <------------------+
 *                   |              |           |                    |
 *                   |              +--+--------+                    |
 * switch==1                   &&      ^                             |
 * it's time to connnect cloud &&      |                             |
 * create cloud channel success        |                             |
 *                   |                 |                     switch==0             ||
 *                   |                 |                     tcp keepalive timeout ||
 *                   |      switch==0               ||       cloud channel error
 *                   |      connected state timeout ||               |
 *                   |      cloud channel error                      |
 *                   v                 |                             |
 *             +-----+-----+           |                       +-----+-----+
 *             |           +-----------+                       |           |
 *             | connected |                                   | handshake |
 *             |           +---------------------------------->+           |
 *             +-+------+--+      recv handshake response      +--+-----+--+
 *               |      ^                                         |     ^
 *               |      |                                         |     |
 *               +------+                                         +-----+
 *      connected state no timeout                           keepalive the normal
 *
 *******************************************************************************************/
void* remote_proxy_thread(void* params)
{
    ra_handle_t *ra_handle = (ra_handle_t *) params;
    REMOTE_PROXY_INFO_S g_remote_proxy_info;
    REMOTE_PROXY_INFO_S *remote_proxy_info = &g_remote_proxy_info;
    memset(remote_proxy_info, 0x0, sizeof(REMOTE_PROXY_INFO_S));
    _sub_switch_topic(params);
    core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "remote proxy thread start!\r\n ");

    //初始化资源
    if(0 != init_remote_proxy_resource(remote_proxy_info,ra_handle))
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "init remote proxy resource error!\r\n");
        return NULL;
    }

    aiot_sysdep_portfile_t *sysdep = aiot_sysdep_get_portfile();
    if (sysdep == NULL) {
        return NULL;
    }
    remote_proxy_info->sysdep = sysdep;
    //初始化重连时间
    remote_proxy_info->retry_info.connect_time = 0;
    //作为代理处理南北向数据，以下为状态机处理内容
    while (1)
    {
        //更新通道参数
        REMOTE_PROXY_STATE_E last_state = remote_proxy_info->cloud_channel_state;
        update_cloud_channel_params(remote_proxy_info, ra_handle);

        if(CLOUD_CHANNEL_CLOSED == remote_proxy_info->cloud_channel_state)
        {
            cloud_channel_closed_state_proc(remote_proxy_info, ra_handle->remote_proxy_channel_switch);
        }
        else if(CLOUD_CHANNEL_CONNECTED == remote_proxy_info->cloud_channel_state)
        {
            cloud_channel_connected_state_proc(remote_proxy_info, ra_handle->remote_proxy_channel_switch);
        }
        else if(CLOUD_CHANNEL_HANDSHAKE == remote_proxy_info->cloud_channel_state)
        {
            cloud_channel_hand_shake_state_proc(remote_proxy_info, ra_handle->remote_proxy_channel_switch);
        }
        else
        {
            cloud_channel_error_state_proc(remote_proxy_info, ra_handle->remote_proxy_channel_switch);
        }
        // 更新线程计数器
        UPDATE_PROXY_THREAD_RUNNING_CNT(remote_proxy_info);

        if(last_state != remote_proxy_info->cloud_channel_state)
        {
            if(remote_proxy_info->cloud_channel_state == CLOUD_CHANNEL_HANDSHAKE)
                remote_proxy_event_handle(ra_handle, AIOT_RA_EVT_CONNECT);
            else if(last_state == CLOUD_CHANNEL_HANDSHAKE)
            {
                remote_proxy_event_handle(ra_handle, AIOT_RA_EVT_DISCONNECT);
            }
        }

        if(1 == ra_handle->pthread_exit_flag)
        {
            release_remote_proxy(&g_remote_proxy_info);
            break;
        }
    }
    release_ra_buffer(&g_remote_proxy_info.cloud_read_buffer);
    release_ra_buffer(&g_remote_proxy_info.cloud_write_buffer);
    sysdep->core_sysdep_mutex_deinit(&g_remote_proxy_info.session_list.list_lock);
    sysdep->core_sysdep_free(remote_proxy_info->cloud_channel_params.services_list);
    _unsub_switch_topic(ra_handle);
    core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "remote proxy thread exit!\r\n");

    return NULL;
}

void remote_proxy_event_handle(ra_handle_t *ra_handle, aiot_ra_event_type type)
{
    aiot_ra_event_t event;
    event.type = type;
    ra_handle->event_handle(ra_handle, &event, ra_handle->userdata);
}
