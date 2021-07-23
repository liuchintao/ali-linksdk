#include <stdio.h>
#include "core_stdinc.h"
#include "core_string.h"
#include "core_log.h"

#include "aiot_ra_private.h"
#include "ra_buffer_mgr.h"
#include "ra_proxy_channel.h"
#include "ra_proxy_protocol.h"
#include "ra_proxy_thread.h"
#include "ra_proxy_trans.h"

typedef struct
{
    RA_BUFFER_INFO_S *channel_buffer;                      //buffer
    int is_fin;
} HAND_SHAKE_S;


int get_remote_access_protocol_header(RA_BUFFER_INFO_S *channel_buffer, PROXY_PROT_HEADER_S *hdr)
{
    char *buffer = get_ra_buffer_read_pointer(channel_buffer);
    if (0 != parse_proxy_protocol_header(buffer, hdr))
    {
        //此数据包头异常，可以重新开始接收
        core_log1(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "parse proxy header failed: %s", buffer);
        return STATE_REMOTE_ACCESS_FAILED;
    }

    return STATE_SUCCESS;
}

int send_cloud_channel_hand_shake_request(REMOTE_PROXY_INFO_S *remote_proxy_info,const char *service_list)
{
    int header_len = 0;
    int payload_len = 0;
    char common_buffer[DEFAULT_MSG_HDR_LEN] = {0};
    int writen_len = 0;
    int ret_code = STATE_REMOTE_ACCESS_FAILED;

    const char *pk = remote_proxy_info->cloud_channel_params.pk;
    const char *dn = remote_proxy_info->cloud_channel_params.dn;
    const char *ds = remote_proxy_info->cloud_channel_params.ds;
    void *cloud_connection = remote_proxy_info->cloud_channel_params.cloud_connection;
    RA_BUFFER_INFO_S *channel_buffer = &remote_proxy_info->cloud_write_buffer;
    reset_ra_buffer(channel_buffer);

    payload_len = splice_proxy_protocol_hand_shake_payload(channel_buffer->buffer,channel_buffer->size,(char*)pk, (char*)dn, (char*)ds, (char*)service_list);
    if (payload_len <= 0)
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "splice proxy protocol handshake payload failed!\r\n");
        goto end_label;
    }
    if(0 != move_ra_buffer_write_pointer(channel_buffer,payload_len))
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "move buffer write pointer failed!\r\n");
        goto end_label;
    }

    header_len = splice_proxy_protocol_header(common_buffer,DEFAULT_MSG_HDR_LEN,MSG_SERVICE_PROVIDER_CONN_REQ, payload_len, DEFAULT_MSG_ID_HDSK, NULL);
    if(header_len <= 0)
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "splice proxy protocol header failed!\r\n");
        goto end_label;
    }

    core_log2(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "handshake payload:%.*s", &payload_len, channel_buffer->buffer);
    core_log2(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "handshake  header:%.*s", &header_len, common_buffer);

    //拼接报文
    if( 0 != join_content_before_ra_buffer(common_buffer,header_len,channel_buffer))
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "join content before buffer error\r\n");
        return STATE_REMOTE_ACCESS_FAILED;
    }

    payload_len = get_ra_buffer_read_len(channel_buffer);
    core_log2(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "request package:%.*s", &payload_len, channel_buffer->buffer);

    writen_len = write_cloud_proxy_channel(cloud_connection, channel_buffer->buffer, get_ra_buffer_read_len(channel_buffer),remote_proxy_info->cloud_channel_params.trans_timeout);
    if (writen_len != get_ra_buffer_read_len(channel_buffer))
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "handshake send msg failed\r\n");
        goto end_label;
    }

    ret_code = STATE_SUCCESS;

end_label:

    return ret_code;

}

int send_cloud_channel_release_session_request(REMOTE_PROXY_INFO_S *remote_proxy_info,char *msg_id, char *session_id)
{
    void *cloud_connection = remote_proxy_info->cloud_channel_params.cloud_connection;
    int writen_len = 0;
    int header_len = 0;
    RA_BUFFER_INFO_S *channel_buffer = &remote_proxy_info->cloud_write_buffer;
    reset_ra_buffer(channel_buffer);

    header_len = splice_proxy_protocol_header(channel_buffer->buffer,DEFAULT_MSG_HDR_LEN,MSG_SERVICE_CONSUMER_RELEASE_SESSION,0, msg_id, session_id);
    if(header_len <= 0)
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "splice Header error!\r\n");
        return STATE_REMOTE_ACCESS_FAILED;
    }

    if(0 != move_ra_buffer_write_pointer(channel_buffer,header_len))
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "move buffer write pointer failed!\r\n");
        return STATE_REMOTE_ACCESS_FAILED;
    }

    core_log2(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "release session header:%.*s", &header_len,channel_buffer->buffer);

    writen_len = write_cloud_proxy_channel(cloud_connection, channel_buffer->buffer, get_ra_buffer_read_len(channel_buffer),remote_proxy_info->cloud_channel_params.trans_timeout);
    if (writen_len != get_ra_buffer_read_len(channel_buffer))
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "release request send msg failed\r\n");
        return STATE_REMOTE_ACCESS_FAILED;
    }

    return STATE_SUCCESS;
}

int send_cloud_channel_keepalive_ping(REMOTE_PROXY_INFO_S *remote_proxy_info)
{
    void *cloud_connection = remote_proxy_info->cloud_channel_params.cloud_connection;
    int writen_len = 0;
    int header_len = 0;
    RA_BUFFER_INFO_S *channel_buffer = &remote_proxy_info->cloud_write_buffer;
    reset_ra_buffer(channel_buffer);

    remote_proxy_info->keepalive_cnt++;
    core_log2(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "session keepalive ping header:%.*s\r\n", &header_len, channel_buffer->buffer);

    header_len = splice_proxy_protocol_header(channel_buffer->buffer,DEFAULT_MSG_HDR_LEN,MSG_KEEPALIVE_PING,0,NULL, NULL);
    if(header_len <= 0)
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "splice Header error!\r\n");
        return STATE_REMOTE_ACCESS_FAILED;
    }

    if(0 != move_ra_buffer_write_pointer(channel_buffer,header_len))
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "move buffer write pointer failed!\r\n");
        return STATE_REMOTE_ACCESS_FAILED;
    }

    writen_len = write_cloud_proxy_channel(cloud_connection, channel_buffer->buffer, get_ra_buffer_read_len(channel_buffer),remote_proxy_info->cloud_channel_params.trans_timeout);
    if (writen_len != get_ra_buffer_read_len(channel_buffer))
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "release keepalive ping send msg failed\r\n");
        return STATE_REMOTE_ACCESS_FAILED;
    }

    return STATE_SUCCESS;
}

/*********************************************************
 * 接口名称：cloud_channel_response_with_error
 * 描       述：响应云端错误信息
 * 输入参数：REMOTE_PROXY_INFO_S *remote_proxy_info
 * 输出参数：
 * 返  回 值：
 * 说       明：
 *********************************************************/
int cloud_channel_response_with_error(REMOTE_PROXY_INFO_S *remote_proxy_info,int code, char *msg, char *msg_id, char *session_id)
{
    void *cloud_connection = remote_proxy_info->cloud_channel_params.cloud_connection;
    int writen_len = 0;
    int payload_len = 0;
    int header_len = 0;
    char common_buffer[DEFAULT_MSG_HDR_LEN] = {0};
    RA_BUFFER_INFO_S *channel_buffer = &remote_proxy_info->cloud_write_buffer;
    reset_ra_buffer(channel_buffer);

    payload_len = splice_proxy_protocol_response_payload(channel_buffer->buffer,channel_buffer->size,code, NULL, msg);
    if (payload_len <= 0)
    {
        return STATE_REMOTE_ACCESS_FAILED;
    }
    if(0 != move_ra_buffer_write_pointer(channel_buffer,payload_len))
    {
        return STATE_REMOTE_ACCESS_FAILED;
    }
    header_len = splice_proxy_protocol_header(common_buffer,DEFAULT_MSG_HDR_LEN,MSG_RESP_OK,payload_len, msg_id, session_id);
    if(header_len <= 0)
    {
        return STATE_REMOTE_ACCESS_FAILED;
    }

    core_log2(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "reponse  payload:%.*s", &payload_len,channel_buffer->buffer);
    core_log2(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "reponse  header:%.*s", &header_len,common_buffer);

    //拼接报文
    if( 0 != join_content_before_ra_buffer(common_buffer,header_len,channel_buffer))
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "join content before buffer error\r\n");
        return STATE_REMOTE_ACCESS_FAILED;
    }

    writen_len = write_cloud_proxy_channel(cloud_connection, channel_buffer->buffer, get_ra_buffer_read_len(channel_buffer),remote_proxy_info->cloud_channel_params.trans_timeout);
    if (writen_len != get_ra_buffer_read_len(channel_buffer))
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "remote_access_error_response send msg failed\r\n");
        return STATE_REMOTE_ACCESS_FAILED;
    }

    return STATE_SUCCESS;
}

int cloud_channel_response_new_session(REMOTE_PROXY_INFO_S *remote_proxy_info, const char *msg_id, const char *session_id)
{
    void *cloud_connection = remote_proxy_info->cloud_channel_params.cloud_connection;
    int writen_len = 0;
    int payload_len = 0;
    int header_len = 0;
    RA_BUFFER_INFO_S *channel_buffer = &remote_proxy_info->cloud_write_buffer;
    char common_buffer[DEFAULT_MSG_HDR_LEN] = {0};
    reset_ra_buffer(channel_buffer);

    char data[128] = { 0 };
    snprintf(data, sizeof(data), "{\"session_id\": \"%s\"}", session_id);
    payload_len = splice_proxy_protocol_response_payload(channel_buffer->buffer,channel_buffer->size,ERR_TYPE_SUCCESS, data, "new session response");
    if (payload_len <= 0)
    {
        return STATE_REMOTE_ACCESS_FAILED;
    }
    if(0 != move_ra_buffer_write_pointer(channel_buffer,payload_len))
    {
        return STATE_REMOTE_ACCESS_FAILED;
    }

    header_len = splice_proxy_protocol_header(common_buffer,DEFAULT_MSG_HDR_LEN,MSG_RESP_OK,payload_len, (char*)msg_id, (char*)session_id);
    if(header_len <= 0)
    {
        return STATE_REMOTE_ACCESS_FAILED;
    }

    core_log2(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "reponse payload:%.*s", &payload_len,channel_buffer->buffer);
    core_log2(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "reponse header:%.*s", &header_len,common_buffer);

    //拼接报文
    if( 0 != join_content_before_ra_buffer(common_buffer,header_len,channel_buffer))
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "join content before buffer error\r\n");
        return STATE_REMOTE_ACCESS_FAILED;
    }

    writen_len = write_cloud_proxy_channel(cloud_connection, channel_buffer->buffer, get_ra_buffer_read_len(channel_buffer),remote_proxy_info->cloud_channel_params.trans_timeout);
    if (writen_len != get_ra_buffer_read_len(channel_buffer))
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "send new session response failed!\r\n");
        return STATE_REMOTE_ACCESS_FAILED;
    }

    return STATE_SUCCESS;

}

int cloud_channel_response_release_session(REMOTE_PROXY_INFO_S *remote_proxy_info, const char *msg_id, const char *session_id)
{
    void *cloud_connection = remote_proxy_info->cloud_channel_params.cloud_connection;
    RA_BUFFER_INFO_S *channel_buffer = &remote_proxy_info->cloud_write_buffer;
    char common_buffer[DEFAULT_MSG_HDR_LEN] = {0};
    reset_ra_buffer(channel_buffer);
    int writen_len = 0;
    int payload_len = 0;
    int header_len = 0;


    char data[128] = { 0 };
    snprintf(data, sizeof(data), "{\"session_id\": \"%s\"}", session_id);
    payload_len = splice_proxy_protocol_response_payload(channel_buffer->buffer,channel_buffer->size,ERR_TYPE_SUCCESS, data, (char*)"release session response");
    if (payload_len <= 0)
    {
        return STATE_REMOTE_ACCESS_FAILED;
    }
    if(0 != move_ra_buffer_write_pointer(channel_buffer,payload_len))
    {
        return STATE_REMOTE_ACCESS_FAILED;
    }

    header_len = splice_proxy_protocol_header(common_buffer,DEFAULT_MSG_HDR_LEN,MSG_RESP_OK, payload_len, (char*)msg_id, (char*)session_id);
    if(header_len <= 0)
    {
        return STATE_REMOTE_ACCESS_FAILED;
    }

    core_log2(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "reponse payload:%.*s", &payload_len,channel_buffer->buffer);
    core_log2(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "reponse header:%.*s", &header_len,common_buffer);

    //拼接报文
    if( 0 != join_content_before_ra_buffer(common_buffer,header_len,channel_buffer))
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "join content before buffer error\r\n");
        return STATE_REMOTE_ACCESS_FAILED;
    }

    writen_len = write_cloud_proxy_channel(cloud_connection, channel_buffer->buffer, get_ra_buffer_read_len(channel_buffer),remote_proxy_info->cloud_channel_params.trans_timeout);
    if (writen_len != get_ra_buffer_read_len(channel_buffer))
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "send release session response failed!\r\n");
        return STATE_REMOTE_ACCESS_FAILED;
    }

    return STATE_SUCCESS;
}


int cloud_channel_response_verify_account(REMOTE_PROXY_INFO_S *remote_proxy_info, const char *msg_id, const char *session_id)
{
    void *cloud_connection = remote_proxy_info->cloud_channel_params.cloud_connection;
    RA_BUFFER_INFO_S *channel_buffer = &remote_proxy_info->cloud_write_buffer;
    char common_buffer[DEFAULT_MSG_HDR_LEN] = {0};
    reset_ra_buffer(channel_buffer);
    int writen_len = 0;
    int payload_len = 0;
    int header_len = 0;

    payload_len = splice_proxy_protocol_response_payload(channel_buffer->buffer,channel_buffer->size,ERR_TYPE_SUCCESS, NULL, "verify account ok");
    if (payload_len <= 0)
    {
        return STATE_REMOTE_ACCESS_FAILED;
    }
    if(0 != move_ra_buffer_write_pointer(channel_buffer,payload_len))
    {
        return STATE_REMOTE_ACCESS_FAILED;
    }

    header_len = splice_proxy_protocol_header(common_buffer,DEFAULT_MSG_HDR_LEN,MSG_RESP_OK, payload_len, (char*)msg_id, (char*)session_id);
    if(header_len <= 0)
    {
        return STATE_REMOTE_ACCESS_FAILED;
    }

    core_log2(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "reponse payload:%.*s", &payload_len,channel_buffer->buffer);
    core_log2(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "reponse header:%.*s", &header_len,common_buffer);

    //拼接报文
    if( 0 != join_content_before_ra_buffer(common_buffer,header_len,channel_buffer))
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "join content before buffer error\r\n");
        return STATE_REMOTE_ACCESS_FAILED;
    }

    writen_len = write_cloud_proxy_channel(cloud_connection, channel_buffer->buffer, get_ra_buffer_read_len(channel_buffer),remote_proxy_info->cloud_channel_params.trans_timeout);
    if (writen_len != get_ra_buffer_read_len(channel_buffer))
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "send verify_accout response failed!\r\n");
        return STATE_REMOTE_ACCESS_FAILED;
    }

    return STATE_SUCCESS;
}

