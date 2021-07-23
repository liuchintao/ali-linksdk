/*
 * remote_access_proxy_thread.h
 *
 *  Created on: 2019年6月27日
 *      Author: weixia.lw
 */

#ifndef ADVANCED_SERVICES_REMOTE_ACCESS_DAEMON_REMOTE_ACCESS_PROXY_THREAD_H_
#define ADVANCED_SERVICES_REMOTE_ACCESS_DAEMON_REMOTE_ACCESS_PROXY_THREAD_H_

#include "aiot_ra_private.h"
#include "ra_buffer_mgr.h"
#include "ra_session_mgr.h"

/*与云端建联配置*/
typedef struct CLOUD_CHANNEL_PARAMS
{
    char         *host;
    char         *port;
    char         *private_key;
    unsigned int        trans_timeout;
    const char         *get_uRL;
    const char         *origin;
    void               *cloud_connection;
    const char         *pk;
    const char         *dn;
    const char         *ds;
    int                 flag;
    LOCAL_SERVICES_S   *local_services;
    char               *services_list;                         //服务列表
    void               *cred;
} CLOUD_CHANNEL_PARAMS_S;

/*远程通道状态*/
typedef enum REMOTE_PROXY_STATE
{
    CLOUD_CHANNEL_CLOSED = 0,
    CLOUD_CHANNEL_CONNECTED,
    CLOUD_CHANNEL_HANDSHAKE,
}REMOTE_PROXY_STATE_E;

typedef struct RETRY_CONNECT_INFO
{
    int                    retry_times;
    uint64_t               connect_time;
}RETRY_CONNECT_INFO_S;

typedef struct REMOTE_PROXY_INFO
{
    aiot_sysdep_portfile_t*   sysdep;                            /*底层依赖回调合集的引用指针 */
    CLOUD_CHANNEL_PARAMS_S   cloud_channel_params;                   //连接云端通道的参数
    REMOTE_PROXY_STATE_E     cloud_channel_state;                    //云通道的连接状态
    uint64_t                 hand_shake_time;                        //握手状态的时间
    SESSION_LIST_S           session_list;                         //建立的session的管理hash表
    RA_BUFFER_INFO_S         cloud_read_buffer;                      //接收云端数据使用的buffer，用于向本地服务转发
    RA_BUFFER_INFO_S         cloud_write_buffer;                     //接收本地数据，向云端转发时使用的buffer
    RETRY_CONNECT_INFO_S     retry_info;
    int                      thread_running_cnt;                     // proxy线程运行计数器,用于判断线程是否正常运行
    int                      keepalive_cnt;                         // proxy线程运行计数器,用于判断线程是否正常运行
} REMOTE_PROXY_INFO_S;

void* remote_proxy_thread(void* params);
void  remote_proxy_event_handle(ra_handle_t *ra_handle, aiot_ra_event_type type);

#endif /* ADVANCED_SERVICES_REMOTE_ACCESS_DAEMON_REMOTE_ACCESS_PROXY_THREAD_H_ */
