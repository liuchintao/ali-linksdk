/*
 * aiot_ra_api.h
 *
 *  Created on: 2020年12月17日
 *      Author: miaozhaoxia
 */

#ifndef _AIOT_RA_PRIVATE_H_
#define _AIOT_RA_PRIVATE_H_
#include "core_stdinc.h"
#include "core_sysdep.h"
#include "core_list.h"
#include "aiot_ra_api.h"
#define VERSION "2.1"

#define REMOTE_ACCESS_MODULE_NAME "REMOTE-ACCESS"
#define DEFAULT_MSG_ID_HDSK "msg_id_for_handshake"

#define IIOT_DEVICE_NAME_LEN_MAX (32 + 8)
#define IIOT_PRODUCT_KEY_LEN_MAX (32 + 8)
#define IIOT_DEVICE_SECRET_MAX (64 + 8)
#define HOST_LEN_MAX             (128+8)
#define PORT_LEN_MAX             (8+8)
#define PATH_NAME_LEN_MAX        (64+8)
#define VERSION_NAME_LEN_MAX     (32+8)

#define CLOUD_TOPIC_LEN_MAX 128


#define DEFAULT_LEN_PORT         5
#define DEFAULT_MSG_HDR_LEN      1024
#define DEFAULT_LEN_USER_NAME    256
#define DEFAULT_LEN_PASSWORD     256

#define DEFAULT_SEND_MSG_BUFFER_LEN (5 * DEFAULT_MSG_HDR_LEN)
#define DEFAULT_MSG_BUFFER_LEN (5 * DEFAULT_MSG_HDR_LEN)

#define KEEP_ALIVE_INTERVAL  5
#define KEEP_ALIVE_COUNT     3

#define SEND_WAITING_PERIOD_MS 50

#define SERVICE_LIST_MAX_CNT  20

#define DEFAULT_LEN_SERVICE_NAME 32
#define DEFAULT_LEN_SERVICE_TYPE 16
#define DEFAULT_LEN_IP           24

/**
 * @brief 本地服务类型的抽象描述
 *
 */
typedef struct REMOTE_SERVICE_NODE {
    /**
     * @brief 服务类型
     */
    char                        type[DEFAULT_LEN_SERVICE_TYPE];
    /**
     * @brief 服务名称
     */
    char                        name[DEFAULT_LEN_SERVICE_NAME];
    /**
     * @brief 服务IP地址
     */
    char                        ip[DEFAULT_LEN_IP];
    /**
     * @brief 服务端口号
     */
    unsigned int                port;
    /**
     * @brief 服务链表，用户不用关心
     */
    struct core_list_head       node;
}LOCAL_SERVICE_NODE_S;

typedef struct
{
    unsigned int        		service_count;
    struct core_list_head       service_list;   //远程服务信息链表，其node为_lOCAL_SERVICE_NODE_S
}LOCAL_SERVICES_S;

typedef struct {
    void*                     mqtt_handle;
    aiot_ra_event_handler_t   event_handle;
    void*                     userdata;                          /* 组件调用入参之一 */
    char                      pk[IIOT_PRODUCT_KEY_LEN_MAX];      //云端PK
    char                      dn[IIOT_DEVICE_NAME_LEN_MAX];      //云端DN
    char                      ds[IIOT_DEVICE_SECRET_MAX];        //云端DS
    char                      cloud_host[HOST_LEN_MAX];           //远程连接通道云端服务地址，可以是域名
    char                      cloud_port[PORT_LEN_MAX];           //远程连接通道云端服务端口
    unsigned int              remote_proxy_channel_switch;          //远程代理通道的开关
    unsigned int              has_switch_event;                    //是否有开关事件
    LOCAL_SERVICES_S          local_services;                     //远程服务信息
    char                      version[VERSION_NAME_LEN_MAX];     //版本号
    void                      *cred;
    unsigned int              pthread_exit_flag;                 //线程退出需求标志
} ra_handle_t;

#endif /* ADVANCED_SERVICES_REMOTE_ACCESS_DAEMON_REMOTE_ACCESS_PARAMS_H_ */

