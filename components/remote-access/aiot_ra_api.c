/**
 * @file aiot_ra_api.c
 * @brief remote-access模块的API接口实现, 提供获取utc时间的能力
 *
 * @copyright Copyright (C) 2015-2020 Alibaba Group Holding Limited
 *
 */
#include "aiot_ra_private.h"

#include "core_stdinc.h"
#include "core_log.h"
#include "aiot_sysdep_api.h"
#include "aiot_state_api.h"
#include "aiot_ra_api.h"
#include "ra_proxy_thread.h"

void *aiot_ra_init(void)
{
    aiot_sysdep_portfile_t *sysdep = NULL;
    ra_handle_t *ra_handle = NULL;
    sysdep = aiot_sysdep_get_portfile();
    if (NULL == sysdep) {
       return NULL;
    }

    ra_handle = sysdep->core_sysdep_malloc(sizeof(ra_handle_t), REMOTE_ACCESS_MODULE_NAME);
    if (ra_handle == NULL) {
       return NULL;
    }
    memset(ra_handle, 0, sizeof(ra_handle_t));
    CORE_INIT_LIST_HEAD(&ra_handle->local_services.service_list);
    return ra_handle;
}

static void _release_all_service_info(LOCAL_SERVICES_S *local_services)
{
    aiot_sysdep_portfile_t *sysdep = NULL;
    sysdep = aiot_sysdep_get_portfile();
    if (NULL == sysdep) {
       return;
    }
    LOCAL_SERVICE_NODE_S *item = NULL, *next = NULL;
    core_list_for_each_entry_safe(item, next, &local_services->service_list, node, LOCAL_SERVICE_NODE_S)
    {
        core_list_del(&item->node);
        sysdep->core_sysdep_free(item);
    }
}
int32_t aiot_ra_setopt(void *handle, aiot_ra_option_t option, void *data)
{
//    int32_t res = STATE_SUCCESS;
    ra_handle_t *ra_handle = (ra_handle_t*)handle;

    if (ra_handle == NULL || data == NULL) {
        return STATE_USER_INPUT_NULL_POINTER;
    }
    if (option >= AIOT_RAOPT_MAX) {
        return STATE_USER_INPUT_OUT_RANGE;
    }

    switch(option)
    {
    case AIOT_RAOPT_MQTT_HANDLE:
        ra_handle->mqtt_handle = data;
        break;
    case AIOT_RAOPT_EVENT_HANDLER:
        ra_handle->event_handle = (aiot_ra_event_handler_t)data;
        break;
    case AIOT_RAOPT_USERDATA:
        ra_handle->userdata = data;
        break;
    case AIOT_RAOPT_PRODUCT_KEY:
        strncpy(ra_handle->pk, (char *)data, IIOT_PRODUCT_KEY_LEN_MAX - 1);
        break;
    case AIOT_RAOPT_DEVICE_NAME:
        strncpy(ra_handle->dn, (char *)data, IIOT_DEVICE_NAME_LEN_MAX - 1);
        break;
    case AIOT_RAOPT_DEVICE_SECRET:
        strncpy(ra_handle->ds, (char *)data, IIOT_DEVICE_SECRET_MAX - 1);
        break;
    case AIOT_RAOPT_NETWORK_CRED:{
            aiot_sysdep_portfile_t *sysdep = aiot_sysdep_get_portfile();
            if (ra_handle->cred != NULL) {
                sysdep->core_sysdep_free(ra_handle->cred);
                ra_handle->cred = NULL;
            }
            ra_handle->cred = sysdep->core_sysdep_malloc(sizeof(aiot_sysdep_network_cred_t), REMOTE_ACCESS_MODULE_NAME);
            if (ra_handle->cred != NULL) {
                memset(ra_handle->cred, 0, sizeof(aiot_sysdep_network_cred_t));
                memcpy(ra_handle->cred, data, sizeof(aiot_sysdep_network_cred_t));
            } else {
                return STATE_SYS_DEPEND_MALLOC_FAILED;
            }
        }
        break;
    case AIOT_RAOPT_CLOUD_HOST:
        strncpy(ra_handle->cloud_host, (char *)data, (HOST_LEN_MAX - 1));
        break;
    case AIOT_RAOPT_CLOUD_PORT:
        strncpy(ra_handle->cloud_port, (char *)data, (PORT_LEN_MAX - 1));
        break;
    default:
        break;
    }

    return STATE_SUCCESS;
}
int32_t aiot_ra_deinit(void **handle)
{
    if(NULL == handle || NULL == *handle)
    {
       return STATE_USER_INPUT_OUT_RANGE;
    }

    ra_handle_t *ra_handle = *(ra_handle_t**)handle;
    aiot_sysdep_portfile_t *sysdep = aiot_sysdep_get_portfile();
    if (NULL == sysdep) {
       return STATE_REMOTE_ACCESS_FAILED;
    }

    if (ra_handle->cred != NULL) {
        sysdep->core_sysdep_free(ra_handle->cred);
        ra_handle->cred = NULL;
    }

    _release_all_service_info(&ra_handle->local_services);
    sysdep->core_sysdep_free(*handle);
    return STATE_SUCCESS;
}
void* aiot_ra_start(void *handle)
{
    ra_handle_t *ra_handle = (ra_handle_t*)handle;
    static int32_t result;
    if(NULL == ra_handle)
    {
        result = STATE_USER_INPUT_NULL_POINTER;
        return &result;
    }
#if defined(__linux__) && defined(__GLIBC__)
    result = STATE_SUCCESS;
#else
    result = STATE_REMOTE_ACCESS_SYSTEM_NOT_LINUX;
    return &result;
#endif
    if(NULL == ra_handle->mqtt_handle)
    {
        result = STATE_REMOTE_ACCESS_MISSING_MQTT_HADNL;
    }
    else if(0 == strnlen(ra_handle->pk, IIOT_PRODUCT_KEY_LEN_MAX))
    {
        result = STATE_REMOTE_ACCESS_MISSING_PRODUCT_KEY;
    }
    else if(0 == strnlen(ra_handle->dn, IIOT_DEVICE_NAME_LEN_MAX))
    {
        result = STATE_REMOTE_ACCESS_MISSING_DEVICE_NAME;
    }
    else if(0 == strnlen(ra_handle->ds, IIOT_DEVICE_SECRET_MAX))
    {
        result = STATE_REMOTE_ACCESS_MISSING_DEVICE_SECRET;
    }
    else if(0 == strnlen(ra_handle->cloud_host, HOST_LEN_MAX))
    {
        result = STATE_REMOTE_ACCESS_CLOUD_HOST;
    }
    else if(0 == strnlen(ra_handle->cloud_port, PORT_LEN_MAX))
    {
        result = STATE_REMOTE_ACCESS_CLOUD_PORT;
    }
    else
    {
        remote_proxy_thread(handle);
        result = STATE_SUCCESS;
    }
    
    return &result;
}

int32_t  aiot_ra_stop(void *handle)
{
    ra_handle_t *ra_handle = (ra_handle_t*)handle;
    if(NULL == ra_handle)
    {
        return STATE_USER_INPUT_NULL_POINTER;
    }

    ra_handle->pthread_exit_flag = 1;
    return STATE_SUCCESS;
}
