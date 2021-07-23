/*
 * remote_access_proxy_protocol_packet.c
 *
 *  Created on: 2019年6月29日
 *      Author: weixia.lw
 */
#include <stdio.h>
#include "core_stdinc.h"
#include "core_string.h"
#include "core_log.h"
#include "core_sha256.h"

#include "aiot_ra_private.h"
#include "ra_proxy_channel.h"
#include "ra_proxy_protocol.h"


int splice_proxy_protocol_header(char* buffer, int size, int msg_type, int payload_len, char *msg_id, char *token)
{
    aiot_sysdep_portfile_t *sysdep = aiot_sysdep_get_portfile();
    if (NULL == sysdep) {
       return -1;
    }
    long time = sysdep->core_sysdep_time() / 1000;
    memset(buffer, 0, size);
    int ret = snprintf(buffer, size - 1, MSG_HEAD_FMT, msg_type, payload_len, msg_id == NULL ? rand_string_static() : msg_id, time, token == NULL ? "" : token);
    return ret;
}

int splice_proxy_protocol_response_payload(char* buffer, int size, int code, char *data, char *msg)
{
    memset(buffer, 0, size);
    int ret = snprintf(buffer, size - 1, MSG_RESPONSE_FMT, code, !msg ? "null" : msg, !data ? "null" : data);

    return ret;
}

#define HMAC_SHA256_BYTES 32
static char *calc_sign(char *uuid, char *dn, char *pk, char *ds)
{
    static char *format = "clientId%sdeviceName%sproductKey%stimestamp%lu";
    static unsigned char msg[DEFAULT_MSG_HDR_LEN] = { 0 };
    uint8_t mac[HMAC_SHA256_BYTES];
    static char ret[DEFAULT_MSG_HDR_LEN] = { 0 };
    aiot_sysdep_portfile_t *sysdep = aiot_sysdep_get_portfile();
    if (NULL == sysdep) {
       return NULL;
    }
    long time = sysdep->core_sysdep_time() / 1000;

    memset(msg, 0, sizeof(msg));
    memset(mac, 0, sizeof(mac));
    memset(ret, 0, sizeof(ret));

    snprintf((char *) msg, sizeof(msg), format, uuid, dn, pk, time);
    core_log1(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "sign string is :  %s", msg);
    core_hmac_sha256(msg, strlen((char *) msg), (unsigned char *) ds, strlen((char *) ds) + 1, mac);
    //hmac_sha256(mac, msg, strlen((char *) msg), (unsigned char *) ds, strlen((char *) ds) + 1);
    int j = 0;
    for (j = 0; j < HMAC_SHA256_BYTES; j++)
        sprintf(ret + strlen(ret), "%02x", mac[j]);

    return ret;
}

int splice_proxy_protocol_hand_shake_payload(char* buffer, int size, char *pk, char *dn, char *ds, char *service_meta)
{
    int msg_len = 0;
    char *local_ip = "";
    char *local_mac = "";
    char *sign = NULL;
    static char *g_uuid = "alibaba_iot";

    sign = calc_sign(g_uuid, dn, pk, ds);

    if (!sign)
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "failed to sign\r\n");
        return -1;
    }

    msg_len = strlen(MSG_HDSK_FMT) + strlen(g_uuid) + strlen(pk) + strlen(dn) + strlen(VERSION) + strlen(local_ip) + strlen(local_mac) + strlen(service_meta) + strlen(sign) + 1;
    if (msg_len >= size)
    {
        core_log(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "cloud channel hand shake payload is longer than buffer\r\n");
        return -1;
    }

    memset(buffer, 0, size);
    int ret = snprintf(buffer, msg_len, MSG_HDSK_FMT, g_uuid, pk, dn, VERSION, local_ip, local_mac, service_meta, sign);

    return ret;
}

int parse_proxy_protocol_hand_shake_response(char *buf, int buf_len, int *code)
{
    char *value = NULL;
    uint32_t value_len = 0;
    int32_t res = STATE_SUCCESS;
    uint32_t value_uint;

    if ((res = core_json_value(buf, buf_len, "code", strlen("code"),
                               &value, &value_len)) < 0 ||
        (res = core_str2uint(value, value_len, &value_uint) < 0)) {
        core_log1(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "cloud response packet error: %s ", buf);
        return STATE_REMOTE_ACCESS_FAILED;
    }
    *code = value_uint;
    return STATE_SUCCESS;
}

int parse_proxy_protocol_header(char *buf, PROXY_PROT_HEADER_S *hdr)
{
    int hdr_len = 0;
    uint32_t ret_len = 0, value = 0;
    char *ret = NULL, *hdr_start = NULL, *hdr_end = NULL;
    int32_t res = STATE_SUCCESS;
    if (!buf || !hdr)
    {
        return STATE_REMOTE_ACCESS_FAILED;
    }

    if (buf[0] != '{')
    {
        goto _exit;
    }

    hdr_start = buf;

    hdr_end = strchr(buf, '}');
    if (hdr_end == NULL)
    {
        goto _exit;
    }
    hdr_len = hdr_end - hdr_start + 1;

    if ((res = core_json_value(hdr_start, hdr_len, "msg_type", strlen("msg_type"), &ret, &ret_len)) < 0) {
    	goto _exit;
    }
    core_str2uint(ret, ret_len, &value);
    hdr->msg_type = value;

    if ((res = core_json_value(hdr_start, hdr_len, "service_type", strlen("service_type"), &ret, &ret_len)) == STATE_SUCCESS) {
        core_str2uint(ret, ret_len, &value);
        hdr->srv_type = value;
    }

    if ((res = core_json_value(hdr_start, hdr_len, "payload_len", strlen("payload_len"), &ret, &ret_len)) < 0) {
    	goto _exit;
    }
    core_str2uint(ret, ret_len, &value);
    hdr->payload_len = value;

    if ((res = core_json_value(hdr_start, hdr_len, "msg_id", strlen("msg_id"), &ret, &ret_len)) == STATE_SUCCESS) {
    	strncpy(hdr->msgID, ret, ret_len < 63 ? ret_len : 63);
    }

    if ((res = core_json_value(hdr_start, hdr_len, "timestamp", strlen("timestamp"), &ret, &ret_len)) == STATE_SUCCESS) {
        core_str2uint(ret, ret_len, &value);
        hdr->timestamp = value;
    }

    if ((res = core_json_value(hdr_start, hdr_len, "token", strlen("token"), &ret, &ret_len)) == STATE_SUCCESS) {
        strncpy(hdr->token, ret, ret_len < 63 ? ret_len : 63);
    }

    hdr->hdr_len = hdr_end - hdr_start + sizeof("\r \r ");

    return STATE_SUCCESS;
_exit:
    core_log1(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "header json formate error:  %s \r\n", buf);
    return STATE_REMOTE_ACCESS_FAILED;
}

void parse_proxy_protocol_new_session_payload(char *buf, int buf_len, PROXY_PROT_SESSION_PARAMS_S *session_params)
{
    char *ret = NULL;
    uint32_t len_val = 0,value = 0;
    int32_t res = STATE_SUCCESS;

    if (!buf)
    {
        return;
    }

    core_log2(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "new session payload: %.*s\r\n", &buf_len,buf);
    //default configure.
    strncpy(session_params->name, "ssh_localhost", sizeof(session_params->name) - 1);
    strncpy(session_params->type, "SSH", sizeof(session_params->type) - 1);
    strncpy(session_params->ip, "127.0.0.1", sizeof(session_params->ip) - 1);
    session_params->port = 22;

    //read from cloud.
    if ((res = core_json_value(buf, buf_len, "service_name", strlen("service_name"), &ret, &len_val)) == STATE_SUCCESS) {
        memset(session_params->name, 0, sizeof(session_params->name));
        strncpy(session_params->name, ret, len_val > sizeof(session_params->name) - 1 ? sizeof(session_params->name) - 1 : len_val);
    }

    if ((res = core_json_value(buf, buf_len, "service_type", strlen("service_type"), &ret, &len_val)) == STATE_SUCCESS) {
        memset(session_params->type, 0, sizeof(session_params->type));
        strncpy(session_params->type, ret, len_val > sizeof(session_params->type) - 1 ? sizeof(session_params->type) - 1 : len_val);
    }

    if ((res = core_json_value(buf, buf_len, "service_ip", strlen("service_ip"), &ret, &len_val)) == STATE_SUCCESS) {
        memset(session_params->ip, 0, sizeof(session_params->ip));
        strncpy(session_params->ip, ret, len_val > sizeof(session_params->ip) - 1 ? sizeof(session_params->ip) - 1 : len_val);
    }

    if ((res = core_json_value(buf, buf_len, "service_port", strlen("service_port"), &ret, &len_val)) == STATE_SUCCESS) {
        core_str2uint(ret, len_val, &value);
        session_params->port  = value;
    }
}

int parse_proxy_protocol_verify_account(char *buf, int buf_len, PROXY_PROT_ACCOUNT_S *account)
{
    char *ret = NULL;
    uint32_t len_val = 0;
    int32_t res = STATE_SUCCESS;

    if ((res = core_json_value(buf, buf_len, "username", strlen("username"), &ret, &len_val)) == STATE_SUCCESS) {
        core_log1(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "verify account body is invalid: %s \r\n", buf);
        goto end_label;
    }

    memset(account->user, 0x00, sizeof(account->user));
    if(len_val > sizeof(account->user) -1)
    {
        core_log1(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "account:username is too long: %s \r\n", buf);
        goto end_label;
    }
    strncpy(account->user, ret, len_val);
    
    if ((res = core_json_value(buf, buf_len, "password", strlen("password"), &ret, &len_val)) == STATE_SUCCESS) {
        core_log1(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "verify account body is invalid: %s \r\n", buf);
        goto end_label;
    }
   
    memset(account->passwd, 0x00, sizeof(account->passwd));
    if(len_val > sizeof(account->passwd) -1)
    {
        core_log1(aiot_sysdep_get_portfile(), STATE_REMOTE_ACCESS_BASE, "account:password is too long: %s \r\n", buf);
        goto end_label;
    }
    strncpy(account->passwd, ret, len_val);

    return STATE_SUCCESS;

end_label:
    return STATE_REMOTE_ACCESS_FAILED;

}


char *rand_string_static()
{
    aiot_sysdep_portfile_t *sysdep = aiot_sysdep_get_portfile();
    static char str[32];
    uint8_t rand_value[32];
    size_t size = sizeof(str);
    const char charset[] = "abcdefghijklmnopqrstuvwxyz_aBCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    sysdep->core_sysdep_rand(rand_value, size);
    memset(str, 0, sizeof(str));
    if (size) {
        --size;
        size_t n = 0;
        for (n = 0; n < size; n++) {
            int key = rand_value[n] % (int) (sizeof(charset) - 1);
            str[n] = charset[key];
        }
        str[size] = '\0';
    }
    return str;
}
