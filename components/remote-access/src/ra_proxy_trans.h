#ifndef REMOTE_ACCESS_PROXY_TRANS
#define REMOTE_ACCESS_PROXY_TRANS

#include "ra_buffer_mgr.h"
#include "ra_proxy_protocol.h"
#include "ra_proxy_thread.h"

int send_cloud_channel_hand_shake_request(REMOTE_PROXY_INFO_S *remote_proxy_info,const char *service_list);
int get_remote_access_protocol_header(RA_BUFFER_INFO_S *channel_buffer, PROXY_PROT_HEADER_S *hdr);
int send_cloud_channel_release_session_request(REMOTE_PROXY_INFO_S *remote_proxy_info,char *msg_id, char *session_id);
int cloud_channel_response_with_error(REMOTE_PROXY_INFO_S *remote_proxy_info,int code, char *msg, char *msg_id, char *session_id);
int cloud_channel_response_new_session(REMOTE_PROXY_INFO_S *remote_proxy_info, const char *msg_id, const char *session_id);
int cloud_channel_response_release_session(REMOTE_PROXY_INFO_S *remote_proxy_info, const char *msg_id, const char *session_id);
int cloud_channel_response_verify_account(REMOTE_PROXY_INFO_S *remote_proxy_info, const char *msg_id, const char *session_id);
int send_cloud_channel_keepalive_ping(REMOTE_PROXY_INFO_S *remote_proxy_info);

#endif
