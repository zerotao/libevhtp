#ifndef __EVHTP_WS_H__
#define __EVHTP_WS_H__

/**
 * @brief attempt to find the sec-webSocket-key from the input headers,
 *       append the magic string to it, sha1 encode it, then base64 encode
 *       into the output header "sec-websocket-accept"
 *
 * @param hdrs_in
 * @param hdrs_out
 *
 * @return 0 on success, -1 on error
 */

struct evhtp_ws_parser_s;

typedef struct evhtp_ws_parser_s evhtp_ws_parser;

int evhtp_ws_gen_handshake(evhtp_kvs_t * hdrs_in, evhtp_kvs_t * hdrs_out);
int evhtp_websocket_set_content( const char *data, int data_length, unsigned char *dst, const unsigned int dst_len );

#endif

