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
struct evhtp_ws_frame_s;
struct evhtp_ws_frame_hdr_s;
struct evhtp_ws_data_s;

typedef struct evhtp_ws_parser_s    evhtp_ws_parser;
typedef struct evhtp_ws_frame_s     evhtp_ws_frame;
typedef struct evhtp_ws_frame_hdr_s evhtp_ws_frame_hdr;
typedef struct evhtp_ws_data_s      evhtp_ws_data;

evhtp_ws_parser * evhtp_ws_parser_new(void);
int               evhtp_ws_gen_handshake(evhtp_kvs_t * hdrs_in, evhtp_kvs_t * hdrs_out);
ssize_t           evhtp_ws_parser_run(evhtp_ws_parser * p, const char * data, size_t len);
evhtp_ws_data   * evhtp_ws_data_new(const char * data, size_t len);
unsigned char   * evhtp_ws_data_pack(evhtp_ws_data * data, size_t * out_len);

#endif

