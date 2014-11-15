#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

#include "evhtp2/evhtp.h"
#include "evhtp2/ws/evhtp_ws.h"
#ifdef EVHTP_ENABLE_EVTHR
#include "evhtp2/evhtp_thr.h"
#endif

void
testcb(evhtp_req_t * req, void * a) {
    const char         * str    = a;
    struct evbuffer    * resp;
    struct evbuffer    * inbuf  = evhtp_req_buffer_in(req);
    struct bufferevent * bev    = evhtp_req_get_bev(req);
    size_t               inlen  = evbuffer_get_length(inbuf);
    unsigned char      * outbuf;
    size_t               outlen = 0;
    evhtp_ws_data      * ws_data;


    fprintf(stderr, "Uhm...%.*s\n", (int)inlen, evbuffer_pullup(inbuf, inlen));

    ws_data = evhtp_ws_data_new("Hello", 5);
    outbuf  = evhtp_ws_data_pack(ws_data, &outlen);

    resp    = evbuffer_new();
    evbuffer_add(resp, outbuf, outlen);

    evhtp_send_reply_body(req, resp);
}

int
main(int argc, char ** argv) {
    struct event_base * evbase = event_base_new();
    evhtp_t           * htp    = evhtp_new(evbase, NULL);

    evhtp_set_cb(htp, "ws:///ws", testcb, NULL);

    evhtp_bind_socket(htp, "0.0.0.0", 8081, 1024);
    event_base_loop(evbase, 0);

    return 0;
}

