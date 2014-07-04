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
    struct evbuffer    * inbuf  = evhtp_req_buffer_in(req);
    struct bufferevent * bev    = evhtp_req_get_bev(req);
    size_t               inlen  = evbuffer_get_length(inbuf);
    unsigned char      * outbuf;
    size_t               outlen = 0;


    printf("Uhm...%.*s\n", (int)inlen, evbuffer_pullup(inbuf, inlen));

    outbuf = evhtp_ws_pack(evbuffer_pullup(inbuf, inlen), inlen, &outlen);
    assert(outbuf != NULL);

    printf("Writing %zu\n", outlen);
    bufferevent_write(bev, outbuf, outlen);

    evbuffer_drain(inbuf, inlen);
    /*
     * evbuffer_add_printf(evhtp_req_buffer_out(req), "%s", str);
     * evhtp_send_reply(req, EVHTP_RES_OK);
     */
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

