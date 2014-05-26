#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "evhtp2/evhtp.h"
#ifdef EVHTP_ENABLE_EVTHR
#include "evhtp2/evhtp_thr.h"
#endif

void
testcb(evhtp_req_t * req, void * a) {
    const char * str = a;

    printf("Uhm...\n");
    evbuffer_add_printf(evhtp_req_buffer_out(req), "%s", str);
    evhtp_send_reply(req, EVHTP_RES_OK);
}

int
main(int argc, char ** argv) {
    struct event_base * evbase = event_base_new();
    evhtp_t           * htp    = evhtp_new(evbase, NULL);

    evhtp_set_cb(htp, "/ws", NULL, NULL);
    evhtp_set_cb(htp, "/simple/", testcb, "simple");
    evhtp_set_cb(htp, "/1/ping", testcb, "one");
    evhtp_set_cb(htp, "/1/ping.json", testcb, "two");

#ifdef EVHTP_ENABLE_EVTHR
    evhtp_use_threads(htp, NULL, 4, NULL);
#endif
    evhtp_bind_socket(htp, "0.0.0.0", 8081, 1024);

    event_base_loop(evbase, 0);
    evhtp_unbind_socket(htp);
    evhtp_free(htp);
    event_base_free(evbase);

    return 0;
}

