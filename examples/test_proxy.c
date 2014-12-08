#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>

#include <evhtp2/evhtp.h>
#include <evhtp2/evhtp_thr.h>
#include <evhtp2/evhtp_parser.h>

int
make_request(struct event_base * evbase,
             evhtp_thr_t       * evthr,
             const char * const  host,
             const short         port,
             const char * const  path,
             evhtp_hdrs_t      * headers,
             evhtp_callback_cb   cb,
             void              * arg) {
    evhtp_conn_t * conn;
    evhtp_req_t  * request;

    conn         = evhtp_conn_new(evbase, host, port);
    evhtp_conn_set_thread(conn, evthr);
    request      = evhtp_req_new(cb, arg);

    evhtp_hdrs_add_header(evhtp_req_get_headers_out(request), evhtp_hdr_new("Host", "localhost", 0, 0));
    evhtp_hdrs_add_header(evhtp_req_get_headers_in(request), evhtp_hdr_new("User-Agent", "libevhtp", 0, 0));
    evhtp_hdrs_add_header(evhtp_req_get_headers_out(request), evhtp_hdr_new("Connection", "close", 0, 0));

    evhtp_hdrs_add_headers(evhtp_req_get_headers_out(request), headers);

    printf("Making backend request...\n");
    evhtp_make_req(conn, request, evhtp_method_GET, path);
    printf("Ok.\n");

    return 0;
}

static void
backend_cb(evhtp_req_t * backend_req, void * arg) {
    evhtp_req_t * frontend_req = (evhtp_req_t *)arg;

    evbuffer_prepend_buffer(evhtp_req_buffer_out(frontend_req), evhtp_req_buffer_in(backend_req));
    evhtp_hdrs_add_headers(evhtp_req_get_headers_out(frontend_req), evhtp_req_get_headers_in(backend_req));

    /*
     * char body[1024] = { '\0' };
     * ev_ssize_t len = evbuffer_copyout(frontend_req->buffer_out, body, sizeof(body));
     * printf("Backend %zu: %s\n", len, body);
     */

    evhtp_send_reply(frontend_req, EVHTP_RES_OK);
    evhtp_req_resume(frontend_req);
}

static void
frontend_cb(evhtp_req_t * req, void * arg) {
    evhtp_conn_t    * conn;
    evhtp_thr_t     * thr;
    evhtp_uri_t     * uri;
    evhtp_path_t    * path;

    conn = evhtp_req_get_conn(req);
    thr = evhtp_conn_get_thread(conn);

    printf("  Received frontend request on thread %p... ", thr);

    /* Pause the frontend request while we run the backend requests. */
    evhtp_req_pause(req);

    path = evhtp_uri_get_path(evhtp_req_get_uri(req));
    make_request(evhtp_conn_get_evbase(conn),
                 evhtp_conn_get_thread(conn),
                 "127.0.0.1", 80,
                 evhtp_path_get_full(path),
                 evhtp_req_get_headers_in(req), backend_cb, req);
}

/* Terminate gracefully on SIGTERM */
void
sigterm_cb(int fd, short event, void * arg) {
    struct event_base     * evbase = (struct event_base *)arg;
    struct timeval tv     = { .tv_usec = 100000, .tv_sec = 0 }; /* 100 ms */

    event_base_loopexit(evbase, &tv);
}

void
init_thread_cb(evhtp_t * htp, evhtp_thr_t * thr, void * arg) {
    static int aux = 0;

    printf("Spinning up a thread: %d\n", ++aux);
    evhtp_thr_set_aux(thr, &aux);
}

int
main(int argc, char ** argv) {
    struct event *ev_sigterm;
    struct event_base * evbase  = event_base_new();
    evhtp_t     * evhtp   = evhtp_new(evbase, NULL);

    evhtp_set_gencb(evhtp, frontend_cb, NULL);

#if 0
#ifndef EVHTP_DISABLE_SSL
    evhtp_ssl_cfg_t scfg1 = { 0 };

    scfg1.pemfile  = "./server.pem";
    scfg1.privfile = "./server.pem";

    evhtp_ssl_init(evhtp, &scfg1);
#endif
#endif

    evhtp_use_threads(evhtp, init_thread_cb, 8, NULL);
#ifndef WIN32
    ev_sigterm = evsignal_new(evbase, SIGTERM, sigterm_cb, evbase);
    evsignal_add(ev_sigterm, NULL);
#endif
    evhtp_bind_socket(evhtp, "0.0.0.0", 8081, 1024);
    event_base_loop(evbase, 0);

    printf("Clean exit\n");
    return 0;
}

