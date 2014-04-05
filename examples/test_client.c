#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <inttypes.h>
#include <evhtp.h>

static void
req_cb(evhtp_req_t * req, void * arg) {
    printf("hi %zu\n", evbuffer_get_length(evhtp_req_buffer_in(req)));
}

static evhtp_res
print_data(evhtp_req_t * req, struct evbuffer * buf, void * arg) {
    printf("Got %zu bytes\n", evbuffer_get_length(buf));

    return EVHTP_RES_OK;
}

static evhtp_res
print_new_chunk_len(evhtp_req_t * req, uint64_t len, void * arg) {
    printf("started new chunk, %" PRIu64 "  bytes\n", len);

    return EVHTP_RES_OK;
}

static evhtp_res
print_chunk_complete(evhtp_req_t * req, void * arg) {
    printf("ended a single chunk\n");

    return EVHTP_RES_OK;
}

static evhtp_res
print_chunks_complete(evhtp_req_t * req, void * arg) {
    printf("all chunks read\n");

    return EVHTP_RES_OK;
}

int
main(int argc, char ** argv) {
    struct event_base * evbase;
    evhtp_conn_t      * conn;
    evhtp_req_t       * req;
    evhtp_hdrs_t      * headers;

    evbase  = event_base_new();
    conn    = evhtp_conn_new(evbase, "75.126.169.52", 80);
    req     = evhtp_req_new(req_cb, evbase);
    headers = evhtp_req_get_headers_out(req);

    evhtp_req_set_hook(req, evhtp_hook_on_read, print_data, evbase);
    evhtp_req_set_hook(req, evhtp_hook_on_new_chunk, print_new_chunk_len, NULL);
    evhtp_req_set_hook(req, evhtp_hook_on_chunk_complete, print_chunk_complete, NULL);
    evhtp_req_set_hook(req, evhtp_hook_on_chunks_complete, print_chunks_complete, NULL);

    evhtp_hdrs_add_header(headers, evhtp_hdr_new("Host", "ieatfood.net", 0, 0));
    evhtp_hdrs_add_header(headers, evhtp_hdr_new("User-Agent", "libevhtp", 0, 0));
    evhtp_hdrs_add_header(headers, evhtp_hdr_new("Connection", "close", 0, 0));

    evhtp_make_req(conn, req, evhtp_method_GET, "/");

    event_base_loop(evbase, 0);
    event_base_free(evbase);

    return 0;
}

