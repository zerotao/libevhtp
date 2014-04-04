#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <inttypes.h>
#include <evhtp.h>

static void
request_cb(evhtp_request_t * req, void * arg) {
    printf("hi %zu\n", evbuffer_get_length(evhtp_request_buffer_in(req)));
}

static evhtp_res
print_data(evhtp_request_t * req, struct evbuffer * buf, void * arg) {
    printf("Got %zu bytes\n", evbuffer_get_length(buf));

    return EVHTP_RES_OK;
}

static evhtp_res
print_new_chunk_len(evhtp_request_t * req, uint64_t len, void * arg) {
    printf("started new chunk, %" PRIu64 "  bytes\n", len);

    return EVHTP_RES_OK;
}

static evhtp_res
print_chunk_complete(evhtp_request_t * req, void * arg) {
    printf("ended a single chunk\n");

    return EVHTP_RES_OK;
}

static evhtp_res
print_chunks_complete(evhtp_request_t * req, void * arg) {
    printf("all chunks read\n");

    return EVHTP_RES_OK;
}

int
main(int argc, char ** argv) {
    struct event_base  * evbase;
    evhtp_connection_t * conn;
    evhtp_request_t    * request;
    evhtp_headers_t    * headers;

    evbase  = event_base_new();
    conn    = evhtp_connection_new(evbase, "75.126.169.52", 80);
    request = evhtp_request_new(request_cb, evbase);
    headers = evhtp_request_get_headers_out(request);

    evhtp_request_set_hook(request, evhtp_hook_on_read, print_data, evbase);
    evhtp_request_set_hook(request, evhtp_hook_on_new_chunk, print_new_chunk_len, NULL);
    evhtp_request_set_hook(request, evhtp_hook_on_chunk_complete, print_chunk_complete, NULL);
    evhtp_request_set_hook(request, evhtp_hook_on_chunks_complete, print_chunks_complete, NULL);

    evhtp_headers_add_header(headers, evhtp_header_new("Host", "ieatfood.net", 0, 0));
    evhtp_headers_add_header(headers, evhtp_header_new("User-Agent", "libevhtp", 0, 0));
    evhtp_headers_add_header(headers, evhtp_header_new("Connection", "close", 0, 0));

    evhtp_make_request(conn, request, evhtp_method_GET, "/");

    event_base_loop(evbase, 0);
    event_base_free(evbase);

    return 0;
}

