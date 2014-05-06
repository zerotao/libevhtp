#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

#include <evhtp2/evhtp.h>
#include <evhtp2/ws/evhtp_ws.h>

static int
_begin(evhtp_ws_parser * p) {
    printf("_begin\n");

    return 0;
}

static int
_payload(evhtp_ws_parser * p, const char * data, size_t len) {
    printf("_payload data = %p, len = %zu\n", data, len);
    printf("_payload %.*s\n", (int)len, data);

    return 0;
}

static int
_complete(evhtp_ws_parser * p) {
    printf("_complete\n");

    return 0;
}

static evhtp_ws_hooks hooks = {
    .on_msg_begin    = _begin,
    .on_msg_payload  = _payload,
    .on_msg_complete = _complete
};

int
main(int argc, char ** argv) {
    evhtp_ws_parser * ws_parser;
    evhtp_ws_data   * ws_data;
    void            * ws_packed;
    size_t            ws_packed_len;
    char            * input;

    assert(argc >= 2);

    input     = argv[1];
    assert(input != NULL);

    ws_parser = evhtp_ws_parser_new();
    assert(ws_parser != NULL);

    ws_data   = evhtp_ws_data_new(input, strlen(input));
    assert(ws_data != NULL);

    ws_packed = evhtp_ws_data_pack(ws_data, &ws_packed_len);
    assert(ws_packed != NULL);

    evhtp_ws_parser_run(ws_parser, &hooks, ws_packed, ws_packed_len);

    evhtp_ws_data_free(ws_data);
    free(ws_packed);
    free(ws_parser);

    return 0;
} /* main */

