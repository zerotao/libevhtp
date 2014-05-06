#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

#include <evhtp2/evhtp.h>
#include <evhtp2/ws/evhtp_ws.h>

int
main(int argc, char ** argv) {
    char              out[1024];
    char            * in = "abcd";
    evhtp_ws_parser * p  = evhtp_ws_parser_new();
    int               l  = evhtp_websocket_set_content(in, strlen(in), out, sizeof(out));

    evhtp_ws_parser_run(p, out, (size_t)l);
    printf("%.*s", l, out);

    return 0;
}

