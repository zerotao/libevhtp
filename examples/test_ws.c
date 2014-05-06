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
    char              out[65936];
    char              in[65536] = { "A" };
    size_t            p_len     = 0;
    evhtp_ws_parser * p         = evhtp_ws_parser_new();
    evhtp_ws_data   * d         = evhtp_ws_data_new(in, sizeof(in));

    assert(p != NULL);
    assert(d != NULL);

    void * packet = evhtp_ws_data_pack(d, &p_len);
    assert(packet != NULL);

    printf("packed data is %zu\n", p_len);
    return 0;
}

