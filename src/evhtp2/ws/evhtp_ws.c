/*
 * While this looks nothing like the original code, my initial point of
 * reference was from Marcin Kelar's parser. His license is included here.
 *
 * Marcin originally had his code under the GPL license, I kept seeing his code
 * referenced in other projects, but could not find the original (more
 * specifically, the original license). I ended up finding his email
 * address and asked if I could use it with a less restrictive license.
 * He responded immediately and said yes, and he did! That's an awesome
 * example of the OSS world. Thank you very much Mr. Kelar.
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2012-2014 Marcin Kelar
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * The original API can be found here:
 * https://github.com/OrionExplorer/c-websocket
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

#include "evhtp2/internal.h"
#include "../evhtp.h"
#include "base.h"
#include "sha1.h"
#include "evhtp_ws.h"

#define EVHTP_WS_MAGIC       "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define EVHTP_WS_MAGIC_SZ    36
#define PARSER_STACK_MAX     8192

struct evhtp_ws_frame_hdr_s {
    uint8_t fin    : 1,
            rsv1   : 1,
            rsv2   : 1,
            rsv3   : 1,
            opcode : 4;

    #define OP_CONT          0x0
    #define OP_TEXT          0x1
    #define OP_BIN           0x2
    #define OP_NCONTROL_RES1 0x3
    #define OP_NCONTROL_RES2 0x4
    #define OP_NCONTROL_RES3 0x5
    #define OP_NCONTROL_RES4 0x6
    #define OP_NCONTROL_RES5 0x7
    #define OP_CLOSE         0x8
    #define OP_PING          0x9
    #define OP_PONG          0xA
    #define OP_CONTROL_RES1  0xB
    #define OP_CONTROL_RES2  0xC
    #define OP_CONTROL_RES3  0xD
    #define OP_CONTROL_RES4  0xE
    #define OP_CONTROL_RES5  0xF

    uint8_t mask : 1,
            len  : 7;
} __attribute__ ((__packed__));

struct evhtp_ws_data_s {
    evhtp_ws_frame_hdr hdr;
    char               payload[0];
};

struct evhtp_ws_frame_s {
    evhtp_ws_frame_hdr hdr;

    uint32_t masking_key;
    uint64_t payload_len;
    char     payload[];
};

enum evhtp_ws_parser_state {
    ws_s_start = 0,
    ws_s_fin_rsv_opcode,
    ws_s_mask_payload_len,
    ws_s_ext_payload_len_16,
    ws_s_ext_payload_len_64,
    ws_s_masking_key,
    ws_s_payload
};

typedef enum evhtp_ws_parser_state evhtp_ws_parser_state;

struct evhtp_ws_parser_s {
    evhtp_ws_frame        frame;
    evhtp_ws_parser_state state;
    uint64_t              content_len;
    uint64_t              orig_content_len;
};

static uint8_t _fext_len[129] = {
    [0]   = 0,
    [126] = 2,
    [127] = 8
};


#define MIN_READ(a, b)                    ((a) < (b) ? (a) : (b))
#define HAS_MASKING_KEY_HDR(__frame)      ((__frame)->mask == 1)
#define HAS_EXTENDED_PAYLOAD_HDR(__frame) ((__frame)->len >= 126)
#define EXTENDED_PAYLOAD_HDR_LEN(__sz) \
    ((__sz >= 126) ? ((__sz == 126) ? 16 : 64) : 0)


ssize_t
evhtp_ws_parser_run(evhtp_ws_parser * p, evhtp_ws_hooks * hooks, const char * data, size_t len) {
    uint8_t byte;
    char    c;
    size_t  i;

    if (!hooks) {
        return (ssize_t)len;
    }

    for (i = 0; i < len; i++) {
        int res;

        byte = (uint8_t)data[i];

        switch (p->state) {
            case ws_s_start:
                memset(&p->frame, 0, sizeof(p->frame));

                p->state            = ws_s_fin_rsv_opcode;
                p->content_len      = 0;
                p->orig_content_len = 0;

                if (hooks->on_msg_begin) {
                    if ((hooks->on_msg_begin)(p)) {
                        return i;
                    }
                }

            /* fall-through */
            case ws_s_fin_rsv_opcode:
                p->frame.hdr.fin    = (byte & 0x1);
                p->frame.hdr.opcode = (byte & 0xF);

                p->state          = ws_s_mask_payload_len;
                break;
            case ws_s_mask_payload_len:

                p->frame.hdr.mask = (byte & 0x1);
                p->frame.hdr.len  = (byte >> 1);

                switch (EXTENDED_PAYLOAD_HDR_LEN(p->frame.hdr.len)) {
                    case 0:
                        p->frame.payload_len = p->frame.hdr.len;
                        p->content_len       = p->frame.payload_len;

                        if (p->frame.hdr.mask == 1) {
                            p->state = ws_s_masking_key;
                            break;
                        }

                        p->state = ws_s_payload;
                        break;
                    case 16:
                        p->state = ws_s_ext_payload_len_16;
                        break;
                    case 64:
                        p->state = ws_s_ext_payload_len_64;
                        break;
                    default:
                        return -1;
                } /* switch */

                break;
            case ws_s_ext_payload_len_16:
                if (MIN_READ((const char *)(data + len) - &data[i], 2) < 2) {
                    return i;
                }

                p->frame.payload_len = *(uint16_t *)&data[i];
                p->content_len       = p->frame.payload_len;

                if (p->frame.hdr.mask == 1) {
                    p->state = ws_s_masking_key;
                }

                /* we only increment 1 instead of 2 since this byte counts as 1 */
                i       += 1;
                p->state = ws_s_payload;

                break;
            case ws_s_ext_payload_len_64:
                if (MIN_READ((const char *)(data + len) - &data[i], 8) < 8) {
                    return i;
                }

                p->frame.payload_len = *(uint64_t *)&data[i];
                p->content_len       = p->frame.payload_len;

                /* we only increment by 7, since this byte counts as 1 (total 8
                 * bytes.
                 */
                i       += 7;
                p->state = ws_s_payload;
                break;
            case ws_s_payload:
            {
                const char * pp      = &data[i];
                const char * pe      = (const char *)(data + len);
                uint64_t     to_read = MIN_READ(pe - pp, p->content_len);

                if (to_read > 0) {
                    if (hooks->on_msg_payload) {
                        if ((hooks->on_msg_payload)(p, pp, to_read)) {
                            return i;
                        }
                    }

                    p->content_len -= to_read;
                    i += to_read;
                }

                if (p->content_len == 0) {
                    if (hooks->on_msg_complete) {
                        if ((hooks->on_msg_complete)(p)) {
                            return i;
                        }
                    }

                    p->state = ws_s_start;
                }
            }
            break;
        } /* switch */
    }

    return i;
}         /* evhtp_ws_parser_run */

int
evhtp_ws_gen_handshake(evhtp_kvs_t * hdrs_in, evhtp_kvs_t * hdrs_out) {
    const char * ws_key;
    char       * magic_w_ws_key;
    size_t       magic_w_ws_key_len;
    size_t       ws_key_len;
    sha1_ctx     sha;
    char       * out        = NULL;
    size_t       out_bytes  = 0;
    char         digest[20] = { 0 };
    char         sha1[42]   = { 0 };

    if (!hdrs_in || !hdrs_out) {
        return -1;
    }

    if (!(ws_key = evhtp_kv_find(hdrs_in, "sec-webSocket-key"))) {
        return -1;
    }

    if ((ws_key_len = strlen(ws_key)) == 0) {
        return -1;
    }

    magic_w_ws_key_len = EVHTP_WS_MAGIC_SZ + ws_key_len + 1;

    if (!(magic_w_ws_key = calloc(magic_w_ws_key_len, 1))) {
        return -1;
    }

    memcpy(magic_w_ws_key, ws_key, ws_key_len);
    memcpy((void *)(magic_w_ws_key + ws_key_len), EVHTP_WS_MAGIC, EVHTP_WS_MAGIC_SZ);

    sha1_init(&sha);
    sha1_update(&sha, magic_w_ws_key, magic_w_ws_key_len);
    sha1_finalize(&sha, digest);
    sha1_tostr(digest, sha1);

    if (base_encode(base64_rfc, magic_w_ws_key,
                    magic_w_ws_key_len, (void **)&out, &out_bytes) == -1) {
        free(magic_w_ws_key);
        return -1;
    }

    out = realloc(out, out_bytes + 1);
    out[out_bytes] = '\0';

    evhtp_kvs_add_kv(hdrs_out,
                     evhtp_kv_new("Sec-WebSocket-Accept", out, 1, 0));

    free(magic_w_ws_key);

    return 0;
} /* evhtp_ws_gen_handshake */

EXPORT_SYMBOL(evhtp_ws_gen_handshake);

evhtp_ws_data *
evhtp_ws_data_new(const char * data, size_t len) {
    evhtp_ws_data * ws_data;
    uint8_t         extra_bytes;
    uint8_t         frame_len;
    size_t          ws_datalen;

    if (len <= 125) {
        frame_len = 0;
    } else if (len > 125 && len <= 65535) {
        frame_len = 126;
    } else {
        frame_len = 127;
    }

    extra_bytes          = _fext_len[frame_len];
    ws_datalen           = sizeof(evhtp_ws_data) + len + extra_bytes;

    ws_data              = calloc(ws_datalen, 1);
    ws_data->hdr.len     = frame_len ? frame_len : len;
    ws_data->hdr.fin     = 1;
    ws_data->hdr.opcode |= OP_TEXT;

    if (frame_len) {
        memcpy(ws_data->payload, &len, extra_bytes);
    }

    memcpy((char *)(ws_data->payload + extra_bytes), data, len);

    return ws_data;
}

EXPORT_SYMBOL(evhtp_ws_data_new);

void
evhtp_ws_data_free(evhtp_ws_data * ws_data) {
    return free(ws_data);
}

EXPORT_SYMBOL(evhtp_ws_data_free);

unsigned char *
evhtp_ws_data_pack(evhtp_ws_data * ws_data, size_t * out_len) {
    unsigned char * payload_start;
    unsigned char * payload_end;
    unsigned char * res;
    uint8_t         ext_len;

    if (!ws_data) {
        return NULL;
    }

    payload_start = (unsigned char *)(ws_data->payload);

    switch (ws_data->hdr.len) {
        case 126:
            payload_end  = (unsigned char *)(payload_start +
                                             *(uint16_t *)ws_data->payload);
            payload_end += 2;
            break;
        case 127:
            payload_end  = (unsigned char *)(payload_start +
                                             *(uint64_t *)ws_data->payload);
            payload_end += 8;
            break;
        default:
            payload_end  = (unsigned char *)(payload_start +
                                             ws_data->hdr.len);
            break;
    }


    if (!(res = calloc(sizeof(evhtp_ws_frame_hdr) + (payload_end - payload_start), 1))) {
        return NULL;
    }

    /* uint16_t w = htons(*(uint16_t *)&ws_data->hdr); */
    memcpy((void *)res, &ws_data->hdr, sizeof(evhtp_ws_frame_hdr));
    memcpy((void *)(res + sizeof(evhtp_ws_frame_hdr)),
           payload_start, (payload_end - payload_start));

    *out_len = sizeof(evhtp_ws_frame_hdr) + (payload_end - payload_start);

    return res;
} /* evhtp_ws_data_pack */

EXPORT_SYMBOL(evhtp_ws_data_pack);

unsigned char *
evhtp_ws_pack(const char * data, size_t len, size_t * out_len) {
    evhtp_ws_data * w_data;
    unsigned char * res;

    if (!data || !len) {
        return NULL;
    }

    if (!(w_data = evhtp_ws_data_new(data, len))) {
        return NULL;
    }

    res = evhtp_ws_data_pack(w_data, out_len);

    evhtp_ws_data_free(w_data);

    return res;
}

EXPORT_SYMBOL(evhtp_ws_pack);

evhtp_ws_parser *
evhtp_ws_parser_new(void) {
    return calloc(sizeof(evhtp_ws_parser), 1);
}

EXPORT_SYMBOL(evhtp_ws_parser_new);

