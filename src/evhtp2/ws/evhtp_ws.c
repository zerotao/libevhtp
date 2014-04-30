/*
 * THIS CODE IS BASED OFF OF THE FOLLOWING WORK / LICENSE:
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

#define EVHTP_WS_MAGIC    "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define EVHTP_WS_MAGIC_SZ 36

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

#if 0
/*
 * int evhtp_websocket_set_content( const char *data, int data_length, unsigned char *dst )
 * @data - entire data received with socket
 * @data_length - size of @data
 * @dst - pointer to char array where the result will be stored
 * @dst_len - size of @dst
 * @return - WebSocket frame size */
int
evhtp_websocket_set_content( const char *data, int data_length, unsigned char *dst, const unsigned int dst_len ) {
    unsigned char *message = ( unsigned char * )malloc( 65535 * sizeof( char ) );
    int            i;
    int            data_start_index;

    message[0] = 129;

    if ( data_length <= 125 ) {
        message[1]       = ( unsigned char )data_length;
        data_start_index = 2;
    } else if ( data_length > 125 && data_length <= 65535 ) {
        message[1]       = 126;
        message[2]       = ( unsigned char )( ( data_length >> 8 ) & 255 );
        message[3]       = ( unsigned char )( ( data_length ) & 255 );
        data_start_index = 4;
    } else {
        message[1]       = 127;
        message[2]       = ( unsigned char )( ( data_length >> 56 ) & 255 );
        message[3]       = ( unsigned char )( ( data_length >> 48 ) & 255 );
        message[4]       = ( unsigned char )( ( data_length >> 40 ) & 255 );
        message[5]       = ( unsigned char )( ( data_length >> 32 ) & 255 );
        message[6]       = ( unsigned char )( ( data_length >> 24 ) & 255 );
        message[7]       = ( unsigned char )( ( data_length >> 16 ) & 255 );
        message[8]       = ( unsigned char )( ( data_length >> 8 ) & 255 );
        message[9]       = ( unsigned char )( ( data_length ) & 255 );
        data_start_index = 10;
    }

    for ( i = 0; i < data_length; i++ ) {
        message[ data_start_index + i ] = ( unsigned char )data[i];
    }

    for ( i = 0; i < data_length + data_start_index; i++ ) {
        dst[i] = ( unsigned char )message[ i ];
    }

    if ( message ) {
        free( message );
        message = NULL;
    }

    return i;
} /* evhtp_websocket_set_content */

/*
 * int evhtp_websocket_get_content( const char *data, int data_length, unsigned char *dst )
 * @data - entire data received with socket
 * @data_length - size of @data
 * @dst - pointer to char array, where the result will be stored
 * @return - size of @dst */
int
evhtp_websocket_get_content( const char *data, int data_length, unsigned char *dst, const unsigned int dst_len ) {
    unsigned int  i, j;
    unsigned char mask[4];
    unsigned int  packet_length         = 0;
    unsigned int  length_code           = 0;
    int           index_first_mask      = 0;
    int           index_first_data_byte = 0;

    if ( ( unsigned char )data[0] != 129 ) {
        dst = NULL;
        if ( ( unsigned char )data[0] == 136 ) {
            /* WebSocket client disconnected */
            return -2;
        }
        /* Unknown error */
        return -1;
    }

    length_code = ((unsigned char)data[1]) & 127;

    if ( length_code <= 125 ) {
        index_first_mask = 2;

        mask[0]          = data[2];
        mask[1]          = data[3];
        mask[2]          = data[4];
        mask[3]          = data[5];
    } else if ( length_code == 126 ) {
        index_first_mask = 4;

        mask[0]          = data[4];
        mask[1]          = data[5];
        mask[2]          = data[6];
        mask[3]          = data[7];
    } else if ( length_code == 127 ) {
        index_first_mask = 10;

        mask[0]          = data[10];
        mask[1]          = data[11];
        mask[2]          = data[12];
        mask[3]          = data[13];
    }

    index_first_data_byte = index_first_mask + 4;

    packet_length         = data_length - index_first_data_byte;

    for ( i = index_first_data_byte, j = 0; i < data_length; i++, j++ ) {
        dst[ j ] = ( unsigned char )data[ i ] ^ mask[ j % 4];
    }

    return packet_length;
} /* evhtp_websocket_get_content */

/*
 * short evhtp_websocket_valid_connection( const char *data )
 * @data - entire data received with socket
 * @return - 0 = false / 1 = true */
short
evhtp_websocket_valid_connection( const char *data ) {
    char *connection_header = ( char * )malloc( 64 * sizeof( char ) );
    short result = 0;

    request_get_header_value( data, "Connection:", connection_header, 64 );

    if ( connection_header == NULL ) {
        return 0;
    }

    result = ( strstr( data, evhtp_websocket_KEY_HEADER ) != NULL && ( strstr( connection_header, "Upgrade" ) != NULL || strstr( connection_header, "upgrade" ) != NULL) );

    if ( connection_header ) {
        free( connection_header );
        connection_header = NULL;
    }

    return result;
}

/*
 * int evhtp_websocket_client_version( const char *data )
 * @data - entire data received with socket
 * @return - value from client's Sec-WebSocket-Version key */
int
evhtp_websocket_client_version( const char *data ) {
    char *version_header = ( char * )malloc( 32 * sizeof( char ) );
    int   result;

    request_get_header_value( data, "Sec-WebSocket-Version:", version_header, 32 );

    if ( version_header == NULL ) {
        return -1;
    }

    result = atoi( version_header );

    if ( version_header ) {
        free( version_header );
        version_header = NULL;
    }

    return result;

#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

/*******************************************************************
*
*  WebSocket Protocol Implementation
*
+ WebSocket versions:
+       - 13
+ Dependencies:
+       - sha1.h and sha1.c from http://www.packetizer.com/security/sha1/ (included)
+       - base64.h and base64.c (included)
+ Known bugs:
+       - evhtp_websocket_generate_handshake: sha.Message_Digest[i] => sha1_part fails if leading zero is found
+
+  Author: Marcin Kelar ( marcin.kelar@gmail.com )
*******************************************************************/
#include <stdio.h>
#include "include/cWebSockets.h"

/*
 * void request_get_header_value( const char *data, const char *requested_key )
 * @data - entire data received with socket
 * @requested_key - requested key
 * @dst - pointer to char array where the result will be stored,
 * @dst_len - size of @dst */
    void
    request_get_header_value( const char *data, const char *requested_key, char *dst, unsigned int dst_len ) {
        char *src = ( char * )malloc( 65535 * sizeof( char ) );
        char *result_handler;
        char *result;
        char *tmp_header_key;
        int   i   = 0;

        strncpy( src, data, 65535 );

        tmp_header_key = strstr( ( char * )src, requested_key );
        if ( tmp_header_key == NULL ) {
            dst = NULL;
            return;
        }

        result_handler = ( char * )malloc( 1024 * sizeof( char ) );
        result         = ( char * )calloc( 256, sizeof( char ) );

        strncpy( result_handler, tmp_header_key, 1024 );
        tmp_header_key = NULL;

        while ( ( result[ i ] = result_handler[ i ] ) != '\015' ) {
            if ( result_handler[ i ] != '\015' ) {
                i++;
            }
        }
        result[ i ]    = '\0';

        free( result_handler );
        result_handler = NULL;

        strncpy( dst, strstr( result, ": " ) + 2, dst_len );
        free( src );
        src    = NULL;
        free( result );
        result = NULL;
    }

/*
 * void evhtp_websocket_generate_handshake( const char *data, char *dst, unsigned int dst_len )
 * @data - entire data received with socket
 * @dst - pointer to char array where the result will be stored
 * @dst_len - size of @dst */
    void
    evhtp_websocket_generate_handshake( const char *data, char *dst, const unsigned int dst_len ) {
        char          origin[ 512 ];
        char          host[ 512 ];
        char          additional_headers[ 2048 ];
        char          sec_websocket_key[ 512 ];
        char          sec_websocket_key_sha1[ 512 ];
        char          sha1_part[ 32 ];
        SHA1Context   sha;
        unsigned char sha1_hex[ 512 ];
        unsigned char sha1_tmp[ 512 ];
        unsigned char sec_websocket_accept[ 512 ];
        int           source_len;
        int           i;

        memset( sha1_hex, '\0', 512 );
        memset( sha1_tmp, '\0', 32 );
        memset( sec_websocket_accept, '\0', 512 );

        request_get_header_value( data, "Origin:", origin, 512 );
        request_get_header_value( data, "Host:", host, 512 );

        if ( origin != NULL && host != NULL ) {
            sprintf( additional_headers, "Origin: %s\r\nHost: %s", origin, host );
        } else {
            sprintf( additional_headers, "Origin: %s\r\nHost: %s", "null", "null" );
        }

        request_get_header_value(data, evhtp_websocket_KEY_HEADER, sec_websocket_key, 512 );
        if ( sec_websocket_key == NULL ) {
            dst = NULL;
            return;
        }

        strncat( sec_websocket_key, evhtp_websocket_MAGIC_STRING, 512 );

        SHA1Reset( &sha );
        SHA1Input( &sha, ( const unsigned char * )sec_websocket_key, strlen( sec_websocket_key ) );
        SHA1Result( &sha );

        for ( i = 0; i < 5; i++ ) {
            snprintf( sha1_part, 32, "%x", sha.Message_Digest[i] );
            strncat( sha1_tmp, sha1_part, 512 );
        }

        strncpy( sec_websocket_key_sha1, sha1_tmp, 512 );
        source_len = xstr2str( sha1_hex, 512, sec_websocket_key_sha1 );
        base64_encode( sha1_hex, source_len - 1, sec_websocket_accept, 512 );

        snprintf( dst, dst_len, evhtp_websocket_HANDSHAKE_RESPONSE, additional_headers, sec_websocket_accept );
    } /* evhtp_websocket_generate_handshake */

/*
 * int evhtp_websocket_set_content( const char *data, int data_length, unsigned char *dst )
 * @data - entire data received with socket
 * @data_length - size of @data
 * @dst - pointer to char array where the result will be stored
 * @dst_len - size of @dst
 * @return - WebSocket frame size */
    int
    evhtp_websocket_set_content( const char *data, int data_length, unsigned char *dst, const unsigned int dst_len ) {
        unsigned char *message = ( unsigned char * )malloc( 65535 * sizeof( char ) );
        int            i;
        int            data_start_index;

        message[0] = 129;

        if ( data_length <= 125 ) {
            message[1]       = ( unsigned char )data_length;
            data_start_index = 2;
        } else if ( data_length > 125 && data_length <= 65535 ) {
            message[1]       = 126;
            message[2]       = ( unsigned char )( ( data_length >> 8 ) & 255 );
            message[3]       = ( unsigned char )( ( data_length ) & 255 );
            data_start_index = 4;
        } else {
            message[1]       = 127;
            message[2]       = ( unsigned char )( ( data_length >> 56 ) & 255 );
            message[3]       = ( unsigned char )( ( data_length >> 48 ) & 255 );
            message[4]       = ( unsigned char )( ( data_length >> 40 ) & 255 );
            message[5]       = ( unsigned char )( ( data_length >> 32 ) & 255 );
            message[6]       = ( unsigned char )( ( data_length >> 24 ) & 255 );
            message[7]       = ( unsigned char )( ( data_length >> 16 ) & 255 );
            message[8]       = ( unsigned char )( ( data_length >> 8 ) & 255 );
            message[9]       = ( unsigned char )( ( data_length ) & 255 );
            data_start_index = 10;
        }

        for ( i = 0; i < data_length; i++ ) {
            message[ data_start_index + i ] = ( unsigned char )data[i];
        }

        for ( i = 0; i < data_length + data_start_index; i++ ) {
            dst[i] = ( unsigned char )message[ i ];
        }

        if ( message ) {
            free( message );
            message = NULL;
        }

        return i;
    } /* evhtp_websocket_set_content */

/*
 * int evhtp_websocket_get_content( const char *data, int data_length, unsigned char *dst )
 * @data - entire data received with socket
 * @data_length - size of @data
 * @dst - pointer to char array, where the result will be stored
 * @return - size of @dst */
    int
    evhtp_websocket_get_content( const char *data, int data_length, unsigned char *dst, const unsigned int dst_len ) {
        unsigned int  i, j;
        unsigned char mask[4];
        unsigned int  packet_length         = 0;
        unsigned int  length_code           = 0;
        int           index_first_mask      = 0;
        int           index_first_data_byte = 0;

        if ( ( unsigned char )data[0] != 129 ) {
            dst = NULL;
            if ( ( unsigned char )data[0] == 136 ) {
                /* WebSocket client disconnected */
                return -2;
            }
            /* Unknown error */
            return -1;
        }

        length_code = ((unsigned char)data[1]) & 127;

        if ( length_code <= 125 ) {
            index_first_mask = 2;

            mask[0]          = data[2];
            mask[1]          = data[3];
            mask[2]          = data[4];
            mask[3]          = data[5];
        } else if ( length_code == 126 ) {
            index_first_mask = 4;

            mask[0]          = data[4];
            mask[1]          = data[5];
            mask[2]          = data[6];
            mask[3]          = data[7];
        } else if ( length_code == 127 ) {
            index_first_mask = 10;

            mask[0]          = data[10];
            mask[1]          = data[11];
            mask[2]          = data[12];
            mask[3]          = data[13];
        }

        index_first_data_byte = index_first_mask + 4;

        packet_length         = data_length - index_first_data_byte;

        for ( i = index_first_data_byte, j = 0; i < data_length; i++, j++ ) {
            dst[ j ] = ( unsigned char )data[ i ] ^ mask[ j % 4];
        }

        return packet_length;
    } /* evhtp_websocket_get_content */

/*
 * short evhtp_websocket_valid_connection( const char *data )
 * @data - entire data received with socket
 * @return - 0 = false / 1 = true */
    short
    evhtp_websocket_valid_connection( const char *data ) {
        char *connection_header = ( char * )malloc( 64 * sizeof( char ) );
        short result = 0;

        request_get_header_value( data, "Connection:", connection_header, 64 );

        if ( connection_header == NULL ) {
            return 0;
        }

        result = ( strstr( data, evhtp_websocket_KEY_HEADER ) != NULL && ( strstr( connection_header, "Upgrade" ) != NULL || strstr( connection_header, "upgrade" ) != NULL) );

        if ( connection_header ) {
            free( connection_header );
            connection_header = NULL;
        }

        return result;
    }

/*
 * int evhtp_websocket_client_version( const char *data )
 * @data - entire data received with socket
 * @return - value from client's Sec-WebSocket-Version key */
    int
    evhtp_websocket_client_version( const char *data ) {
        char *version_header = ( char * )malloc( 32 * sizeof( char ) );
        int   result;

        request_get_header_value( data, "Sec-WebSocket-Version:", version_header, 32 );

        if ( version_header == NULL ) {
            return -1;
        }

        result = atoi( version_header );

        if ( version_header ) {
            free( version_header );
            version_header = NULL;
        }

        return result;
    }

#endif
