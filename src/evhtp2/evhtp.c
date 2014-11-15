#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <strings.h>
#include <inttypes.h>
#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#else
#define WINVER 0x0501
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#ifndef NO_SYS_UN
#include <sys/un.h>
#endif
#include <limits.h>
#include <assert.h>

#include "evhtp2/evhtp-internal.h"

static int            _evhtp_req_parser_start(evhtp_parser * p);
static int            _evhtp_req_parser_path(evhtp_parser * p, const char * data, size_t len);
static int            _evhtp_req_parser_args(evhtp_parser * p, const char * data, size_t len);
static int            _evhtp_req_parser_header_key(evhtp_parser * p, const char * data, size_t len);
static int            _evhtp_req_parser_header_val(evhtp_parser * p, const char * data, size_t len);
static int            _evhtp_req_parser_hostname(evhtp_parser * p, const char * data, size_t len);
static int            _evhtp_req_parser_headers(evhtp_parser * p);
static int            _evhtp_req_parser_body(evhtp_parser * p, const char * data, size_t len);
static int            _evhtp_req_parser_fini(evhtp_parser * p);
static int            _evhtp_req_parser_chunk_new(evhtp_parser * p);
static int            _evhtp_req_parser_chunk_fini(evhtp_parser * p);
static int            _evhtp_req_parser_chunks_fini(evhtp_parser * p);
static int            _evhtp_req_parser_headers_start(evhtp_parser * p);

static void           _evhtp_conn_readcb(struct bufferevent * bev, void * arg);

static evhtp_conn_t * _evhtp_conn_new(evhtp_t * htp, evutil_socket_t sock, evhtp_type type);

static evhtp_uri_t  * _evhtp_uri_new(void);
static void           _evhtp_uri_free(evhtp_uri_t * uri);

static evhtp_path_t * _evhtp_path_new(const char * data, size_t len);
static void           _evhtp_path_free(evhtp_path_t * path);

#define HOOK_AVAIL(var, hook_name)             (var->hooks && var->hooks->hook_name)
#define HOOK_FUNC(var, hook_name)              (var->hooks->hook_name)
#define HOOK_ARGS(var, hook_name)              var->hooks->hook_name ## _arg

#define HOOK_REQUEST_RUN(req, hook_name, ...)  do {                                   \
        if (HOOK_AVAIL(req, hook_name)) {                                             \
            return HOOK_FUNC(req, hook_name) (req, __VA_ARGS__,                       \
                                              HOOK_ARGS(req, hook_name));             \
        }                                                                             \
                                                                                      \
        if (HOOK_AVAIL(evhtp_req_get_conn(req), hook_name)) {                         \
            return HOOK_FUNC(req->conn, hook_name) (req, __VA_ARGS__,                 \
                                                    HOOK_ARGS(req->conn, hook_name)); \
        }                                                                             \
} while (0)

#define HOOK_REQUEST_RUN_NARGS(req, hook_name) do {                                   \
        if (HOOK_AVAIL(req, hook_name)) {                                             \
            return HOOK_FUNC(req, hook_name) (req,                                    \
                                              HOOK_ARGS(req, hook_name));             \
        }                                                                             \
                                                                                      \
        if (HOOK_AVAIL(req->conn, hook_name)) {                                       \
            return HOOK_FUNC(req->conn, hook_name) (req,                              \
                                                    HOOK_ARGS(req->conn, hook_name)); \
        }                                                                             \
} while (0);

#ifdef EVHTP_ENABLE_EVTHR
#define _evhtp_lock(h)                         do { \
        if (h->lock) {                              \
            pthread_mutex_lock(h->lock);            \
        }                                           \
} while (0)

#define _evhtp_unlock(h)                       do { \
        if (h->lock) {                              \
            pthread_mutex_unlock(h->lock);          \
        }                                           \
} while (0)
#else
#define _evhtp_lock(h)                         do {} while (0)
#define _evhtp_unlock(h)                       do {} while (0)
#endif

#define __GEN_GET_PATH_FUNC(valname, valtype)      \
    inline valtype                                 \
    evhtp_path_get_ ## valname(evhtp_path_t * k) { \
        return k->valname;                         \
    }                                              \
    EXPORT_SYMBOL(evhtp_path_get_ ## valname);

__GEN_GET_PATH_FUNC(full, const char *);
__GEN_GET_PATH_FUNC(path, const char *);
__GEN_GET_PATH_FUNC(file, const char *);
__GEN_GET_PATH_FUNC(match_start, const char *);
__GEN_GET_PATH_FUNC(match_end, const char *);
__GEN_GET_PATH_FUNC(matched_soff, unsigned int);
__GEN_GET_PATH_FUNC(matched_eoff, unsigned int);

#define __GEN_GET_KV_FUNC(valname, valtype)    \
    inline valtype                             \
    evhtp_kv_get_ ## valname(evhtp_kv_t * k) { \
        return k->valname;                     \
    }                                          \
    EXPORT_SYMBOL(evhtp_kv_get_ ## valname);

__GEN_GET_KV_FUNC(key, const char *);
__GEN_GET_KV_FUNC(val, const char *);
__GEN_GET_KV_FUNC(klen, size_t);
__GEN_GET_KV_FUNC(k_heaped, uint8_t);
__GEN_GET_KV_FUNC(v_heaped, uint8_t);


static const char *
status_code_to_str(evhtp_res code) {
    switch (code) {
        case EVHTP_RES_200:
            return "OK";
        case EVHTP_RES_300:
            return "Redirect";
        case EVHTP_RES_400:
            return "Bad Request";
        case EVHTP_RES_NOTFOUND:
            return "Not Found";
        case EVHTP_RES_SERVERR:
            return "Internal Server Error";
        case EVHTP_RES_CONTINUE:
            return "Continue";
        case EVHTP_RES_FORBIDDEN:
            return "Forbidden";
        case EVHTP_RES_SWITCH_PROTO:
            return "Switching Protocols";
        case EVHTP_RES_MOVEDPERM:
            return "Moved Permanently";
        case EVHTP_RES_PROCESSING:
            return "Processing";
        case EVHTP_RES_URI_TOOLONG:
            return "URI Too Long";
        case EVHTP_RES_CREATED:
            return "Created";
        case EVHTP_RES_ACCEPTED:
            return "Accepted";
        case EVHTP_RES_NAUTHINFO:
            return "No Auth Info";
        case EVHTP_RES_NOCONTENT:
            return "No Content";
        case EVHTP_RES_RSTCONTENT:
            return "Reset Content";
        case EVHTP_RES_PARTIAL:
            return "Partial Content";
        case EVHTP_RES_MSTATUS:
            return "Multi-Status";
        case EVHTP_RES_IMUSED:
            return "IM Used";
        case EVHTP_RES_FOUND:
            return "Found";
        case EVHTP_RES_SEEOTHER:
            return "See Other";
        case EVHTP_RES_NOTMOD:
            return "Not Modified";
        case EVHTP_RES_USEPROXY:
            return "Use Proxy";
        case EVHTP_RES_SWITCHPROXY:
            return "Switch Proxy";
        case EVHTP_RES_TMPREDIR:
            return "Temporary Redirect";
        case EVHTP_RES_UNAUTH:
            return "Unauthorized";
        case EVHTP_RES_PAYREQ:
            return "Payment Required";
        case EVHTP_RES_METHNALLOWED:
            return "Not Allowed";
        case EVHTP_RES_NACCEPTABLE:
            return "Not Acceptable";
        case EVHTP_RES_PROXYAUTHREQ:
            return "Proxy Authentication Required";
        case EVHTP_RES_TIMEOUT:
            return "Request Timeout";
        case EVHTP_RES_CONFLICT:
            return "Conflict";
        case EVHTP_RES_GONE:
            return "Gone";
        case EVHTP_RES_LENREQ:
            return "Length Required";
        case EVHTP_RES_PRECONDFAIL:
            return "Precondition Failed";
        case EVHTP_RES_ENTOOLARGE:
            return "Entity Too Large";
        case EVHTP_RES_URITOOLARGE:
            return "Request-URI Too Long";
        case EVHTP_RES_UNSUPPORTED:
            return "Unsupported Media Type";
        case EVHTP_RES_RANGENOTSC:
            return "Requested Range Not Satisfiable";
        case EVHTP_RES_EXPECTFAIL:
            return "Expectation Failed";
        case EVHTP_RES_IAMATEAPOT:
            return "I'm a teapot";
        case EVHTP_RES_NOTIMPL:
            return "Not Implemented";
        case EVHTP_RES_BADGATEWAY:
            return "Bad Gateway";
        case EVHTP_RES_SERVUNAVAIL:
            return "Service Unavailable";
        case EVHTP_RES_GWTIMEOUT:
            return "Gateway Timeout";
        case EVHTP_RES_VERNSUPPORT:
            return "HTTP Version Not Supported";
        case EVHTP_RES_BWEXEED:
            return "Bandwidth Limit Exceeded";
    } /* switch */

    return "UNKNOWN";
}     /* status_code_to_str */

/**
 * @brief callback definitions for req processing from libhtparse
 */
static evhtp_parser_hooks req_psets = {
    .on_msg_begin       = _evhtp_req_parser_start,
    .method             = NULL,
    .scheme             = NULL,
    .host               = NULL,
    .port               = NULL,
    .path               = _evhtp_req_parser_path,
    .args               = _evhtp_req_parser_args,
    .uri                = NULL,
    .on_hdrs_begin      = _evhtp_req_parser_headers_start,
    .hdr_key            = _evhtp_req_parser_header_key,
    .hdr_val            = _evhtp_req_parser_header_val,
    .hostname           = _evhtp_req_parser_hostname,
    .on_hdrs_complete   = _evhtp_req_parser_headers,
    .on_new_chunk       = _evhtp_req_parser_chunk_new,
    .on_chunk_complete  = _evhtp_req_parser_chunk_fini,
    .on_chunks_complete = _evhtp_req_parser_chunks_fini,
    .body               = _evhtp_req_parser_body,
    .on_msg_complete    = _evhtp_req_parser_fini
};

static int
_ws_msg_start(evhtp_ws_parser * p) {
    evhtp_req_t * req;

    req = evhtp_ws_parser_get_userdata(p);
    assert(req != NULL);

    printf("BEGIN!\n");

    return 0;
}

static int
_ws_msg_fini(evhtp_ws_parser * p) {
    evhtp_req_t * req;

    req = evhtp_ws_parser_get_userdata(p);
    assert(req != NULL);

    if (req->cb) {
        (req->cb)(req, req->cbarg);
    }

    printf("COMPLETE!\n");

    return 0;
}

static int
_ws_msg_data(evhtp_ws_parser * p, const char * d, size_t l) {
    evhtp_req_t * req;

    req = evhtp_ws_parser_get_userdata(p);
    assert(req != NULL);

    evbuffer_add(req->buffer_in, d, l);
    printf("Got %zu %.*s\n", l, (int)l, d);

    return 0;
}

static evhtp_ws_hooks ws_hooks = {
    .on_msg_start = _ws_msg_start,
    .on_msg_data  = _ws_msg_data,
    .on_msg_fini  = _ws_msg_fini
};

/*
 * PRIVATE FUNCTIONS
 */

/**
 * @brief a weak hash function
 *
 * @param str a null terminated string
 *
 * @return an unsigned integer hash of str
 */
static inline unsigned int
_evhtp_quick_hash(const char * str) {
    unsigned int h = 0;

    for (; *str; str++) {
        h = 31 * h + *str;
    }

    return h;
}

/**
 * @brief helper function to determine if http version is HTTP/1.0
 *
 * @param major the major version number
 * @param minor the minor version number
 *
 * @return 1 if HTTP/1.0, else 0
 */
#define _evhtp_is_http_10(__major, __minor) (__major == 1 && __minor == 0) ? 1 : 0

/**
 * @brief helper function to determine if http version is HTTP/1.1
 *
 * @param major the major version number
 * @param minor the minor version number
 *
 * @return 1 if HTTP/1.1, else 0
 */
#define _evhtp_is_http_11(__major, __minor) (__major == 1 && __minor >= 1) ? 1 : 0

/**
 * @brief returns the HTTP protocol version
 *
 * @param major the major version number
 * @param minor the minor version number
 *
 * @return EVHTP_PROTO_10 if HTTP/1.0, EVHTP_PROTO_11 if HTTP/1.1, otherwise
 *         EVHTP_PROTO_INVALID
 */
static inline evhtp_proto
_evhtp_protocol(const char major, const char minor) {
    if (_evhtp_is_http_10(major, minor)) {
        return EVHTP_PROTO_10;
    }

    if (_evhtp_is_http_11(major, minor)) {
        return EVHTP_PROTO_11;
    }

    return EVHTP_PROTO_INVALID;
}

/**
 * @brief runs the user-defined on_path hook for a req
 *
 * @param req the req structure
 * @param path the path structure
 *
 * @return EVHTP_RES_OK on success, otherwise something else.
 */
static inline evhtp_res
_evhtp_path_hook(evhtp_req_t * req, evhtp_path_t * path) {
    HOOK_REQUEST_RUN(req, on_path, path);

    return EVHTP_RES_OK;
}

/**
 * @brief runs the user-defined on_header hook for a req
 *
 * once a full key: value header has been parsed, this will call the hook
 *
 * @param req the req strucutre
 * @param header the header structure
 *
 * @return EVHTP_RES_OK on success, otherwise something else.
 */
static inline evhtp_res
_evhtp_hdr_hook(evhtp_req_t * req, evhtp_hdr_t * header) {
    HOOK_REQUEST_RUN(req, on_header, header);

    return EVHTP_RES_OK;
}

/**
 * @brief runs the user-defined on_Headers hook for a req after all headers
 *        have been parsed.
 *
 * @param req the req structure
 * @param headers the headers tailq structure
 *
 * @return EVHTP_RES_OK on success, otherwise something else.
 */
static inline evhtp_res
_evhtp_hdrs_hook(evhtp_req_t * req, evhtp_hdrs_t * headers) {
    HOOK_REQUEST_RUN(req, on_headers, headers);

    return EVHTP_RES_OK;
}

/**
 * @brief runs the user-defined on_body hook for reqs containing a body.
 *        the data is stored in the req->buffer_in so the user may either
 *        leave it, or drain upon being called.
 *
 * @param req the req strucutre
 * @param buf a evbuffer containing body data
 *
 * @return EVHTP_RES_OK on success, otherwise something else.
 */
static inline evhtp_res
_evhtp_body_hook(evhtp_req_t * req, struct evbuffer * buf) {
    HOOK_REQUEST_RUN(req, on_read, buf);

    return EVHTP_RES_OK;
}

/**
 * @brief runs the user-defined hook called just prior to a req been
 *        free()'d
 *
 * @param req thereq structure
 *
 * @return EVHTP_RES_OK on success, otherwise treated as an error
 */
static inline evhtp_res
_evhtp_req_fini_hook(evhtp_req_t * req) {
    HOOK_REQUEST_RUN_NARGS(req, on_req_fini);

    return EVHTP_RES_OK;
}

static inline evhtp_res
_evhtp_chunk_new_hook(evhtp_req_t * req, uint64_t len) {
    HOOK_REQUEST_RUN(req, on_new_chunk, len);

    return EVHTP_RES_OK;
}

static inline evhtp_res
_evhtp_chunk_fini_hook(evhtp_req_t * req) {
    HOOK_REQUEST_RUN_NARGS(req, on_chunk_fini);

    return EVHTP_RES_OK;
}

static inline evhtp_res
_evhtp_chunks_fini_hook(evhtp_req_t * req) {
    HOOK_REQUEST_RUN_NARGS(req, on_chunks_fini);

    return EVHTP_RES_OK;
}

static inline evhtp_res
_evhtp_hdrs_start_hook(evhtp_req_t * req) {
    HOOK_REQUEST_RUN_NARGS(req, on_headers_start);

    return EVHTP_RES_OK;
}

/**
 * @brief runs the user-definedhook called just prior to a conn being
 *        closed
 *
 * @param conn the conn structure
 *
 * @return EVHTP_RES_OK on success, but pretty much ignored in any case.
 */
static inline evhtp_res
_evhtp_conn_fini_hook(evhtp_conn_t * conn) {
    if (conn->hooks && conn->hooks->on_conn_fini) {
        return (conn->hooks->on_conn_fini)(conn,
                                           conn->hooks->on_conn_fini_arg);
    }

    return EVHTP_RES_OK;
}

static inline evhtp_res
_evhtp_hostname_hook(evhtp_req_t * r, const char * hostname) {
    HOOK_REQUEST_RUN(r, on_hostname, hostname);

    return EVHTP_RES_OK;
}

static inline evhtp_res
_evhtp_conn_write_hook(evhtp_conn_t * conn) {
    if (conn->hooks && conn->hooks->on_write) {
        return (conn->hooks->on_write)(conn,
                                       conn->hooks->on_write_arg);
    }

    return EVHTP_RES_OK;
}

/**
 * @brief glob/wildcard type pattern matching.
 *
 * Note: This code was derived from redis's (v2.6) stringmatchlen() function.
 *
 * @param pattern
 * @param string
 *
 * @return
 */
static int
_evhtp_glob_match(const char * pattern, const char * string) {
    size_t pat_len;
    size_t str_len;

    if (!pattern || !string) {
        return 0;
    }

    pat_len = strlen(pattern);
    str_len = strlen(string);

    while (pat_len) {
        if (pattern[0] == '*') {
            while (pattern[1] == '*') {
                pattern++;
                pat_len--;
            }

            if (pat_len == 1) {
                return 1;
            }

            while (str_len) {
                if (_evhtp_glob_match(pattern + 1, string)) {
                    return 1;
                }

                string++;
                str_len--;
            }

            return 0;
        } else {
            if (pattern[0] != string[0]) {
                return 0;
            }

            string++;
            str_len--;
        }

        pattern++;
        pat_len--;

        if (str_len == 0) {
            while (*pattern == '*') {
                pattern++;
                pat_len--;
            }
            break;
        }
    }

    if (pat_len == 0 && str_len == 0) {
        return 1;
    }

    return 0;
} /* _evhtp_glob_match */

static evhtp_callback_t *
_evhtp_callback_find(evhtp_callbacks_t * cbs,
                     const char        * path,
                     unsigned int      * start_offset,
                     unsigned int      * end_offset) {
#ifdef EVHTP_ENABLE_REGEX
    regmatch_t         pmatch[28];
#endif
    evhtp_callback_t * callback;

    if (cbs == NULL) {
        return NULL;
    }

    TAILQ_FOREACH(callback, cbs, next) {
        switch (callback->type) {
            case evhtp_callback_type_hash:
                if (strcmp(callback->val.path, path) == 0) {
                    *start_offset = 0;
                    *end_offset   = (unsigned int)strlen(path);
                    return callback;
                }
                break;
#ifdef EVHTP_ENABLE_REGEX
            case evhtp_callback_type_regex:
                if (regexec(callback->val.regex, path, callback->val.regex->re_nsub + 1, pmatch, 0) == 0) {
                    *start_offset = pmatch[callback->val.regex->re_nsub].rm_so;
                    *end_offset   = pmatch[callback->val.regex->re_nsub].rm_eo;

                    return callback;
                }

                break;
#endif
            case evhtp_callback_type_glob:
                if (_evhtp_glob_match(callback->val.glob, path) == 1) {
                    *start_offset = 0;
                    *end_offset   = (unsigned int)strlen(path);
                    return callback;
                }
            default:
                break;
        } /* switch */
    }

    return NULL;
}         /* _evhtp_callback_find */

/**
 * @brief Creates a new evhtp_req_t
 *
 * @param c
 *
 * @return evhtp_req_t structure on success, otherwise NULL
 */
static evhtp_req_t *
_evhtp_req_new(evhtp_conn_t * c) {
    evhtp_req_t * req;

    if (!(req = calloc(sizeof(evhtp_req_t), 1))) {
        return NULL;
    }

    req->conn        = c;
    req->htp         = c ? c->htp : NULL;
    req->status      = EVHTP_RES_OK;
    req->buffer_in   = evbuffer_new();
    req->buffer_out  = evbuffer_new();
    req->headers_in  = malloc(sizeof(evhtp_hdrs_t));
    req->headers_out = malloc(sizeof(evhtp_hdrs_t));

    TAILQ_INIT(req->headers_in);
    TAILQ_INIT(req->headers_out);

    return req;
}

/**
 * @brief frees all data in an evhtp_req_t along with calling finished hooks
 *
 * @param req the req structure
 */
static void
_evhtp_req_free(evhtp_req_t * req) {
    if (req == NULL) {
        return;
    }

    _evhtp_req_fini_hook(req);
    _evhtp_uri_free(req->uri);

    evhtp_hdrs_free(req->headers_in);
    evhtp_hdrs_free(req->headers_out);

    if (req->buffer_in) {
        evbuffer_free(req->buffer_in);
    }

    if (req->buffer_out) {
        evbuffer_free(req->buffer_out);
    }

    /* XXX should be evhtp_ws_parser_free() */
    free(req->ws_parser);
    free(req->hooks);
    free(req);
}

/**
 * @brief create an overlay URI structure
 *
 * @return evhtp_uri_t
 */
static evhtp_uri_t *
_evhtp_uri_new(void) {
    evhtp_uri_t * uri;

    if (!(uri = calloc(sizeof(evhtp_uri_t), 1))) {
        return NULL;
    }

    return uri;
}

/**
 * @brief frees an overlay URI structure
 *
 * @param uri evhtp_uri_t
 */
static void
_evhtp_uri_free(evhtp_uri_t * uri) {
    if (uri == NULL) {
        return;
    }

    evhtp_query_free(uri->query);
    _evhtp_path_free(uri->path);

    free(uri->fragment);
    free(uri->query_raw);
    free(uri);
}

/**
 * @brief parses the path and file from an input buffer
 *
 * @details in order to properly create a structure that can match
 *          both a path and a file, this will parse a string into
 *          what it considers a path, and a file.
 *
 * @details if for example the input was "/a/b/c", the parser will
 *          consider "/a/b/" as the path, and "c" as the file.
 *
 * @param data raw input data (assumes a /path/[file] structure)
 * @param len length of the input data
 *
 * @return evhtp_req_t * on success, NULL on error.
 */
static evhtp_path_t *
_evhtp_path_new(const char * data, size_t len) {
    evhtp_path_t * req_path;
    const char   * data_end = (const char *)(data + len);
    char         * path     = NULL;
    char         * file     = NULL;

    if (!(req_path = calloc(sizeof(evhtp_path_t), 1))) {
        return NULL;
    }

    if (len == 0) {
        /*
         * odd situation here, no preceding "/", so just assume the path is "/"
         */
        path = strdup("/");
    } else if (*data != '/') {
        /* req like GET stupid HTTP/1.0, treat stupid as the file, and
         * assume the path is "/"
         */
        path = strdup("/");
        file = strndup(data, len);
    } else {
        if (data[len - 1] != '/') {
            /*
             * the last character in data is assumed to be a file, not the end of path
             * loop through the input data backwards until we find a "/"
             */
            size_t i;

            for (i = (len - 1); i != 0; i--) {
                if (data[i] == '/') {
                    /*
                     * we have found a "/" representing the start of the file,
                     * and the end of the path
                     */
                    size_t path_len;
                    size_t file_len;

                    path_len = (size_t)(&data[i] - data) + 1;
                    file_len = (size_t)(data_end - &data[i + 1]);

                    /* check for overflow */
                    if ((const char *)(data + path_len) > data_end) {
                        fprintf(stderr, "PATH Corrupted.. (path_len > len)\n");
                        free(req_path);
                        return NULL;
                    }

                    /* check for overflow */
                    if ((const char *)(&data[i + 1] + file_len) > data_end) {
                        fprintf(stderr, "FILE Corrupted.. (file_len > len)\n");
                        free(req_path);
                        return NULL;
                    }

                    path = strndup(data, path_len);
                    file = strndup(&data[i + 1], file_len);

                    break;
                }
            }

            if (i == 0 && data[i] == '/' && !file && !path) {
                /* drops here if the req is something like GET /foo */
                path = strdup("/");

                if (len > 1) {
                    file = strndup((const char *)(data + 1), len);
                }
            }
        } else {
            /* the last character is a "/", thus the req is just a path */
            path = strndup(data, len);
        }
    }

    if (len != 0) {
        req_path->full = strndup(data, len);
    }

    req_path->path = path;
    req_path->file = file;

    return req_path;
}     /* _evhtp_path_new */

static void
_evhtp_path_free(evhtp_path_t * path) {
    if (path == NULL) {
        return;
    }

    free(path->full);

    free(path->path);
    free(path->file);
    free(path->match_start);
    free(path->match_end);

    free(path);
}

static int
_evhtp_req_parser_start(evhtp_parser * p) {
    evhtp_conn_t * c = evhtp_parser_get_userdata(p);

    if (c->type == evhtp_type_client) {
        return 0;
    }

    if (c->paused) {
        return -1;
    }

    if (c->req) {
        if (c->req->finished == 1) {
            _evhtp_req_free(c->req);
        } else {
            return -1;
        }
    }

    if (!(c->req = _evhtp_req_new(c))) {
        return -1;
    }

    return 0;
}

static int
_evhtp_req_parser_args(evhtp_parser * p, const char * data, size_t len) {
    evhtp_conn_t * c   = evhtp_parser_get_userdata(p);
    evhtp_uri_t  * uri = c->req->uri;

    if (c->type == evhtp_type_client) {
        /* as a client, technically we should never get here, but just in case
         * we return a 0 to the parser to continue.
         */
        return 0;
    }

    if (!(uri->query = evhtp_parse_query(data, len))) {
        c->req->status = EVHTP_RES_ERROR;
        return -1;
    }

    uri->query_raw = calloc(len + 1, 1);
    memcpy(uri->query_raw, data, len);

    return 0;
}

static int
_evhtp_req_parser_headers_start(evhtp_parser * p) {
    evhtp_conn_t * c = evhtp_parser_get_userdata(p);

    if ((c->req->status = _evhtp_hdrs_start_hook(c->req)) != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}

static int
_evhtp_req_parser_header_key(evhtp_parser * p, const char * data, size_t len) {
    evhtp_conn_t * c = evhtp_parser_get_userdata(p);
    char         * key_s;           /* = strndup(data, len); */
    evhtp_hdr_t  * hdr;

    key_s      = malloc(len + 1);
    key_s[len] = '\0';
    memcpy(key_s, data, len);

    if ((hdr = evhtp_hdr_key_add(c->req->headers_in, key_s, 0)) == NULL) {
        c->req->status = EVHTP_RES_FATAL;
        return -1;
    }

    hdr->k_heaped = 1;
    return 0;
}

static int
_evhtp_req_parser_header_val(evhtp_parser * p, const char * data, size_t len) {
    evhtp_conn_t * c = evhtp_parser_get_userdata(p);
    char         * val_s;
    evhtp_hdr_t  * header;

    val_s      = malloc(len + 1);
    val_s[len] = '\0';
    memcpy(val_s, data, len);

    if ((header = evhtp_hdr_val_add(c->req->headers_in, val_s, 0)) == NULL) {
        free(val_s);
        c->req->status = EVHTP_RES_FATAL;
        return -1;
    }

    header->v_heaped = 1;

    if ((c->req->status = _evhtp_hdr_hook(c->req, header)) != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}

static inline evhtp_t *
_evhtp_req_find_vhost(evhtp_t * evhtp, const char * name) {
    evhtp_t       * evhtp_vhost;
    evhtp_alias_t * evhtp_alias;

    TAILQ_FOREACH(evhtp_vhost, &evhtp->vhosts, next_vhost) {
        if (evhtp_vhost->server_name == NULL) {
            continue;
        }

        if (_evhtp_glob_match(evhtp_vhost->server_name, name) == 1) {
            return evhtp_vhost;
        }

        TAILQ_FOREACH(evhtp_alias, &evhtp_vhost->aliases, next) {
            if (evhtp_alias->alias == NULL) {
                continue;
            }

            if (_evhtp_glob_match(evhtp_alias->alias, name) == 1) {
                return evhtp_vhost;
            }
        }
    }

    return NULL;
}

inline evhtp_t *
evhtp_req_find_vhost(evhtp_t * evhtp, const char * name) {
    return _evhtp_req_find_vhost(evhtp, name);
}

static inline int
_evhtp_req_set_callbacks(evhtp_req_t * req) {
    evhtp_t          * evhtp;
    evhtp_conn_t     * conn;
    evhtp_uri_t      * uri;
    evhtp_path_t     * path;
    evhtp_hooks_t    * hooks;
    evhtp_callback_t * callback;
    evhtp_callback_cb  cb;
    void             * cbarg;

    if (req == NULL) {
        return -1;
    }

    if ((evhtp = req->htp) == NULL) {
        return -1;
    }

    if ((conn = req->conn) == NULL) {
        return -1;
    }

    if ((uri = req->uri) == NULL) {
        return -1;
    }

    if ((path = uri->path) == NULL) {
        return -1;
    }

    hooks    = NULL;
    callback = NULL;
    cb       = NULL;
    cbarg    = NULL;

    if ((callback = _evhtp_callback_find(evhtp->callbacks, path->full,
                                         &path->matched_soff, &path->matched_eoff))) {
        /* matched a callback using both path and file (/a/b/c/d) */
        cb    = callback->cb;
        cbarg = callback->cbarg;
        hooks = callback->hooks;
    } else if ((callback = _evhtp_callback_find(evhtp->callbacks, path->path,
                                                &path->matched_soff, &path->matched_eoff))) {
        /* matched a callback using *just* the path (/a/b/c/) */
        cb    = callback->cb;
        cbarg = callback->cbarg;
        hooks = callback->hooks;
    } else {
        /* no callbacks found for either case, use defaults */
        cb    = evhtp->defaults.cb;
        cbarg = evhtp->defaults.cbarg;

        path->matched_soff = 0;
        path->matched_eoff = (unsigned int)strlen(path->full);
    }

    if (path->match_start == NULL) {
        path->match_start = calloc(strlen(path->full) + 1, 1);
    }

    if (path->match_end == NULL) {
        path->match_end = calloc(strlen(path->full) + 1, 1);
    }

    if (path->matched_soff != UINT_MAX /*ONIG_REGION_NOTPOS*/) {
        if (path->matched_eoff - path->matched_soff) {
            memcpy(path->match_start, (void *)(path->full + path->matched_soff),
                   path->matched_eoff - path->matched_soff);
        } else {
            memcpy(path->match_start, (void *)(path->full + path->matched_soff),
                   strlen((const char *)(path->full + path->matched_soff)));
        }

        memcpy(path->match_end,
               (void *)(path->full + path->matched_eoff),
               strlen(path->full) - path->matched_eoff);
    }

    if (hooks != NULL) {
        if (req->hooks == NULL) {
            req->hooks = malloc(sizeof(evhtp_hooks_t));
        }

        memcpy(req->hooks, hooks, sizeof(evhtp_hooks_t));
    }

    req->cb             = cb;
    req->cbarg          = cbarg;
    req->cb_has_websock = callback ? callback->websock : 0;

    return 0;
} /* _evhtp_req_set_callbacks */

static int
_evhtp_req_parser_hostname(evhtp_parser * p, const char * data, size_t len) {
    evhtp_conn_t * c = evhtp_parser_get_userdata(p);
    evhtp_t      * evhtp;
    evhtp_t      * evhtp_vhost;

#ifdef EVHTP_ENABLE_SSL
    if (c->vhost_via_sni == 1 && c->ssl != NULL) {
        /* use the SNI set hostname instead of the header hostname */
        const char * host;

        host = SSL_get_servername(c->ssl, TLSEXT_NAMETYPE_host_name);

        if ((c->req->status = _evhtp_hostname_hook(c->req, host)) != EVHTP_RES_OK) {
            return -1;
        }

        return 0;
    }
#endif

    evhtp = c->htp;

    /* since this is called after _evhtp_req_parser_path(), which already
     * setup callbacks for the URI, we must now attempt to find callbacks which
     * are specific to this host.
     */
    _evhtp_lock(evhtp);
    {
        if ((evhtp_vhost = _evhtp_req_find_vhost(evhtp, data))) {
            _evhtp_lock(evhtp_vhost);
            {
                /* if we found a match for the host, we must set the htp
                 * variables for both the conn and the req.
                 */
                c->htp      = evhtp_vhost;
                c->req->htp = evhtp_vhost;

                _evhtp_req_set_callbacks(c->req);
            }
            _evhtp_unlock(evhtp_vhost);
        }
    }
    _evhtp_unlock(evhtp);

    if ((c->req->status = _evhtp_hostname_hook(c->req, data)) != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
} /* _evhtp_req_parser_hostname */

static int
_evhtp_req_parser_path(evhtp_parser * p, const char * data, size_t len) {
    evhtp_conn_t * c = evhtp_parser_get_userdata(p);
    evhtp_uri_t  * uri;
    evhtp_path_t * path;

    if (!(uri = _evhtp_uri_new())) {
        c->req->status = EVHTP_RES_FATAL;
        return -1;
    }

    if (!(path = _evhtp_path_new(data, len))) {
        _evhtp_uri_free(uri);
        c->req->status = EVHTP_RES_FATAL;
        return -1;
    }

    uri->path      = path;
    uri->scheme    = evhtp_parser_get_scheme(p);

    c->req->method = evhtp_parser_get_method(p);
    c->req->uri    = uri;

    _evhtp_lock(c->htp);
    {
        _evhtp_req_set_callbacks(c->req);
    }
    _evhtp_unlock(c->htp);

    if ((c->req->status = _evhtp_path_hook(c->req, path)) != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}     /* _evhtp_req_parser_path */

static int
_evhtp_req_parser_headers(evhtp_parser * p) {
    evhtp_conn_t * c   = evhtp_parser_get_userdata(p);
    evhtp_req_t  * req = c->req;

    /* XXX proto should be set with evhtp_parsers on_hdrs_begin hook */
    req->keepalive = evhtp_parser_should_keep_alive(p);
    req->proto     = _evhtp_protocol(evhtp_parser_get_major(p), evhtp_parser_get_minor(p));
    req->status    = _evhtp_hdrs_hook(req, req->headers_in);

    if (req->status != EVHTP_RES_OK) {
        return -1;
    }

    if (c->type != evhtp_type_server) {
        return 0;
    }

    if (!c->htp->disable_100_cont) {
        if (evhtp_hdr_find(req->headers_in, "Expect")) {
            evbuffer_add_printf(bufferevent_get_output(c->bev),
                                "HTTP/%d.%d 100 Continue\r\n\r\n",
                                evhtp_parser_get_major(p),
                                evhtp_parser_get_minor(p));
        }
    }

    if (req->cb && req->cb_has_websock) {
        /* the callback that was set was enabled with websocket support, here we
         * check the value of the Connection header, and if "Upgrade" is the
         * value, we attempt to create the handshake. If the handshake fails for
         * any reason, the entire request is dropped.
         *
         * On the other hand, if the handshake is a success, we must set the
         * request 'websocket' value to 1, and start a response with a SWITCH
         * PROTOCOL response. This lets the _evhtp_conn_readcb() function to
         * process further data as websockets, instead of normal HTTP.
         */
        const char * conn_val;

        if ((conn_val = evhtp_hdr_find(req->headers_in, "Connection"))) {
            if (!strcmp(conn_val, "Upgrade")) {
                int ws_hs_res;

                ws_hs_res = evhtp_ws_gen_handshake(
                    req->headers_in,
                    req->headers_out);

                if (ws_hs_res == -1) {
                    return -1;
                }

                req->websock = 1;

                evhtp_send_reply_start(req, EVHTP_RES_SWITCH_PROTO);
            }
        }
    }

    return 0;
} /* _evhtp_req_parser_headers */

static int
_evhtp_req_parser_body(evhtp_parser * p, const char * data, size_t len) {
    evhtp_conn_t    * c   = evhtp_parser_get_userdata(p);
    struct evbuffer * buf;
    int               res = 0;

    if (c->max_body_size > 0 && c->body_bytes_read + len >= c->max_body_size) {
        c->error       = 1;
        c->req->status = EVHTP_RES_DATA_TOO_LONG;

        return -1;
    }

    buf = evbuffer_new();
    evbuffer_add(buf, data, len);

    if ((c->req->status = _evhtp_body_hook(c->req, buf)) != EVHTP_RES_OK) {
        res = -1;
    }

    if (evbuffer_get_length(buf)) {
        evbuffer_add_buffer(c->req->buffer_in, buf);
    }

    evbuffer_free(buf);

    c->body_bytes_read += len;

    return res;
}

static int
_evhtp_req_parser_chunk_new(evhtp_parser * p) {
    evhtp_conn_t * c = evhtp_parser_get_userdata(p);

    if ((c->req->status = _evhtp_chunk_new_hook(c->req,
                                                evhtp_parser_get_content_length(p))) != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}

static int
_evhtp_req_parser_chunk_fini(evhtp_parser * p) {
    evhtp_conn_t * c = evhtp_parser_get_userdata(p);

    if ((c->req->status = _evhtp_chunk_fini_hook(c->req)) != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}

static int
_evhtp_req_parser_chunks_fini(evhtp_parser * p) {
    evhtp_conn_t * c = evhtp_parser_get_userdata(p);

    if ((c->req->status = _evhtp_chunks_fini_hook(c->req)) != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}

/**
 * @brief determines if the req body contains the query arguments.
 *        if the query is NULL and the contenet length of the body has never
 *        been drained, and the content-type is x-www-form-urlencoded, the
 *        function returns 1
 *
 * @param req
 *
 * @return 1 if evhtp can use the body as the query arguments, 0 otherwise.
 */
static int
_evhtp_should_parse_query_body(evhtp_req_t * req) {
    const char * content_type;

    if (req == NULL) {
        return 0;
    }

    if (req->uri == NULL || req->uri->query != NULL) {
        return 0;
    }

    if (evhtp_req_content_len(req) == 0) {
        return 0;
    }

    if (evhtp_req_content_len(req) !=
        evbuffer_get_length(req->buffer_in)) {
        return 0;
    }

    content_type = evhtp_kv_find(req->headers_in, "content-type");

    if (content_type == NULL) {
        return 0;
    }

    if (strncasecmp(content_type, "application/x-www-form-urlencoded", 33)) {
        return 0;
    }

    return 1;
}

static int
_evhtp_req_parser_fini(evhtp_parser * p) {
    evhtp_conn_t * c = evhtp_parser_get_userdata(p);

    if (c->paused == 1) {
        return -1;
    }

    if (c->req && c->req->websock) {
        /* websockets have been set for this request, we don't want to do any
         * further processing on it.
         */
        return 0;
    }

    /* check to see if we should use the body of the req as the query
     * arguments.
     */
    if (_evhtp_should_parse_query_body(c->req) == 1) {
        const char      * body;
        size_t            body_len;
        evhtp_uri_t     * uri;
        struct evbuffer * buf_in;

        uri            = c->req->uri;
        buf_in         = c->req->buffer_in;

        body_len       = evbuffer_get_length(buf_in);
        body           = (const char *)evbuffer_pullup(buf_in, body_len);

        uri->query_raw = calloc(body_len + 1, 1);
        memcpy(uri->query_raw, body, body_len);

        uri->query     = evhtp_parse_query(body, body_len);
    }


    /*
     * XXX c->req should never be NULL, but we have found some path of
     * execution where this actually happens. We will check for now, but the bug
     * path needs to be tracked down.
     *
     */
    if (c->req && c->req->cb) {
        (c->req->cb)(c->req, c->req->cbarg);
    }

    if (c->paused == 1) {
        return -1;
    }

    return 0;
} /* _evhtp_req_parser_fini */

static int
_evhtp_create_headers(evhtp_hdr_t * header, void * arg) {
    struct evbuffer * buf = arg;

    evbuffer_add(buf, header->key, header->klen);
    evbuffer_add(buf, ": ", 2);
    evbuffer_add(buf, header->val, header->vlen);
    evbuffer_add(buf, "\r\n", 2);
    return 0;
}

static struct evbuffer *
_evhtp_create_reply(evhtp_req_t * req, evhtp_res code) {
    struct evbuffer * buf          = evbuffer_new();
    const char      * content_type = evhtp_hdr_find(req->headers_out, "Content-Type");
    char              res_buf[1024];
    int               sres;

    if (evhtp_parser_get_multipart(req->conn->parser) == 1) {
        goto check_proto;
    }

    if (evbuffer_get_length(req->buffer_out) && req->chunked == 0) {
        /* add extra headers (like content-length/type) if not already present */

        if (!evhtp_hdr_find(req->headers_out, "Content-Length")) {
            char lstr[128];
#ifndef WIN32
            sres = snprintf(lstr, sizeof(lstr), "%zu",
                            evbuffer_get_length(req->buffer_out));
#else
            sres = snprintf(lstr, sizeof(lstr), "%u",
                            evbuffer_get_length(req->buffer_out));
#endif

            if (sres >= sizeof(lstr) || sres < 0) {
                /* overflow condition, this should never happen, but if it does,
                 * well lets just shut the conn down */
                req->keepalive = 0;
                goto check_proto;
            }

            evhtp_hdrs_add_header(req->headers_out,
                                  evhtp_hdr_new("Content-Length", lstr, 0, 1));
        }

        if (!content_type) {
            evhtp_hdrs_add_header(req->headers_out,
                                  evhtp_hdr_new("Content-Type", "text/plain", 0, 0));
        }
    } else {
        if (!evhtp_hdr_find(req->headers_out, "Content-Length")) {
            const char * chunked = evhtp_hdr_find(req->headers_out,
                                                  "transfer-encoding");

            if (!chunked || !strstr(chunked, "chunked")) {
                evhtp_hdrs_add_header(req->headers_out,
                                      evhtp_hdr_new("Content-Length", "0", 0, 0));
            }
        }
    }

check_proto:
    /* add the proper keep-alive type headers based on http version */
    switch (req->proto) {
        case EVHTP_PROTO_11:
            if (req->keepalive == 0) {
                /* protocol is HTTP/1.1 but client wanted to close */
                evhtp_hdrs_add_header(req->headers_out,
                                      evhtp_hdr_new("Connection", "close", 0, 0));
            }
            break;
        case EVHTP_PROTO_10:
            if (req->keepalive == 1) {
                /* protocol is HTTP/1.0 and clients wants to keep established */
                evhtp_hdrs_add_header(req->headers_out,
                                      evhtp_hdr_new("Connection", "keep-alive", 0, 0));
            }
            break;
        default:
            /* this sometimes happens when a response is made but paused before
             * the method has been parsed */
            evhtp_parser_set_major(req->conn->parser, 1);
            evhtp_parser_set_minor(req->conn->parser, 0);
            break;
    } /* switch */


    /* attempt to add the status line into a temporary buffer and then use
     * evbuffer_add(). Using plain old snprintf() will be faster than
     * evbuffer_add_printf(). If the snprintf() fails, which it rarely should,
     * we fallback to using evbuffer_add_printf().
     */

    sres = snprintf(res_buf, sizeof(res_buf), "HTTP/%d.%d %d %s\r\n",
                    evhtp_parser_get_major(req->conn->parser),
                    evhtp_parser_get_minor(req->conn->parser),
                    code, status_code_to_str(code));

    if (sres >= sizeof(res_buf) || sres < 0) {
        /* failed to fit the whole thing in the res_buf, so just fallback to
         * using evbuffer_add_printf().
         */
        evbuffer_add_printf(buf, "HTTP/%d.%d %d %s\r\n",
                            evhtp_parser_get_major(req->conn->parser),
                            evhtp_parser_get_minor(req->conn->parser),
                            code, status_code_to_str(code));
    } else {
        /* copy the res_buf using evbuffer_add() instead of add_printf() */
        evbuffer_add(buf, res_buf, sres);
    }


    evhtp_hdrs_for_each(req->headers_out, _evhtp_create_headers, buf);
    evbuffer_add(buf, "\r\n", 2);

    if (evbuffer_get_length(req->buffer_out)) {
        evbuffer_add_buffer(buf, req->buffer_out);
    }

    return buf;
}     /* _evhtp_create_reply */

static void
_evhtp_conn_resumecb(int fd, short events, void * arg) {
    evhtp_conn_t * c = arg;

    c->paused = evhtp_pause_s_nil;

    if (c->req) {
        c->req->status = EVHTP_RES_OK;
    }

    if (c->free_conn == 1) {
        evhtp_conn_free(c);
        return;
    }

    /* XXX this is a hack to show a potential fix for issues/86, the main indea
     * is that you call resume AFTER you have sent the reply (not BEFORE).
     *
     * When it has been decided this is a proper fix, the pause bit should be
     * changed to a state-type flag.
     */

    if (evbuffer_get_length(bufferevent_get_output(c->bev))) {
        bufferevent_enable(c->bev, EV_WRITE);
        c->paused = evhtp_pause_s_waiting;
    } else {
        bufferevent_enable(c->bev, EV_READ | EV_WRITE);
        _evhtp_conn_readcb(c->bev, c);
    }
}

static void
_evhtp_conn_readcb(struct bufferevent * bev, void * arg) {
    evhtp_conn_t * c   = arg;
    evhtp_req_t  * req = c->req;
    void         * buf;
    size_t         nread;
    size_t         avail;

    avail = evbuffer_get_length(bufferevent_get_input(bev));

    if (avail == 0) {
        return;
    }

    if (req) {
        req->status = EVHTP_RES_OK;
    }

    if (c->paused) {
        return;
    }

    buf = evbuffer_pullup(bufferevent_get_input(bev), avail);

    if (req && req->websock) {
        /* process this data as websocket data, if the websocket parser has not
         * been allocated, we allocate it first.
         */
        if (req->ws_parser == NULL) {
            req->ws_parser = evhtp_ws_parser_new();

            evhtp_ws_parser_set_userdata(req->ws_parser, req);
        }

        assert(req->ws_parser != NULL);

        /* XXX need a parser_init / parser_set_userdata */
        nread = evhtp_ws_parser_run(req->ws_parser,
                                    &ws_hooks, buf, avail);
    } else {
        /* process as normal HTTP data. */
        nread = evhtp_parser_run(c->parser,
                                 &req_psets, buf, avail);
    }

    if (c->owner != 1) {
        /*
         * someone has taken the ownership of this conn, we still need to
         * drain the input buffer that had been read up to this point.
         */
        evbuffer_drain(bufferevent_get_input(bev), nread);
        evhtp_conn_free(c);
        return;
    }

    req = c->req;

    if (req) {
        switch (req->status) {
            case EVHTP_RES_DATA_TOO_LONG:
                if (req->hooks && req->hooks->on_error) {
                    (*req->hooks->on_error)(req, -1, req->hooks->on_error_arg);
                }
                evhtp_conn_free(c);
                return;
            default:
                break;
        }
    }

    evbuffer_drain(bufferevent_get_input(bev), nread);

    if (req && req->status == EVHTP_RES_PAUSE) {
        evhtp_req_pause(req);
    } else if (avail != nread) {
        evhtp_conn_free(c);
    }
} /* _evhtp_conn_readcb */

static void
_evhtp_conn_writecb(struct bufferevent * bev, void * arg) {
    evhtp_conn_t * c = arg;

    if (c->req == NULL) {
        return;
    }

    _evhtp_conn_write_hook(c);

    if (c->paused) {
        return;
    }

    if (c->paused == evhtp_pause_s_waiting) {
        c->paused = evhtp_pause_s_nil;

        bufferevent_enable(bev, EV_READ);

        if (evbuffer_get_length(bufferevent_get_input(bev))) {
            _evhtp_conn_readcb(bev, arg);
        }

        return;
    }

    if (c->req->finished == 0 || evbuffer_get_length(bufferevent_get_output(bev))) {
        return;
    }


    /*
     * if there is a set maximum number of keepalive reqs configured, check
     * to make sure we are not over it. If we have gone over the max we set the
     * keepalive bit to 0, thus closing the conn.
     */
    if (c->htp->max_keepalive_reqs) {
        if (++c->num_reqs >= c->htp->max_keepalive_reqs) {
            c->req->keepalive = 0;
        }
    }

    if (c->req->keepalive == 1) {
        _evhtp_req_free(c->req);

        c->req = NULL;
        c->body_bytes_read = 0;

        if (c->htp->parent && c->vhost_via_sni == 0) {
            /* this req was servied by a virtual host evhtp_t structure
             * which was *NOT* found via SSL SNI lookup. In this case we want to
             * reset our conns evhtp_t structure back to the original so
             * that subsequent reqs can have a different Host: header.
             */
            evhtp_t * orig_htp = c->htp->parent;

            c->htp = orig_htp;
        }

        evhtp_parser_init(c->parser, evhtp_parser_type_request);

        evhtp_parser_set_userdata(c->parser, c);
        return;
    } else {
        evhtp_conn_free(c);
        return;
    }

    return;
} /* _evhtp_conn_writecb */

static void
_evhtp_conn_eventcb(struct bufferevent * bev, short events, void * arg) {
    evhtp_conn_t * c = arg;

    if (c->hooks && c->hooks->on_event) {
        (c->hooks->on_event)(c, events, c->hooks->on_event_arg);
    }

    if ((events & BEV_EVENT_CONNECTED)) {
        if (c->type == evhtp_type_client) {
            c->connected = 1;

            bufferevent_setcb(bev,
                              _evhtp_conn_readcb,
                              _evhtp_conn_writecb,
                              _evhtp_conn_eventcb, c);
        }

        return;
    }

#ifdef EVHTP_ENABLE_SSL
    if (c->ssl && !(events & BEV_EVENT_EOF)) {
        /* XXX need to do better error handling for SSL specific errors */
        c->error = 1;

        if (c->req) {
            c->req->error = 1;
        }
    }
#endif

    if (events == (BEV_EVENT_EOF | BEV_EVENT_READING)) {
        if (errno == EAGAIN) {
            /* libevent will sometimes recv again when it's not actually ready,
             * this results in a 0 return value, and errno will be set to EAGAIN
             * (try again). This does not mean there is a hard socket error, but
             * simply needs to be read again.
             *
             * but libevent will disable the read side of the bufferevent
             * anyway, so we must re-enable it.
             */
            bufferevent_enable(bev, EV_READ);
            errno = 0;
            return;
        }
    }

    c->error     = 1;
    c->connected = 0;

    if (c->req && c->req->hooks && c->req->hooks->on_error) {
        (*c->req->hooks->on_error)(c->req, events,
                                   c->req->hooks->on_error_arg);
    }


    if (c->paused) {
        c->free_conn = 1;
    } else {
        evhtp_conn_free((evhtp_conn_t *)arg);
    }
} /* _evhtp_conn_eventcb */

static int
_evhtp_run_pre_accept(evhtp_t * htp, evhtp_conn_t * conn) {
    void    * args;
    evhtp_res res;

    if (htp->defaults.pre_accept == NULL) {
        return 0;
    }

    args = htp->defaults.pre_accept_cbarg;
    res  = htp->defaults.pre_accept(conn, args);

    if (res != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}

static int
_evhtp_conn_accept(struct event_base * evbase, evhtp_conn_t * conn) {
    struct timeval * c_recv_timeo;
    struct timeval * c_send_timeo;

    if (_evhtp_run_pre_accept(conn->htp, conn) < 0) {
        evutil_closesocket(conn->sock);
        return -1;
    }

#ifdef EVHTP_ENABLE_SSL
    if (conn->htp->ssl_ctx != NULL) {
        conn->ssl = SSL_new(conn->htp->ssl_ctx);
        conn->bev = bufferevent_openssl_socket_new(evbase,
                                                   conn->sock,
                                                   conn->ssl,
                                                   BUFFEREVENT_SSL_ACCEPTING,
                                                   conn->htp->bev_flags);
        SSL_set_app_data(conn->ssl, conn);
        goto end;
    }
#endif

    conn->bev = bufferevent_socket_new(evbase,
                                       conn->sock,
                                       conn->htp->bev_flags);
#ifdef EVHTP_ENABLE_SSL
end:
#endif

    if (conn->recv_timeo.tv_sec || conn->recv_timeo.tv_usec) {
        c_recv_timeo = &conn->recv_timeo;
    } else if (conn->htp->recv_timeo.tv_sec ||
               conn->htp->recv_timeo.tv_usec) {
        c_recv_timeo = &conn->htp->recv_timeo;
    } else {
        c_recv_timeo = NULL;
    }

    if (conn->send_timeo.tv_sec || conn->send_timeo.tv_usec) {
        c_send_timeo = &conn->send_timeo;
    } else if (conn->htp->send_timeo.tv_sec ||
               conn->htp->send_timeo.tv_usec) {
        c_send_timeo = &conn->htp->send_timeo;
    } else {
        c_send_timeo = NULL;
    }

    evhtp_conn_set_timeouts(conn, c_recv_timeo, c_send_timeo);

    conn->resume_ev = event_new(evbase, -1, EV_READ | EV_PERSIST,
                                _evhtp_conn_resumecb, conn);
    event_add(conn->resume_ev, NULL);

    bufferevent_enable(conn->bev, EV_READ);
    bufferevent_setcb(conn->bev,
                      _evhtp_conn_readcb,
                      _evhtp_conn_writecb,
                      _evhtp_conn_eventcb, conn);

    return 0;
}     /* _evhtp_conn_accept */

static void
_evhtp_default_req_cb(evhtp_req_t * req, void * arg) {
    evhtp_send_reply(req, EVHTP_RES_NOTFOUND);
}

static evhtp_conn_t *
_evhtp_conn_new(evhtp_t * htp, evutil_socket_t sock, evhtp_type type) {
    evhtp_conn_t    * conn;
    evhtp_parser_type ptype;

    switch (type) {
        case evhtp_type_client:
            ptype = evhtp_parser_type_response;
            break;
        case evhtp_type_server:
            ptype = evhtp_parser_type_request;
            break;
        default:
            return NULL;
    }

    if (!(conn = calloc(sizeof(evhtp_conn_t), 1))) {
        return NULL;
    }

    conn->error     = 0;
    conn->owner     = 1;
    conn->connected = 0;
    conn->paused    = evhtp_pause_s_nil;
    conn->sock      = sock;
    conn->htp       = htp;
    conn->type      = type;
    conn->parser    = evhtp_parser_new();

    evhtp_parser_init(conn->parser, ptype);
    evhtp_parser_set_userdata(conn->parser, conn);

    TAILQ_INIT(&conn->pending);

    return conn;
}

#ifdef LIBEVENT_HAS_SHUTDOWN
#ifdef EVHTP_ENABLE_SSL
static void
_evhtp_shutdown_eventcb(struct bufferevent * bev, short events, void * arg) {
}

#endif
#endif

static int
_evhtp_run_post_accept(evhtp_t * htp, evhtp_conn_t * conn) {
    void    * args;
    evhtp_res res;

    if (htp->defaults.post_accept == NULL) {
        return 0;
    }

    args = htp->defaults.post_accept_cbarg;
    res  = htp->defaults.post_accept(conn, args);

    if (res != EVHTP_RES_OK) {
        return -1;
    }

    return 0;
}

#ifdef EVHTP_ENABLE_EVTHR
static void
_evhtp_run_in_thread(evhtp_thr_t * thr, void * arg, void * shared) {
    evhtp_t      * htp  = shared;
    evhtp_conn_t * conn = arg;

    conn->evbase = evhtp_thr_get_base(thr);
    conn->thread = thr;

    if (_evhtp_conn_accept(conn->evbase, conn) < 0) {
        evhtp_conn_free(conn);
        return;
    }

    if (_evhtp_run_post_accept(htp, conn) < 0) {
        evhtp_conn_free(conn);
        return;
    }
}

#endif

static void
_evhtp_accept_cb(struct evconnlistener * serv, int fd, struct sockaddr * s, int sl, void * arg) {
    evhtp_t      * htp = arg;
    evhtp_conn_t * conn;

    if (!(conn = _evhtp_conn_new(htp, fd, evhtp_type_server))) {
        return;
    }

    conn->saddr = malloc(sl);
    memcpy(conn->saddr, s, sl);

#ifdef EVHTP_ENABLE_EVTHR
    if (htp->thr_pool != NULL) {
        if (evhtp_thr_pool_defer(htp->thr_pool,
                                 _evhtp_run_in_thread, conn) != EVHTP_THR_RES_OK) {
            evutil_closesocket(conn->sock);
            evhtp_conn_free(conn);
            return;
        }
        return;
    }
#endif
    conn->evbase = htp->evbase;

    if (_evhtp_conn_accept(htp->evbase, conn) < 0) {
        evhtp_conn_free(conn);
        return;
    }

    if (_evhtp_run_post_accept(htp, conn) < 0) {
        evhtp_conn_free(conn);
        return;
    }
}

/*
 * PUBLIC FUNCTIONS
 */

evhtp_method
evhtp_req_get_method(evhtp_req_t * r) {
    return evhtp_parser_get_method(r->conn->parser);
}

/**
 * @brief pauses a conn (disables reading)
 *
 * @param c a evhtp_conn_t * structure
 */
void
evhtp_conn_pause(evhtp_conn_t * c) {
    c->paused = evhtp_pause_s_paused;

    bufferevent_disable(c->bev, EV_READ | EV_WRITE);
    return;
}

/**
 * @brief resumes a conn (enables reading) and activates resume event.
 *
 * @param c
 */
void
evhtp_conn_resume(evhtp_conn_t * c) {
    c->paused = evhtp_pause_s_nil;

    event_active(c->resume_ev, EV_WRITE, 1);
    return;
}

/**
 * @brief Wrapper around evhtp_conn_pause
 *
 * @see evhtp_conn_pause
 *
 * @param req
 */
void
evhtp_req_pause(evhtp_req_t * req) {
    req->status = EVHTP_RES_PAUSE;
    evhtp_conn_pause(req->conn);
}

/**
 * @brief Wrapper around evhtp_conn_resume
 *
 * @see evhtp_conn_resume
 *
 * @param req
 */
void
evhtp_req_resume(evhtp_req_t * req) {
    evhtp_conn_resume(req->conn);
}

evhtp_hdr_t *
evhtp_hdr_key_add(evhtp_hdrs_t * headers, const char * key, char kalloc) {
    evhtp_hdr_t * header;

    if (!(header = evhtp_hdr_new(key, NULL, kalloc, 0))) {
        return NULL;
    }

    evhtp_hdrs_add_header(headers, header);

    return header;
}

evhtp_hdr_t *
evhtp_hdr_val_add(evhtp_hdrs_t * headers, const char * val, char valloc) {
    evhtp_hdr_t * header;

    if (!headers || !val) {
        return NULL;
    }

    if (!(header = TAILQ_LAST(headers, evhtp_kvs))) {
        return NULL;
    }

    if (header->val != NULL) {
        return NULL;
    }

    header->vlen = strlen(val);

    if (valloc == 1) {
        header->val = malloc(header->vlen + 1);
        header->val[header->vlen] = '\0';
        memcpy(header->val, val, header->vlen);
    } else {
        header->val = (char *)val;
    }

    header->v_heaped = valloc;

    return header;
}

evhtp_kvs_t *
evhtp_kvs_new(void) {
    evhtp_kvs_t * kvs = malloc(sizeof(evhtp_kvs_t));

    TAILQ_INIT(kvs);
    return kvs;
}

evhtp_kv_t *
evhtp_kv_new(const char * key, const char * val, char kalloc, char valloc) {
    evhtp_kv_t * kv;

    if (!(kv = malloc(sizeof(evhtp_kv_t)))) {
        return NULL;
    }

    kv->k_heaped = kalloc;
    kv->v_heaped = valloc;
    kv->klen     = 0;
    kv->vlen     = 0;
    kv->key      = NULL;
    kv->val      = NULL;

    if (key != NULL) {
        kv->klen = strlen(key);

        if (kalloc == 1) {
            char * s = malloc(kv->klen + 1);

            s[kv->klen] = '\0';
            memcpy(s, key, kv->klen);
            kv->key     = s;
        } else {
            kv->key = (char *)key;
        }
    }

    if (val != NULL) {
        kv->vlen = strlen(val);

        if (valloc == 1) {
            char * s = malloc(kv->vlen + 1);

            s[kv->vlen] = '\0';
            memcpy(s, val, kv->vlen);
            kv->val     = s;
        } else {
            kv->val = (char *)val;
        }
    }

    return kv;
}     /* evhtp_kv_new */

void
evhtp_kv_free(evhtp_kv_t * kv) {
    if (kv == NULL) {
        return;
    }

    if (kv->k_heaped) {
        free(kv->key);
    }

    if (kv->v_heaped) {
        free(kv->val);
    }

    free(kv);
}

void
evhtp_kv_rm_and_free(evhtp_kvs_t * kvs, evhtp_kv_t * kv) {
    if (kvs == NULL || kv == NULL) {
        return;
    }

    TAILQ_REMOVE(kvs, kv, next);

    evhtp_kv_free(kv);
}

void
evhtp_kvs_free(evhtp_kvs_t * kvs) {
    evhtp_kv_t * kv;
    evhtp_kv_t * save;

    if (kvs == NULL) {
        return;
    }

    for (kv = TAILQ_FIRST(kvs); kv != NULL; kv = save) {
        save = TAILQ_NEXT(kv, next);

        TAILQ_REMOVE(kvs, kv, next);

        evhtp_kv_free(kv);
    }

    free(kvs);
}

int
evhtp_kvs_for_each(evhtp_kvs_t * kvs, evhtp_kvs_iterator cb, void * arg) {
    evhtp_kv_t * kv;

    if (kvs == NULL || cb == NULL) {
        return -1;
    }

    TAILQ_FOREACH(kv, kvs, next) {
        int res;

        if ((res = cb(kv, arg))) {
            return res;
        }
    }

    return 0;
}

const char *
evhtp_kv_find(evhtp_kvs_t * kvs, const char * key) {
    evhtp_kv_t * kv;

    if (kvs == NULL || key == NULL) {
        return NULL;
    }

    TAILQ_FOREACH(kv, kvs, next) {
        if (strcasecmp(kv->key, key) == 0) {
            return kv->val;
        }
    }

    return NULL;
}

evhtp_kv_t *
evhtp_kvs_find_kv(evhtp_kvs_t * kvs, const char * key) {
    evhtp_kv_t * kv;

    if (kvs == NULL || key == NULL) {
        return NULL;
    }

    TAILQ_FOREACH(kv, kvs, next) {
        if (strcasecmp(kv->key, key) == 0) {
            return kv;
        }
    }

    return NULL;
}

void
evhtp_kvs_add_kv(evhtp_kvs_t * kvs, evhtp_kv_t * kv) {
    if (kvs == NULL || kv == NULL) {
        return;
    }

    TAILQ_INSERT_TAIL(kvs, kv, next);
}

void
evhtp_kvs_add_kvs(evhtp_kvs_t * dst, evhtp_kvs_t * src) {
    if (dst == NULL || src == NULL) {
        return;
    }

    evhtp_kv_t * kv;

    TAILQ_FOREACH(kv, src, next) {
        evhtp_kvs_add_kv(dst, evhtp_kv_new(kv->key, kv->val, kv->k_heaped, kv->v_heaped));
    }
}

typedef enum {
    s_query_start = 0,
    s_query_question_mark,
    s_query_separator,
    s_query_key,
    s_query_val,
    s_query_key_hex_1,
    s_query_key_hex_2,
    s_query_val_hex_1,
    s_query_val_hex_2,
    s_query_done
} query_parser_state;

static inline int
evhtp_is_hex_query_char(unsigned char ch) {
    switch (ch) {
        case 'a': case 'A':
        case 'b': case 'B':
        case 'c': case 'C':
        case 'd': case 'D':
        case 'e': case 'E':
        case 'f': case 'F':
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            return 1;
        default:
            return 0;
    } /* switch */
}

enum unscape_state {
    unscape_state_start = 0,
    unscape_state_hex1,
    unscape_state_hex2
};

int
evhtp_unescape_string(unsigned char ** out, unsigned char * str, size_t str_len) {
    unsigned char    * optr;
    unsigned char    * sptr;
    unsigned char      d;
    unsigned char      ch;
    unsigned char      c;
    size_t             i;
    enum unscape_state state;

    if (out == NULL || *out == NULL) {
        return -1;
    }

    state = unscape_state_start;
    optr  = *out;
    sptr  = str;
    d     = 0;

    for (i = 0; i < str_len; i++) {
        ch = *sptr++;

        switch (state) {
            case unscape_state_start:
                if (ch == '%') {
                    state = unscape_state_hex1;
                    break;
                }

                *optr++ = ch;

                break;
            case unscape_state_hex1:
                if (ch >= '0' && ch <= '9') {
                    d     = (unsigned char)(ch - '0');
                    state = unscape_state_hex2;
                    break;
                }

                c = (unsigned char)(ch | 0x20);

                if (c >= 'a' && c <= 'f') {
                    d     = (unsigned char)(c - 'a' + 10);
                    state = unscape_state_hex2;
                    break;
                }

                state   = unscape_state_start;
                *optr++ = ch;
                break;
            case unscape_state_hex2:
                state   = unscape_state_start;

                if (ch >= '0' && ch <= '9') {
                    ch      = (unsigned char)((d << 4) + ch - '0');

                    *optr++ = ch;
                    break;
                }

                c = (unsigned char)(ch | 0x20);

                if (c >= 'a' && c <= 'f') {
                    ch      = (unsigned char)((d << 4) + c - 'a' + 10);
                    *optr++ = ch;
                    break;
                }

                break;
        } /* switch */
    }

    return 0;
}         /* evhtp_unescape_string */

evhtp_query_t *
evhtp_parse_query(const char * query, size_t len) {
    evhtp_query_t    * query_args;
    query_parser_state state   = s_query_start;
    char             * key_buf = NULL;
    char             * val_buf = NULL;
    int                key_idx;
    int                val_idx;
    unsigned char      ch;
    size_t             i;

    query_args = evhtp_query_new();

    if (!(key_buf = malloc(len + 1))) {
        return NULL;
    }

    if (!(val_buf = malloc(len + 1))) {
        free(key_buf);
        return NULL;
    }

    key_idx = 0;
    val_idx = 0;

    for (i = 0; i < len; i++) {
        ch = query[i];

        if (key_idx >= len || val_idx >= len) {
            goto error;
        }

        switch (state) {
            case s_query_start:
                memset(key_buf, 0, len);
                memset(val_buf, 0, len);

                key_idx = 0;
                val_idx = 0;

                switch (ch) {
                    case '?':
                        state = s_query_key;
                        break;
                    case '/':
                        state = s_query_question_mark;
                        break;
                    default:
                        state = s_query_key;
                        goto query_key;
                }

                break;
            case s_query_question_mark:
                switch (ch) {
                    case '?':
                        state = s_query_key;
                        break;
                    case '/':
                        state = s_query_question_mark;
                        break;
                    default:
                        goto error;
                }
                break;
query_key:
            case s_query_key:
                switch (ch) {
                    case '=':
                        state = s_query_val;
                        break;
                    case '%':
                        key_buf[key_idx++] = ch;
                        key_buf[key_idx] = '\0';
                        state = s_query_key_hex_1;
                        break;
                    case ';':
                    case '&':
                        /* no = for key, so ignore it and look for next key */
                        memset(key_buf, 0, len);
                        key_idx            = 0;
                        break;
                    default:
                        key_buf[key_idx++] = ch;
                        key_buf[key_idx]   = '\0';
                        break;
                }
                break;
            case s_query_key_hex_1:
                if (!evhtp_is_hex_query_char(ch)) {
                    /* not hex, so we treat as a normal key */
                    if ((key_idx + 2) >= len) {
                        /* we need to insert \%<ch>, but not enough space */
                        goto error;
                    }

                    key_buf[key_idx - 1] = '%';
                    key_buf[key_idx++]   = ch;
                    key_buf[key_idx]     = '\0';
                    state = s_query_key;
                    break;
                }

                key_buf[key_idx++] = ch;
                key_buf[key_idx]   = '\0';

                state = s_query_key_hex_2;
                break;
            case s_query_key_hex_2:
                if (!evhtp_is_hex_query_char(ch)) {
                    goto error;
                }

                key_buf[key_idx++] = ch;
                key_buf[key_idx]   = '\0';

                state = s_query_key;
                break;
            case s_query_val:
                switch (ch) {
                    case ';':
                    case '&':
                        evhtp_kvs_add_kv(query_args, evhtp_kv_new(key_buf, val_buf, 1, 1));

                        memset(key_buf, 0, len);
                        memset(val_buf, 0, len);

                        key_idx            = 0;
                        val_idx            = 0;

                        state              = s_query_key;

                        break;
                    case '%':
                        val_buf[val_idx++] = ch;
                        val_buf[val_idx]   = '\0';

                        state              = s_query_val_hex_1;
                        break;
                    default:
                        val_buf[val_idx++] = ch;
                        val_buf[val_idx]   = '\0';

                        break;
                }     /* switch */
                break;
            case s_query_val_hex_1:
                if (!evhtp_is_hex_query_char(ch)) {
                    /* not really a hex val */
                    if ((val_idx + 2) >= len) {
                        /* we need to insert \%<ch>, but not enough space */
                        goto error;
                    }


                    val_buf[val_idx - 1] = '%';
                    val_buf[val_idx++]   = ch;
                    val_buf[val_idx]     = '\0';

                    state = s_query_val;
                    break;
                }

                val_buf[val_idx++] = ch;
                val_buf[val_idx]   = '\0';

                state = s_query_val_hex_2;
                break;
            case s_query_val_hex_2:
                if (!evhtp_is_hex_query_char(ch)) {
                    goto error;
                }

                val_buf[val_idx++] = ch;
                val_buf[val_idx]   = '\0';

                state = s_query_val;
                break;
            default:
                /* bad state */
                goto error;
        }       /* switch */
    }

    if (key_idx && (val_idx || state == s_query_val)) {
        evhtp_kvs_add_kv(query_args, evhtp_kv_new(key_buf, val_buf, 1, 1));
    }

    free(key_buf);
    free(val_buf);

    return query_args;
error:
    free(key_buf);
    free(val_buf);

    return NULL;
}     /* evhtp_parse_query */

void
evhtp_send_reply_start(evhtp_req_t * req, evhtp_res code) {
    evhtp_conn_t    * c;
    struct evbuffer * reply_buf;

    c = evhtp_req_get_conn(req);

    if (!(reply_buf = _evhtp_create_reply(req, code))) {
        evhtp_conn_free(c);
        return;
    }

    bufferevent_write_buffer(c->bev, reply_buf);
    evbuffer_free(reply_buf);
}

void
evhtp_send_reply_body(evhtp_req_t * req, struct evbuffer * buf) {
    evhtp_conn_t * c;

    c = req->conn;

    bufferevent_write_buffer(c->bev, buf);
}

void
evhtp_send_reply_end(evhtp_req_t * req) {
    req->finished = 1;
}

void
evhtp_send_reply(evhtp_req_t * req, evhtp_res code) {
    evhtp_conn_t    * c;
    struct evbuffer * reply_buf;

    c = evhtp_req_get_conn(req);
    req->finished = 1;

    if (!(reply_buf = _evhtp_create_reply(req, code))) {
        evhtp_conn_free(req->conn);
        return;
    }

    bufferevent_write_buffer(evhtp_conn_get_bev(c), reply_buf);
    evbuffer_free(reply_buf);
}

int
evhtp_response_needs_body(const evhtp_res code, const evhtp_method method) {
    return code != EVHTP_RES_NOCONTENT &&
           code != EVHTP_RES_NOTMOD &&
           (code < 100 || code >= 200) &&
           method != evhtp_method_HEAD;
}

void
evhtp_send_reply_chunk_start(evhtp_req_t * req, evhtp_res code) {
    evhtp_hdr_t * content_len;

    if (evhtp_response_needs_body(code, req->method)) {
        content_len = evhtp_hdrs_find_header(req->headers_out, "Content-Length");

        switch (req->proto) {
            case EVHTP_PROTO_11:

                /*
                 * prefer HTTP/1.1 chunked encoding to closing the conn;
                 * note RFC 2616 section 4.4 forbids it with Content-Length:
                 * and it's not necessary then anyway.
                 */

                evhtp_kv_rm_and_free(req->headers_out, content_len);
                req->chunked = 1;
                break;
            case EVHTP_PROTO_10:
                /*
                 * HTTP/1.0 can be chunked as long as the Content-Length header
                 * is set to 0
                 */
                evhtp_kv_rm_and_free(req->headers_out, content_len);

                evhtp_hdrs_add_header(req->headers_out,
                                      evhtp_hdr_new("Content-Length", "0", 0, 0));

                req->chunked = 1;
                break;
            default:
                req->chunked = 0;
                break;
        } /* switch */
    } else {
        req->chunked = 0;
    }

    if (req->chunked == 1) {
        evhtp_hdrs_add_header(req->headers_out,
                              evhtp_hdr_new("Transfer-Encoding", "chunked", 0, 0));

        /*
         * if data already exists on the output buffer, we automagically convert
         * it to the first chunk.
         */
        if (evbuffer_get_length(req->buffer_out) > 0) {
            char lstr[128];
            int  sres;

            sres = snprintf(lstr, sizeof(lstr), "%x\r\n",
                            (unsigned)evbuffer_get_length(req->buffer_out));

            if (sres >= sizeof(lstr) || sres < 0) {
                /* overflow condition, shouldn't ever get here, but lets
                 * terminate the conn asap */
                goto end;
            }

            evbuffer_prepend(req->buffer_out, lstr, strlen(lstr));
            evbuffer_add(req->buffer_out, "\r\n", 2);
        }
    }

end:
    evhtp_send_reply_start(req, code);
} /* evhtp_send_reply_chunk_start */

void
evhtp_send_reply_chunk(evhtp_req_t * req, struct evbuffer * buf) {
    struct evbuffer * output;

    output = bufferevent_get_output(req->conn->bev);

    if (evbuffer_get_length(buf) == 0) {
        return;
    }
    if (req->chunked) {
        evbuffer_add_printf(output, "%x\r\n",
                            (unsigned)evbuffer_get_length(buf));
    }
    evhtp_send_reply_body(req, buf);

    if (req->chunked == 1) {
        evbuffer_add(output, "\r\n", 2);
    }

    bufferevent_flush(req->conn->bev, EV_WRITE, BEV_FLUSH);
}

void
evhtp_send_reply_chunk_end(evhtp_req_t * req) {
    if (req->chunked) {
        evbuffer_add(bufferevent_get_output(evhtp_req_get_bev(req)),
                     "0\r\n\r\n", 5);
    }

    evhtp_send_reply_end(req);
}

void
evhtp_unbind_socket(evhtp_t * htp) {
    evconnlistener_free(htp->server);
    htp->server = NULL;
}

int
evhtp_bind_sockaddr(evhtp_t * htp, struct sockaddr * sa, size_t sin_len, int backlog) {
#ifndef WIN32
    signal(SIGPIPE, SIG_IGN);
#endif

    htp->server = evconnlistener_new_bind(htp->evbase, _evhtp_accept_cb, (void *)htp,
                                          LEV_OPT_THREADSAFE | LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
                                          backlog, sa, sin_len);
    if (!htp->server) {
        return -1;
    }

#ifdef USE_DEFER_ACCEPT
    {
        evutil_socket_t sock;
        int             one = 1;

        sock = evconnlistener_get_fd(htp->server);

        setsockopt(sock, IPPROTO_TCP, TCP_DEFER_ACCEPT, &one, (ev_socklen_t)sizeof(one));
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, (ev_socklen_t)sizeof(one));
    }
#endif

#ifdef EVHTP_ENABLE_SSL
    if (htp->ssl_ctx != NULL) {
        /* if ssl is enabled and we have virtual hosts, set our servername
         * callback. We do this here because we want to make sure that this gets
         * set after all potential virtualhosts have been set, not just after
         * ssl_init.
         */
        if (TAILQ_FIRST(&htp->vhosts) != NULL) {
            SSL_CTX_set_tlsext_servername_callback(htp->ssl_ctx,
                                                   evhtp_ssl_servername);
        }
    }
#endif

    return 0;
}

int
evhtp_bind_socket(evhtp_t * htp, const char * baddr, uint16_t port, int backlog) {
    struct sockaddr_in  sin;
    struct sockaddr_in6 sin6;

#ifndef NO_SYS_UN
    struct sockaddr_un sun;
#endif
    struct sockaddr  * sa;
    size_t             sin_len;

    memset(&sin, 0, sizeof(sin));

    if (!strncmp(baddr, "ipv6:", 5)) {
        memset(&sin6, 0, sizeof(sin6));

        baddr           += 5;
        sin_len          = sizeof(struct sockaddr_in6);
        sin6.sin6_port   = htons(port);
        sin6.sin6_family = AF_INET6;

        evutil_inet_pton(AF_INET6, baddr, &sin6.sin6_addr);
        sa = (struct sockaddr *)&sin6;
    } else if (!strncmp(baddr, "unix:", 5)) {
#ifndef NO_SYS_UN
        baddr += 5;

        if (strlen(baddr) >= sizeof(sun.sun_path)) {
            return -1;
        }

        memset(&sun, 0, sizeof(sun));

        sin_len        = sizeof(struct sockaddr_un);
        sun.sun_family = AF_UNIX;

        strncpy(sun.sun_path, baddr, strlen(baddr));

        sa = (struct sockaddr *)&sun;
#else
        fprintf(stderr, "System does not support AF_UNIX sockets\n");
        return -1;
#endif
    } else {
        if (!strncmp(baddr, "ipv4:", 5)) {
            baddr += 5;
        }

        sin_len             = sizeof(struct sockaddr_in);

        sin.sin_family      = AF_INET;
        sin.sin_port        = htons(port);
        sin.sin_addr.s_addr = inet_addr(baddr);

        sa = (struct sockaddr *)&sin;
    }

    return evhtp_bind_sockaddr(htp, sa, sin_len, backlog);
} /* evhtp_bind_socket */

void
evhtp_callbacks_free(evhtp_callbacks_t * callbacks) {
    evhtp_callback_t * callback;
    evhtp_callback_t * tmp;

    if (callbacks == NULL) {
        return;
    }

    TAILQ_FOREACH_SAFE(callback, callbacks, next, tmp) {
        TAILQ_REMOVE(callbacks, callback, next);

        evhtp_callback_free(callback);
    }

    free(callbacks);
}

evhtp_callback_t *
evhtp_callback_new(const char * path, evhtp_callback_type type, evhtp_callback_cb cb, void * arg) {
    evhtp_callback_t * hcb;

    if (!(hcb = calloc(sizeof(evhtp_callback_t), 1))) {
        return NULL;
    }

    if (strncmp(path, "ws://", 5) == 0) {
        hcb->websock = 1;
        path        += 5;
    }

    hcb->type  = type;
    hcb->cb    = cb;
    hcb->cbarg = arg;

    switch (type) {
        case evhtp_callback_type_hash:
            hcb->hash      = _evhtp_quick_hash(path);
            hcb->val.path  = strdup(path);
            break;
#ifdef EVHTP_ENABLE_REGEX
        case evhtp_callback_type_regex:
            hcb->val.regex = malloc(sizeof(regex_t));

            if (regcomp(hcb->val.regex, (char *)path, REG_EXTENDED) != 0) {
                free(hcb->val.regex);
                free(hcb);
                return NULL;
            }
            break;
#endif
        case evhtp_callback_type_glob:
            hcb->val.glob = strdup(path);
            break;
        default:
            free(hcb);
            return NULL;
    } /* switch */

    return hcb;
}     /* evhtp_callback_new */

void
evhtp_callback_free(evhtp_callback_t * callback) {
    if (callback == NULL) {
        return;
    }

    switch (callback->type) {
        case evhtp_callback_type_hash:
            free(callback->val.path);
            break;
        case evhtp_callback_type_glob:
            free(callback->val.glob);
            break;
#ifdef EVHTP_ENABLE_REGEX
        case evhtp_callback_type_regex:
            regfree(callback->val.regex);
            free(callback->val.regex);
            break;
#endif
    }

    if (callback->hooks) {
        free(callback->hooks);
    }

    free(callback);

    return;
}

int
evhtp_callbacks_add_callback(evhtp_callbacks_t * cbs, evhtp_callback_t * cb) {
    TAILQ_INSERT_TAIL(cbs, cb, next);

    return 0;
}

int
evhtp_set_hook(evhtp_hooks_t ** hooks, evhtp_hook_type type, evhtp_hook cb, void * arg) {
    if (*hooks == NULL) {
        if (!(*hooks = calloc(sizeof(evhtp_hooks_t), 1))) {
            return -1;
        }
    }

    switch (type) {
        case evhtp_hook_on_headers_start:
            (*hooks)->on_headers_start     = (evhtp_hook_headers_start_cb)cb;
            (*hooks)->on_headers_start_arg = arg;
            break;
        case evhtp_hook_on_header:
            (*hooks)->on_header = (evhtp_hook_header_cb)cb;
            (*hooks)->on_header_arg        = arg;
            break;
        case evhtp_hook_on_headers:
            (*hooks)->on_headers           = (evhtp_hook_headers_cb)cb;
            (*hooks)->on_headers_arg       = arg;
            break;
        case evhtp_hook_on_path:
            (*hooks)->on_path = (evhtp_hook_path_cb)cb;
            (*hooks)->on_path_arg          = arg;
            break;
        case evhtp_hook_on_read:
            (*hooks)->on_read = (evhtp_hook_read_cb)cb;
            (*hooks)->on_read_arg          = arg;
            break;
        case evhtp_hook_on_req_fini:
            (*hooks)->on_req_fini          = (evhtp_hook_req_fini_cb)cb;
            (*hooks)->on_req_fini_arg      = arg;
            break;
        case evhtp_hook_on_conn_fini:
            (*hooks)->on_conn_fini         = (evhtp_hook_conn_fini_cb)cb;
            (*hooks)->on_conn_fini_arg     = arg;
            break;
        case evhtp_hook_on_error:
            (*hooks)->on_error = (evhtp_hook_err_cb)cb;
            (*hooks)->on_error_arg         = arg;
            break;
        case evhtp_hook_on_new_chunk:
            (*hooks)->on_new_chunk         = (evhtp_hook_chunk_new_cb)cb;
            (*hooks)->on_new_chunk_arg     = arg;
            break;
        case evhtp_hook_on_chunk_complete:
            (*hooks)->on_chunk_fini        = (evhtp_hook_chunk_fini_cb)cb;
            (*hooks)->on_chunk_fini_arg    = arg;
            break;
        case evhtp_hook_on_chunks_complete:
            (*hooks)->on_chunks_fini       = (evhtp_hook_chunks_fini_cb)cb;
            (*hooks)->on_chunks_fini_arg   = arg;
            break;
        case evhtp_hook_on_hostname:
            (*hooks)->on_hostname          = (evhtp_hook_hostname_cb)cb;
            (*hooks)->on_hostname_arg      = arg;
            break;
        case evhtp_hook_on_write:
            (*hooks)->on_write = (evhtp_hook_write_cb)cb;
            (*hooks)->on_write_arg         = arg;
            break;
        case evhtp_hook_on_event:
            (*hooks)->on_event = (evhtp_hook_event_cb)cb;
            (*hooks)->on_event_arg         = arg;
            break;
        default:
            return -1;
    }     /* switch */

    return 0;
}         /* evhtp_set_hook */

int
evhtp_unset_hook(evhtp_hooks_t ** hooks, evhtp_hook_type type) {
    return evhtp_set_hook(hooks, type, NULL, NULL);
}

int
evhtp_unset_all_hooks(evhtp_hooks_t ** hooks) {
    int res = 0;

    if (evhtp_unset_hook(hooks, evhtp_hook_on_headers_start)) {
        res -= 1;
    }

    if (evhtp_unset_hook(hooks, evhtp_hook_on_header)) {
        res -= 1;
    }

    if (evhtp_unset_hook(hooks, evhtp_hook_on_headers)) {
        res -= 1;
    }

    if (evhtp_unset_hook(hooks, evhtp_hook_on_path)) {
        res -= 1;
    }

    if (evhtp_unset_hook(hooks, evhtp_hook_on_read)) {
        res -= 1;
    }

    if (evhtp_unset_hook(hooks, evhtp_hook_on_req_fini)) {
        res -= 1;
    }

    if (evhtp_unset_hook(hooks, evhtp_hook_on_conn_fini)) {
        res -= 1;
    }

    if (evhtp_unset_hook(hooks, evhtp_hook_on_error)) {
        res -= 1;
    }

    if (evhtp_unset_hook(hooks, evhtp_hook_on_new_chunk)) {
        res -= 1;
    }

    if (evhtp_unset_hook(hooks, evhtp_hook_on_chunk_complete)) {
        res -= 1;
    }

    if (evhtp_unset_hook(hooks, evhtp_hook_on_chunks_complete)) {
        res -= 1;
    }

    if (evhtp_unset_hook(hooks, evhtp_hook_on_hostname)) {
        res -= 1;
    }

    if (evhtp_unset_hook(hooks, evhtp_hook_on_write)) {
        return -1;
    }

    if (evhtp_unset_hook(hooks, evhtp_hook_on_event)) {
        return -1;
    }

    return res;
} /* evhtp_unset_all_hooks */

inline uint64_t
evhtp_req_get_content_len(evhtp_req_t * req) {
    return evhtp_parser_get_content_length(req->conn->parser);
}

EXPORT_SYMBOL(evhtp_req_get_content_len);

inline int
evhtp_req_set_hook(evhtp_req_t * req,
                   evhtp_hook_type type, evhtp_hook cb, void * arg) {
    return evhtp_set_hook(&req->hooks, type, cb, arg);
}

EXPORT_SYMBOL(evhtp_req_set_hook);

inline int
evhtp_conn_set_hook(evhtp_conn_t * conn,
                    evhtp_hook_type type, evhtp_hook cb, void * arg) {
    return evhtp_set_hook(&conn->hooks, type, cb, arg);
}

EXPORT_SYMBOL(evhtp_conn_set_hook);

inline int
evhtp_callback_set_hook(evhtp_callback_t * callback,
                        evhtp_hook_type type, evhtp_hook cb, void * arg) {
    return evhtp_set_hook(&callback->hooks, type, cb, arg);
}

EXPORT_SYMBOL(evhtp_callback_set_hook);

evhtp_callback_t *
evhtp_set_cb(evhtp_t * htp, const char * path, evhtp_callback_cb cb, void * arg) {
    evhtp_callback_t * hcb;

    _evhtp_lock(htp);

    if (htp->callbacks == NULL) {
        if (!(htp->callbacks = calloc(sizeof(evhtp_callbacks_t), 1))) {
            _evhtp_unlock(htp);
            return NULL;
        }

        TAILQ_INIT(htp->callbacks);
    }

    if (!(hcb = evhtp_callback_new(path, evhtp_callback_type_hash, cb, arg))) {
        _evhtp_unlock(htp);
        return NULL;
    }

    if (evhtp_callbacks_add_callback(htp->callbacks, hcb)) {
        evhtp_callback_free(hcb);
        _evhtp_unlock(htp);
        return NULL;
    }

    _evhtp_unlock(htp);
    return hcb;
}

#ifdef EVHTP_ENABLE_EVTHR
int
evhtp_use_callback_locks(evhtp_t * htp) {
    if (htp == NULL) {
        return -1;
    }

    if (!(htp->lock = malloc(sizeof(pthread_mutex_t)))) {
        return -1;
    }

    return pthread_mutex_init(htp->lock, NULL);
}

#endif

#ifdef EVHTP_ENABLE_REGEX
evhtp_callback_t *
evhtp_set_regex_cb(evhtp_t * htp, const char * pattern, evhtp_callback_cb cb, void * arg) {
    evhtp_callback_t * hcb;

    _evhtp_lock(htp);

    if (htp->callbacks == NULL) {
        if (!(htp->callbacks = calloc(sizeof(evhtp_callbacks_t), 1))) {
            _evhtp_unlock(htp);
            return NULL;
        }

        TAILQ_INIT(htp->callbacks);
    }

    if (!(hcb = evhtp_callback_new(pattern, evhtp_callback_type_regex, cb, arg))) {
        _evhtp_unlock(htp);
        return NULL;
    }

    if (evhtp_callbacks_add_callback(htp->callbacks, hcb)) {
        evhtp_callback_free(hcb);
        _evhtp_unlock(htp);
        return NULL;
    }

    _evhtp_unlock(htp);
    return hcb;
}

#endif

evhtp_callback_t *
evhtp_set_glob_cb(evhtp_t * htp, const char * pattern, evhtp_callback_cb cb, void * arg) {
    evhtp_callback_t * hcb;

    _evhtp_lock(htp);

    if (htp->callbacks == NULL) {
        if (!(htp->callbacks = calloc(sizeof(evhtp_callbacks_t), 1))) {
            _evhtp_unlock(htp);
            return NULL;
        }

        TAILQ_INIT(htp->callbacks);
    }

    if (!(hcb = evhtp_callback_new(pattern, evhtp_callback_type_glob, cb, arg))) {
        _evhtp_unlock(htp);
        return NULL;
    }

    if (evhtp_callbacks_add_callback(htp->callbacks, hcb)) {
        evhtp_callback_free(hcb);
        _evhtp_unlock(htp);
        return NULL;
    }

    _evhtp_unlock(htp);
    return hcb;
}

void
evhtp_set_gencb(evhtp_t * htp, evhtp_callback_cb cb, void * arg) {
    htp->defaults.cb    = cb;
    htp->defaults.cbarg = arg;
}

void
evhtp_set_pre_accept_cb(evhtp_t * htp, evhtp_pre_accept_cb cb, void * arg) {
    htp->defaults.pre_accept       = cb;
    htp->defaults.pre_accept_cbarg = arg;
}

void
evhtp_set_post_accept_cb(evhtp_t * htp, evhtp_post_accept_cb cb, void * arg) {
    htp->defaults.post_accept       = cb;
    htp->defaults.post_accept_cbarg = arg;
}

inline struct event_base *
evhtp_conn_get_evbase(evhtp_conn_t * conn) {
    return conn->evbase;
}

EXPORT_SYMBOL(evhtp_conn_get_evbase);

inline struct bufferevent *
evhtp_conn_get_bev(evhtp_conn_t * conn) {
    return conn->bev;
}

struct bufferevent *
evhtp_conn_take_ownership(evhtp_conn_t * conn) {
    struct bufferevent * bev = evhtp_conn_get_bev(conn);

    if (conn->hooks) {
        evhtp_unset_all_hooks(&conn->hooks);
    }

    if (conn->req && conn->req->hooks) {
        evhtp_unset_all_hooks(&conn->req->hooks);
    }

    evhtp_conn_set_bev(conn, NULL);

    conn->owner = 0;

    bufferevent_disable(bev, EV_READ);
    bufferevent_setcb(bev, NULL, NULL, NULL, NULL);

    return bev;
}

inline struct bufferevent *
evhtp_req_get_bev(evhtp_req_t * req) {
    return evhtp_conn_get_bev(req->conn);
}

inline struct bufferevent *
evhtp_req_take_ownership(evhtp_req_t * req) {
    return evhtp_conn_take_ownership(evhtp_req_get_conn(req));
}

inline struct event_base *
evhtp_req_get_evbase(evhtp_req_t * req) {
    return evhtp_conn_get_evbase(req->conn);
}

EXPORT_SYMBOL(evhtp_req_get_evbase);

inline void
evhtp_conn_set_bev(evhtp_conn_t * conn, struct bufferevent * bev) {
    conn->bev = bev;
}

inline void
evhtp_req_set_bev(evhtp_req_t * req, struct bufferevent * bev) {
    evhtp_conn_set_bev(req->conn, bev);
}

evhtp_conn_t *
evhtp_req_get_conn(evhtp_req_t * req) {
    return req->conn;
}

inline void
evhtp_conn_set_timeouts(evhtp_conn_t         * c,
                        const struct timeval * rtimeo,
                        const struct timeval * wtimeo) {
    if (!c) {
        return;
    }

    if (rtimeo || wtimeo) {
        bufferevent_set_timeouts(c->bev, rtimeo, wtimeo);
    }
}

void
evhtp_conn_set_max_body_size(evhtp_conn_t * c, uint64_t len) {
    if (len == 0) {
        c->max_body_size = c->htp->max_body_size;
    } else {
        c->max_body_size = len;
    }
}

void
evhtp_req_set_max_body_size(evhtp_req_t * req, uint64_t len) {
    evhtp_conn_set_max_body_size(req->conn, len);
}

void
evhtp_conn_free(evhtp_conn_t * conn) {
    if (conn == NULL) {
        return;
    }

    _evhtp_req_free(conn->req);
    _evhtp_conn_fini_hook(conn);

    free(conn->parser);
    free(conn->hooks);
    free(conn->saddr);

    if (conn->resume_ev) {
        event_free(conn->resume_ev);
    }

    if (conn->bev) {
#ifdef LIBEVENT_HAS_SHUTDOWN
        bufferevent_shutdown(conn->bev, _evhtp_shutdown_eventcb);
#else
#ifdef EVHTP_ENABLE_SSL
        if (conn->ssl != NULL) {
            SSL_set_shutdown(conn->ssl, SSL_RECEIVED_SHUTDOWN);
            SSL_shutdown(conn->ssl);
        }
#endif
        bufferevent_free(conn->bev);
#endif
    }

    free(conn);
}     /* evhtp_conn_free */

void
evhtp_req_free(evhtp_req_t * req) {
    _evhtp_req_free(req);
}

void
evhtp_set_timeouts(evhtp_t * htp, const struct timeval * r_timeo, const struct timeval * w_timeo) {
    if (r_timeo != NULL) {
        htp->recv_timeo = *r_timeo;
    }

    if (w_timeo != NULL) {
        htp->send_timeo = *w_timeo;
    }
}

void
evhtp_set_max_keepalive_reqs(evhtp_t * htp, uint64_t num) {
    htp->max_keepalive_reqs = num;
}

/**
 * @brief set bufferevent flags, defaults to BEV_OPT_CLOSE_ON_FREE
 *
 * @param htp
 * @param flags
 */
void
evhtp_set_bev_flags(evhtp_t * htp, int flags) {
    htp->bev_flags = flags;
}

void
evhtp_set_max_body_size(evhtp_t * htp, uint64_t len) {
    htp->max_body_size = len;
}

void
evhtp_disable_100_continue(evhtp_t * htp) {
    htp->disable_100_cont = 1;
}

int
evhtp_add_alias(evhtp_t * evhtp, const char * name) {
    evhtp_alias_t * alias;

    if (evhtp == NULL || name == NULL) {
        return -1;
    }

    if (!(alias = calloc(sizeof(evhtp_alias_t), 1))) {
        return -1;
    }

    alias->alias = strdup(name);

    TAILQ_INSERT_TAIL(&evhtp->aliases, alias, next);

    return 0;
}

/**
 * @brief add a virtual host.
 *
 * NOTE: If SSL is being used and the vhost was found via SNI, the Host: header
 *       will *NOT* be used to find a matching vhost.
 *
 *       Also, any hooks which are set prior to finding a vhost that are hooks
 *       which are after the host hook, they are overwritten by the callbacks
 *       and hooks set for the vhost specific evhtp_t structure.
 *
 * @param evhtp
 * @param name
 * @param vhost
 *
 * @return
 */
int
evhtp_add_vhost(evhtp_t * evhtp, const char * name, evhtp_t * vhost) {
    if (evhtp == NULL || name == NULL || vhost == NULL) {
        return -1;
    }

    if (TAILQ_FIRST(&vhost->vhosts) != NULL) {
        /* vhosts cannot have secondary vhosts defined */
        return -1;
    }

    if (!(vhost->server_name = strdup(name))) {
        return -1;
    }

    /* set the parent of this vhost so when the req has been completely
     * serviced, the vhost can be reset to the original evhtp structure.
     *
     * This allows for a keep-alive conn to make multiple reqs with
     * different Host: values.
     */
    vhost->parent             = evhtp;

    /* inherit various flags from the parent evhtp structure */
    vhost->bev_flags          = evhtp->bev_flags;
    vhost->max_body_size      = evhtp->max_body_size;
    vhost->max_keepalive_reqs = evhtp->max_keepalive_reqs;
    vhost->recv_timeo         = evhtp->recv_timeo;
    vhost->send_timeo         = evhtp->send_timeo;

    TAILQ_INSERT_TAIL(&evhtp->vhosts, vhost, next_vhost);

    return 0;
}

evhtp_t *
evhtp_new(struct event_base * evbase, void * arg) {
    evhtp_t * htp;

    if (evbase == NULL) {
        return NULL;
    }

    if (!(htp = calloc(sizeof(evhtp_t), 1))) {
        return NULL;
    }

    htp->arg       = arg;
    htp->evbase    = evbase;
    htp->bev_flags = BEV_OPT_CLOSE_ON_FREE;

    TAILQ_INIT(&htp->vhosts);
    TAILQ_INIT(&htp->aliases);

    evhtp_set_gencb(htp, _evhtp_default_req_cb, (void *)htp);

    return htp;
}

void
evhtp_free(evhtp_t * evhtp) {
    evhtp_alias_t * evhtp_alias, * tmp;

    if (evhtp == NULL) {
        return;
    }

#ifdef EVHTP_ENABLE_EVTHR
    if (evhtp->thr_pool) {
        evhtp_thr_pool_stop(evhtp->thr_pool);
        evhtp_thr_pool_free(evhtp->thr_pool);
    }
#endif

    if (evhtp->server_name) {
        free(evhtp->server_name);
    }

    if (evhtp->callbacks) {
        evhtp_callbacks_free(evhtp->callbacks);
    }

    TAILQ_FOREACH_SAFE(evhtp_alias, &evhtp->aliases, next, tmp) {
        if (evhtp_alias->alias != NULL) {
            free(evhtp_alias->alias);
        }
        TAILQ_REMOVE(&evhtp->aliases, evhtp_alias, next);
        free(evhtp_alias);
    }

#ifdef EVHTP_ENABLE_SSL
    if (evhtp->ssl_ctx) {
        SSL_CTX_free(evhtp->ssl_ctx);
    }
#endif

    free(evhtp);
}

inline struct evbuffer *
evhtp_req_buffer_out(evhtp_req_t * req) {
    return req->buffer_out;
}

EXPORT_SYMBOL(evhtp_req_buffer_out);

inline struct evbuffer *
evhtp_req_buffer_in(evhtp_req_t * req) {
    return req->buffer_in;
}

EXPORT_SYMBOL(evhtp_req_buffer_in);

inline evhtp_hdrs_t *
evhtp_req_get_headers_out(evhtp_req_t * req) {
    return req->headers_out;
}

EXPORT_SYMBOL(evhtp_req_get_headers_out);

inline evhtp_hdrs_t *
evhtp_req_get_headers_in(evhtp_req_t * req) {
    return req->headers_in;
}

EXPORT_SYMBOL(evhtp_req_get_headers_in);

/*****************************************************************
* client req functions                                      *
*****************************************************************/

evhtp_conn_t *
evhtp_conn_new(struct event_base * evbase, const char * addr, uint16_t port) {
    evhtp_conn_t     * conn;
    struct sockaddr_in sin;

    if (evbase == NULL) {
        return NULL;
    }

    if (!(conn = _evhtp_conn_new(NULL, -1, evhtp_type_client))) {
        return NULL;
    }

    sin.sin_family      = AF_INET;
    sin.sin_addr.s_addr = inet_addr(addr);
    sin.sin_port        = htons(port);

    conn->evbase        = evbase;
    conn->bev           = bufferevent_socket_new(evbase, -1, BEV_OPT_CLOSE_ON_FREE);

    bufferevent_enable(conn->bev, EV_READ);

    bufferevent_setcb(conn->bev, NULL, NULL,
                      _evhtp_conn_eventcb, conn);

    bufferevent_socket_connect(conn->bev,
                               (struct sockaddr *)&sin, sizeof(sin));

    return conn;
}

evhtp_req_t *
evhtp_req_new(evhtp_callback_cb cb, void * arg) {
    evhtp_req_t * r;

    if (!(r = _evhtp_req_new(NULL))) {
        return NULL;
    }

    r->cb    = cb;
    r->cbarg = arg;
    r->proto = EVHTP_PROTO_11;

    return r;
}

int
evhtp_make_req(evhtp_conn_t * c, evhtp_req_t * r,
               evhtp_method meth, const char * uri) {
    struct evbuffer * obuf;
    char            * proto;

    obuf    = bufferevent_get_output(c->bev);
    r->conn = c;
    c->req  = r;

    switch (r->proto) {
        case EVHTP_PROTO_10:
            proto = "1.0";
            break;
        case EVHTP_PROTO_11:
        default:
            proto = "1.1";
            break;
    }

    evbuffer_add_printf(obuf, "%s %s HTTP/%s\r\n",
                        evhtp_parser_get_methodstr_m(meth), uri, proto);

    evhtp_hdrs_for_each(r->headers_out, _evhtp_create_headers, obuf);
    evbuffer_add_reference(obuf, "\r\n", 2, NULL, NULL);

    return 0;
}

unsigned int
evhtp_req_status(evhtp_req_t * r) {
    return evhtp_parser_get_status(r->conn->parser);
}

EXPORT_SYMBOL(evhtp_new);
EXPORT_SYMBOL(evhtp_free);
EXPORT_SYMBOL(evhtp_set_timeouts);
EXPORT_SYMBOL(evhtp_set_bev_flags);

EXPORT_SYMBOL(evhtp_disable_100_continue);
EXPORT_SYMBOL(evhtp_use_callback_locks);
EXPORT_SYMBOL(evhtp_set_gencb);
EXPORT_SYMBOL(evhtp_set_pre_accept_cb);
EXPORT_SYMBOL(evhtp_set_post_accept_cb);
EXPORT_SYMBOL(evhtp_set_cb);

#ifdef EVHTP_ENABLE_REGEX
EXPORT_SYMBOL(evhtp_set_regex_cb);
#endif

EXPORT_SYMBOL(evhtp_set_glob_cb);
EXPORT_SYMBOL(evhtp_set_hook);
EXPORT_SYMBOL(evhtp_unset_hook);
EXPORT_SYMBOL(evhtp_unset_all_hooks);
EXPORT_SYMBOL(evhtp_bind_socket);
EXPORT_SYMBOL(evhtp_unbind_socket);
EXPORT_SYMBOL(evhtp_bind_sockaddr);

#ifdef EVHTP_ENABLE_EVTHR
EXPORT_SYMBOL(evhtp_use_threads);
#endif

EXPORT_SYMBOL(evhtp_send_reply);
EXPORT_SYMBOL(evhtp_send_reply_start);
EXPORT_SYMBOL(evhtp_send_reply_body);
EXPORT_SYMBOL(evhtp_send_reply_end);
EXPORT_SYMBOL(evhtp_response_needs_body);
EXPORT_SYMBOL(evhtp_send_reply_chunk_start);
EXPORT_SYMBOL(evhtp_send_reply_chunk);
EXPORT_SYMBOL(evhtp_send_reply_chunk_end);
EXPORT_SYMBOL(evhtp_callback_new);
EXPORT_SYMBOL(evhtp_callback_free);
EXPORT_SYMBOL(evhtp_callbacks_add_callback);
EXPORT_SYMBOL(evhtp_add_vhost);
EXPORT_SYMBOL(evhtp_add_alias);
EXPORT_SYMBOL(evhtp_kv_new);
EXPORT_SYMBOL(evhtp_kvs_new);
EXPORT_SYMBOL(evhtp_kv_free);
EXPORT_SYMBOL(evhtp_kvs_free);
EXPORT_SYMBOL(evhtp_kv_rm_and_free);
EXPORT_SYMBOL(evhtp_kv_find);
EXPORT_SYMBOL(evhtp_kvs_find_kv);
EXPORT_SYMBOL(evhtp_kvs_add_kv);
EXPORT_SYMBOL(evhtp_kvs_add_kvs);
EXPORT_SYMBOL(evhtp_kvs_for_each);
EXPORT_SYMBOL(evhtp_parse_query);
EXPORT_SYMBOL(evhtp_unescape_string);
EXPORT_SYMBOL(evhtp_hdr_new);
EXPORT_SYMBOL(evhtp_hdr_key_add);
EXPORT_SYMBOL(evhtp_hdr_val_add);
EXPORT_SYMBOL(evhtp_hdrs_add_header);
EXPORT_SYMBOL(evhtp_hdr_find);
EXPORT_SYMBOL(evhtp_req_get_method);
EXPORT_SYMBOL(evhtp_conn_pause);
EXPORT_SYMBOL(evhtp_conn_resume);
EXPORT_SYMBOL(evhtp_req_pause);
EXPORT_SYMBOL(evhtp_req_resume);
EXPORT_SYMBOL(evhtp_req_get_conn);
EXPORT_SYMBOL(evhtp_conn_set_bev);
EXPORT_SYMBOL(evhtp_req_set_bev);
EXPORT_SYMBOL(evhtp_conn_get_bev);
EXPORT_SYMBOL(evhtp_conn_set_timeouts);
EXPORT_SYMBOL(evhtp_req_get_bev);
EXPORT_SYMBOL(evhtp_conn_take_ownership);
EXPORT_SYMBOL(evhtp_conn_free);
EXPORT_SYMBOL(evhtp_req_free);
EXPORT_SYMBOL(evhtp_set_max_body_size);
EXPORT_SYMBOL(evhtp_conn_set_max_body_size);
EXPORT_SYMBOL(evhtp_req_set_max_body_size);
EXPORT_SYMBOL(evhtp_set_max_keepalive_reqs);
EXPORT_SYMBOL(evhtp_conn_new);
EXPORT_SYMBOL(evhtp_req_new);
EXPORT_SYMBOL(evhtp_make_req);
EXPORT_SYMBOL(evhtp_req_status);
