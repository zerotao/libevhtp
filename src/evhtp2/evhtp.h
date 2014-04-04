#ifndef __EVHTP_EVHTP_H__
#define __EVHTP_EVHTP_H__

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include <evhtp2/evhtp-config.h>
#include <evhtp2/parser.h>

#ifdef EVHTP_ENABLE_REGEX
#include <evhtp2/regex.h>
#endif

#ifdef EVHTP_ENABLE_EVTHR
#include <evhtp2/evthr.h>
#endif

#ifdef EVHTP_ENABLE_SSL
#include <evhtp2/ssl.h>
#endif

enum evhtp_pause_state_s {
    evhtp_pause_s_nil = 0,
    evhtp_pause_s_paused,
    evhtp_pause_s_waiting
};

enum evhtp_callback_type_s {
    evhtp_callback_type_hash,
    evhtp_callback_type_glob,
#ifdef EVHTP_ENABLE_REGEX
    evhtp_callback_type_regex
#endif
#endif
};

/**
 * @brief types associated with where a developer can hook into
 *        during the request processing cycle.
 */
enum evhtp_hook_type_s {
    evhtp_hook_on_header,       /**< type which defines to hook after one header has been parsed */
    evhtp_hook_on_headers,      /**< type which defines to hook after all headers have been parsed */
    evhtp_hook_on_path,         /**< type which defines to hook once a path has been parsed */
    evhtp_hook_on_read,         /**< type which defines to hook whenever the parser recieves data in a body */
    evhtp_hook_on_request_fini, /**< type which defines to hook before the request is free'd */
    evhtp_hook_on_connection_fini,
    evhtp_hook_on_new_chunk,
    evhtp_hook_on_chunk_complete,
    evhtp_hook_on_chunks_complete,
    evhtp_hook_on_headers_start,
    evhtp_hook_on_error,        /**< type which defines to hook whenever an error occurs */
    evhtp_hook_on_hostname,
    evhtp_hook_on_write
};


enum evhtp_proto {
    EVHTP_PROTO_INVALID,
    EVHTP_PROTO_10,
    EVHTP_PROTO_11
};

/* XXX internalize this */
enum evhtp_type {
    evhtp_type_client,
    evhtp_type_server
};

struct evhtp_s;
struct evhtp_kv_s;
struct evhtp_kvs_s;
struct evhtp_uri_s;
struct evhtp_path_s;
struct evhtp_hooks_s;
struct evhtp_alias_s;
struct evhtp_request_s;
struct evhtp_default_s;
struct evhtp_defaults_s;
struct evhtp_callback_s;
struct evhtp_callbacks_s;
struct evhtp_authority_s;
struct evhtp_connection_s;

typedef struct evhtp_s             evhtp_t;
typedef struct evhtp_kv_s          evhtp_kv_t;
typedef struct evhtp_kv_s          evhtp_header_t;
typedef struct evhtp_kvs_s         evhtp_kvs_t;
typedef struct evhtp_kvs_s         evhtp_headers_t;
typedef struct evhtp_uri_s         evhtp_uri_t;
typedef struct evhtp_path_s        evhtp_path_t;
typedef struct evhtp_hooks_s       evhtp_hooks_t;
typedef struct evhtp_alias_s       evhtp_alias_t;
typedef struct evhtp_request_s     evhtp_request_t;
typedef struct evhtp_default_s     evhtp_default_t;
typedef struct evhtp_defaults_s    evhtp_defaults_t;
typedef struct evhtp_callback_s    evhtp_callback_t;
typedef struct evhtp_callbacks_s   evhtp_callbacks_t;
typedef struct evhtp_authority_s   evhtp_authority_t;
typedef struct evhtp_connection_s  evhtp_connection_t;

typedef enum evhtp_pause_state_s   evhtp_pause_state_t;
typedef enum evhtp_callback_type_s evhtp_callback_type_t;
typedef enum evhtp_hook_type_s     evhtp_hook_type_t;
typedef enum evhtp_pause_state_s   evhtp_pause_state_t;

typedef uint16_t                   evhtp_res;
typedef uint8_t                    evhtp_error_flags;

typedef void (*evhtp_callback_cb)(evhtp_request_t * req, void * arg);
typedef void (*evhtp_hook_err_cb)(evhtp_request_t * req, evhtp_error_flags errtype, void * arg);

#ifdef EVHTP_ENABLE_EVTHR
typedef void (*evhtp_thread_init_cb)(evhtp_t * htp, evthr_t * thr, void * arg);
#endif

/* Generic hook for passing ISO tests */
typedef evhtp_res (*evhtp_hook)();
typedef evhtp_res (*evhtp_pre_accept_cb)(evhtp_connection_t * conn, void * arg);
typedef evhtp_res (*evhtp_post_accept_cb)(evhtp_connection_t * conn, void * arg);
typedef evhtp_res (*evhtp_hook_header_cb)(evhtp_request_t * req, evhtp_header_t * hdr, void * arg);
typedef evhtp_res (*evhtp_hook_headers_cb)(evhtp_request_t * req, evhtp_headers_t * hdr, void * arg);
typedef evhtp_res (*evhtp_hook_path_cb)(evhtp_request_t * req, evhtp_path_t * path, void * arg);
typedef evhtp_res (*evhtp_hook_read_cb)(evhtp_request_t * req, evbuf_t * buf, void * arg);
typedef evhtp_res (*evhtp_hook_request_fini_cb)(evhtp_request_t * req, void * arg);
typedef evhtp_res (*evhtp_hook_connection_fini_cb)(evhtp_connection_t * connection, void * arg);
typedef evhtp_res (*evhtp_hook_chunk_new_cb)(evhtp_request_t * r, uint64_t len, void * arg);
typedef evhtp_res (*evhtp_hook_chunk_fini_cb)(evhtp_request_t * r, void * arg);
typedef evhtp_res (*evhtp_hook_chunks_fini_cb)(evhtp_request_t * r, void * arg);
typedef evhtp_res (*evhtp_hook_headers_start_cb)(evhtp_request_t * r, void * arg);
typedef evhtp_res (*evhtp_hook_hostname_cb)(evhtp_request_t * r, const char * hostname, void * arg);
typedef evhtp_res (*evhtp_hook_write_cb)(evhtp_connection_t * conn, void * arg);

typedef int (*evhtp_kvs_iterator)(evhtp_kv_t * kv, void * arg);
typedef int (*evhtp_headers_iterator)(evhtp_header_t * header, void * arg);

/**
 * @brief creates a new evhtp_t instance
 *
 * @param evbase the initialized event base
 * @param arg user-defined argument which is evhtp_t specific
 *
 * @return a new evhtp_t structure or NULL on error
 */
evhtp_t * evhtp_new(evbase_t * evbase, void * arg);
void      evhtp_free(evhtp_t * evhtp);

/**
 * @brief set a read/write timeout on all things evhtp_t. When the timeout
 *        expires your error hook will be called with the libevent supplied event
 *        flags.
 *
 * @param htp the base evhtp_t struct
 * @param r read-timeout in timeval
 * @param w write-timeout in timeval.
 */
void evhtp_set_timeouts(evhtp_t * htp, const struct timeval * r, const struct timeval * w);
void evhtp_set_bev_flags(evhtp_t * htp, int flags);

#ifdef EVHTP_ENABLE_EVTHR
/**
 * @brief creates a lock around callbacks and hooks, allowing for threaded
 * applications to add/remove/modify hooks & callbacks in a thread-safe manner.
 *
 * @param htp
 *
 * @return 0 on success, -1 on error
 */
int evhtp_use_callback_locks(evhtp_t * htp);
int evhtp_use_threads(evhtp_t * htp, evhtp_thread_init_cb init_cb, int nthreads, void * arg);
#endif
#endif
