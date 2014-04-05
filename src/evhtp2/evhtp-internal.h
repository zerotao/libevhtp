#ifndef __EVHTP_INTERNAL_H__
#define __EVHTP_INTERNAL_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/queue.h>

#include "evhtp2/evhtp-config.h"
#include "evhtp2/internal.h"
#include "evhtp2/evhtp_parser.h"
#include "evhtp2/evhtp.h"

#ifdef EVHTP_ENABLE_SSL
#include "evhtp2/evhtp_ssl.h"
#include "evhtp2/evhtp_ssl-internal.h"
#endif

#ifdef EVHTP_ENABLE_EVTHR
#include "evhtp2/evhtp_thr.h"
#endif

#ifdef EVHTP_ENABLE_REGEX
#include "evhtp2/regex/evhtp_regex.h"
#endif

struct evhtp_defaults {
    evhtp_callback_cb    cb;
    evhtp_pre_accept_cb  pre_accept;
    evhtp_post_accept_cb post_accept;
    void               * cbarg;
    void               * pre_accept_cbarg;
    void               * post_accept_cbarg;
};

/**
 * @brief main structure containing all configuration information
 */
struct evhtp {
    struct event_base     * evbase;               /**< the initialized event_base */
    struct evconnlistener * server;               /**< the libevent listener struct */
    evhtp_t               * parent;               /**< only when this is a vhost */
    char                  * server_name;          /**< the name included in Host: responses */
    void                  * arg;                  /**< user-defined evhtp_t specific arguments */
    uint16_t                bev_flags;            /**< bufferevent flags to use on bufferevent_*_socket_new() */
    uint64_t                max_body_size;
    uint32_t                max_keepalive_reqs;
    uint8_t                 disable_100_cont : 1; /**< if set, evhtp will not respond to Expect: 100-continue */

#ifdef EVHTP_ENABLE_SSL
    evhtp_ssl_ctx_t * ssl_ctx;                    /**< if ssl enabled, this is the servers CTX */
    evhtp_ssl_cfg_t * ssl_cfg;
#endif

#ifdef EVHTP_ENABLE_EVTHR
    evhtp_thr_pool_t   * thr_pool;                /**< conn threadpool */
    pthread_mutex_t    * lock;                    /**< parent lock for add/del cbs in threads */
    evhtp_thread_init_cb thread_init_cb;
    void               * thread_init_cbarg;
#endif

    evhtp_callbacks_t * callbacks;
    evhtp_defaults_t    defaults;

    struct timeval recv_timeo;
    struct timeval send_timeo;

    TAILQ_HEAD(, evhtp_alias) aliases;
    TAILQ_HEAD(, evhtp) vhosts;
    TAILQ_ENTRY(evhtp) next_vhost;
};

struct evhtp_conn {
    evhtp_t            * htp;
    evutil_socket_t      sock;
    struct event_base  * evbase;
    struct bufferevent * bev;
    struct event       * resume_ev;
    struct sockaddr    * saddr;
    struct timeval       recv_timeo;          /**< conn read timeouts (overrides global) */
    struct timeval       send_timeo;          /**< conn write timeouts (overrides global) */
    evhtp_req_t        * req;                 /**< the req currently being processed */
    evhtp_hooks_t      * hooks;
    evhtp_parser       * parser;
    uint8_t              error         : 1;
    uint8_t              owner         : 1;   /**< set to 1 if this structure owns the bufferevent */
    uint8_t              vhost_via_sni : 1;   /**< set to 1 if the vhost was found via SSL SNI */
    uint8_t              free_conn     : 1;
    uint64_t             max_body_size;
    uint64_t             body_bytes_read;
    uint64_t             num_reqs;
    evhtp_type           type;                /**< server or client */
    evhtp_pause_state    paused;

#ifdef EVHTP_ENABLE_EVTHR
    evhtp_thr_t * thread;
#endif
#ifdef EVHTP_ENABLE_SSL
    evhtp_ssl_t * ssl;
#endif

    TAILQ_HEAD(, evhtp_req) pending;       /**< client pending data */
};

/**
 * @brief a structure containing all information for a http req.
 */
struct evhtp_req {
    evhtp_t         * htp;                 /**< the parent evhtp_t structure */
    evhtp_conn_t    * conn;                /**< the associated conn */
    evhtp_hooks_t   * hooks;               /**< req specific hooks */
    evhtp_uri_t     * uri;                 /**< req URI information */
    struct evbuffer * buffer_in;           /**< buffer containing data from client */
    struct evbuffer * buffer_out;          /**< buffer containing data to client */
    evhtp_hdrs_t    * headers_in;          /**< headers from client */
    evhtp_hdrs_t    * headers_out;         /**< headers to client */
    evhtp_proto       proto;               /**< HTTP protocol used */
    evhtp_method      method;              /**< HTTP method used */
    evhtp_res         status;              /**< The HTTP response code or other error conditions */
    uint8_t           keepalive : 1;       /**< set to 1 if the conn is keep-alive */
    uint8_t           finished  : 1;       /**< set to 1 if the req is fully processed */
    uint8_t           chunked   : 1;       /**< set to 1 if the req is chunked */

    evhtp_callback_cb cb;                  /**< the function to call when fully processed */
    void            * cbarg;               /**< argument which is passed to the cb function */
    int               error;

    TAILQ_ENTRY(evhtp_req) next;
};

struct evhtp_alias {
    char * alias;

    TAILQ_ENTRY(evhtp_alias) next;
};

/**
 * @brief structure containing a single callback and configuration
 *
 * The definition structure which is used within the evhtp_callbacks_t
 * structure. This holds information about what should execute for either
 * a single or regex path.
 *
 * For example, if you registered a callback to be executed on a req
 * for "/herp/derp", your defined callback will be executed.
 *
 * Optionally you can set callback-specific hooks just like per-conn
 * hooks using the same rules.
 *
 */
struct evhtp_callback {
    evhtp_callback_type type;           /**< the type of callback (regex|path) */
    evhtp_callback_cb   cb;             /**< the actual callback function */
    unsigned int        hash;           /**< the full hash generated integer */
    void              * cbarg;          /**< user-defind arguments passed to the cb */
    evhtp_hooks_t     * hooks;          /**< per-callback hooks */

    union {
        char * path;
        char * glob;
#ifdef EVHTP_ENABLE_REGEX
        regex_t * regex;
#endif
    } val;

    TAILQ_ENTRY(evhtp_callback) next;
};

TAILQ_HEAD(evhtp_callbacks, evhtp_callback);

/**
 * @brief a generic key/value structure
 */
struct evhtp_kv {
    char * key;
    char * val;
    size_t klen;
    size_t vlen;

    uint8_t k_heaped : 1; /**< set to 1 if the key can be free()'d */
    uint8_t v_heaped : 1; /**< set to 1 if the val can be free()'d */

    TAILQ_ENTRY(evhtp_kv) next;
};

TAILQ_HEAD(evhtp_kvs, evhtp_kv);

/**
 * @brief a generic container representing an entire URI strucutre
 */
struct evhtp_uri {
    evhtp_authority_t * authority;
    evhtp_path_t      * path;
    unsigned char     * fragment;     /**< data after '#' in uri */
    unsigned char     * query_raw;    /**< the unparsed query arguments */
    evhtp_query_t     * query;        /**< list of k/v for query arguments */
    evhtp_parser_scheme scheme;       /**< set if a scheme is found */
};

/**
 * @brief structure which represents authority information in a URI
 */
struct evhtp_authority {
    char   * username;                /**< the username in URI (scheme://USER:.. */
    char   * password;                /**< the password in URI (scheme://...:PASS.. */
    char   * hostname;                /**< hostname if present in URI */
    uint16_t port;                    /**< port if present in URI */
};

/**
 * @brief structure which represents a URI path and or file
 */
struct evhtp_path {
    char       * full;                /**< the full path+file (/a/b/c.html) */
    char       * path;                /**< the path (/a/b/) */
    char       * file;                /**< the filename if present (c.html) */
    char       * match_start;
    char       * match_end;
    unsigned int matched_soff;        /**< offset of where the uri starts
                                       *   mainly used for regex matching
                                       */
    unsigned int matched_eoff;        /**< offset of where the uri ends
                                       *   mainly used for regex matching
                                       */
};

struct evhtp_hooks {
    evhtp_hook_headers_start_cb on_headers_start;
    evhtp_hook_header_cb        on_header;
    evhtp_hook_headers_cb       on_headers;
    evhtp_hook_path_cb          on_path;
    evhtp_hook_read_cb          on_read;
    evhtp_hook_req_fini_cb      on_req_fini;
    evhtp_hook_conn_fini_cb     on_conn_fini;
    evhtp_hook_err_cb           on_error;
    evhtp_hook_chunk_new_cb     on_new_chunk;
    evhtp_hook_chunk_fini_cb    on_chunk_fini;
    evhtp_hook_chunks_fini_cb   on_chunks_fini;
    evhtp_hook_hostname_cb      on_hostname;
    evhtp_hook_write_cb         on_write;

    void * on_headers_start_arg;
    void * on_header_arg;
    void * on_headers_arg;
    void * on_path_arg;
    void * on_read_arg;
    void * on_req_fini_arg;
    void * on_conn_fini_arg;
    void * on_error_arg;
    void * on_new_chunk_arg;
    void * on_chunk_fini_arg;
    void * on_chunks_fini_arg;
    void * on_hostname_arg;
    void * on_write_arg;
};

evhtp_t * evhtp_req_find_vhost(evhtp_t * evhtp, const char * name);

#ifdef __cplusplus
}
#endif

#endif
