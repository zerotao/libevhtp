#ifndef __EVHTP_H__
#define __EVHTP_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include <evhtp2/evhtp-config.h>
#include <evhtp2/evhtp_parser.h>

#ifdef EVHTP_ENABLE_EVTHR
#include <evhtp2/evhtp_thr.h>
#endif

#define EVHTP_RES_ERROR         0
#define EVHTP_RES_PAUSE         1
#define EVHTP_RES_FATAL         2
#define EVHTP_RES_USER          3
#define EVHTP_RES_DATA_TOO_LONG 4
#define EVHTP_RES_OK            200

#define EVHTP_RES_100           100
#define EVHTP_RES_CONTINUE      100
#define EVHTP_RES_SWITCH_PROTO  101
#define EVHTP_RES_PROCESSING    102
#define EVHTP_RES_URI_TOOLONG   122

#define EVHTP_RES_200           200
#define EVHTP_RES_CREATED       201
#define EVHTP_RES_ACCEPTED      202
#define EVHTP_RES_NAUTHINFO     203
#define EVHTP_RES_NOCONTENT     204
#define EVHTP_RES_RSTCONTENT    205
#define EVHTP_RES_PARTIAL       206
#define EVHTP_RES_MSTATUS       207
#define EVHTP_RES_IMUSED        226

#define EVHTP_RES_300           300
#define EVHTP_RES_MCHOICE       300
#define EVHTP_RES_MOVEDPERM     301
#define EVHTP_RES_FOUND         302
#define EVHTP_RES_SEEOTHER      303
#define EVHTP_RES_NOTMOD        304
#define EVHTP_RES_USEPROXY      305
#define EVHTP_RES_SWITCHPROXY   306
#define EVHTP_RES_TMPREDIR      307

#define EVHTP_RES_400           400
#define EVHTP_RES_BADREQ        400
#define EVHTP_RES_UNAUTH        401
#define EVHTP_RES_PAYREQ        402
#define EVHTP_RES_FORBIDDEN     403
#define EVHTP_RES_NOTFOUND      404
#define EVHTP_RES_METHNALLOWED  405
#define EVHTP_RES_NACCEPTABLE   406
#define EVHTP_RES_PROXYAUTHREQ  407
#define EVHTP_RES_TIMEOUT       408
#define EVHTP_RES_CONFLICT      409
#define EVHTP_RES_GONE          410
#define EVHTP_RES_LENREQ        411
#define EVHTP_RES_PRECONDFAIL   412
#define EVHTP_RES_ENTOOLARGE    413
#define EVHTP_RES_URITOOLARGE   414
#define EVHTP_RES_UNSUPPORTED   415
#define EVHTP_RES_RANGENOTSC    416
#define EVHTP_RES_EXPECTFAIL    417
#define EVHTP_RES_IAMATEAPOT    418

#define EVHTP_RES_500           500
#define EVHTP_RES_SERVERR       500
#define EVHTP_RES_NOTIMPL       501
#define EVHTP_RES_BADGATEWAY    502
#define EVHTP_RES_SERVUNAVAIL   503
#define EVHTP_RES_GWTIMEOUT     504
#define EVHTP_RES_VERNSUPPORT   505
#define EVHTP_RES_BWEXEED       509

enum evhtp_pause_state {
    evhtp_pause_s_nil = 0,
    evhtp_pause_s_paused,
    evhtp_pause_s_waiting
};

enum evhtp_callback_type {
    evhtp_callback_type_hash,
    evhtp_callback_type_glob,
#ifdef EVHTP_ENABLE_REGEX
    evhtp_callback_type_regex
#endif
};

/**
 * @brief types associated with where a developer can hook into
 *        during the req processing cycle.
 */
enum evhtp_hook_type {
    evhtp_hook_on_header,   /**< type which defines to hook after one header has been parsed */
    evhtp_hook_on_headers,  /**< type which defines to hook after all headers have been parsed */
    evhtp_hook_on_path,     /**< type which defines to hook once a path has been parsed */
    evhtp_hook_on_read,     /**< type which defines to hook whenever the parser recieves data in a body */
    evhtp_hook_on_req_fini, /**< type which defines to hook before the req is free'd */
    evhtp_hook_on_conn_fini,
    evhtp_hook_on_new_chunk,
    evhtp_hook_on_chunk_complete,
    evhtp_hook_on_chunks_complete,
    evhtp_hook_on_headers_start,
    evhtp_hook_on_error,    /**< type which defines to hook whenever an error occurs */
    evhtp_hook_on_hostname,
    evhtp_hook_on_write,
    evhtp_hook_on_event
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

struct evhtp;
struct evhtp_kv;
struct evhtp_kvs;
struct evhtp_uri;
struct evhtp_path;
struct evhtp_hooks;
struct evhtp_alias;
struct evhtp_req;
struct evhtp_default;
struct evhtp_defaults;
struct evhtp_callback;
struct evhtp_callbacks;
struct evhtp_authority;
struct evhtp_conn;

typedef struct evhtp             evhtp_t;
typedef struct evhtp_kv          evhtp_kv_t;
typedef struct evhtp_kv          evhtp_hdr_t;
typedef struct evhtp_kvs         evhtp_query_t;
typedef struct evhtp_kvs         evhtp_kvs_t;
typedef struct evhtp_kvs         evhtp_hdrs_t;
typedef struct evhtp_uri         evhtp_uri_t;
typedef struct evhtp_path        evhtp_path_t;
typedef struct evhtp_hooks       evhtp_hooks_t;
typedef struct evhtp_alias       evhtp_alias_t;
typedef struct evhtp_req         evhtp_req_t;
typedef struct evhtp_default     evhtp_default_t;
typedef struct evhtp_defaults    evhtp_defaults_t;
typedef struct evhtp_callback    evhtp_callback_t;
typedef struct evhtp_callbacks   evhtp_callbacks_t;
typedef struct evhtp_authority   evhtp_authority_t;
typedef struct evhtp_conn        evhtp_conn_t;

typedef enum evhtp_callback_type evhtp_callback_type;
typedef enum evhtp_hook_type     evhtp_hook_type;
typedef enum evhtp_pause_state   evhtp_pause_state;
typedef enum evhtp_type          evhtp_type;
typedef enum evhtp_proto         evhtp_proto;

typedef uint16_t                 evhtp_res;
typedef uint8_t                  evhtp_error_flags;

#ifdef EVHTP_ENABLE_EVTHR
typedef void (*evhtp_thread_init_cb)(evhtp_t * htp, evhtp_thr_t * thr, void * arg);
#endif
typedef void (*evhtp_callback_cb)(evhtp_req_t * req, void * arg);
typedef void (*evhtp_hook_err_cb)(evhtp_req_t * req, evhtp_error_flags errtype, void * arg);

/* Generic hook for passing ISO tests */
typedef evhtp_res (*evhtp_hook)();
typedef evhtp_res (*evhtp_pre_accept_cb)(evhtp_conn_t * conn, void * arg);
typedef evhtp_res (*evhtp_post_accept_cb)(evhtp_conn_t * conn, void * arg);
typedef evhtp_res (*evhtp_hook_header_cb)(evhtp_req_t * req, evhtp_hdr_t * hdr, void * arg);
typedef evhtp_res (*evhtp_hook_headers_cb)(evhtp_req_t * req, evhtp_hdrs_t * hdr, void * arg);
typedef evhtp_res (*evhtp_hook_path_cb)(evhtp_req_t * req, evhtp_path_t * path, void * arg);
typedef evhtp_res (*evhtp_hook_read_cb)(evhtp_req_t * req, struct evbuffer * buf, void * arg);
typedef evhtp_res (*evhtp_hook_req_fini_cb)(evhtp_req_t * req, void * arg);
typedef evhtp_res (*evhtp_hook_conn_fini_cb)(evhtp_conn_t * conn, void * arg);
typedef evhtp_res (*evhtp_hook_chunk_new_cb)(evhtp_req_t * r, uint64_t len, void * arg);
typedef evhtp_res (*evhtp_hook_chunk_fini_cb)(evhtp_req_t * r, void * arg);
typedef evhtp_res (*evhtp_hook_chunks_fini_cb)(evhtp_req_t * r, void * arg);
typedef evhtp_res (*evhtp_hook_headers_start_cb)(evhtp_req_t * r, void * arg);
typedef evhtp_res (*evhtp_hook_hostname_cb)(evhtp_req_t * r, const char * hostname, void * arg);
typedef evhtp_res (*evhtp_hook_write_cb)(evhtp_conn_t * conn, void * arg);
typedef void (*evhtp_hook_event_cb)(evhtp_conn_t * conn, short events, void * arg);

typedef int (*evhtp_kvs_iterator)(evhtp_kv_t * kv, void * arg);
typedef int (*evhtp_hdrs_iterator)(evhtp_hdr_t * header, void * arg);

/**
 * @brief creates a new evhtp_t instance
 *
 * @param evbase the initialized event base
 * @param arg user-defined argument which is evhtp_t specific
 *
 * @return a new evhtp_t structure or NULL on error
 */
evhtp_t * evhtp_new(struct event_base * evbase, void * arg);
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

/**
 * @brief when a client sends an Expect: 100-continue, if this is function is
 *        called, evhtp will not send a HTTP/x.x continue response.
 *
 * @param htp
 */
void evhtp_disable_100_continue(evhtp_t * htp);

/**
 * @brief sets a callback which is called if no other callbacks are matched
 *
 * @param htp the initialized evhtp_t
 * @param cb  the function to be executed
 * @param arg user-defined argument passed to the callback
 */
void evhtp_set_gencb(evhtp_t * htp, evhtp_callback_cb cb, void * arg);
void evhtp_set_pre_accept_cb(evhtp_t * htp, evhtp_pre_accept_cb, void * arg);
void evhtp_set_post_accept_cb(evhtp_t * htp, evhtp_post_accept_cb, void * arg);


/**
 * @brief sets a callback to be executed on a specific path
 *
 * @param htp the initialized evhtp_t
 * @param path the path to match
 * @param cb the function to be executed
 * @param arg user-defined argument passed to the callback
 *
 * @return evhtp_callback_t * on success, NULL on error.
 */
evhtp_callback_t * evhtp_set_cb(evhtp_t * htp, const char * path, evhtp_callback_cb cb, void * arg);


/**
 * @brief sets a callback to be executed based on a regex pattern
 *
 * @param htp the initialized evhtp_t
 * @param pattern a POSIX compat regular expression
 * @param cb the function to be executed
 * @param arg user-defined argument passed to the callback
 *
 * @return evhtp_callback_t * on success, NULL on error
 */
#ifndef EVHTP_DISABLE_REGEX
evhtp_callback_t * evhtp_set_regex_cb(evhtp_t * htp, const char * pattern, evhtp_callback_cb cb, void * arg);
#endif



/**
 * @brief sets a callback to to be executed on simple glob/wildcard patterns
 *        this is useful if the app does not care about what was matched, but
 *        just that it matched. This is technically faster than regex.
 *
 * @param htp
 * @param pattern wildcard pattern, the '*' can be set at either or both the front or end.
 * @param cb
 * @param arg
 *
 * @return
 */
evhtp_callback_t * evhtp_set_glob_cb(evhtp_t * htp, const char * pattern, evhtp_callback_cb cb, void * arg);

/**
 * @brief sets a callback hook for either a conn or a path/regex .
 *
 * A user may set a variety of hooks either per-conn, or per-callback.
 * This allows the developer to hook into various parts of the req processing
 * cycle.
 *
 * a per-conn hook can be set at any time, but it is recommended to set these
 * during either a pre-accept phase, or post-accept phase. This allows a developer
 * to set hooks before any other hooks are called.
 *
 * a per-callback hook works differently. In this mode a developer can setup a set
 * of hooks prior to starting the event loop for specific callbacks. For example
 * if you wanted to hook something ONLY for a callback set by evhtp_set_cb or
 * evhtp_set_regex_cb this is the method of doing so.
 *
 * per-callback example:
 *
 * evhtp_callback_t * cb = evhtp_set_regex_cb(htp, "/anything/(.*)", default_cb, NULL);
 *
 * evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, anything_headers_cb, NULL);
 *
 * evhtp_set_hook(&cb->hooks, evhtp_hook_on_fini, anything_fini_cb, NULL);
 *
 * With the above example, once libevhtp has determined that it has a user-defined
 * callback for /anything/.*; anything_headers_cb will be executed after all headers
 * have been parsed, and anything_fini_cb will be executed before the req is
 * free()'d.
 *
 * The same logic applies to per-conn hooks, but it should be noted that if
 * a per-callback hook is set, the per-conn hook will be ignored.
 *
 * @param hooks double pointer to the evhtp_hooks_t structure
 * @param type the hook type
 * @param cb the callback to be executed.
 * @param arg optional argument which is passed when the callback is executed
 *
 * @return 0 on success, -1 on error (if hooks is NULL, it is allocated)
 */
int evhtp_set_hook(evhtp_hooks_t ** hooks, evhtp_hook_type type, evhtp_hook cb, void * arg);

/**
 * @brief remove a specific hook from being called.
 *
 * @param hooks
 * @param type
 *
 * @return
 */
int evhtp_unset_hook(evhtp_hooks_t ** hooks, evhtp_hook_type type);

/**
 * @brief removes all hooks.
 *
 * @param hooks
 *
 * @return
 */
int evhtp_unset_all_hooks(evhtp_hooks_t ** hooks);

int evhtp_req_set_hook(evhtp_req_t * r, evhtp_hook_type type, evhtp_hook cb, void * arg);
int evhtp_conn_set_hook(evhtp_conn_t * c, evhtp_hook_type type, evhtp_hook cb, void * arg);
int evhtp_callback_set_hook(evhtp_callback_t * c, evhtp_hook_type type, evhtp_hook cb, void * arg);

/**
 * @brief bind to a socket, optionally with specific protocol support
 *        formatting. The addr can be defined as one of the following:
 *          ipv6:<ipv6addr> for binding to an IPv6 address.
 *          unix:<named pipe> for binding to a unix named socket
 *          ipv4:<ipv4addr> for binding to an ipv4 address
 *        Otherwise the addr is assumed to be ipv4.
 *
 * @param htp
 * @param addr
 * @param port
 * @param backlog
 *
 * @return
 */
int evhtp_bind_socket(evhtp_t * htp, const char * addr, uint16_t port, int backlog);

/**
 * @brief stops the listening socket.
 *
 * @param htp
 */
void evhtp_unbind_socket(evhtp_t * htp);

/**
 * @brief bind to an already allocated sockaddr.
 *
 * @param htp
 * @param
 * @param sin_len
 * @param backlog
 *
 * @return
 */
int  evhtp_bind_sockaddr(evhtp_t * htp, struct sockaddr *, size_t sin_len, int backlog);

void evhtp_send_reply(evhtp_req_t * req, evhtp_res code);
void evhtp_send_reply_start(evhtp_req_t * req, evhtp_res code);
void evhtp_send_reply_body(evhtp_req_t * req, struct evbuffer * buf);
void evhtp_send_reply_end(evhtp_req_t * req);

/**
 * @brief Determine if a response should have a body.
 * Follows the rules in RFC 2616 section 4.3.
 * @return 1 if the response MUST have a body; 0 if the response MUST NOT have
 *     a body.
 */
int evhtp_response_needs_body(const evhtp_res code, const evhtp_method method);


/**
 * @brief start a chunked response. If data already exists on the output buffer,
 *        this will be converted to the first chunk.
 *
 * @param req
 * @param code
 */
void evhtp_send_reply_chunk_start(evhtp_req_t * req, evhtp_res code);


/**
 * @brief send a chunk reply.
 *
 * @param req
 * @param buf
 */
void evhtp_send_reply_chunk(evhtp_req_t * req, struct evbuffer * buf);


/**
 * @brief call when all chunks have been sent and you wish to send the last
 *        bits. This will add the last 0CRLFCRCL and call send_reply_end().
 *
 * @param req
 */
void evhtp_send_reply_chunk_end(evhtp_req_t * req);

/**
 * @brief creates a new evhtp_callback_t structure.
 *
 * All callbacks are stored in this structure
 * which define what the final function to be
 * called after all parsing is done. A callback
 * can be either a static string or a regular
 * expression.
 *
 * @param path can either be a static path (/path/to/resource/) or
 *        a POSIX compatible regular expression (^/resource/(.*))
 * @param type informs the function what type of of information is
 *        is contained within the path argument. This can either be
 *        callback_type_path, or callback_type_regex.
 * @param cb the callback function to be invoked
 * @param arg optional argument which is passed when the callback is executed.
 *
 * @return 0 on success, -1 on error.
 */
evhtp_callback_t * evhtp_callback_new(const char * path, evhtp_callback_type type, evhtp_callback_cb cb, void * arg);
void               evhtp_callback_free(evhtp_callback_t * callback);


/**
 * @brief Adds a evhtp_callback_t to the evhtp_callbacks_t list
 *
 * @param cbs an allocated evhtp_callbacks_t structure
 * @param cb  an initialized evhtp_callback_t structure
 *
 * @return 0 on success, -1 on error
 */
int evhtp_callbacks_add_callback(evhtp_callbacks_t * cbs, evhtp_callback_t * cb);


/**
 * @brief add an evhtp_t structure (with its own callbacks) to a base evhtp_t
 *        structure for virtual hosts. It should be noted that if you enable SSL
 *        on the base evhtp_t and your version of OpenSSL supports SNI, the SNI
 *        hostname will always take precedence over the Host header value.
 *
 * @param evhtp
 * @param name
 * @param vhost
 *
 * @return
 */
int evhtp_add_vhost(evhtp_t * evhtp, const char * name, evhtp_t * vhost);


/**
 * @brief Add an alias hostname for a virtual-host specific evhtp_t. This avoids
 *        having multiple evhtp_t virtual hosts with the same callback for the same
 *        vhost.
 *
 * @param evhtp
 * @param name
 *
 * @return
 */
int evhtp_add_alias(evhtp_t * evhtp, const char * name);

/**
 * @brief Allocates a new key/value structure.
 *
 * @param key null terminated string
 * @param val null terminated string
 * @param kalloc if set to 1, the key will be copied, if 0 no copy is done.
 * @param valloc if set to 1, the val will be copied, if 0 no copy is done.
 *
 * @return evhtp_kv_t * on success, NULL on error.
 */
evhtp_kv_t  * evhtp_kv_new(const char * key, const char * val, char kalloc, char valloc);
evhtp_kvs_t * evhtp_kvs_new(void);

void          evhtp_kv_free(evhtp_kv_t * kv);
void          evhtp_kvs_free(evhtp_kvs_t * kvs);
void          evhtp_kv_rm_and_free(evhtp_kvs_t * kvs, evhtp_kv_t * kv);

const char  * evhtp_kv_find(evhtp_kvs_t * kvs, const char * key);
evhtp_kv_t  * evhtp_kvs_find_kv(evhtp_kvs_t * kvs, const char * key);


/**
 * @brief appends a key/val structure to a evhtp_kvs_t tailq
 *
 * @param kvs an evhtp_kvs_t structure
 * @param kv  an evhtp_kv_t structure
 */
void evhtp_kvs_add_kv(evhtp_kvs_t * kvs, evhtp_kv_t * kv);

/**
 * @brief appends all key/val structures from src tailq onto dst tailq
 *
 * @param dst an evhtp_kvs_t structure
 * @param src an evhtp_kvs_t structure
 */
void evhtp_kvs_add_kvs(evhtp_kvs_t * dst, evhtp_kvs_t * src);
int  evhtp_kvs_for_each(evhtp_kvs_t * kvs, evhtp_kvs_iterator cb, void * arg);

#define EVHTP_KV_GET_FN(vname, vtype) vtype evhtp_kv_get_ ## vname(evhtp_kv_t *);
EVHTP_KV_GET_FN(key, const char *);
EVHTP_KV_GET_FN(val, const char *);
EVHTP_KV_GET_FN(klen, size_t);
EVHTP_KV_GET_FN(k_heaped, uint8_t);
EVHTP_KV_GET_FN(v_heaped, uint8_t);

/**
 * @brief Parses the query portion of the uri into a set of key/values
 *
 * Parses query arguments like "?herp=derp&foo=bar;blah=baz"
 *
 * @param query data containing the uri query arguments
 * @param len size of the data
 *
 * @return evhtp_query_t * on success, NULL on error
 */
evhtp_query_t * evhtp_parse_query(const char * query, size_t len);


/**
 * @brief Unescapes strings like '%7B1,%202,%203%7D' would become '{1, 2, 3}'
 *
 * @param out double pointer where output is stored. This is allocated by the user.
 * @param str the string to unescape
 * @param str_len the length of the string to unescape
 *
 * @return 0 on success, -1 on error
 */
int evhtp_unescape_string(unsigned char ** out, unsigned char * str, size_t str_len);

/**
 * @brief creates a new evhtp_hdr_t key/val structure
 *
 * @param key a null terminated string
 * @param val a null terminated string
 * @param kalloc if 1, key will be copied, otherwise no copy performed
 * @param valloc if 1, val will be copied, otehrwise no copy performed
 *
 * @return evhtp_hdr_t * or NULL on error
 */
evhtp_hdr_t * evhtp_hdr_new(const char * key, const char * val, char kalloc, char valloc);

/**
 * @brief creates a new evhtp_hdr_t, sets only the key, and adds to the
 *        evhtp_hdrs TAILQ
 *
 * @param headers the evhtp_hdrs_t TAILQ (evhtp_kv_t)
 * @param key a null terminated string
 * @param kalloc if 1 the string will be copied, otherwise assigned
 *
 * @return an evhtp_hdr_t pointer or NULL on error
 */
evhtp_hdr_t * evhtp_hdr_key_add(evhtp_hdrs_t * headers, const char * key, char kalloc);


/**
 * @brief finds the last header in the headers tailq and adds the value
 *
 * @param headers the evhtp_hdrs_t TAILQ (evhtp_kv_t)
 * @param val a null terminated string
 * @param valloc if 1 the string will be copied, otherwise assigned
 *
 * @return an evhtp_hdr_t pointer or NULL on error
 */
evhtp_hdr_t * evhtp_hdr_val_add(evhtp_hdrs_t * headers, const char * val, char valloc);


/**
 * @brief adds an evhtp_hdr_t to the end of the evhtp_hdrs_t tailq
 *
 * @param headers
 * @param header
 */
void evhtp_hdrs_add_header(evhtp_hdrs_t * headers, evhtp_hdr_t * header);

/**
 * @brief finds the value of a key in a evhtp_hdrs_t structure
 *
 * @param headers the evhtp_hdrs_t tailq
 * @param key the key to find
 *
 * @return the value of the header key if found, NULL if not found.
 */
const char * evhtp_hdr_find(evhtp_hdrs_t * headers, const char * key);

#define evhtp_hdr_find         evhtp_kv_find
#define evhtp_hdrs_find_header evhtp_kvs_find_kv
#define evhtp_hdrs_for_each    evhtp_kvs_for_each
#define evhtp_hdr_new          evhtp_kv_new
#define evhtp_hdr_free         evhtp_kv_free
#define evhtp_hdrs_new         evhtp_kvs_new
#define evhtp_hdrs_free        evhtp_kvs_free
#define evhtp_hdr_rm_and_free  evhtp_kv_rm_and_free
#define evhtp_hdrs_add_header  evhtp_kvs_add_kv
#define evhtp_hdrs_add_headers evhtp_kvs_add_kvs
#define evhtp_query_new        evhtp_kvs_new
#define evhtp_query_free       evhtp_kvs_free


/**
 * @brief returns the htp_method enum version of the req method.
 *
 * @param r
 *
 * @return htp_method enum
 */
evhtp_method evhtp_req_get_method(evhtp_req_t * r);

void         evhtp_conn_pause(evhtp_conn_t * conn);
void         evhtp_conn_resume(evhtp_conn_t * conn);
void         evhtp_req_pause(evhtp_req_t * req);
void         evhtp_req_resume(evhtp_req_t * req);


/**
 * @brief returns the underlying evhtp_conn_t structure from a req
 *
 * @param req
 *
 * @return evhtp_conn_t on success, otherwise NULL
 */
evhtp_conn_t * evhtp_req_get_conn(evhtp_req_t * req);

/**
 * @brief Sets the conns underlying bufferevent
 *
 * @param conn
 * @param bev
 */
void evhtp_conn_set_bev(evhtp_conn_t * conn, struct bufferevent * bev);

/**
 * @brief sets the underlying bufferevent for a evhtp_req
 *
 * @param req
 * @param bev
 */
void evhtp_req_set_bev(evhtp_req_t * req, struct bufferevent * bev);


/**
 * @brief returns the underlying conns bufferevent
 *
 * @param conn
 *
 * @return bufferevent on success, otherwise NULL
 */
struct bufferevent * evhtp_conn_get_bev(evhtp_conn_t * conn);
struct event_base  * evhtp_conn_get_evbase(evhtp_conn_t * conn);


/**
 * @brief sets a conn-specific read/write timeout which overrides the
 *        global read/write settings.
 *
 * @param conn
 * @param r timeval for read
 * @param w timeval for write
 */
void evhtp_conn_set_timeouts(evhtp_conn_t * conn, const struct timeval * r, const struct timeval * w);

/**
 * @brief returns the underlying reqs bufferevent
 *
 * @param req
 *
 * @return bufferevent on success, otherwise NULL
 */
struct bufferevent * evhtp_req_get_bev(evhtp_req_t * req);
struct event_base  * evhtp_req_get_evbase(evhtp_req_t * req);


/**
 * @brief let a user take ownership of the underlying bufferevent and free
 *        all other underlying resources.
 *
 * Warning: this will free all evhtp_conn/req structures, remove all
 * associated hooks and reset the bufferevent to defaults, i.e., disable
 * EV_READ, and set all callbacks to NULL.
 *
 * @param conn
 *
 * @return underlying conns bufferevent.
 */
struct bufferevent * evhtp_conn_take_ownership(evhtp_conn_t * conn);


/**
 * @brief free's all conn related resources, this will also call your
 *        req fini hook and req fini hook.
 *
 * @param conn
 */
void evhtp_conn_free(evhtp_conn_t * conn);
void evhtp_req_free(evhtp_req_t * req);

/**
 * @brief set a max body size to accept for an incoming req, this will
 *        default to unlimited.
 *
 * @param htp
 * @param len
 */
void evhtp_set_max_body_size(evhtp_t * htp, uint64_t len);


/**
 * @brief set a max body size for a specific conn, this will default to
 *        the size set by evhtp_set_max_body_size
 *
 * @param conn
 * @param len
 */
void evhtp_conn_set_max_body_size(evhtp_conn_t * conn, uint64_t len);

/**
 * @brief just calls evhtp_conn_set_max_body_size for the req.
 *
 * @param req
 * @param len
 */
void evhtp_req_set_max_body_size(evhtp_req_t * req, uint64_t len);

/**
 * @brief sets a maximum number of reqs that a single conn can make.
 *
 * @param htp
 * @param num
 */
void evhtp_set_max_keepalive_reqs(evhtp_t * htp, uint64_t num);

#define evhtp_req_content_len evhtp_req_get_content_len
struct evbuffer * evhtp_req_buffer_out(evhtp_req_t * req);
struct evbuffer * evhtp_req_buffer_in(evhtp_req_t * req);
uint64_t          evhtp_req_get_content_len(evhtp_req_t * req);
evhtp_hdrs_t    * evhtp_req_get_headers_out(evhtp_req_t * req);
evhtp_hdrs_t    * evhtp_req_get_headers_in(evhtp_req_t * req);

#define EVHTP_PATH_GET_FN(vname, vtype) vtype evhtp_path_get_ ## vname(evhtp_path_t *);
EVHTP_PATH_GET_FN(full, const char *);
EVHTP_PATH_GET_FN(path, const char *);
EVHTP_PATH_GET_FN(file, const char *);
EVHTP_PATH_GET_FN(match_start, const char *);
EVHTP_PATH_GET_FN(match_end, const char *);
EVHTP_PATH_GET_FN(matched_soff, unsigned int);
EVHTP_PATH_GET_FN(matched_eoff, unsigned int);

#ifdef EVHTP_ENABLE_EVTHR
int evhtp_use_threads(evhtp_t * htp, evhtp_thread_init_cb init_cb, int nthreads, void * arg);
#endif

/*****************************************************************
* client req functions                                      *
*****************************************************************/

/**
 * @brief allocate a new conn
 */
evhtp_conn_t * evhtp_conn_new(struct event_base * evbase, const char * addr, uint16_t port);

/**
 * @brief allocate a new req
 */
evhtp_req_t * evhtp_req_new(evhtp_callback_cb cb, void * arg);

/**
 * @brief make a client req
 */
int          evhtp_make_req(evhtp_conn_t * c, evhtp_req_t * r, evhtp_method meth, const char * uri);
unsigned int evhtp_req_status(evhtp_req_t *);

#ifdef __cplusplus
}
#endif

#endif
