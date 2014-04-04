#ifndef __EVHTP_PARSER_H__
#define __EVHTP_PARSER_H__

struct evhtp_parser;

enum evhtp_parser_type {
    evhtp_parser_type_request = 0,
    evhtp_parser_type_response
};

enum evhtp_parser_scheme {
    evhtp_parser_scheme_none = 0,
    evhtp_parser_scheme_ftp,
    evhtp_parser_scheme_http,
    evhtp_parser_scheme_https,
    evhtp_parser_scheme_nfs,
    evhtp_parser_scheme_unknown
};

enum evhtp_parser_method {
    evhtp_parser_method_GET = 0,
    evhtp_parser_method_HEAD,
    evhtp_parser_method_POST,
    evhtp_parser_method_PUT,
    evhtp_parser_method_DELETE,
    evhtp_parser_method_MKCOL,
    evhtp_parser_method_COPY,
    evhtp_parser_method_MOVE,
    evhtp_parser_method_OPTIONS,
    evhtp_parser_method_PROPFIND,
    evhtp_parser_method_PROPPATCH,
    evhtp_parser_method_LOCK,
    evhtp_parser_method_UNLOCK,
    evhtp_parser_method_TRACE,
    evhtp_parser_method_CONNECT, /* RFC 2616 */
    evhtp_parser_method_PATCH,   /* RFC 5789 */
    evhtp_parser_method_UNKNOWN,
};

enum evhtp_parser_error {
    evhtp_parser_error_none = 0,
    evhtp_parser_error_too_big,
    evhtp_parser_error_inval_method,
    evhtp_parser_error_inval_reqline,
    evhtp_parser_error_inval_schema,
    evhtp_parser_error_inval_proto,
    evhtp_parser_error_inval_ver,
    evhtp_parser_error_inval_hdr,
    evhtp_parser_error_inval_chunk_sz,
    evhtp_parser_error_inval_chunk,
    evhtp_parser_error_inval_state,
    evhtp_parser_error_user,
    evhtp_parser_error_status,
    evhtp_parser_error_generic
};

typedef struct evhtp_parser       evhtp_parser;
typedef struct evhtp_parser_hooks evhtp_parser_hooks;

typedef enum evhtp_parser_scheme  evhtp_parser_scheme;
typedef enum evhtp_parser_method  evhtp_parser_method;
typedef enum evhtp_parser_type    evhtp_parser_type;
typedef enum evhtp_parser_error   evhtp_parser_error;

typedef int (*evhtp_parser_hook)(evhtp_parser *);
typedef int (*evhtp_parser_data_hook)(evhtp_parser *, const char *, size_t);


struct evhtp_parser_hooks {
    evhtp_parser_hook      on_msg_begin;
    evhtp_parser_data_hook method;
    evhtp_parser_data_hook scheme;             /* called if scheme is found */
    evhtp_parser_data_hook host;               /* called if a host was in the request scheme */
    evhtp_parser_data_hook port;               /* called if a port was in the request scheme */
    evhtp_parser_data_hook path;               /* only the path of the uri */
    evhtp_parser_data_hook args;               /* only the arguments of the uri */
    evhtp_parser_data_hook uri;                /* the entire uri including path/args */
    evhtp_parser_hook      on_hdrs_begin;
    evhtp_parser_data_hook hdr_key;
    evhtp_parser_data_hook hdr_val;
    evhtp_parser_data_hook hostname;
    evhtp_parser_hook      on_hdrs_complete;
    evhtp_parser_hook      on_new_chunk;       /* called after parsed chunk octet */
    evhtp_parser_hook      on_chunk_complete;  /* called after single parsed chunk */
    evhtp_parser_hook      on_chunks_complete; /* called after all parsed chunks processed */
    evhtp_parser_data_hook body;
    evhtp_parser_hook      on_msg_complete;
};


size_t              evhtp_parser_run(evhtp_parser *, evhtp_parser_hooks *, const char *, size_t);
int                 evhtp_parser_should_keep_alive(evhtp_parser * p);
evhtp_parser_scheme evhtp_parser_get_scheme(evhtp_parser *);
evhtp_parser_method evhtp_parser_get_method(evhtp_parser *);
const char        * evhtp_parser_get_methodstr(evhtp_parser *);
const char        * evhtp_parser_get_methodstr_m(evhtp_parser_method);
void                evhtp_parser_set_major(evhtp_parser *, unsigned char);
void                evhtp_parser_set_minor(evhtp_parser *, unsigned char);
unsigned char       evhtp_parser_get_major(evhtp_parser *);
unsigned char       evhtp_parser_get_minor(evhtp_parser *);
unsigned char       evhtp_parser_get_multipart(evhtp_parser *);
unsigned int        evhtp_parser_get_status(evhtp_parser *);
uint64_t            evhtp_parser_get_content_length(evhtp_parser *);
uint64_t            evhtp_parser_get_content_pending(evhtp_parser *);
uint64_t            evhtp_parser_get_total_bytes_read(evhtp_parser *);
evhtp_parser_error  evhtp_parser_get_error(evhtp_parser *);
const char        * evhtp_parser_get_strerror(evhtp_parser *);
void              * evhtp_parser_get_userdata(evhtp_parser *);
void                evhtp_parser_set_userdata(evhtp_parser *, void *);
void                evhtp_parser_init(evhtp_parser *, evhtp_parser_type);
evhtp_parser      * evhtp_parser_new(void);

#endif

