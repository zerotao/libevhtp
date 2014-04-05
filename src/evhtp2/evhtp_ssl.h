#ifndef __EVHTP_SSL_H__
#define __EVHTP_SSL_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <evhtp2/evhtp-config.h>

#ifdef EVHTP_ENABLE_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>

enum evhtp_ssl_cache_type {
    evhtp_ssl_cache_type_disabled = 0,
    evhtp_ssl_cache_type_internal,
    evhtp_ssl_cache_type_user,
    evhtp_ssl_cache_type_builtin
};

typedef SSL                       evhtp_ssl_t;
typedef X509                      evhtp_x509_t;
typedef SSL_CTX                   evhtp_ssl_ctx_t;
typedef SSL_SESSION               evhtp_ssl_sess_t;
typedef X509_STORE_CTX            evhtp_x509_store_ctx_t;
typedef struct evhtp_ssl_cfg      evhtp_ssl_cfg_t;

typedef enum evhtp_ssl_cache_type evhtp_ssl_cache_type;

typedef int (*evhtp_ssl_verify_cb)(int pre_verify, evhtp_x509_store_ctx_t * ctx);
typedef int (*evhtp_ssl_chk_issued_cb)(evhtp_x509_store_ctx_t * ctx, evhtp_x509_t * x, evhtp_x509_t * issuer);
typedef int (*evhtp_ssl_cache_add)(evhtp_conn_t * conn, unsigned char * sid, int sid_len, evhtp_ssl_sess_t * sess);
typedef void (*evhtp_ssl_cache_del)(evhtp_t * htp, unsigned char * sid, int sid_len);
typedef void * (*evhtp_ssl_cache_init)(evhtp_t *);
typedef evhtp_ssl_sess_t * (*evhtp_ssl_cache_get)(evhtp_conn_t * conn, unsigned char * sid, int sid_len);

struct evhtp_ssl_cfg {
    char * pemfile;
    char * privfile;
    char * cafile;
    char * capath;
    char * ciphers;
    char * named_curve;
    char * dhparams;
    long   opts;
    long   ctx_timeout;
    int    verify_peer;
    int    verify_depth;
    long   store_flags;
    long   cache_timeout;
    long   cache_size;
    void * args;

    evhtp_ssl_cache_type    cache_type;
    evhtp_ssl_cache_init    cache_init;
    evhtp_ssl_cache_add     cache_add;
    evhtp_ssl_cache_get     cache_get;
    evhtp_ssl_cache_del     cache_del;
    evhtp_ssl_verify_cb     x509_verify_cb;
    evhtp_ssl_chk_issued_cb x509_chk_issued_cb;
};


int evhtp_ssl_init(evhtp_t * htp, evhtp_ssl_cfg_t * ssl_cfg);

#ifdef EVHTP_ENABLE_EVTHR
int evhtp_ssl_use_threads(void);
#endif

#endif

#ifdef __cplusplus
}
#endif
#endif

