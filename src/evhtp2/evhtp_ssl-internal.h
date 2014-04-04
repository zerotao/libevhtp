#ifndef __EVHTP_SSL_INTERNAL_H__
#define __EVHTP_SSL_INTERNAL_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "evhtp2/evhtp-config.h"

#ifdef EVHTP_ENABLE_SSL
#include "evhtp2/internal.h"
#include "evhtp2/evhtp-internal.h"
#include "evhtp2/evhtp_ssl.h"

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

int evhtp_ssl_servername(evhtp_ssl_t * ssl, int * unused, void * arg);

#ifdef __cplusplus
}
#endif
#endif
#endif
