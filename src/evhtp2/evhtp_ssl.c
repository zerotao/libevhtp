#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

#include "evhtp2/evhtp_ssl-internal.h"

static int             session_id_context    = 1;
#ifdef EVHTP_ENABLE_EVTHR
static int             ssl_num_locks;
static evhtp_mutex_t * ssl_locks;
static int             ssl_locks_initialized = 0;
#endif

#ifdef EVHTP_ENABLE_EVTHR
static unsigned long
_evhtp_ssl_get_thread_id(void) {
#ifndef WIN32
    return (unsigned long)pthread_self();
#else
    return (unsigned long)(pthread_self().p);
#endif
}

static void
_evhtp_ssl_thread_lock(int mode, int type, const char * file, int line) {
    if (type < ssl_num_locks) {
        if (mode & CRYPTO_LOCK) {
            pthread_mutex_lock(&(ssl_locks[type]));
        } else {
            pthread_mutex_unlock(&(ssl_locks[type]));
        }
    }
}

#endif

static void
_evhtp_ssl_delete_cache_ent(evhtp_ssl_ctx_t * ctx, evhtp_ssl_sess_t * sess) {
    evhtp_t         * htp;
    evhtp_ssl_cfg_t * cfg;
    unsigned char   * sid;
    unsigned int      slen;

    htp  = (evhtp_t *)SSL_CTX_get_app_data(ctx);
    cfg  = htp->ssl_cfg;

    sid  = sess->session_id;
    slen = sess->session_id_length;

    if (cfg->cache_del) {
        (cfg->cache_del)(htp, sid, slen);
    }
}

static int
_evhtp_ssl_add_cache_ent(evhtp_ssl_t * ssl, evhtp_ssl_sess_t * sess) {
    evhtp_connection_t * connection;
    evhtp_ssl_cfg_t    * cfg;
    unsigned char      * sid;
    int                  slen;

    connection = (evhtp_connection_t *)SSL_get_app_data(ssl);
    cfg        = connection->htp->ssl_cfg;

    sid        = sess->session_id;
    slen       = sess->session_id_length;

    SSL_set_timeout(sess, cfg->cache_timeout);

    if (cfg->cache_add) {
        return (cfg->cache_add)(connection, sid, slen, sess);
    }

    return 0;
}

static evhtp_ssl_sess_t *
_evhtp_ssl_get_cache_ent(evhtp_ssl_t * ssl, unsigned char * sid, int sid_len, int * copy) {
    evhtp_connection_t * connection;
    evhtp_ssl_cfg_t    * cfg;
    evhtp_ssl_sess_t   * sess;

    connection = (evhtp_connection_t * )SSL_get_app_data(ssl);
    cfg        = connection->htp->ssl_cfg;
    sess       = NULL;

    if (cfg->cache_get) {
        sess = (cfg->cache_get)(connection, sid, sid_len);
    }

    *copy = 0;

    return sess;
}

static int
_evhtp_ssl_servername(evhtp_ssl_t * ssl, int * unused, void * arg) {
    const char         * sname;
    evhtp_connection_t * connection;
    evhtp_t            * evhtp;
    evhtp_t            * evhtp_vhost;

    if (!(sname = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name))) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    if (!(connection = SSL_get_app_data(ssl))) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    if (!(evhtp = connection->htp)) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    if ((evhtp_vhost = evhtp_request_find_vhost(evhtp, sname))) {
        connection->htp           = evhtp_vhost;
        connection->vhost_via_sni = 1;

        SSL_set_SSL_CTX(ssl, evhtp_vhost->ssl_ctx);
        SSL_set_options(ssl, SSL_CTX_get_options(ssl->ctx));

        if ((SSL_get_verify_mode(ssl) == SSL_VERIFY_NONE) ||
            (SSL_num_renegotiations(ssl) == 0)) {
            SSL_set_verify(ssl, SSL_CTX_get_verify_mode(ssl->ctx),
                           SSL_CTX_get_verify_callback(ssl->ctx));
        }

        return SSL_TLSEXT_ERR_OK;
    }

    return SSL_TLSEXT_ERR_NOACK;
} /* _evhtp_ssl_servername */

inline int
evhtp_ssl_servername(evhtp_ssl_t * ssl, int * unused, void * arg) {
    return _evhtp_ssl_servername(ssl, unused, arg);
}

#ifdef EVHTP_ENABLE_EVTHR
int
evhtp_ssl_use_threads(void) {
    int i;

    if (ssl_locks_initialized == 1) {
        return 0;
    }

    ssl_locks_initialized = 1;

    ssl_num_locks         = CRYPTO_num_locks();
    ssl_locks = malloc(ssl_num_locks * sizeof(evhtp_mutex_t));

    for (i = 0; i < ssl_num_locks; i++) {
        pthread_mutex_init(&(ssl_locks[i]), NULL);
    }

    CRYPTO_set_id_callback(_evhtp_ssl_get_thread_id);
    CRYPTO_set_locking_callback(_evhtp_ssl_thread_lock);

    return 0;
}

EXPORT_SYMBOL(evhtp_ssl_use_threads);

#endif

int
evhtp_ssl_init(evhtp_t * htp, evhtp_ssl_cfg_t * cfg) {
#ifdef EVHTP_ENABLE_FUTURE_STUFF
    evhtp_ssl_cache_init init_cb = NULL;
    evhtp_ssl_cache_add  add_cb  = NULL;
    evhtp_ssl_cache_get  get_cb  = NULL;
    evhtp_ssl_cache_del  del_cb  = NULL;
#endif
    long                 cache_mode;

    if (cfg == NULL || htp == NULL || cfg->pemfile == NULL) {
        return -1;
    }

    SSL_library_init();
    SSL_load_error_strings();
    RAND_poll();

#if OPENSSL_VERSION_NUMBER < 0x10000000L
    STACK_OF(SSL_COMP) * comp_methods = SSL_COMP_get_compression_methods();
    sk_SSL_COMP_zero(comp_methods);
#endif

    htp->ssl_cfg = cfg;
    htp->ssl_ctx = SSL_CTX_new(SSLv23_server_method());

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
    SSL_CTX_set_options(htp->ssl_ctx, SSL_MODE_RELEASE_BUFFERS | SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_timeout(htp->ssl_ctx, cfg->ctx_timeout);
#endif

    SSL_CTX_set_options(htp->ssl_ctx, cfg->opts);

#ifndef OPENSSL_NO_ECDH
    if (cfg->named_curve != NULL) {
        EC_KEY * ecdh = NULL;
        int      nid  = 0;

        nid  = OBJ_sn2nid(cfg->named_curve);
        if (nid == 0) {
            fprintf(stderr, "ECDH initialization failed: unknown curve %s\n", cfg->named_curve);
        }
        ecdh = EC_KEY_new_by_curve_name(nid);
        if (ecdh == NULL) {
            fprintf(stderr, "ECDH initialization failed for curve %s\n", cfg->named_curve);
        }
        SSL_CTX_set_tmp_ecdh(htp->ssl_ctx, ecdh);
        EC_KEY_free(ecdh);
    }
#endif /* OPENSSL_NO_ECDH */
#ifndef OPENSSL_NO_DH
    if (cfg->dhparams != NULL) {
        FILE *fh;
        DH   *dh;

        fh = fopen(cfg->dhparams, "r");
        if (fh != NULL) {
            dh = PEM_read_DHparams(fh, NULL, NULL, NULL);
            if (dh != NULL) {
                SSL_CTX_set_tmp_dh(htp->ssl_ctx, dh);
                DH_free(dh);
            } else {
                fprintf(stderr, "DH initialization failed: unable to parse file %s\n", cfg->dhparams);
            }
            fclose(fh);
        } else {
            fprintf(stderr, "DH initialization failed: unable to open file %s\n", cfg->dhparams);
        }
    }
#endif /* OPENSSL_NO_DH */

    if (cfg->ciphers != NULL) {
        SSL_CTX_set_cipher_list(htp->ssl_ctx, cfg->ciphers);
    }

    SSL_CTX_load_verify_locations(htp->ssl_ctx, cfg->cafile, cfg->capath);
    X509_STORE_set_flags(SSL_CTX_get_cert_store(htp->ssl_ctx), cfg->store_flags);
    SSL_CTX_set_verify(htp->ssl_ctx, cfg->verify_peer, cfg->x509_verify_cb);

    if (cfg->x509_chk_issued_cb != NULL) {
        htp->ssl_ctx->cert_store->check_issued = cfg->x509_chk_issued_cb;
    }

    if (cfg->verify_depth) {
        SSL_CTX_set_verify_depth(htp->ssl_ctx, cfg->verify_depth);
    }

    switch (cfg->cache_type) {
        case evhtp_ssl_cache_type_disabled:
            cache_mode = SSL_SESS_CACHE_OFF;
            break;
#ifdef EVHTP_ENABLE_FUTURE_STUFF
        case evhtp_ssl_cache_type_user:
            cache_mode = SSL_SESS_CACHE_SERVER |
                         SSL_SESS_CACHE_NO_INTERNAL |
                         SSL_SESS_CACHE_NO_INTERNAL_LOOKUP;

            init_cb    = cfg->cache_init;
            add_cb     = cfg->cache_add;
            get_cb     = cfg->cache_get;
            del_cb     = cfg->cache_del;
            break;
        case evhtp_ssl_cache_type_builtin:
            cache_mode = SSL_SESS_CACHE_SERVER |
                         SSL_SESS_CACHE_NO_INTERNAL |
                         SSL_SESS_CACHE_NO_INTERNAL_LOOKUP;

            init_cb    = _evhtp_ssl_builtin_init;
            add_cb     = _evhtp_ssl_builtin_add;
            get_cb     = _evhtp_ssl_builtin_get;
            del_cb     = _evhtp_ssl_builtin_del;
            break;
#endif
        case evhtp_ssl_cache_type_internal:
        default:
            cache_mode = SSL_SESS_CACHE_SERVER;
            break;
    }     /* switch */

    SSL_CTX_use_certificate_file(htp->ssl_ctx, cfg->pemfile, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(htp->ssl_ctx,
                                cfg->privfile ? cfg->privfile : cfg->pemfile, SSL_FILETYPE_PEM);

    SSL_CTX_set_session_id_context(htp->ssl_ctx,
                                   (void *)&session_id_context,
                                   sizeof(session_id_context));

    SSL_CTX_set_app_data(htp->ssl_ctx, htp);
    SSL_CTX_set_session_cache_mode(htp->ssl_ctx, cache_mode);

    if (cache_mode != SSL_SESS_CACHE_OFF) {
        SSL_CTX_sess_set_cache_size(htp->ssl_ctx,
                                    cfg->cache_size ? cfg->cache_size : 1024);

        if (cfg->cache_type == evhtp_ssl_cache_type_builtin ||
            cfg->cache_type == evhtp_ssl_cache_type_user) {
            SSL_CTX_sess_set_new_cb(htp->ssl_ctx, _evhtp_ssl_add_cache_ent);
            SSL_CTX_sess_set_get_cb(htp->ssl_ctx, _evhtp_ssl_get_cache_ent);
            SSL_CTX_sess_set_remove_cb(htp->ssl_ctx, _evhtp_ssl_delete_cache_ent);

            if (cfg->cache_init) {
                cfg->args = (cfg->cache_init)(htp);
            }
        }
    }

    return 0;
} /* evhtp_ssl_init */

EXPORT_SYMBOL(evhtp_ssl_init);
