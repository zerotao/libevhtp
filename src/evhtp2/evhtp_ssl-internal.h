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

EVHTP_EXPORT int evhtp_ssl_servername(evhtp_ssl_t * ssl, int * unused, void * arg);

#ifdef __cplusplus
}
#endif
#endif
#endif
