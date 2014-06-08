#ifndef __EVHTP___INTERNAL_H__
#define __EVHTP___INTERNAL_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "evhtp2/evhtp-config.h"


#ifdef EVHTP_HAS_VISIBILITY_HIDDEN
#define __visible __attribute__((visibility("default")))
#define EXPORT_SYMBOL(x) typeof(x)(x)__visible
#else
#define EXPORT_SYMBOL(n)
#endif

#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)        \
    for ((var) = TAILQ_FIRST((head));                     \
         (var) && ((tvar) = TAILQ_NEXT((var), field), 1); \
         (var) = (tvar))
#endif

#ifndef EVHTP_HEX_DIGITS
#define EVHTP_HEX_DIGITS "0123456789abcdef"
#endif

#ifndef EVHTP_BIT_ISSET
#define EVHTP_BIT_ISSET(target, bit) \
    (((target) & (bit)) ? 1 : 0)
#endif

#ifndef HAVE_STRNLEN
static inline size_t
strnlen(const char * s, size_t maxlen) {
    const char * e;
    size_t       n;

    for (e = s, n = 0; *e && n < maxlen; e++, n++) {
        ;
    }

    return n;
}

#endif

#ifndef HAVE_STRNDUP
static inline char *
strndup(const char * s, size_t n) {
    size_t len = strnlen(s, n);
    char * ret;

    if (len < n) {
        return strdup(s);
    }

    ret    = malloc(n + 1);
    ret[n] = '\0';

    strncpy(ret, s, n);
    return ret;
}

#endif

#ifndef HAVE_NTOHLL
#if HOST_BIG_ENDIAN
#define ntohll(x) (x)
#else
static inline uint64_t
ntohll(uint64_t v) {
    uint64_t  h;
    uint8_t * p = (uint8_t *)&h;

    *p++ = (uint8_t)(v >> 56 & 0xff);
    *p++ = (uint8_t)(v >> 48 & 0xff);
    *p++ = (uint8_t)(v >> 40 & 0xff);
    *p++ = (uint8_t)(v >> 32 & 0xff);
    *p++ = (uint8_t)(v >> 24 & 0xff);
    *p++ = (uint8_t)(v >> 16 & 0xff);
    *p++ = (uint8_t)(v >> 8 & 0xff);
    *p   = (uint8_t)(v >> 0 & 0xff);

    return h;
}

#endif
#endif

#ifndef HAVE_HTONLL
#if HOST_BIG_ENDIAN
#define htonll(x) (x)
#else
static inline uint64_t
htonll(uint64_t v) {
    uint64_t  h = 0;
    uint8_t * p = (uint8_t *)&v;

    h |= (uint64_t)*p++ << 56;
    h |= (uint64_t)*p++ << 48;
    h |= (uint64_t)*p++ << 40;
    h |= (uint64_t)*p++ << 32;
    h |= (uint64_t)*p++ << 24;
    h |= (uint64_t)*p++ << 16;
    h |= (uint64_t)*p++ << 8;
    h |= (uint64_t)*p << 0;

    return h;
}

#endif
#endif

#ifdef __cplusplus
}
#endif
#endif
