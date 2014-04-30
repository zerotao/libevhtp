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


#ifdef __cplusplus
}
#endif
#endif
