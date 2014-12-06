#ifndef __EVHTP_THR_EVTHR_THR_H__
#define __EVHTP_THR_EVTHR_THR_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sched.h>
#include <pthread.h>
#include <sys/queue.h>
#include <event2/event.h>
#include <event2/thread.h>

enum evhtp_thr_res {
    EVHTP_THR_RES_OK = 0,
    EVHTP_THR_RES_BACKLOG,
    EVHTP_THR_RES_RETRY,
    EVHTP_THR_RES_NOCB,
    EVHTP_THR_RES_FATAL
};

struct evhtp_thr_pool;
struct evhtp_thr;

typedef struct evhtp_thr_pool evhtp_thr_pool_t;
typedef struct evhtp_thr      evhtp_thr_t;
typedef pthread_mutex_t       evhtp_mutex_t;

typedef enum evhtp_thr_res    evhtp_thr_res;

typedef void (*evhtp_thr_cb)(evhtp_thr_t * thr, void * cmd_arg, void * shared);
typedef void (*evhtp_thr_init_cb)(evhtp_thr_t * thr, void * shared);
typedef void (*evhtp_thread_init_cb)(evhtp_t * htp, evhtp_thr_t * thr, void * arg);

EVHTP_EXPORT evhtp_thr_t       * evhtp_thr_new(evhtp_thr_init_cb init_cb, void * arg);
EVHTP_EXPORT struct event_base * evhtp_thr_get_base(evhtp_thr_t * thr);
EVHTP_EXPORT void                evhtp_thr_set_aux(evhtp_thr_t * thr, void * aux);
EVHTP_EXPORT void              * evhtp_thr_get_aux(evhtp_thr_t * thr);
EVHTP_EXPORT int                 evhtp_thr_start(evhtp_thr_t * evhtp_thr);
EVHTP_EXPORT evhtp_thr_res       evhtp_thr_stop(evhtp_thr_t * evhtp_thr);
EVHTP_EXPORT evhtp_thr_res       evhtp_thr_defer(evhtp_thr_t * evhtp_thr, evhtp_thr_cb cb, void * arg);
EVHTP_EXPORT void                evhtp_thr_free(evhtp_thr_t * evhtp_thr);

EVHTP_EXPORT evhtp_thr_pool_t  * evhtp_thr_pool_new(int nthreads, evhtp_thr_init_cb init_cb, void * shared);
EVHTP_EXPORT int                 evhtp_thr_pool_start(evhtp_thr_pool_t * pool);
EVHTP_EXPORT evhtp_thr_res       evhtp_thr_pool_stop(evhtp_thr_pool_t * pool);
EVHTP_EXPORT evhtp_thr_res       evhtp_thr_pool_defer(evhtp_thr_pool_t * pool, evhtp_thr_cb cb, void * arg);
EVHTP_EXPORT void                evhtp_thr_pool_free(evhtp_thr_pool_t * pool);

EVHTP_EXPORT int                 evhtp_use_threads(evhtp_t * htp, evhtp_thread_init_cb init_cb, int nthreads, void * arg);

EVHTP_EXPORT EVHTP_CONN_GET_FN(thread, evhtp_thr_t *);
EVHTP_EXPORT evhtp_thr_t *evhtp_conn_set_thread(evhtp_conn_t *, evhtp_thr_t *);

#ifdef __cplusplus
}
#endif

#endif /* __EVHTP_THR_H__ */

