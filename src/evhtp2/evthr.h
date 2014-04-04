#ifndef __EVHTP_EVTHR_H__
#define __EVHTP_EVTHR_H__

#include <evhtp/audit-config.h>

#ifdef EVHTP_ENABLE_EVTHR
#include <evhtp/evthr/evhtp_evthr.h>

typedef void (*evhtp_thread_init_cb)(evhtp_t * htp, evthr_t * thr, void * arg);

/**
 * @brief creates a lock around callbacks and hooks, allowing for threaded
 * applications to add/remove/modify hooks & callbacks in a thread-safe manner.
 *
 * @param htp
 *
 * @return 0 on success, -1 on error
 */
int evhtp_use_callback_locks(evhtp_t * htp);
int evhtp_use_threads(evhtp_t * htp, evhtp_thread_init_cb init_cb, int nthreads, void * arg);

#endif

#endif

