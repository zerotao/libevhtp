#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#ifndef WIN32
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#endif

#include <unistd.h>
#include <pthread.h>

#include <event2/event.h>
#include <event2/thread.h>

#include "evhtp2/internal.h"
#include "evhtp2/evhtp_thr.h"

typedef struct evhtp_thr_cmd        evhtp_thr_cmd_t;
typedef struct evhtp_thr_pool_slist evhtp_thr_pool_slist_t;

struct evhtp_thr_cmd {
    uint8_t      stop;
    void       * args;
    evhtp_thr_cb cb;
};

TAILQ_HEAD(evhtp_thr_pool_slist, evhtp_thr);

struct evhtp_thr_pool {
    int                    nthreads;
    evhtp_thr_pool_slist_t threads;
};

struct evhtp_thr {
    int                 rdr;
    int                 wdr;
    char                err;
    struct event      * event;
    struct event_base * evbase;
    pthread_mutex_t     lock;
    pthread_mutex_t     rlock;
    pthread_t         * thr;
    evhtp_thr_init_cb   init_cb;
    void              * arg;
    void              * aux;

    TAILQ_ENTRY(evhtp_thr) next;
};

static inline int
_evhtp_thr_read(evhtp_thr_t * thr, evhtp_thr_cmd_t * cmd, evutil_socket_t sock) {
    if (recv(sock, cmd, sizeof(evhtp_thr_cmd_t), 0) != sizeof(evhtp_thr_cmd_t)) {
        return 0;
    }

    return 1;
}

static void
_evhtp_thr_read_cmd(evutil_socket_t sock, short which, void * args) {
    evhtp_thr_t   * thread;
    evhtp_thr_cmd_t cmd;
    int             stopped;

    if (!(thread = (evhtp_thr_t *)args)) {
        return;
    }

    pthread_mutex_lock(&thread->rlock);

    stopped = 0;

    while (_evhtp_thr_read(thread, &cmd, sock) == 1) {
        if (cmd.stop == 1) {
            stopped = 1;
            break;
        }

        if (cmd.cb != NULL) {
            (cmd.cb)(thread, cmd.args, thread->arg);
        }
    }

    pthread_mutex_unlock(&thread->rlock);

    if (stopped == 1) {
        event_base_loopbreak(thread->evbase);
    }

    return;
} /* _evhtp_thr_read_cmd */

static void *
_evhtp_thr_loop(void * args) {
    evhtp_thr_t * thread;

    if (!(thread = (evhtp_thr_t *)args)) {
        return NULL;
    }

    if (thread == NULL || thread->thr == NULL) {
        pthread_exit(NULL);
    }

    thread->evbase = event_base_new();
    thread->event  = event_new(thread->evbase, thread->rdr,
                               EV_READ | EV_PERSIST, _evhtp_thr_read_cmd, args);

    event_add(thread->event, NULL);

    pthread_mutex_lock(&thread->lock);

    if (thread->init_cb != NULL) {
        thread->init_cb(thread, thread->arg);
    }

    pthread_mutex_unlock(&thread->lock);

    event_base_loop(thread->evbase, 0);

    if (thread->err == 1) {
        fprintf(stderr, "FATAL ERROR!\n");
    }

    pthread_exit(NULL);
}

evhtp_thr_res
evhtp_thr_defer(evhtp_thr_t * thread, evhtp_thr_cb cb, void * arg) {
    evhtp_thr_cmd_t cmd;


    cmd.cb   = cb;
    cmd.args = arg;
    cmd.stop = 0;

    pthread_mutex_lock(&thread->rlock);

    if (send(thread->wdr, &cmd, sizeof(cmd), 0) <= 0) {
        pthread_mutex_unlock(&thread->rlock);
        return EVHTP_THR_RES_RETRY;
    }

    pthread_mutex_unlock(&thread->rlock);

    return EVHTP_THR_RES_OK;
}

evhtp_thr_res
evhtp_thr_stop(evhtp_thr_t * thread) {
    evhtp_thr_cmd_t cmd;

    /* cmd.magic = _EVHTP_THR_MAGIC; */
    cmd.cb   = NULL;
    cmd.args = NULL;
    cmd.stop = 1;

    pthread_mutex_lock(&thread->rlock);

    if (write(thread->wdr, &cmd, sizeof(evhtp_thr_cmd_t)) < 0) {
        pthread_mutex_unlock(&thread->rlock);
        return EVHTP_THR_RES_RETRY;
    }

    pthread_mutex_unlock(&thread->rlock);

    return EVHTP_THR_RES_OK;
}

struct event_base *
evhtp_thr_get_base(evhtp_thr_t * thr) {
    return thr->evbase;
}

void
evhtp_thr_set_aux(evhtp_thr_t * thr, void * aux) {
    thr->aux = aux;
}

void *
evhtp_thr_get_aux(evhtp_thr_t * thr) {
    return thr->aux;
}

evhtp_thr_t *
evhtp_thr_new(evhtp_thr_init_cb init_cb, void * args) {
    evhtp_thr_t * thread;
    int           fds[2];

    if (evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == -1) {
        return NULL;
    }

    evutil_make_socket_nonblocking(fds[0]);
    evutil_make_socket_nonblocking(fds[1]);

    if (!(thread = calloc(sizeof(evhtp_thr_t), 1))) {
        return NULL;
    }

    thread->thr     = malloc(sizeof(pthread_t));
    thread->init_cb = init_cb;
    thread->arg     = args;
    thread->rdr     = fds[0];
    thread->wdr     = fds[1];

    if (pthread_mutex_init(&thread->lock, NULL)) {
        evhtp_thr_free(thread);
        return NULL;
    }

    if (pthread_mutex_init(&thread->rlock, NULL)) {
        evhtp_thr_free(thread);
        return NULL;
    }

    return thread;
} /* evhtp_thr_new */

int
evhtp_thr_start(evhtp_thr_t * thread) {
    int res;

    if (thread == NULL || thread->thr == NULL) {
        return -1;
    }

    if (pthread_create(thread->thr, NULL, _evhtp_thr_loop, (void *)thread)) {
        return -1;
    }

    res = pthread_detach(*thread->thr);

    return res;
}

void
evhtp_thr_free(evhtp_thr_t * thread) {
    if (thread == NULL) {
        return;
    }

    if (thread->rdr > 0) {
        close(thread->rdr);
    }

    if (thread->wdr > 0) {
        close(thread->wdr);
    }

    if (thread->thr) {
        free(thread->thr);
    }

    if (thread->event) {
        event_free(thread->event);
    }

    if (thread->evbase) {
        event_base_free(thread->evbase);
    }

    free(thread);
} /* evhtp_thr_free */

void
evhtp_thr_pool_free(evhtp_thr_pool_t * pool) {
    evhtp_thr_t * thread;
    evhtp_thr_t * save;

    if (pool == NULL) {
        return;
    }

    TAILQ_FOREACH_SAFE(thread, &pool->threads, next, save) {
        TAILQ_REMOVE(&pool->threads, thread, next);

        evhtp_thr_free(thread);
    }

    free(pool);
}

evhtp_thr_res
evhtp_thr_pool_stop(evhtp_thr_pool_t * pool) {
    evhtp_thr_t * thr;
    evhtp_thr_t * save;

    if (pool == NULL) {
        return EVHTP_THR_RES_FATAL;
    }

    TAILQ_FOREACH_SAFE(thr, &pool->threads, next, save) {
        evhtp_thr_stop(thr);
    }

    return EVHTP_THR_RES_OK;
}

evhtp_thr_res
evhtp_thr_pool_defer(evhtp_thr_pool_t * pool, evhtp_thr_cb cb, void * arg) {
    evhtp_thr_t * thr = NULL;

    if (pool == NULL) {
        return EVHTP_THR_RES_FATAL;
    }

    if (cb == NULL) {
        return EVHTP_THR_RES_NOCB;
    }

    thr = TAILQ_FIRST(&pool->threads);

    TAILQ_REMOVE(&pool->threads, thr, next);
    TAILQ_INSERT_TAIL(&pool->threads, thr, next);


    return evhtp_thr_defer(thr, cb, arg);
} /* evhtp_thr_pool_defer */

evhtp_thr_pool_t *
evhtp_thr_pool_new(int nthreads, evhtp_thr_init_cb init_cb, void * shared) {
    evhtp_thr_pool_t * pool;
    int                i;

    if (nthreads == 0) {
        return NULL;
    }

    if (!(pool = calloc(sizeof(evhtp_thr_pool_t), 1))) {
        return NULL;
    }

    pool->nthreads = nthreads;
    TAILQ_INIT(&pool->threads);

    for (i = 0; i < nthreads; i++) {
        evhtp_thr_t * thread;

        if (!(thread = evhtp_thr_new(init_cb, shared))) {
            evhtp_thr_pool_free(pool);
            return NULL;
        }

        TAILQ_INSERT_TAIL(&pool->threads, thread, next);
    }

    return pool;
}

int
evhtp_thr_pool_start(evhtp_thr_pool_t * pool) {
    evhtp_thr_t * evhtp_thr = NULL;

    if (pool == NULL) {
        return -1;
    }

    TAILQ_FOREACH(evhtp_thr, &pool->threads, next) {
        if (evhtp_thr_start(evhtp_thr) < 0) {
            return -1;
        }

        usleep(5000);
    }

    return 0;
}

EXPORT_SYMBOL(evhtp_thr_new);
EXPORT_SYMBOL(evhtp_thr_get_base);
EXPORT_SYMBOL(evhtp_thr_set_aux);
EXPORT_SYMBOL(evhtp_thr_get_aux);
EXPORT_SYMBOL(evhtp_thr_start);
EXPORT_SYMBOL(evhtp_thr_stop);
EXPORT_SYMBOL(evhtp_thr_defer);
EXPORT_SYMBOL(evhtp_thr_free);
EXPORT_SYMBOL(evhtp_thr_pool_new);
EXPORT_SYMBOL(evhtp_thr_pool_start);
EXPORT_SYMBOL(evhtp_thr_pool_stop);
EXPORT_SYMBOL(evhtp_thr_pool_defer);
EXPORT_SYMBOL(evhtp_thr_pool_free);
