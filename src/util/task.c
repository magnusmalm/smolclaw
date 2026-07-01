/*
 * task.c - Structured async task with cancellation
 */

#include "task.h"

#include <pthread.h>
#include <stdlib.h>
#include <time.h>

typedef struct {
    pthread_t       thread;
    atomic_int      done;
    atomic_int      cancel;
    atomic_int      reaped;   /* set once the thread has been joined or detached;
                               * ensures pthread_join/detach happens at most once
                               * across all sc_task_join/sc_task_free calls */
    void           *result;
    sc_task_fn      work;
    void           *arg;
} sc_task_impl_t;

static void *task_thread(void *arg)
{
    sc_task_impl_t *impl = arg;
    impl->result = impl->work(impl->arg, &impl->cancel);
    atomic_store(&impl->done, 1);
    return NULL;
}

/* Join the thread exactly once. Returns 1 if this call performed the join,
 * 0 if it was already reaped (joined or detached) by a prior call. */
static int task_join_once(sc_task_impl_t *impl)
{
    if (atomic_exchange(&impl->reaped, 1) != 0)
        return 0;
    pthread_join(impl->thread, NULL);
    return 1;
}

sc_task_t *sc_task_spawn(sc_task_fn work, void *arg)
{
    if (!work) return NULL;

    sc_task_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    sc_task_impl_t *impl = calloc(1, sizeof(*impl));
    if (!impl) { free(t); return NULL; }

    impl->work = work;
    impl->arg  = arg;
    atomic_init(&impl->done, 0);
    atomic_init(&impl->cancel, 0);
    atomic_init(&impl->reaped, 0);
    t->_impl = impl;

    if (pthread_create(&impl->thread, NULL, task_thread, impl) != 0) {
        free(impl);
        free(t);
        return NULL;
    }

    return t;
}

bool sc_task_poll(sc_task_t *t)
{
    if (!t || !t->_impl) return true;
    sc_task_impl_t *impl = t->_impl;
    return atomic_load(&impl->done) != 0;
}

void *sc_task_join(sc_task_t *t, int timeout_ms)
{
    if (!t || !t->_impl) return NULL;
    sc_task_impl_t *impl = t->_impl;

    if (timeout_ms <= 0) {
        task_join_once(impl);
        return impl->result;
    }

    /* Timed join via polling (POSIX lacks pthread_timedjoin_np portably) */
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 10000000 }; /* 10ms */
    int elapsed = 0;
    while (!atomic_load(&impl->done) && elapsed < timeout_ms) {
        nanosleep(&ts, NULL);
        elapsed += 10;
    }

    if (atomic_load(&impl->done)) {
        task_join_once(impl);
        return impl->result;
    }

    return NULL;  /* timeout — thread still running */
}

void sc_task_cancel(sc_task_t *t)
{
    if (!t || !t->_impl) return;
    sc_task_impl_t *impl = t->_impl;
    atomic_store(&impl->cancel, 1);
}

void sc_task_free(sc_task_t *t)
{
    if (!t) return;
    sc_task_impl_t *impl = t->_impl;
    if (impl) {
        /* Ask a still-running task to cancel and give it up to 5s to finish. */
        if (!atomic_load(&impl->done)) {
            atomic_store(&impl->cancel, 1);
            sc_task_join(t, 5000);  /* reaps via task_join_once if it finishes */
        }

        if (atomic_load(&impl->done)) {
            /* Terminated: join exactly once (no-op if a prior sc_task_join
             * already reaped it — avoids the double pthread_join UB), free. */
            task_join_once(impl);
            free(impl);
        } else if (atomic_exchange(&impl->reaped, 1) == 0) {
            /* Ignored cancel for 5s: detach so the OS reclaims the thread on
             * exit, and DO NOT free impl — the detached thread still writes
             * impl->result / impl->done. Deliberately leaking impl here is far
             * cheaper than the use-after-free the old free()-after-detach
             * caused, and only happens for a task that ignored cancellation. */
            pthread_detach(impl->thread);
        }
        /* else: already reaped elsewhere — impl is owned there, don't touch it. */
    }
    free(t);
}
