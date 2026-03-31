/*
 * task.h - Structured async task with cancellation
 *
 * Provides a handle-based API for background work: spawn returns a
 * handle that can be polled, joined (with timeout), or cancelled.
 * The work function receives a cancel flag to check periodically.
 *
 * Inspired by Zed's Task<R> pattern — all outstanding tasks are
 * joined on shutdown, preventing orphaned threads.
 */

#ifndef SC_TASK_H
#define SC_TASK_H

#include <stdbool.h>
#include <stdatomic.h>

typedef void *(*sc_task_fn)(void *arg, volatile atomic_int *cancel);

typedef struct sc_task {
    void *_impl;  /* opaque — see task.c */
} sc_task_t;

/* Spawn a background task. Returns NULL on failure. */
sc_task_t *sc_task_spawn(sc_task_fn work, void *arg);

/* Check if the task has completed (non-blocking). */
bool sc_task_poll(sc_task_t *t);

/* Wait for the task to complete and return its result.
 * timeout_ms <= 0 means wait forever. Returns NULL on timeout. */
void *sc_task_join(sc_task_t *t, int timeout_ms);

/* Request cancellation. The work function should check the cancel
 * flag periodically and exit early when set. */
void sc_task_cancel(sc_task_t *t);

/* Free the task handle. If the task is still running, cancels and
 * joins with a 5-second timeout before freeing. */
void sc_task_free(sc_task_t *t);

#endif /* SC_TASK_H */
