/*
 * rate_limit.c - Token-bucket rate limiter per key
 *
 * Fixed-size bucket table (64 entries). Each bucket tracks tokens for a
 * channel+chat_id key. Tokens refill at max_per_minute/60 per second.
 * LRU eviction when table is full.
 */

#include "rate_limit.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#define MAX_BUCKETS 64
#define KEY_MAX     128

typedef struct {
    char key[KEY_MAX];
    double tokens;
    time_t last_refill;
} bucket_t;

struct sc_rate_limiter {
    bucket_t buckets[MAX_BUCKETS];
    int count;
    int max_per_minute;
    double refill_per_sec;
    pthread_mutex_t lock;
};

sc_rate_limiter_t *sc_rate_limiter_new(int max_per_minute)
{
    sc_rate_limiter_t *rl = calloc(1, sizeof(*rl));
    if (!rl) return NULL;
    rl->max_per_minute = max_per_minute;
    rl->refill_per_sec = max_per_minute > 0 ? (double)max_per_minute / 60.0 : 0;
    pthread_mutex_init(&rl->lock, NULL);
    return rl;
}

static bucket_t *find_bucket(sc_rate_limiter_t *rl, const char *key)
{
    for (int i = 0; i < rl->count; i++) {
        if (strncmp(rl->buckets[i].key, key, KEY_MAX - 1) == 0)
            return &rl->buckets[i];
    }
    return NULL;
}

static bucket_t *alloc_bucket(sc_rate_limiter_t *rl, const char *key)
{
    bucket_t *b;
    if (rl->count < MAX_BUCKETS) {
        b = &rl->buckets[rl->count++];
    } else {
        /* Evict oldest (lowest last_refill) */
        int oldest = 0;
        for (int i = 1; i < rl->count; i++) {
            if (rl->buckets[i].last_refill < rl->buckets[oldest].last_refill)
                oldest = i;
        }
        b = &rl->buckets[oldest];
    }
    memset(b, 0, sizeof(*b));
    strncpy(b->key, key, KEY_MAX - 1);
    b->key[KEY_MAX - 1] = '\0';
    b->tokens = (double)rl->max_per_minute;
    b->last_refill = time(NULL);
    return b;
}

static void refill(sc_rate_limiter_t *rl, bucket_t *b, time_t now)
{
    double elapsed = difftime(now, b->last_refill);
    if (elapsed > 0) {
        b->tokens += elapsed * rl->refill_per_sec;
        if (b->tokens > (double)rl->max_per_minute)
            b->tokens = (double)rl->max_per_minute;
        b->last_refill = now;
    }
}

int sc_rate_limiter_check(sc_rate_limiter_t *rl, const char *key)
{
    if (!rl || rl->max_per_minute <= 0 || !key) return 1;

    pthread_mutex_lock(&rl->lock);

    time_t now = time(NULL);
    bucket_t *b = find_bucket(rl, key);
    if (!b) {
        b = alloc_bucket(rl, key);
    }

    refill(rl, b, now);

    int allowed;
    if (b->tokens >= 1.0) {
        b->tokens -= 1.0;
        allowed = 1;
    } else {
        allowed = 0;
    }

    pthread_mutex_unlock(&rl->lock);
    return allowed;
}

void sc_rate_limiter_free(sc_rate_limiter_t *rl)
{
    if (!rl) return;
    pthread_mutex_destroy(&rl->lock);
    free(rl);
}
