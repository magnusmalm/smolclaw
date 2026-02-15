#ifndef SC_RATE_LIMIT_H
#define SC_RATE_LIMIT_H

/*
 * Token-bucket rate limiter per key (channel+chat_id).
 * Thread-safe: uses a simple linear scan over a fixed-size bucket table.
 */

typedef struct sc_rate_limiter sc_rate_limiter_t;

/* Create a rate limiter. max_per_minute = 0 disables limiting. */
sc_rate_limiter_t *sc_rate_limiter_new(int max_per_minute);

/* Check if a message from key is allowed. Returns 1 if allowed, 0 if rate-limited. */
int sc_rate_limiter_check(sc_rate_limiter_t *rl, const char *key);

/* Free rate limiter */
void sc_rate_limiter_free(sc_rate_limiter_t *rl);

#endif /* SC_RATE_LIMIT_H */
