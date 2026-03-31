/*
 * util/arena.c - Bump allocator
 *
 * Single contiguous block with a bump pointer. When exhausted, grows
 * by doubling. Reset moves the bump pointer back to start without
 * releasing memory — ideal for per-turn allocation patterns.
 */

#include "arena.h"

#include <stdlib.h>
#include <string.h>

#define SC_ARENA_DEFAULT_CAP (64 * 1024)  /* 64 KB */
#define SC_ARENA_ALIGN       8

struct sc_arena {
    char  *base;
    size_t used;
    size_t cap;
};

sc_arena_t *sc_arena_new(size_t initial_cap)
{
    sc_arena_t *a = calloc(1, sizeof(*a));
    if (!a) return NULL;

    a->cap = initial_cap > 0 ? initial_cap : SC_ARENA_DEFAULT_CAP;
    a->base = malloc(a->cap);
    if (!a->base) {
        free(a);
        return NULL;
    }
    a->used = 0;
    return a;
}

void *sc_arena_alloc(sc_arena_t *a, size_t n)
{
    if (!a || n == 0) return NULL;

    /* Align to 8 bytes */
    size_t aligned = (n + SC_ARENA_ALIGN - 1) & ~(size_t)(SC_ARENA_ALIGN - 1);

    if (a->used + aligned > a->cap) {
        /* Grow: double or fit, whichever is larger */
        size_t new_cap = a->cap * 2;
        if (new_cap < a->used + aligned)
            new_cap = a->used + aligned;

        char *new_base = realloc(a->base, new_cap);
        if (!new_base) return NULL;
        a->base = new_base;
        a->cap = new_cap;
    }

    void *ptr = a->base + a->used;
    a->used += aligned;
    return ptr;
}

char *sc_arena_strdup(sc_arena_t *a, const char *s)
{
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *dst = sc_arena_alloc(a, len);
    if (dst) memcpy(dst, s, len);
    return dst;
}

void sc_arena_reset(sc_arena_t *a)
{
    if (a) a->used = 0;
}

void sc_arena_free(sc_arena_t *a)
{
    if (!a) return;
    free(a->base);
    free(a);
}

size_t sc_arena_used(const sc_arena_t *a)
{
    return a ? a->used : 0;
}

size_t sc_arena_capacity(const sc_arena_t *a)
{
    return a ? a->cap : 0;
}
