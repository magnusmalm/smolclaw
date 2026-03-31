/*
 * util/arena.h - Bump allocator for per-turn allocations
 *
 * Allocates from a contiguous block, reset at turn end. No individual
 * frees needed — reset clears all allocations at once. Falls back to
 * malloc if the arena is exhausted.
 */

#ifndef SC_ARENA_H
#define SC_ARENA_H

#include <stddef.h>

typedef struct sc_arena sc_arena_t;

/* Create arena with initial capacity (bytes). 0 = default 64KB. */
sc_arena_t *sc_arena_new(size_t initial_cap);

/* Allocate n bytes (8-byte aligned). Returns NULL on failure. */
void *sc_arena_alloc(sc_arena_t *a, size_t n);

/* Duplicate a string into the arena. */
char *sc_arena_strdup(sc_arena_t *a, const char *s);

/* Reset: reuse arena memory without freeing the block.
 * All previous pointers become invalid. */
void sc_arena_reset(sc_arena_t *a);

/* Free arena and its backing memory. */
void sc_arena_free(sc_arena_t *a);

/* Current usage stats. */
size_t sc_arena_used(const sc_arena_t *a);
size_t sc_arena_capacity(const sc_arena_t *a);

#endif /* SC_ARENA_H */
