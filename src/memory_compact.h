#ifndef SC_MEMORY_COMPACT_H
#define SC_MEMORY_COMPACT_H

#include "providers/types.h"

/*
 * Compact MEMORY.md using the LLM if it exceeds the size threshold.
 *
 * Reads MEMORY.md, sends it to the LLM with a curation prompt,
 * and writes the compacted version back. Recent entries are kept
 * verbatim, older entries are summarized or dropped.
 *
 * Returns 0 if compaction ran (or wasn't needed), -1 on error.
 * threshold_bytes: only compact if MEMORY.md exceeds this (0 = always).
 */
int sc_memory_compact(const char *workspace, sc_provider_t *provider,
                       const char *model, size_t threshold_bytes);

#endif /* SC_MEMORY_COMPACT_H */
