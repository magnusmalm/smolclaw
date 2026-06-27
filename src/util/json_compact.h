/*
 * smolclaw - JSON-aware tool result compaction (Phase 1.7)
 *
 * Semantically shrinks large JSON tool results before they enter the session
 * history: long string fields (content/output/diff/...) are truncated and big
 * arrays (matches/entries/...) are capped, with a "compacted": true marker on
 * the affected object. Distinct from output_filter.c (syntactic CLI filters).
 */
#ifndef SC_JSON_COMPACT_H
#define SC_JSON_COMPACT_H

/*
 * If `content` parses as a JSON object/array and contains oversized string
 * fields or arrays, return a newly-allocated compacted JSON string (caller
 * frees). Returns NULL if `content` is not JSON, or if nothing needed
 * compacting (caller keeps the original).
 *
 * max_field_chars: cap for known long string fields (e.g. 4096).
 * max_array_items: cap for known array fields (e.g. 50).
 */
char *sc_json_compact_for_llm(const char *content, int max_field_chars,
                              int max_array_items);

#endif /* SC_JSON_COMPACT_H */
