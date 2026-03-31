/*
 * memory_compact.c - AI-driven MEMORY.md compaction
 *
 * When MEMORY.md grows beyond a threshold, sends it to the LLM
 * for curation. Recent entries are kept verbatim, older entries
 * are compressed or dropped. Inspired by icarus-daedalus's
 * HOT/WARM/COLD compaction scheme.
 */

#include "memory_compact.h"
#include "memory.h"
#include "logger.h"
#include "util/str.h"

#include "cJSON.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TAG "compact"
#define COMPACT_MAX_TOKENS 4096
#define DEFAULT_THRESHOLD  (50 * 1024)  /* 50 KB */

static const char COMPACT_SYSTEM_PROMPT[] =
    "You are a memory curator. You receive an agent's MEMORY.md file and "
    "must return a compacted version.\n\n"
    "Rules:\n"
    "1. Entries from the last 3 days: keep VERBATIM (do not change wording).\n"
    "2. Entries from 4-14 days ago: compress each to 1-2 sentences, preserving "
    "key facts, decisions, names, and dates.\n"
    "3. Entries older than 14 days: keep only if they record a durable fact "
    "(user preference, architectural decision, recurring pattern). Drop "
    "ephemeral status updates and transient observations.\n"
    "4. Preserve all headings and organizational structure.\n"
    "5. If an older entry is referenced by a recent entry, keep enough context "
    "for the reference to make sense.\n"
    "6. Output ONLY the compacted MEMORY.md content. No commentary.\n"
    "7. If the file is already compact enough, return it unchanged.\n"
    "8. REMOVE anything derivable from code, git history, or external APIs. "
    "Do not persist file paths, function names, code structure, or debugging "
    "findings — the agent can rediscover these by reading the code. Only keep "
    "decisions, surprises, non-obvious context, and user preferences.\n"
    "9. Convert all relative dates to absolute dates (e.g., 'yesterday' to "
    "'2026-03-30') so entries remain interpretable over time.";

int sc_memory_compact(const char *workspace, sc_provider_t *provider,
                       const char *model, size_t threshold_bytes)
{
    if (!workspace || !provider || !model)
        return -1;

    sc_memory_t *mem = sc_memory_new(workspace);
    if (!mem) return -1;

    char *content = sc_memory_read_long_term(mem);
    if (!content || !content[0]) {
        SC_LOG_INFO(TAG, "MEMORY.md is empty, nothing to compact");
        free(content);
        sc_memory_free(mem);
        return 0;
    }

    size_t len = strlen(content);
    size_t threshold = threshold_bytes > 0 ? threshold_bytes : DEFAULT_THRESHOLD;
    if (len < threshold) {
        SC_LOG_INFO(TAG, "MEMORY.md is %zu bytes (threshold %zu), skipping",
                    len, threshold);
        free(content);
        sc_memory_free(mem);
        return 0;
    }

    SC_LOG_INFO(TAG, "Compacting MEMORY.md (%zu bytes, threshold %zu)",
                len, threshold);

    /* Build LLM messages */
    sc_strbuf_t user_msg;
    sc_strbuf_init(&user_msg);

    /* Include current date for the recency rules */
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    sc_strbuf_appendf(&user_msg, "Today is %04d-%02d-%02d.\n\n",
                      tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
    sc_strbuf_appendf(&user_msg, "Here is the MEMORY.md to compact:\n\n%s",
                      content);
    char *user_text = sc_strbuf_finish(&user_msg);
    free(content);

    sc_llm_message_t msgs[2];
    msgs[0] = sc_msg_system(COMPACT_SYSTEM_PROMPT);
    msgs[1] = sc_msg_user(user_text);

    cJSON *options = cJSON_CreateObject();
    cJSON_AddNumberToObject(options, "max_tokens", COMPACT_MAX_TOKENS);
    cJSON_AddNumberToObject(options, "temperature", 0.2);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    sc_llm_response_t *resp = provider->chat(
        provider, msgs, 2, NULL, 0, model, options);
    cJSON_Delete(options);
    free(user_text);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double elapsed = (t1.tv_sec - t0.tv_sec)
                   + (t1.tv_nsec - t0.tv_nsec) / 1e9;

    if (!resp || !resp->content || !resp->content[0]) {
        SC_LOG_ERROR(TAG, "LLM returned empty response for compaction");
        if (resp) sc_llm_response_free(resp);
        sc_memory_free(mem);
        return -1;
    }

    size_t new_len = strlen(resp->content);
    SC_LOG_INFO(TAG, "Compacted %zu -> %zu bytes in %.1fs",
                len, new_len, elapsed);

    /* Only write if the result is actually shorter */
    int rc = 0;
    if (new_len < len) {
        rc = sc_memory_write_long_term(mem, resp->content);
        if (rc == 0)
            SC_LOG_INFO(TAG, "MEMORY.md updated (%.0f%% reduction)",
                        (1.0 - (double)new_len / (double)len) * 100.0);
        else
            SC_LOG_ERROR(TAG, "Failed to write compacted MEMORY.md");
    } else {
        SC_LOG_INFO(TAG, "Compacted result not smaller, keeping original");
    }

    sc_llm_response_free(resp);
    sc_memory_free(mem);
    return rc;
}
