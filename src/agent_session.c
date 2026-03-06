/*
 * agent_session.c - Session summarization and memory consolidation
 *
 * Extracted from agent.c (M-15) to reduce God Object complexity.
 * Summarization runs on a detached worker thread (L-15) to avoid
 * blocking the agent loop during synchronous LLM calls.
 *
 * Thread safety (C-1, C-2, H-1, H-2): The worker thread receives a
 * cloned provider and copied data — it never touches agent state.
 * Results are deferred to main thread via apply_summarize_result().
 */

#include "agent_internal.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cJSON.h"
#include "constants.h"
#include "logger.h"
#include "session.h"
#include "memory.h"
#include "util/str.h"
#include "util/secrets.h"
#include "util/prompt_guard.h"

/* Arguments passed to the summarization worker thread */
typedef struct {
    sc_provider_t *provider;     /* cloned provider for thread use (owned) */
    char *model;                 /* copied */
    char *workspace;             /* copied */
    char *session_key;           /* copied */
    char *transcript;            /* owned, built before launch */
    char *existing_summary;      /* copied from session before launch */
    int session_keep_last;
    int memory_consolidation;
    int summary_max_transcript;
    int context_window;
    /* Result — written by thread, read by main thread after join */
    char *result_summary;        /* NULL if summarization failed */
} sc_summarize_args_t;

static void free_summarize_args(sc_summarize_args_t *args)
{
    if (!args) return;
    if (args->provider && args->provider->destroy)
        args->provider->destroy(args->provider);
    free(args->model);
    free(args->workspace);
    free(args->session_key);
    free(args->transcript);
    free(args->existing_summary);
    free(args->result_summary);
    free(args);
}

static void do_consolidate(sc_summarize_args_t *args, const char *summary)
{
    if (!args->memory_consolidation) return;
    if (!summary || !summary[0]) return;

    sc_llm_message_t msgs[2];
    msgs[0] = sc_msg_system(
        "Extract durable facts worth remembering from this conversation summary. "
        "Output only bullet points (- fact). Include: user preferences, project decisions, "
        "key file paths, recurring patterns, important names/dates. "
        "If nothing is worth remembering long-term, output exactly: NONE");
    msgs[1] = sc_msg_user(summary);

    cJSON *options = cJSON_CreateObject();
    cJSON_AddNumberToObject(options, "max_tokens", SC_CONSOLIDATION_MAX_TOKENS);
    cJSON_AddNumberToObject(options, "temperature", 0.3);

    SC_LOG_INFO("agent", "Calling LLM for memory consolidation...");
    struct timespec con_t0, con_t1;
    clock_gettime(CLOCK_MONOTONIC, &con_t0);

    sc_llm_response_t *resp = args->provider->chat(
        args->provider, msgs, 2, NULL, 0, args->model, options);
    cJSON_Delete(options);

    clock_gettime(CLOCK_MONOTONIC, &con_t1);
    double con_elapsed = (con_t1.tv_sec - con_t0.tv_sec)
                       + (con_t1.tv_nsec - con_t0.tv_nsec) / 1e9;

    if (resp && resp->content && resp->content[0] &&
        strncmp(resp->content, "NONE", 4) != 0) {
        sc_memory_t *mem = sc_memory_new(args->workspace);
        if (mem) {
            sc_strbuf_t sb;
            sc_strbuf_init(&sb);
            sc_strbuf_appendf(&sb, "\n### Auto-consolidated (%s)\n%s",
                              args->session_key, resp->content);
            char *entry = sc_strbuf_finish(&sb);
            char *redacted = sc_redact_secrets(entry);
            const char *to_write = redacted ? redacted : entry;

            if (sc_prompt_guard_scan_high(to_write)) {
                SC_LOG_WARN("agent",
                    "Blocked consolidation: injection pattern in LLM output");
            } else {
                sc_memory_append_today(mem, to_write);
                SC_LOG_INFO("agent",
                    "Consolidated memory from session %s in %.1fs",
                    args->session_key, con_elapsed);
            }
            free(redacted);
            free(entry);
            sc_memory_free(mem);
        }
    }

    if (resp) sc_llm_response_free(resp);
    sc_llm_message_free_fields(&msgs[0]);
    sc_llm_message_free_fields(&msgs[1]);
}

static void do_summarize(sc_summarize_args_t *args)
{
    char *transcript_str = args->transcript;
    args->transcript = NULL;  /* take ownership */

    char *redacted_transcript = sc_redact_secrets(transcript_str);
    if (redacted_transcript) {
        free(transcript_str);
        transcript_str = redacted_transcript;
    }

    sc_llm_message_t msgs[2];
    msgs[0] = sc_msg_system(
        "Summarize the following conversation concisely. Capture key topics, "
        "decisions made, files modified, and important context for continuity. "
        "Keep under 200 words.");
    msgs[1] = sc_msg_user(transcript_str);

    cJSON *options = cJSON_CreateObject();
    cJSON_AddNumberToObject(options, "max_tokens", SC_SUMMARY_MAX_TOKENS);
    cJSON_AddNumberToObject(options, "temperature", 0.3);

    SC_LOG_INFO("agent", "Calling LLM for session summarization...");
    struct timespec sum_t0, sum_t1;
    clock_gettime(CLOCK_MONOTONIC, &sum_t0);

    sc_llm_response_t *resp = args->provider->chat(
        args->provider, msgs, 2, NULL, 0, args->model, options);

    cJSON_Delete(options);

    clock_gettime(CLOCK_MONOTONIC, &sum_t1);
    double sum_elapsed = (sum_t1.tv_sec - sum_t0.tv_sec)
                       + (sum_t1.tv_nsec - sum_t0.tv_nsec) / 1e9;

    if (resp && resp->content && resp->content[0]) {
        SC_LOG_INFO("agent", "Session summarized successfully in %.1fs", sum_elapsed);
        char *redacted_summary = sc_redact_secrets(resp->content);
        args->result_summary = redacted_summary
            ? redacted_summary : sc_strdup(resp->content);
    } else {
        SC_LOG_WARN("agent", "Summarization LLM call failed after %.1fs",
                    sum_elapsed);
    }

    if (resp) sc_llm_response_free(resp);
    sc_llm_message_free_fields(&msgs[0]);
    sc_llm_message_free_fields(&msgs[1]);
    free(transcript_str);

    /* Consolidate using the summary we just produced */
    if (args->result_summary)
        do_consolidate(args, args->result_summary);
}

/* Worker thread function for async summarization */
static void *summarize_thread_fn(void *arg)
{
    sc_summarize_args_t *args = arg;
    do_summarize(args);
    /* args stays alive — main thread reads result_summary and frees */
    return NULL;
}

/* Apply deferred summarization result from the worker thread.
 * Called from main thread only. */
static void apply_summarize_result(sc_agent_t *agent)
{
    if (!atomic_load(&agent->summarize_thread_active)) return;
    pthread_join(agent->summarize_thread, NULL);
    atomic_store(&agent->summarize_thread_active, 0);

    sc_summarize_args_t *args = agent->summarize_pending_args;
    agent->summarize_pending_args = NULL;

    if (args && args->result_summary) {
        sc_session_set_summary(agent->sessions, args->session_key,
                               args->result_summary);
        sc_session_truncate(agent->sessions, args->session_key,
                            args->session_keep_last);
        sc_session_save(agent->sessions, args->session_key);
    }

    free_summarize_args(args);
}

/* Synchronous fallback when provider clone isn't available */
static void summarize_sync(sc_agent_t *agent, sc_summarize_args_t *args)
{
    /* Use agent's provider directly (safe — we're on the main thread) */
    args->provider = agent->provider;
    do_summarize(args);

    if (args->result_summary) {
        sc_session_set_summary(agent->sessions, args->session_key,
                               args->result_summary);
        sc_session_truncate(agent->sessions, args->session_key,
                            args->session_keep_last);
        sc_session_save(agent->sessions, args->session_key);
    }

    /* Don't destroy agent's provider */
    args->provider = NULL;
    free_summarize_args(args);
}

void sc_drain_summarize(sc_agent_t *agent)
{
    apply_summarize_result(agent);
}

void sc_maybe_summarize(sc_agent_t *agent, const char *session_key)
{
    /* Drain previous summarization thread if still active */
    apply_summarize_result(agent);

    int count = 0;
    sc_llm_message_t *history = sc_session_get_history(agent->sessions,
                                                        session_key, &count);

    if (count <= agent->session_summary_threshold)
        return;

    SC_LOG_INFO("agent", "Session %s has %d messages, scheduling async summarization",
                session_key, count);

    /* Build transcript while we still have the history */
    int discard_count = count - agent->session_keep_last;
    sc_strbuf_t transcript;
    sc_strbuf_init(&transcript);

    const char *existing_summary = sc_session_get_summary(agent->sessions,
                                                           session_key);
    if (existing_summary && existing_summary[0]) {
        sc_strbuf_appendf(&transcript, "Previous summary: %s\n\n", existing_summary);
    }

    for (int i = 0; i < discard_count; i++) {
        const char *role = history[i].role;
        if (!role || strcmp(role, "system") == 0)
            continue;

        const char *label = role;
        if (history[i].tool_call_id) {
            label = "tool_result";
        } else if (history[i].tool_call_count > 0) {
            label = "assistant (tool_use)";
        }

        const char *content = history[i].content;
        if (!content) content = "";

        sc_strbuf_appendf(&transcript, "[%s] %s\n", label, content);

        if ((int)transcript.len >= agent->summary_max_transcript) {
            sc_strbuf_append(&transcript, "\n[...truncated...]");
            break;
        }
    }

    char *transcript_str = sc_strbuf_finish(&transcript);

    /* Pack args with snapshots of everything the thread needs */
    sc_summarize_args_t *args = calloc(1, sizeof(*args));
    if (!args) {
        free(transcript_str);
        return;
    }

    args->session_key = sc_strdup(session_key);
    args->transcript = transcript_str;
    args->model = sc_strdup(agent->model);
    args->workspace = sc_strdup(agent->workspace);
    args->session_keep_last = agent->session_keep_last;
    args->memory_consolidation = agent->memory_consolidation;
    args->summary_max_transcript = agent->summary_max_transcript;
    args->context_window = agent->context_window;

    /* Clone provider for thread isolation */
    if (agent->provider->clone) {
        args->provider = agent->provider->clone(agent->provider);
    }

    if (!args->provider) {
        SC_LOG_WARN("agent", "Provider clone unavailable, summarizing synchronously");
        summarize_sync(agent, args);
        return;
    }

    /* Launch worker thread */
    agent->summarize_pending_args = args;

    if (pthread_create(&agent->summarize_thread, NULL,
                        summarize_thread_fn, args) != 0) {
        SC_LOG_WARN("agent", "Failed to create summarization thread, running synchronously");
        agent->summarize_pending_args = NULL;
        summarize_sync(agent, args);
        return;
    }

    atomic_store(&agent->summarize_thread_active, 1);
    SC_LOG_DEBUG("agent", "Summarization thread launched for session %s", session_key);
}
