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
#include "util/task.h"
#include <string.h>
#include <time.h>

#include "cJSON.h"
#include "constants.h"
#include "logger.h"
#include "context.h"
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
    /* Session-isolation routing (Phase 4): when isolated == 1 the
     * consolidation and post-compact reinjection use a namespaced
     * sc_memory_t and per-session scratchpad rather than the workspace
     * shared paths. namespace_id must be set when isolated == 1.
     * See docs/design/session-isolation-plan.md. */
    int isolated;
    char *namespace_id;          /* copied; non-NULL iff isolated == 1 */
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
    free(args->namespace_id);
    free(args->result_summary);
    free(args);
}

/* Keep only "- " bullet lines from the consolidation output. Local
 * models sometimes emit their reasoning monologue despite the
 * bullets-only instruction; none of that may reach memory. Returns a
 * malloc'd string of the bullet lines, or NULL if there are none. */
static char *filter_bullet_lines(const char *s)
{
    if (!s) return NULL;
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    int kept = 0;
    const char *p = s;
    while (*p) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        if (len >= 2 && p[0] == '-' && p[1] == ' ') {
            sc_strbuf_appendf(&sb, "%.*s\n", (int)len, p);
            kept++;
        }
        p += len + (eol ? 1 : 0);
    }
    char *out = sc_strbuf_finish(&sb);
    if (!kept) {
        free(out);
        return NULL;
    }
    return out;
}

static void do_consolidate(sc_summarize_args_t *args, const char *summary)
{
    if (!args->memory_consolidation) return;
    if (!summary || !summary[0]) return;

    sc_llm_message_t msgs[2];
    msgs[0] = sc_msg_system(
        "Extract durable facts worth remembering from this conversation summary. "
        "Output only bullet points (- fact). Include: user preferences, project decisions, "
        "recurring patterns, important names/dates. "
        "EXCLUDE per-run and per-task state: task descriptions, run IDs, "
        "runs/<id>/ workspace paths, repo checkouts, in-progress status — "
        "these go stale immediately and contaminate unrelated future tasks. "
        "EXCLUDE file paths and code structure (rediscoverable from the code). "
        "No commentary, no reasoning — bullets only. "
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

    char *bullets = NULL;
    if (resp && resp->content && resp->content[0] &&
        strncmp(resp->content, "NONE", 4) != 0)
        bullets = filter_bullet_lines(resp->content);
    if (bullets) {
        sc_memory_t *mem = (args->isolated && args->namespace_id)
            ? sc_memory_new_namespaced(args->workspace, args->namespace_id)
            : sc_memory_new(args->workspace);
        if (mem) {
            sc_strbuf_t sb;
            sc_strbuf_init(&sb);
            sc_strbuf_appendf(&sb, "\n### Auto-consolidated (%s)\n%s",
                              args->session_key, bullets);
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
    } else if (resp && resp->content && resp->content[0] &&
               strncmp(resp->content, "NONE", 4) != 0) {
        SC_LOG_WARN("agent",
            "Dropped consolidation output: no bullet lines (model emitted "
            "commentary instead)");
    }

    free(bullets);
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

    /* Retry summarization up to 3 times with backoff.
     * Summarization calls often fail due to rate limiting when the
     * main agent loop is making concurrent API calls. */
    sc_llm_response_t *resp = NULL;
    double sum_elapsed = 0;
    for (int attempt = 0; attempt < 3; attempt++) {
        if (attempt > 0) {
            int backoff_ms = 1000 * (1 << attempt);  /* 2s, 4s */
            SC_LOG_INFO("agent", "Summarization retry %d/%d (backoff %dms)",
                        attempt + 1, 3, backoff_ms);
            struct timespec ts = { .tv_sec = backoff_ms / 1000,
                                   .tv_nsec = (backoff_ms % 1000) * 1000000L };
            nanosleep(&ts, NULL);
        }

        clock_gettime(CLOCK_MONOTONIC, &sum_t0);
        resp = args->provider->chat(
            args->provider, msgs, 2, NULL, 0, args->model, options);
        clock_gettime(CLOCK_MONOTONIC, &sum_t1);
        sum_elapsed = (sum_t1.tv_sec - sum_t0.tv_sec)
                    + (sum_t1.tv_nsec - sum_t0.tv_nsec) / 1e9;

        if (resp && resp->content && resp->content[0])
            break;  /* success */

        SC_LOG_WARN("agent", "Summarization attempt %d failed after %.1fs%s",
                    attempt + 1, sum_elapsed,
                    (resp && resp->http_status) ?
                        (resp->http_status == 429 ? " (rate limited)" :
                         " (API error)") : " (no response)");
        if (resp) { sc_llm_response_free(resp); resp = NULL; }
    }

    cJSON_Delete(options);

    if (resp && resp->content && resp->content[0]) {
        SC_LOG_INFO("agent", "Session summarized successfully in %.1fs", sum_elapsed);
        char *redacted_summary = sc_redact_secrets(resp->content);
        args->result_summary = redacted_summary
            ? redacted_summary : sc_strdup(resp->content);
    } else {
        SC_LOG_WARN("agent", "Summarization failed after 3 attempts");
    }

    if (resp) sc_llm_response_free(resp);
    sc_llm_message_free_fields(&msgs[0]);
    sc_llm_message_free_fields(&msgs[1]);
    free(transcript_str);

    /* Consolidate using the summary we just produced */
    if (args->result_summary)
        do_consolidate(args, args->result_summary);
}

/* Task function for async summarization (sc_task_fn signature) */
static void *summarize_task_fn(void *arg, volatile atomic_int *cancel)
{
    (void)cancel;  /* LLM call is atomic, not cancellable mid-flight */
    sc_summarize_args_t *args = arg;
    do_summarize(args);
    return args;  /* result read by main thread */
}

/* Apply deferred summarization result from the task.
 * Called from main thread only. */
static void apply_summarize_result(sc_agent_t *agent)
{
    if (!agent->summarize_task) return;
    if (!sc_task_poll(agent->summarize_task)) return;

    sc_summarize_args_t *args = sc_task_join(agent->summarize_task, 0);
    sc_task_free(agent->summarize_task);
    agent->summarize_task = NULL;

    if (args && args->result_summary) {
        sc_session_set_summary(agent->sessions, args->session_key,
                               args->result_summary);
        sc_session_truncate(agent->sessions, args->session_key,
                            args->session_keep_last);
        sc_session_save(agent->sessions, args->session_key);
        agent->compact_consecutive_failures = 0;
    } else {
        agent->compact_consecutive_failures++;
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
    if (!agent->summarize_task) return;

    /* Block until the task completes (with 10s timeout) */
    sc_summarize_args_t *args = sc_task_join(agent->summarize_task, 10000);
    sc_task_free(agent->summarize_task);
    agent->summarize_task = NULL;

    if (args && args->result_summary) {
        sc_session_set_summary(agent->sessions, args->session_key,
                               args->result_summary);
        sc_session_truncate(agent->sessions, args->session_key,
                            args->session_keep_last);

        /* Post-compact re-injection: inject a boundary message with
         * refreshed context so the agent doesn't lose workspace awareness
         * after compaction drops old messages. */
        {
            sc_strbuf_t reinject;
            sc_strbuf_init(&reinject);
            sc_strbuf_append(&reinject,
                "[Session compacted. Key context re-injected below.]\n\n");

            /* Re-read long-term memory.
             * In isolated sessions sc_memory_read_long_term() returns NULL
             * (per design §6.2), so the "## Memory" block is skipped — the
             * delegate task's instructions and the per-session scratchpad
             * carry the relevant context instead. */
            sc_memory_t *mem = (args->isolated && args->namespace_id)
                ? sc_memory_new_namespaced(args->workspace, args->namespace_id)
                : sc_memory_new(args->workspace);
            if (mem) {
                char *memory = sc_memory_read_long_term(mem);
                if (memory && memory[0]) {
                    sc_strbuf_append(&reinject, "## Memory\n");
                    /* Cap at 2KB to avoid bloating the re-injection */
                    if (strlen(memory) > 2048) {
                        sc_strbuf_appendf(&reinject, "%.2048s\n[...truncated]\n", memory);
                    } else {
                        sc_strbuf_appendf(&reinject, "%s\n", memory);
                    }
                }
                free(memory);
                sc_memory_free(mem);
            }

            /* Re-read bootstrap files (AGENTS.md, SOUL.md) */
            if (agent->context_builder) {
                char *bootstrap = sc_context_load_bootstrap(agent->context_builder);
                if (bootstrap && bootstrap[0]) {
                    sc_strbuf_append(&reinject, "\n## Bootstrap Context\n");
                    if (strlen(bootstrap) > 2048)
                        sc_strbuf_appendf(&reinject, "%.2048s\n[...truncated]\n", bootstrap);
                    else
                        sc_strbuf_appendf(&reinject, "%s\n", bootstrap);
                }
                free(bootstrap);
            }

            /* Re-read scratchpad (working notes that survive compaction).
             * In isolated sessions use the per-session scratchpad path so
             * one delegate's notes never re-inject into another's compaction. */
            if (args->workspace) {
                char sp_path[1024];
                if (args->isolated && args->namespace_id) {
                    snprintf(sp_path, sizeof(sp_path),
                             "%s/memory/_sessions/%s/scratchpad.md",
                             args->workspace, args->namespace_id);
                } else {
                    snprintf(sp_path, sizeof(sp_path),
                             "%s/state/scratchpad.md", args->workspace);
                }
                FILE *sp_f = fopen(sp_path, "r");
                if (sp_f) {
                    fseek(sp_f, 0, SEEK_END);
                    long sp_sz = ftell(sp_f);
                    if (sp_sz > 0 && sp_sz < 4096) {
                        fseek(sp_f, 0, SEEK_SET);
                        char *sp = malloc(sp_sz + 1);
                        if (sp) {
                            size_t n = fread(sp, 1, sp_sz, sp_f);
                            sp[n] = '\0';
                            sc_strbuf_append(&reinject,
                                "\n## Working Notes (Scratchpad)\n");
                            sc_strbuf_appendf(&reinject, "%s\n", sp);
                            free(sp);
                        }
                    }
                    fclose(sp_f);
                }
            }

            char *reinject_text = sc_strbuf_finish(&reinject);
            if (reinject_text && reinject_text[0]) {
                sc_llm_message_t boundary = sc_msg_user(reinject_text);
                sc_session_add_full_message(agent->sessions,
                                             args->session_key, &boundary);
                sc_llm_message_free_fields(&boundary);
                SC_LOG_INFO("agent", "Post-compact re-injection: %zu bytes",
                            strlen(reinject_text));
            }
            free(reinject_text);
        }

        sc_session_save(agent->sessions, args->session_key);
        agent->compact_consecutive_failures = 0;
    } else {
        agent->compact_consecutive_failures++;
        SC_LOG_WARN("agent", "Compaction failed (%d consecutive)",
                    agent->compact_consecutive_failures);
    }

    free_summarize_args(args);
}

/* Score message information density for smart chunking.
 * Higher score = more important to include in summarization transcript. */
static int score_msg_density(const sc_llm_message_t *msg)
{
    if (!msg->content || !msg->role) return 0;
    if (strcmp(msg->role, "system") == 0) return 0;

    int len = (int)strlen(msg->content);
    if (len < 10) return 1;

    /* Base: content length capped to avoid long outputs dominating */
    int score = len > 500 ? 500 : len;

    /* Role weights: user intent and tool results carry more information */
    if (strcmp(msg->role, "user") == 0)
        score = score * 3 / 2;
    else if (msg->tool_call_count > 0)
        score = score * 5 / 4;
    else if (msg->tool_call_id)
        score = score * 4 / 3;

    /* Pattern bonuses for high-information content */
    if (strstr(msg->content, "```")) score += 100;
    if (strstr(msg->content, "rror")) score += 50;

    return score;
}

void sc_maybe_summarize(sc_agent_t *agent, const char *session_key,
                        int isolated, const char *namespace_id)
{
    /* Drain previous summarization thread if still active */
    apply_summarize_result(agent);

    /* Defensive: isolated requires a namespace_id. If callers set
     * isolated=1 without an id, fall back to shared so consolidation
     * doesn't write nowhere. */
    if (isolated && (!namespace_id || !namespace_id[0])) {
        SC_LOG_WARN("agent",
            "sc_maybe_summarize called with isolated=1 but no namespace_id; "
            "falling back to shared memory");
        isolated = 0;
    }

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

    /* Smart chunking: score messages by density and select the most
     * informative ones within the transcript budget */
    int *scores = calloc((size_t)discard_count, sizeof(int));
    int *selected = calloc((size_t)discard_count, sizeof(int));
    if (!scores || !selected) {
        free(scores);
        free(selected);
        /* Fall through to empty transcript — summarization will handle it */
        goto build_done;
    }

    for (int i = 0; i < discard_count; i++)
        scores[i] = score_msg_density(&history[i]);

    /* Greedily select highest-scored messages until budget is filled */
    {
        int budget = agent->summary_max_transcript - (int)transcript.len;
        for (;;) {
            int best = -1;
            for (int i = 0; i < discard_count; i++) {
                if (!selected[i] && scores[i] > 0 &&
                    (best < 0 || scores[i] > scores[best]))
                    best = i;
            }
            if (best < 0) break;
            int cost;
            if (history[best].tool_call_id) {
                /* Tool results are compressed to ~80 bytes in transcript */
                cost = 80;
            } else {
                cost = (int)strlen(history[best].content ? history[best].content : "") + 30;
            }
            if (cost > budget) { scores[best] = 0; continue; }
            selected[best] = 1;
            budget -= cost;
            scores[best] = 0;
            if (budget <= 0) break;
        }
    }

    /* Build transcript from selected messages in chronological order.
     * Action-only compaction: preserve full tool-call descriptions but
     * compress tool-result content to metadata (tool name, status, size).
     * This helps the summarizer capture *what the agent did* without
     * wasting budget on verbose tool output (e.g. 48KB file reads). */
    for (int i = 0; i < discard_count; i++) {
        if (!selected[i]) continue;

        const char *role = history[i].role;
        if (!role || strcmp(role, "system") == 0) continue;

        if (history[i].tool_call_id) {
            /* Tool result: compress to metadata only */
            const char *content = history[i].content ? history[i].content : "";
            int content_len = (int)strlen(content);
            int line_count = 1;
            for (const char *p = content; *p; p++)
                if (*p == '\n') line_count++;

            /* Extract tool name from XML wrapper if present */
            const char *tool_name = "unknown";
            char tn_buf[64];
            const char *tn = strstr(content, "tool=\"");
            if (tn) {
                tn += 6;
                const char *tn_end = strchr(tn, '"');
                if (tn_end && (tn_end - tn) < (int)sizeof(tn_buf)) {
                    memcpy(tn_buf, tn, (size_t)(tn_end - tn));
                    tn_buf[tn_end - tn] = '\0';
                    tool_name = tn_buf;
                }
            }

            int is_error = (strstr(content, "ERROR") || strstr(content, "error:")
                            || strstr(content, "failed"));

            sc_strbuf_appendf(&transcript,
                "[tool_result: %s -> %s, %d bytes, %d lines]\n",
                tool_name, is_error ? "ERROR" : "ok",
                content_len, line_count);

        } else if (history[i].tool_call_count > 0) {
            /* Assistant with tool calls: list each call with name + args */
            if (history[i].content && history[i].content[0])
                sc_strbuf_appendf(&transcript, "[assistant] %s\n",
                                  history[i].content);

            for (int j = 0; j < history[i].tool_call_count; j++) {
                sc_tool_call_t *tc = &history[i].tool_calls[j];
                char *args_str = tc->arguments
                    ? cJSON_PrintUnformatted(tc->arguments) : NULL;
                /* Truncate large args (e.g. write_file content).
                 * Find a safe cut point that doesn't split UTF-8. */
                if (args_str && strlen(args_str) > 200) {
                    int cut = 197;
                    /* Back up past any UTF-8 continuation bytes (10xxxxxx) */
                    while (cut > 0 && (args_str[cut] & 0xC0) == 0x80)
                        cut--;
                    args_str[cut++] = '.';
                    args_str[cut++] = '.';
                    args_str[cut++] = '.';
                    args_str[cut] = '\0';
                }
                sc_strbuf_appendf(&transcript, "[tool_call: %s(%s)]\n",
                    tc->name ? tc->name : "?",
                    args_str ? args_str : "{}");
                free(args_str);
            }

        } else {
            /* Regular user or assistant message */
            const char *content = history[i].content;
            if (!content) content = "";
            sc_strbuf_appendf(&transcript, "[%s] %s\n", role, content);
        }
    }

    free(scores);
    free(selected);
build_done:
    (void)0;

    char *transcript_str = sc_strbuf_finish(&transcript);

    /* Pack args with snapshots of everything the thread needs */
    sc_summarize_args_t *args = calloc(1, sizeof(*args));
    if (!args) {
        free(transcript_str);
        return;
    }

    args->session_key = sc_strdup(session_key);
    args->transcript = transcript_str;
    args->model = sc_strdup(agent->summary_model
        ? agent->summary_model : agent->model);
    args->workspace = sc_strdup(agent->workspace);
    args->session_keep_last = agent->session_keep_last;
    args->memory_consolidation = agent->memory_consolidation;
    args->summary_max_transcript = agent->summary_max_transcript;
    args->context_window = agent->context_window;
    args->isolated = isolated;
    args->namespace_id = isolated ? sc_strdup(namespace_id) : NULL;

    /* Clone provider for thread isolation */
    if (agent->provider->clone) {
        args->provider = agent->provider->clone(agent->provider);
    }

    if (!args->provider) {
        SC_LOG_WARN("agent", "Provider clone unavailable, summarizing synchronously");
        summarize_sync(agent, args);
        return;
    }

    /* Launch summarization task */
    agent->summarize_task = sc_task_spawn(summarize_task_fn, args);
    if (!agent->summarize_task) {
        SC_LOG_WARN("agent", "Failed to spawn summarization task, running synchronously");
        summarize_sync(agent, args);
        return;
    }

    SC_LOG_DEBUG("agent", "Summarization task spawned for session %s", session_key);
}
