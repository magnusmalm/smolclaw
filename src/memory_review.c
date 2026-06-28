/*
 * memory_review.c — Post-turn memory review (task 4.13, opt-in)
 *
 * Mirrors the summary-time consolidation path but runs after a single
 * successful turn: a compact digest (user message + final response) is sent to
 * an LLM that proposes 0-2 durable memory entries, which are written via the
 * normal memory path. Runs on the agent's provider (optionally a cheaper
 * model), in a background sc_task_t.
 */

#include <stdlib.h>
#include <string.h>

#include "memory_review.h"
#include "agent.h"
#include "memory.h"
#include "providers/types.h"
#include "util/task.h"
#include "util/str.h"
#include "util/secrets.h"
#include "util/prompt_guard.h"
#include "logger.h"
#include "cJSON.h"

#define REVIEW_MAX_ENTRIES   2
#define REVIEW_MAX_TOKENS    256
#define REVIEW_DIGEST_CHARS  4000

/* ---- pure helpers ---------------------------------------------------- */

int sc_memory_review_should_run(int turn_succeeded, int enabled)
{
    return turn_succeeded && enabled ? 1 : 0;
}

/* Strip a leading ```json / ``` fence and trailing ``` if present. Returns a
 * pointer into `s` (start) and writes the usable length to *len. */
static const char *strip_fence(const char *s, size_t *len)
{
    while (*s == ' ' || *s == '\n' || *s == '\r' || *s == '\t') s++;
    if (strncmp(s, "```", 3) == 0) {
        s += 3;
        if (strncmp(s, "json", 4) == 0) s += 4;
        while (*s == ' ' || *s == '\n' || *s == '\r' || *s == '\t') s++;
    }
    size_t n = strlen(s);
    /* Trim a trailing fence. */
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\n' ||
                     s[n - 1] == '\r' || s[n - 1] == '\t')) n--;
    if (n >= 3 && strncmp(s + n - 3, "```", 3) == 0) n -= 3;
    *len = n;
    return s;
}

char **sc_memory_review_parse(const char *llm_content, int max, int *count)
{
    if (count) *count = 0;
    if (!llm_content || max <= 0) return NULL;

    size_t len = 0;
    const char *body = strip_fence(llm_content, &len);
    if (len == 0) return NULL;

    char *buf = malloc(len + 1);
    if (!buf) return NULL;
    memcpy(buf, body, len);
    buf[len] = '\0';

    cJSON *arr = cJSON_Parse(buf);
    free(buf);
    if (!arr || !cJSON_IsArray(arr)) {
        cJSON_Delete(arr);
        return NULL;
    }

    char **out = calloc((size_t)max, sizeof(char *));
    if (!out) { cJSON_Delete(arr); return NULL; }

    int n = 0;
    cJSON *item = NULL;
    cJSON_ArrayForEach(item, arr) {
        if (n >= max) break;
        if (!cJSON_IsString(item) || !item->valuestring) continue;
        /* Skip empty / whitespace-only entries. */
        const char *v = item->valuestring;
        while (*v == ' ' || *v == '\n' || *v == '\t' || *v == '\r') v++;
        if (!*v) continue;
        out[n] = sc_strdup(item->valuestring);
        if (out[n]) n++;
    }
    cJSON_Delete(arr);

    if (n == 0) { free(out); return NULL; }
    if (count) *count = n;
    return out;
}

void sc_memory_review_entries_free(char **entries, int count)
{
    if (!entries) return;
    for (int i = 0; i < count; i++) free(entries[i]);
    free(entries);
}

/* ---- async worker ---------------------------------------------------- */

typedef struct {
    sc_provider_t *provider;   /* cloned for the thread (owned) */
    char *model;               /* copied */
    char *workspace;           /* copied */
    char *digest;              /* owned */
    int notifications;
} review_args_t;

static void review_args_free(review_args_t *a)
{
    if (!a) return;
    if (a->provider && a->provider->destroy) a->provider->destroy(a->provider);
    free(a->model);
    free(a->workspace);
    free(a->digest);
    free(a);
}

static void *review_task_fn(void *arg, volatile atomic_int *cancel)
{
    review_args_t *a = arg;
    if (cancel && atomic_load(cancel)) { review_args_free(a); return NULL; }

    sc_llm_message_t msgs[2];
    msgs[0] = sc_msg_system(
        "You review one completed assistant turn and extract durable facts worth "
        "remembering long-term (user preferences, stable project facts, decisions). "
        "Propose AT MOST 2 entries. EXCLUDE transient state, file paths, and "
        "anything rediscoverable from code. Respond with ONLY a JSON array of "
        "short strings, e.g. [\"fact one\",\"fact two\"]. If nothing is worth "
        "saving, respond with exactly: []");
    msgs[1] = sc_msg_user(a->digest);

    cJSON *options = cJSON_CreateObject();
    cJSON_AddNumberToObject(options, "max_tokens", REVIEW_MAX_TOKENS);
    cJSON_AddNumberToObject(options, "temperature", 0.2);

    sc_llm_response_t *resp = a->provider->chat(
        a->provider, msgs, 2, NULL, 0, a->model, options);
    cJSON_Delete(options);
    sc_llm_message_free_fields(&msgs[0]);
    sc_llm_message_free_fields(&msgs[1]);

    if (cancel && atomic_load(cancel)) {
        if (resp) sc_llm_response_free(resp);
        review_args_free(a);
        return NULL;
    }

    int n = 0;
    char **entries = (resp && resp->content)
        ? sc_memory_review_parse(resp->content, REVIEW_MAX_ENTRIES, &n) : NULL;
    if (resp) sc_llm_response_free(resp);

    if (entries && n > 0) {
        sc_memory_t *mem = sc_memory_new(a->workspace);
        if (mem) {
            for (int i = 0; i < n; i++) {
                char *clean = sc_redact_secrets(entries[i]);
                const char *txt = clean ? clean : entries[i];
                /* Defense-in-depth: never write LLM-proposed text that trips the
                 * high-confidence prompt-injection guard (same as consolidation). */
                if (sc_prompt_guard_scan_high(txt)) {
                    SC_LOG_WARN("memory_review",
                        "skipped proposed entry (injection pattern)");
                } else if (sc_memory_append_long_term(mem, txt) == 0 &&
                           a->notifications >= 1) {
                    if (a->notifications >= 2)
                        SC_LOG_INFO("memory_review", "added memory: %s", txt);
                    else
                        SC_LOG_INFO("memory_review", "added 1 memory entry");
                }
                free(clean);
            }
            sc_memory_free(mem);
        }
    }
    sc_memory_review_entries_free(entries, n);

    review_args_free(a);
    return NULL;
}

/* ---- spawn / reap (main thread) -------------------------------------- */

void sc_memory_review_reap(sc_agent_t *agent)
{
    if (!agent || !agent->review_task) return;
    if (!sc_task_poll(agent->review_task)) return;  /* still running */
    sc_task_join(agent->review_task, 0);
    sc_task_free(agent->review_task);
    agent->review_task = NULL;
}

void sc_memory_review_maybe_spawn(sc_agent_t *agent, const char *user_msg,
                                  const char *final_response)
{
    if (!agent) return;
    sc_memory_review_reap(agent);  /* clear any finished prior review */

    if (!sc_memory_review_should_run(1, agent->memory_background_review))
        return;
    if (agent->review_task) return;   /* one in flight already */
    if (!user_msg || !user_msg[0] || !final_response || !final_response[0])
        return;
    if (!agent->provider || !agent->provider->clone) return;

    /* Build a compact digest (bounded). */
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    char *u = sc_truncate(user_msg, REVIEW_DIGEST_CHARS / 2);
    char *r = sc_truncate(final_response, REVIEW_DIGEST_CHARS / 2);
    sc_strbuf_appendf(&sb, "User asked:\n%s\n\nAssistant replied:\n%s\n",
                      u ? u : "", r ? r : "");
    free(u); free(r);

    review_args_t *a = calloc(1, sizeof(*a));
    if (!a) { sc_strbuf_free(&sb); return; }
    a->digest = sc_strbuf_finish(&sb);
    a->workspace = sc_strdup(agent->workspace);
    a->model = sc_strdup(agent->memory_review_model
        ? agent->memory_review_model
        : (agent->summary_model ? agent->summary_model : agent->model));
    a->notifications = agent->memory_notifications;
    a->provider = agent->provider->clone(agent->provider);

    if (!a->provider || !a->workspace || !a->digest) {
        review_args_free(a);
        return;
    }

    agent->review_task = sc_task_spawn(review_task_fn, a);
    if (!agent->review_task) {
        review_args_free(a);
        return;
    }
    SC_LOG_DEBUG("memory_review", "post-turn review spawned");
}
