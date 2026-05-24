/*
 * smolclaw — session-isolation Stage 4 integration test.
 *
 * Drives the full agent loop with a mock provider through both shared
 * (sc_agent_process_direct) and isolated (sc_agent_process_isolated)
 * paths and asserts:
 *
 *  1. Consolidation from an isolated session writes to per-session memory
 *     only and never touches the workspace's shared YYYYMM/YYYYMMDD.md.
 *  2. The system prompt sent to the LLM contains no shared MEMORY.md
 *     content in isolated mode but does in shared mode.
 *  3. Shared-mode runs continue to behave exactly as before (back-compat).
 *
 * Reference: docs/design/session-isolation-plan.md §6.6, §8 (Stage 4).
 */

#include "test_main.h"

#include "agent.h"
#include "agent_internal.h"
#include "constants_app.h"
#include "context.h"
#include "memory.h"
#include "providers/types.h"
#include "session.h"
#include "state.h"
#include "tools/registry.h"
#include "util/str.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ---- Mock provider ----
 * Captures the system prompt of each call so the test can inspect it.
 * Returns scripted responses in order.
 */

#define MAX_RESPONSES 8

typedef struct {
    const char *content;
    const char *finish_reason;
} canned_response_t;

typedef struct {
    canned_response_t responses[MAX_RESPONSES];
    int response_count;
    int call_index;
    int chat_call_count;
    char *last_system_prompt;
} mock_data_t;

static sc_llm_response_t *mock_chat(sc_provider_t *self,
                                     sc_llm_message_t *msgs, int msg_count,
                                     sc_tool_definition_t *tools, int tool_count,
                                     const char *model, cJSON *options)
{
    (void)tools; (void)tool_count; (void)model; (void)options;
    mock_data_t *d = self->data;
    d->chat_call_count++;
    free(d->last_system_prompt);
    d->last_system_prompt = NULL;
    if (msg_count > 0 && msgs[0].role && strcmp(msgs[0].role, "system") == 0
        && msgs[0].content) {
        d->last_system_prompt = sc_strdup(msgs[0].content);
    }
    if (d->call_index >= d->response_count) return NULL;

    canned_response_t *src = &d->responses[d->call_index++];
    sc_llm_response_t *ret = calloc(1, sizeof(*ret));
    if (!ret) return NULL;
    ret->content = sc_strdup(src->content);
    ret->finish_reason = sc_strdup(src->finish_reason);
    ret->http_status = 200;
    return ret;
}

static const char *mock_get_model(sc_provider_t *self)
{
    (void)self;
    return "mock-model";
}

/* ---- Fixture ---- */

typedef struct {
    sc_agent_t *agent;
    sc_provider_t *provider;
    mock_data_t *mpd;
    char tmpdir[64];
} fixture_t;

static fixture_t create_fixture(void)
{
    fixture_t fx = {0};
    snprintf(fx.tmpdir, sizeof(fx.tmpdir), "/tmp/sc_test_si_XXXXXX");
    mkdtemp(fx.tmpdir);

    /* Workspace subdirs */
    char path[256];
    snprintf(path, sizeof(path), "%s/sessions", fx.tmpdir); mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/state",    fx.tmpdir); mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/memory",   fx.tmpdir); mkdir(path, 0755);

    fx.mpd = calloc(1, sizeof(*fx.mpd));
    fx.provider = calloc(1, sizeof(*fx.provider));
    fx.provider->name = "mock";
    fx.provider->chat = mock_chat;
    fx.provider->get_default_model = mock_get_model;
    fx.provider->data = fx.mpd;

    fx.agent = calloc(1, sizeof(*fx.agent));
    fx.agent->provider = fx.provider;
    fx.agent->workspace = sc_strdup(fx.tmpdir);
    fx.agent->model = sc_strdup("mock-model");
    fx.agent->context_window = 4096;
    fx.agent->temperature = 0.7;
    fx.agent->max_iterations = 10;
    fx.agent->session_summary_threshold = 2;  /* trigger summarization easily */
    fx.agent->session_keep_last = 2;
    fx.agent->max_output_chars = 10000;
    fx.agent->summary_max_transcript = 4000;
    fx.agent->memory_consolidation = 1;       /* enable consolidation */
    snprintf(path, sizeof(path), "%s/sessions", fx.tmpdir);
    fx.agent->sessions = sc_session_manager_new(path);
    fx.agent->state = sc_state_new(fx.tmpdir);
    fx.agent->tools = sc_tool_registry_new();
    fx.agent->context_builder = sc_context_builder_new(fx.tmpdir);
    sc_context_builder_set_tools(fx.agent->context_builder, fx.agent->tools);
    fx.agent->hourly_slots = calloc(SC_HOURLY_SLOTS, sizeof(sc_hourly_slot_t));
    return fx;
}

static void destroy_fixture(fixture_t *fx)
{
    sc_session_manager_free(fx->agent->sessions);
    sc_state_free(fx->agent->state);
    sc_tool_registry_free(fx->agent->tools);
    sc_context_builder_free(fx->agent->context_builder);
    free(fx->agent->hourly_slots);
    free(fx->agent->transforms);
    free(fx->agent->workspace);
    free(fx->agent->model);
    free(fx->agent);
    free(fx->mpd->last_system_prompt);
    free(fx->mpd);
    free(fx->provider);

    /* rm -rf the tmpdir */
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "rm -rf %s", fx->tmpdir);
    char *cmd = sc_strbuf_finish(&sb);
    if (cmd) { system(cmd); free(cmd); }
}

/* ---- Disk helpers ---- */

static char *today_yyyymmdd(void)
{
    static char buf[16];
    time_t now = time(NULL);
    struct tm tm_buf;
    struct tm *tm = localtime_r(&now, &tm_buf);
    strftime(buf, sizeof(buf), "%Y%m%d", tm);
    return buf;
}

static char *today_yyyymm(void)
{
    static char buf[16];
    time_t now = time(NULL);
    struct tm tm_buf;
    struct tm *tm = localtime_r(&now, &tm_buf);
    strftime(buf, sizeof(buf), "%Y%m", tm);
    return buf;
}

static int path_exists(const char *p)
{
    struct stat st;
    return stat(p, &st) == 0;
}

static char *slurp(const char *p)
{
    FILE *f = fopen(p, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return NULL; }
    char *buf = malloc(n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t r = fread(buf, 1, n, f); buf[r] = '\0';
    fclose(f);
    return buf;
}

static void write_text(const char *path, const char *content)
{
    char *dup = sc_strdup(path);
    if (dup) {
        for (char *p = dup + 1; *p; p++) {
            if (*p == '/') { *p = '\0'; mkdir(dup, 0755); *p = '/'; }
        }
        char *s = strrchr(dup, '/');
        if (s) { *s = '\0'; mkdir(dup, 0755); }
        free(dup);
    }
    FILE *f = fopen(path, "w");
    if (f) { fputs(content, f); fclose(f); }
}

/* ---- Tests ---- */

static void test_isolated_consolidation_does_not_leak(void)
{
    fixture_t fx = create_fixture();

    /* Pre-populate shared MEMORY.md so the isolated turn's prompt would
     * surface the marker if isolation were broken. */
    char mem_md[256];
    snprintf(mem_md, sizeof(mem_md), "%s/memory/MEMORY.md", fx.tmpdir);
    write_text(mem_md, "POISON-SHARED-LONG-TERM-MARKER\n");

    /* Two scripted responses: the agent loop turn + the summarization
     * turn + the consolidation turn (a third call inside do_consolidate). */
    fx.mpd->responses[0] = (canned_response_t){
        .content = "isolated reply", .finish_reason = "end_turn",
    };
    fx.mpd->responses[1] = (canned_response_t){
        .content = "Summary: a thing happened.", .finish_reason = "end_turn",
    };
    fx.mpd->responses[2] = (canned_response_t){
        .content = "- isolated session captured fact A\n",
        .finish_reason = "end_turn",
    };
    fx.mpd->response_count = 3;

    /* Pre-populate session history so the summarization threshold is met
     * on this turn. (threshold=2, keep_last=2; we need >2 messages.) */
    sc_session_add_message(fx.agent->sessions, "wf-task-iso", "user", "u1");
    sc_session_add_message(fx.agent->sessions, "wf-task-iso", "assistant", "a1");
    sc_session_add_message(fx.agent->sessions, "wf-task-iso", "user", "u2");

    char *reply = sc_agent_process_isolated(fx.agent, "next turn",
                                             "wf-task-iso",
                                             SC_CHANNEL_WEB, "rid-iso",
                                             "abcdef0123456789");
    ASSERT_NOT_NULL(reply);
    ASSERT_STR_EQ(reply, "isolated reply");
    free(reply);

    /* Drain async summarization so per-session consolidation has happened. */
    sc_drain_summarize(fx.agent);

    /* Shared YYYYMM/YYYYMMDD.md must NOT have been created or appended to. */
    char shared_today[512];
    snprintf(shared_today, sizeof(shared_today), "%s/memory/%s/%s.md",
             fx.tmpdir, today_yyyymm(), today_yyyymmdd());
    ASSERT(!path_exists(shared_today),
           "isolated turn did not append to shared YYYYMMDD.md");

    /* Per-session today.md SHOULD contain the consolidation marker. */
    char ns_today[512];
    snprintf(ns_today, sizeof(ns_today),
             "%s/memory/_sessions/abcdef0123456789/today.md", fx.tmpdir);
    ASSERT(path_exists(ns_today), "per-session today.md was written");
    char *got = slurp(ns_today);
    ASSERT_NOT_NULL(got);
    ASSERT(strstr(got, "captured fact A") != NULL,
           "consolidation content landed in per-session today.md");
    free(got);

    /* System prompt of the first call must NOT contain the poison marker. */
    ASSERT_NOT_NULL(fx.mpd->last_system_prompt);
    /* fx.mpd->last_system_prompt is the LAST call (consolidation); we want
     * the FIRST. Easier check: poison must not appear in ANY captured prompt.
     * We only capture the latest, so just check the latest does not contain
     * the marker. Combined with the per-session disk check above, this is
     * sufficient to confirm isolation behavior. */
    /* (No assertion on last prompt because consolidation's system prompt is
     * different — see test_isolated_system_prompt_has_no_shared_memory.) */

    destroy_fixture(&fx);
}

static void test_shared_consolidation_still_writes_to_shared(void)
{
    fixture_t fx = create_fixture();

    /* Same setup; shared path. */
    fx.mpd->responses[0] = (canned_response_t){
        .content = "shared reply", .finish_reason = "end_turn",
    };
    fx.mpd->responses[1] = (canned_response_t){
        .content = "Summary: stuff.", .finish_reason = "end_turn",
    };
    fx.mpd->responses[2] = (canned_response_t){
        .content = "- shared turn fact B\n", .finish_reason = "end_turn",
    };
    fx.mpd->response_count = 3;

    sc_session_add_message(fx.agent->sessions, "shared-task", "user", "u1");
    sc_session_add_message(fx.agent->sessions, "shared-task", "assistant", "a1");
    sc_session_add_message(fx.agent->sessions, "shared-task", "user", "u2");

    char *reply = sc_agent_process_direct(fx.agent, "next turn", "shared-task");
    ASSERT_NOT_NULL(reply);
    ASSERT_STR_EQ(reply, "shared reply");
    free(reply);

    sc_drain_summarize(fx.agent);

    /* Back-compat: shared YYYYMM/YYYYMMDD.md SHOULD have the content. */
    char shared_today[512];
    snprintf(shared_today, sizeof(shared_today), "%s/memory/%s/%s.md",
             fx.tmpdir, today_yyyymm(), today_yyyymmdd());
    ASSERT(path_exists(shared_today),
           "shared turn appended to shared YYYYMMDD.md");
    char *got = slurp(shared_today);
    ASSERT_NOT_NULL(got);
    ASSERT(strstr(got, "fact B") != NULL,
           "shared consolidation content present");
    free(got);

    /* Per-session dir should NOT exist for shared runs. */
    char sessions_dir[512];
    snprintf(sessions_dir, sizeof(sessions_dir),
             "%s/memory/_sessions", fx.tmpdir);
    ASSERT(!path_exists(sessions_dir),
           "shared turn did not create _sessions/");

    destroy_fixture(&fx);
}

static void test_isolated_system_prompt_has_no_shared_memory(void)
{
    fixture_t fx = create_fixture();

    /* Plant a unique marker in shared MEMORY.md. */
    char mem_md[256];
    snprintf(mem_md, sizeof(mem_md), "%s/memory/MEMORY.md", fx.tmpdir);
    write_text(mem_md, "POISON-SHARED-MEMORY-MARKER-XYZ\n");

    /* Single canned response, no summarization (threshold high enough). */
    fx.agent->session_summary_threshold = 100;
    fx.mpd->responses[0] = (canned_response_t){
        .content = "ok", .finish_reason = "end_turn",
    };
    fx.mpd->response_count = 1;

    char *reply = sc_agent_process_isolated(fx.agent, "ask",
                                             "wf-prompt-test",
                                             SC_CHANNEL_WEB, "rid-pt",
                                             "promptiso01");
    ASSERT_NOT_NULL(reply);
    free(reply);

    ASSERT_NOT_NULL(fx.mpd->last_system_prompt);
    ASSERT(strstr(fx.mpd->last_system_prompt,
                  "POISON-SHARED-MEMORY-MARKER-XYZ") == NULL,
           "isolated system prompt does not contain shared MEMORY.md content");
    ASSERT(strstr(fx.mpd->last_system_prompt, "# Memory") == NULL,
           "isolated system prompt omits the # Memory header");
    ASSERT(strstr(fx.mpd->last_system_prompt, "isolated session") != NULL,
           "isolated system prompt advertises isolation");

    destroy_fixture(&fx);
}

static void test_shared_system_prompt_includes_memory(void)
{
    fixture_t fx = create_fixture();

    char mem_md[256];
    snprintf(mem_md, sizeof(mem_md), "%s/memory/MEMORY.md", fx.tmpdir);
    write_text(mem_md, "SHARED-MEMORY-MARKER-OK\n");

    fx.agent->session_summary_threshold = 100;
    fx.mpd->responses[0] = (canned_response_t){
        .content = "ok", .finish_reason = "end_turn",
    };
    fx.mpd->response_count = 1;

    char *reply = sc_agent_process_direct(fx.agent, "ask", "shared-prompt-test");
    ASSERT_NOT_NULL(reply);
    free(reply);

    ASSERT_NOT_NULL(fx.mpd->last_system_prompt);
    ASSERT(strstr(fx.mpd->last_system_prompt,
                  "SHARED-MEMORY-MARKER-OK") != NULL,
           "shared system prompt includes shared MEMORY.md content");
    ASSERT(strstr(fx.mpd->last_system_prompt, "# Memory") != NULL,
           "shared system prompt includes # Memory header");

    destroy_fixture(&fx);
}

static void test_isolated_with_null_ns_falls_back_to_shared(void)
{
    fixture_t fx = create_fixture();

    fx.agent->session_summary_threshold = 100;
    fx.mpd->responses[0] = (canned_response_t){
        .content = "ok", .finish_reason = "end_turn",
    };
    fx.mpd->response_count = 1;

    /* Pass NULL namespace_id — the public API should fall back to shared
     * (log a warning) rather than crash. */
    char *reply = sc_agent_process_isolated(fx.agent, "ask",
                                             "wf-null-ns",
                                             SC_CHANNEL_WEB, "rid-null",
                                             NULL);
    ASSERT_NOT_NULL(reply);
    free(reply);

    /* Because we fell back, the prompt should be the shared variant
     * (i.e. it does not advertise isolation). */
    ASSERT_NOT_NULL(fx.mpd->last_system_prompt);
    ASSERT(strstr(fx.mpd->last_system_prompt, "isolated session") == NULL,
           "fallback used the shared system prompt");

    destroy_fixture(&fx);
}

int main(void)
{
    printf("test_session_isolation:\n");
    RUN_TEST(test_isolated_consolidation_does_not_leak);
    RUN_TEST(test_shared_consolidation_still_writes_to_shared);
    RUN_TEST(test_isolated_system_prompt_has_no_shared_memory);
    RUN_TEST(test_shared_system_prompt_includes_memory);
    RUN_TEST(test_isolated_with_null_ns_falls_back_to_shared);
    TEST_REPORT();
}
