/*
 * smolclaw - session_search tool tests (task 4.11).
 *
 * Builds a temp sessions dir with a couple of fake .jsonl transcripts, then
 * exercises the tool's `list` and `search` actions via the FTS5 index. Requires
 * SC_ENABLE_SESSION_SEARCH (which pulls in SQLite FTS5 via memory search).
 */

#include "test_main.h"
#include "tools/session_search.h"
#include "tools/types.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static char g_dir[256];

static void write_session(const char *name, const char *text)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", g_dir, name);
    FILE *f = fopen(path, "w");
    if (!f) return;
    /* One JSONL message line — the indexer treats the file as text. */
    fprintf(f, "{\"role\":\"user\",\"content\":\"%s\"}\n", text);
    fclose(f);
}

static sc_tool_result_t *run(sc_tool_t *t, const char *action,
                             const char *query)
{
    cJSON *args = cJSON_CreateObject();
    if (action) cJSON_AddStringToObject(args, "action", action);
    if (query)  cJSON_AddStringToObject(args, "query", query);
    sc_tool_result_t *r = t->execute(t, args, NULL);
    cJSON_Delete(args);
    return r;
}

static void test_session_search_construct(void)
{
    ASSERT_NULL(sc_tool_session_search_new(NULL));
    sc_tool_t *t = sc_tool_session_search_new(g_dir);
    ASSERT_NOT_NULL(t);
    ASSERT_STR_EQ(t->name, "session_search");
    ASSERT_NOT_NULL(t->execute);
    ASSERT_NOT_NULL(t->destroy);
    t->destroy(t);
}

static void test_session_search_list(void)
{
    sc_tool_t *t = sc_tool_session_search_new(g_dir);
    ASSERT_NOT_NULL(t);
    sc_tool_result_t *r = run(t, "list", NULL);
    ASSERT_NOT_NULL(r);
    const char *out = r->for_llm ? r->for_llm : "";
    ASSERT(strstr(out, "deploy-chat.jsonl") != NULL, "list should include sessions");
    ASSERT(strstr(out, "weather-chat.jsonl") != NULL, "list should include sessions");
    sc_tool_result_free(r);
    t->destroy(t);
}

static void test_session_search_finds_match(void)
{
    sc_tool_t *t = sc_tool_session_search_new(g_dir);
    ASSERT_NOT_NULL(t);
    sc_tool_result_t *r = run(t, "search", "deploy");
    ASSERT_NOT_NULL(r);
    const char *out = r->for_llm ? r->for_llm : "";
    ASSERT(strstr(out, "session:deploy-chat") != NULL,
           "search should surface the matching session");
    sc_tool_result_free(r);
    t->destroy(t);
}

static void test_session_search_no_match(void)
{
    sc_tool_t *t = sc_tool_session_search_new(g_dir);
    ASSERT_NOT_NULL(t);
    sc_tool_result_t *r = run(t, "search", "quantumchromodynamics");
    ASSERT_NOT_NULL(r);
    const char *out = r->for_llm ? r->for_llm : "";
    ASSERT(strstr(out, "No matching") != NULL, "no-match should say so");
    sc_tool_result_free(r);
    t->destroy(t);
}

static void test_session_search_requires_query(void)
{
    sc_tool_t *t = sc_tool_session_search_new(g_dir);
    ASSERT_NOT_NULL(t);
    sc_tool_result_t *r = run(t, "search", NULL);
    ASSERT_NOT_NULL(r);
    ASSERT(r->is_error, "search without query should error");
    sc_tool_result_free(r);
    t->destroy(t);
}

int main(void)
{
    printf("test_session_search:\n");

    snprintf(g_dir, sizeof(g_dir), "/tmp/sc_sessearch_XXXXXX");
    if (!mkdtemp(g_dir)) { printf("mkdtemp failed\n"); return 1; }

    write_session("deploy-chat.jsonl",
                  "Let us review the deploy script and the rollout plan.");
    write_session("weather-chat.jsonl",
                  "Will it rain tomorrow during the picnic?");

    RUN_TEST(test_session_search_construct);
    RUN_TEST(test_session_search_list);
    RUN_TEST(test_session_search_finds_match);
    RUN_TEST(test_session_search_no_match);
    RUN_TEST(test_session_search_requires_query);

    /* Cleanup temp dir (best-effort). */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", g_dir);
    if (system(cmd) != 0) { /* ignore */ }

    TEST_REPORT();
}
