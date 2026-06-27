/*
 * smolclaw - gateway slash command tests
 */

#include "test_main.h"
#include "slash.h"
#include "agent.h"
#include "session.h"
#include "util/str.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    sc_agent_t *agent;
    char dir[64];
} slash_ctx_t;

static slash_ctx_t make_ctx(void)
{
    slash_ctx_t c = {0};
    strcpy(c.dir, "/tmp/sc_test_slash_XXXXXX");
    mkdtemp(c.dir);

    c.agent = calloc(1, sizeof(*c.agent));
    c.agent->sessions = sc_session_manager_new(c.dir);
    c.agent->model = sc_strdup("openrouter/test-model");
    c.agent->session_keep_last = 4;
    c.agent->session_summary_threshold = 100;
    return c;
}

static void free_ctx(slash_ctx_t *c)
{
    sc_session_manager_free(c->agent->sessions);
    free(c->agent->model);
    for (int i = 0; i < c->agent->alias_count; i++) {
        free(c->agent->alias_names[i]);
        free(c->agent->alias_models[i]);
    }
    free(c->agent->alias_names);
    free(c->agent->alias_models);
    free(c->agent);

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "rm -rf %s", c->dir);
    char *cmd = sc_strbuf_finish(&sb);
    int rc = system(cmd);
    (void)rc;
    free(cmd);
}

static void test_non_slash_passes_through(void)
{
    slash_ctx_t c = make_ctx();
    char *reply = NULL;
    ASSERT_INT_EQ(sc_slash_dispatch(c.agent, "k", "hello there", &reply), 0);
    ASSERT_NULL(reply);
    /* Leading slash but unknown command → not intercepted. */
    ASSERT_INT_EQ(sc_slash_dispatch(c.agent, "k", "/etc/hosts please", &reply), 0);
    ASSERT_NULL(reply);
    free_ctx(&c);
}

static void test_help(void)
{
    slash_ctx_t c = make_ctx();
    char *reply = NULL;
    ASSERT_INT_EQ(sc_slash_dispatch(c.agent, "k", "/help", &reply), 1);
    ASSERT_NOT_NULL(reply);
    ASSERT(strstr(reply, "/reset") != NULL, "help lists /reset");
    ASSERT(strstr(reply, "/model") != NULL, "help lists /model");
    free(reply);
    free_ctx(&c);
}

static void test_status_and_reset(void)
{
    slash_ctx_t c = make_ctx();

    sc_session_add_message(c.agent->sessions, "k", "user", "one");
    sc_session_add_message(c.agent->sessions, "k", "assistant", "two");

    char *reply = NULL;
    ASSERT_INT_EQ(sc_slash_dispatch(c.agent, "k", "/status", &reply), 1);
    ASSERT_NOT_NULL(reply);
    ASSERT(strstr(reply, "Messages: 2") != NULL, "status shows message count");
    ASSERT(strstr(reply, "openrouter/test-model") != NULL, "status shows model");
    free(reply);

    /* /reset clears the session. */
    reply = NULL;
    ASSERT_INT_EQ(sc_slash_dispatch(c.agent, "k", "/reset", &reply), 1);
    ASSERT_NOT_NULL(reply);
    free(reply);

    int count = -1;
    sc_session_get_history(c.agent->sessions, "k", &count);
    ASSERT_INT_EQ(count, 0);

    /* /new is an alias for /reset. */
    reply = NULL;
    ASSERT_INT_EQ(sc_slash_dispatch(c.agent, "k", "/new", &reply), 1);
    free(reply);

    free_ctx(&c);
}

static void test_model_show_and_set(void)
{
    slash_ctx_t c = make_ctx();

    /* Configure one alias: "fast" -> "openrouter/fast-model". */
    c.agent->alias_names = calloc(1, sizeof(char *));
    c.agent->alias_models = calloc(1, sizeof(char *));
    c.agent->alias_names[0] = sc_strdup("fast");
    c.agent->alias_models[0] = sc_strdup("openrouter/fast-model");
    c.agent->alias_count = 1;

    char *reply = NULL;
    ASSERT_INT_EQ(sc_slash_dispatch(c.agent, "k", "/model", &reply), 1);
    ASSERT(strstr(reply, "openrouter/test-model") != NULL, "shows current model");
    ASSERT(strstr(reply, "fast") != NULL, "lists alias");
    free(reply);

    /* Set via alias. */
    reply = NULL;
    ASSERT_INT_EQ(sc_slash_dispatch(c.agent, "k", "/model fast", &reply), 1);
    ASSERT_STR_EQ(c.agent->model, "openrouter/fast-model");
    free(reply);

    /* Set via literal model name (uppercase command still matches). */
    reply = NULL;
    ASSERT_INT_EQ(sc_slash_dispatch(c.agent, "k", "/MODEL groq/llama3", &reply), 1);
    ASSERT_STR_EQ(c.agent->model, "groq/llama3");
    free(reply);

    free_ctx(&c);
}

static void test_compress_nothing(void)
{
    slash_ctx_t c = make_ctx();
    /* Empty session → below keep_last → no summarization spawned. */
    char *reply = NULL;
    ASSERT_INT_EQ(sc_slash_dispatch(c.agent, "k", "/compress", &reply), 1);
    ASSERT_NOT_NULL(reply);
    ASSERT(strstr(reply, "Nothing to compress") != NULL, "no-op compress reply");
    free(reply);
    free_ctx(&c);
}

int main(void)
{
    printf("test_slash\n");

    RUN_TEST(test_non_slash_passes_through);
    RUN_TEST(test_help);
    RUN_TEST(test_status_and_reset);
    RUN_TEST(test_model_show_and_set);
    RUN_TEST(test_compress_nothing);

    TEST_REPORT();
}
