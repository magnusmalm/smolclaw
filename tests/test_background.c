/*
 * smolclaw - background process management tests
 */

#include "test_main.h"
#include "tools/background.h"
#include "tools/types.h"
#include "constants.h"
#include "cJSON.h"
#include "util/str.h"

#include <unistd.h>

/* Helper: execute tool with JSON args, return result */
static sc_tool_result_t *bg_exec(sc_tool_t *tool, cJSON *args)
{
    sc_tool_result_t *r = tool->execute(tool, args, NULL);
    return r;
}

static void test_exec_bg_and_poll(void)
{
    char tmpdir[] = "/tmp/sc_test_bg_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    sc_tool_t *exec_bg = sc_tool_exec_bg_new(tmpdir, 0, SC_BG_MAX_PROCS);
    sc_tool_t *poll = sc_tool_bg_poll_new();
    sc_tool_t *kill_t = sc_tool_bg_kill_new();
    ASSERT_NOT_NULL(exec_bg);
    ASSERT_NOT_NULL(poll);
    ASSERT_NOT_NULL(kill_t);

    /* Start a background process */
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "command", "echo hello_bg && sleep 60");
    sc_tool_result_t *r = bg_exec(exec_bg, args);
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "slot 0") != NULL, "Should report slot 0");
    sc_tool_result_free(r);
    cJSON_Delete(args);

    /* Wait briefly for output to be available */
    usleep(200000); /* 200ms */

    /* Poll slot 0 */
    args = cJSON_CreateObject();
    cJSON_AddNumberToObject(args, "slot", 0);
    r = bg_exec(poll, args);
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "hello_bg") != NULL, "Should contain output");
    ASSERT(strstr(r->for_llm, "running") != NULL, "Should be running");
    sc_tool_result_free(r);
    cJSON_Delete(args);

    /* Kill it */
    args = cJSON_CreateObject();
    cJSON_AddNumberToObject(args, "slot", 0);
    r = bg_exec(kill_t, args);
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "terminated") != NULL, "Should confirm kill");
    sc_tool_result_free(r);
    cJSON_Delete(args);

    /* Poll killed slot should error */
    args = cJSON_CreateObject();
    cJSON_AddNumberToObject(args, "slot", 0);
    r = bg_exec(poll, args);
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 1);
    sc_tool_result_free(r);
    cJSON_Delete(args);

    exec_bg->destroy(exec_bg);
    poll->destroy(poll);
    kill_t->destroy(kill_t);

    sc_strbuf_t p;
    sc_strbuf_init(&p);
    sc_strbuf_appendf(&p, "rm -rf %s", tmpdir);
    char *cmd = sc_strbuf_finish(&p);
    system(cmd);
    free(cmd);
}

static void test_bg_deny_list(void)
{
    char tmpdir[] = "/tmp/sc_test_bg_deny_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    sc_tool_t *exec_bg = sc_tool_exec_bg_new(tmpdir, 1, SC_BG_MAX_PROCS);
    ASSERT_NOT_NULL(exec_bg);

    /* rm -rf should be blocked */
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "command", "rm -rf /");
    sc_tool_result_t *r = bg_exec(exec_bg, args);
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 1);
    ASSERT(strstr(r->for_llm, "blocked") != NULL, "rm -rf should be blocked");
    sc_tool_result_free(r);
    cJSON_Delete(args);

    /* Path traversal should be blocked */
    args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "command", "cat ../../../etc/passwd");
    r = bg_exec(exec_bg, args);
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 1);
    ASSERT(strstr(r->for_llm, "blocked") != NULL, "traversal should be blocked");
    sc_tool_result_free(r);
    cJSON_Delete(args);

    exec_bg->destroy(exec_bg);
    sc_bg_cleanup_all();

    sc_strbuf_t p;
    sc_strbuf_init(&p);
    sc_strbuf_appendf(&p, "rm -rf %s", tmpdir);
    char *cmd = sc_strbuf_finish(&p);
    system(cmd);
    free(cmd);
}

static void test_bg_max_procs(void)
{
    char tmpdir[] = "/tmp/sc_test_bg_max_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    sc_tool_t *exec_bg = sc_tool_exec_bg_new(tmpdir, 0, SC_BG_MAX_PROCS);
    ASSERT_NOT_NULL(exec_bg);

    /* Fill all slots */
    for (int i = 0; i < SC_BG_MAX_PROCS; i++) {
        cJSON *args = cJSON_CreateObject();
        cJSON_AddStringToObject(args, "command", "sleep 60");
        sc_tool_result_t *r = bg_exec(exec_bg, args);
        ASSERT_NOT_NULL(r);
        ASSERT_INT_EQ(r->is_error, 0);
        sc_tool_result_free(r);
        cJSON_Delete(args);
    }

    /* One more should fail */
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "command", "sleep 60");
    sc_tool_result_t *r = bg_exec(exec_bg, args);
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 1);
    ASSERT(strstr(r->for_llm, "Maximum") != NULL, "Should hit max procs limit");
    sc_tool_result_free(r);
    cJSON_Delete(args);

    exec_bg->destroy(exec_bg);
    sc_bg_cleanup_all();

    sc_strbuf_t p;
    sc_strbuf_init(&p);
    sc_strbuf_appendf(&p, "rm -rf %s", tmpdir);
    char *cmd = sc_strbuf_finish(&p);
    system(cmd);
    free(cmd);
}

static void test_bg_invalid_slot(void)
{
    sc_tool_t *poll = sc_tool_bg_poll_new();
    sc_tool_t *kill_t = sc_tool_bg_kill_new();

    /* Invalid slot number */
    cJSON *args = cJSON_CreateObject();
    cJSON_AddNumberToObject(args, "slot", -1);
    sc_tool_result_t *r = poll->execute(poll, args, NULL);
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 1);
    sc_tool_result_free(r);
    cJSON_Delete(args);

    /* Out-of-range slot */
    args = cJSON_CreateObject();
    cJSON_AddNumberToObject(args, "slot", 99);
    r = kill_t->execute(kill_t, args, NULL);
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 1);
    sc_tool_result_free(r);
    cJSON_Delete(args);

    poll->destroy(poll);
    kill_t->destroy(kill_t);
}

int main(void)
{
    printf("test_background\n");

    RUN_TEST(test_exec_bg_and_poll);
    RUN_TEST(test_bg_deny_list);
    RUN_TEST(test_bg_max_procs);
    RUN_TEST(test_bg_invalid_slot);

    TEST_REPORT();
}
