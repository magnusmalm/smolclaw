/*
 * companion/auth.c — scoped bearer token enforcement (PR 4).
 */

#include "test_main.h"

#include "companion/auth.h"

#include <string.h>

static sc_web_config_t mk_web(void)
{
    sc_web_config_t web = {0};
    web.bearer_token = "admin-secret";
    web.companion_token_count = 2;
    web.companion_tokens = calloc(2, sizeof(*web.companion_tokens));
    web.companion_tokens[0].token = "snap-only";
    web.companion_tokens[0].scopes = calloc(1, sizeof(char *));
    web.companion_tokens[0].scopes[0] = "snap_upload";
    web.companion_tokens[0].scope_count = 1;

    web.companion_tokens[1].token = "chat-only";
    web.companion_tokens[1].scopes = calloc(1, sizeof(char *));
    web.companion_tokens[1].scopes[0] = "chat";
    web.companion_tokens[1].scope_count = 1;
    return web;
}

static void free_web(sc_web_config_t *web)
{
    for (int i = 0; i < web->companion_token_count; i++) {
        free(web->companion_tokens[i].scopes);
    }
    free(web->companion_tokens);
}

static void test_main_bearer_full_access(void)
{
    sc_web_config_t web = mk_web();
    ASSERT_INT_EQ(sc_companion_check_auth(&web, "Bearer admin-secret",
                                          SC_COMP_SCOPE_SNAP_UPLOAD), 1);
    ASSERT_INT_EQ(sc_companion_check_auth(&web, "Bearer admin-secret",
                                          SC_COMP_SCOPE_AUDIT_READ), 1);
    free_web(&web);
}

static void test_scoped_snap_allowed(void)
{
    sc_web_config_t web = mk_web();
    ASSERT_INT_EQ(sc_companion_check_auth(&web, "Bearer snap-only",
                                          SC_COMP_SCOPE_SNAP_UPLOAD), 1);
    free_web(&web);
}

static void test_scoped_snap_denied_chat(void)
{
    sc_web_config_t web = mk_web();
    ASSERT_INT_EQ(sc_companion_check_auth(&web, "Bearer snap-only",
                                          SC_COMP_SCOPE_CHAT), 0);
    free_web(&web);
}

static void test_scoped_chat_allowed(void)
{
    sc_web_config_t web = mk_web();
    ASSERT_INT_EQ(sc_companion_check_auth(&web, "Bearer chat-only",
                                          SC_COMP_SCOPE_CHAT), 0 + 1);
    free_web(&web);
}

static void test_wrong_token_denied(void)
{
    sc_web_config_t web = mk_web();
    ASSERT_INT_EQ(sc_companion_check_auth(&web, "Bearer wrong",
                                          NULL), 0);
    free_web(&web);
}

static void test_missing_bearer_denied(void)
{
    sc_web_config_t web = mk_web();
    ASSERT_INT_EQ(sc_companion_check_auth(&web, NULL, NULL), 0);
    ASSERT_INT_EQ(sc_companion_check_auth(&web, "Basic x", NULL), 0);
    free_web(&web);
}

static void test_any_scope_null_for_companion(void)
{
    sc_web_config_t web = mk_web();
    /* NULL required_scope = any authenticated companion or main bearer */
    ASSERT_INT_EQ(sc_companion_check_auth(&web, "Bearer snap-only", NULL), 1);
    free_web(&web);
}

int main(void)
{
    printf("test_companion_auth:\n");
    RUN_TEST(test_main_bearer_full_access);
    RUN_TEST(test_scoped_snap_allowed);
    RUN_TEST(test_scoped_snap_denied_chat);
    RUN_TEST(test_scoped_chat_allowed);
    RUN_TEST(test_wrong_token_denied);
    RUN_TEST(test_missing_bearer_denied);
    RUN_TEST(test_any_scope_null_for_companion);
    TEST_REPORT();
}