/*
 * Channel manager reload tests — M-3 dm_policy write under security_mutex.
 */

#include "test_main.h"
#include "channels/manager.h"
#include "channels/base.h"
#include "constants_app.h"
#include "config.h"
#include "pairing.h"
#include "util/str.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void stub_destroy(sc_channel_t *ch)
{
    sc_channel_base_free(ch);
}

static sc_channel_t *make_telegram_stub(const char *dm_policy,
                                        char **allow_from, int count)
{
    sc_channel_t *ch = calloc(1, sizeof(*ch));
    if (!ch) return NULL;
    ch->name = SC_CHANNEL_TELEGRAM;
    ch->destroy = stub_destroy;
    sc_channel_init_security(ch, dm_policy, allow_from, count, "telegram");
    return ch;
}

static void test_reload_dm_policy_swapped_with_allow_list(void)
{
    char *allowed[] = { sc_strdup("111") };
    sc_channel_t *ch = make_telegram_stub("allowlist", allowed, 1);
    ASSERT_NOT_NULL(ch);
    ASSERT_INT_EQ(sc_channel_is_allowed(ch, "111"), 1);
    ASSERT_INT_EQ(sc_channel_is_allowed(ch, "999"), 0);
    ASSERT_INT_EQ((int)ch->dm_policy, (int)SC_DM_POLICY_ALLOWLIST);

    sc_channel_t *channels[] = { ch };
    sc_channel_manager_t mgr = {
        .channels = channels,
        .count = 1,
    };

    sc_config_t new_cfg = {0};
    new_cfg.telegram.dm_policy = sc_strdup("open");
    new_cfg.telegram.allow_from = NULL;
    new_cfg.telegram.allow_from_count = 0;
    new_cfg.rate_limit_per_minute = 0;

    sc_channel_manager_reload_config(&mgr, &new_cfg);

    ASSERT_INT_EQ((int)ch->dm_policy, (int)SC_DM_POLICY_OPEN);
    ASSERT_INT_EQ(sc_channel_is_allowed(ch, "999"), 1);

    free(new_cfg.telegram.dm_policy);
    ch->destroy(ch);
    free(allowed[0]);
}

static void test_reload_dm_policy_to_pairing(void)
{
    sc_channel_t *ch = make_telegram_stub("open", NULL, 0);
    ASSERT_NOT_NULL(ch);
    ASSERT_INT_EQ(sc_channel_is_allowed(ch, "stranger"), 1);

    sc_channel_t *channels[] = { ch };
    sc_channel_manager_t mgr = {
        .channels = channels,
        .count = 1,
    };

    sc_config_t new_cfg = {0};
    new_cfg.telegram.dm_policy = sc_strdup("pairing");
    new_cfg.telegram.allow_from = NULL;
    new_cfg.telegram.allow_from_count = 0;

    sc_channel_manager_reload_config(&mgr, &new_cfg);

    ASSERT_INT_EQ((int)ch->dm_policy, (int)SC_DM_POLICY_PAIRING);
    ASSERT_INT_EQ(sc_channel_is_allowed(ch, "stranger"), 0);

    free(new_cfg.telegram.dm_policy);
    ch->destroy(ch);
}

/* Structural guard: dm_policy assignment in reload_allow_list sits inside lock. */
static void test_reload_allow_list_assigns_dm_policy_under_lock(void)
{
    const char *path = NULL;
    if (access("src/channels/manager.c", R_OK) == 0)
        path = "src/channels/manager.c";
    else if (access("../src/channels/manager.c", R_OK) == 0)
        path = "../src/channels/manager.c";
    ASSERT_NOT_NULL(path);

    FILE *fp = fopen(path, "r");  /* path set above */
    ASSERT_NOT_NULL(fp);

    int in_fn = 0;
    int saw_lock = 0;
    int saw_assign = 0;
    int assign_under_lock = 0;
    char line[512];

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "reload_allow_list("))
            in_fn = 1;
        if (!in_fn)
            continue;
        if (strstr(line, "pthread_mutex_lock(&ch->security_mutex)"))
            saw_lock = 1;
        if (strstr(line, "ch->dm_policy ="))
            saw_assign = 1;
        if (strstr(line, "pthread_mutex_unlock(&ch->security_mutex)")) {
            if (saw_lock && saw_assign)
                assign_under_lock = 1;
            break;
        }
    }
    fclose(fp);

    ASSERT(saw_assign, "reload_allow_list should assign ch->dm_policy");
    ASSERT(assign_under_lock,
           "dm_policy assignment must occur between security_mutex lock/unlock");
}

int main(void)
{
    printf("test_channel_manager\n");

    RUN_TEST(test_reload_dm_policy_swapped_with_allow_list);
    RUN_TEST(test_reload_dm_policy_to_pairing);
    RUN_TEST(test_reload_allow_list_assigns_dm_policy_under_lock);

    TEST_REPORT();
}