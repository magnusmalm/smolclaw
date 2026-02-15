/*
 * smolclaw - config tests
 */

#include "test_main.h"
#include "config.h"
#include "constants.h"
#include "util/str.h"

#include <sys/stat.h>
#include <unistd.h>

static void test_config_default(void)
{
    sc_config_t *cfg = sc_config_default();
    ASSERT_NOT_NULL(cfg);

    /* Check default values */
    ASSERT_NOT_NULL(cfg->workspace);
    ASSERT_NOT_NULL(cfg->model);
    ASSERT_STR_EQ(cfg->model, SC_DEFAULT_MODEL);
    ASSERT_INT_EQ(cfg->max_tokens, SC_DEFAULT_MAX_TOKENS);
    ASSERT_INT_EQ(cfg->max_tool_iterations, SC_DEFAULT_MAX_ITERATIONS);

    /* Telegram disabled by default */
    ASSERT_INT_EQ(cfg->telegram.enabled, 0);

    /* Heartbeat defaults */
    ASSERT_INT_EQ(cfg->heartbeat.interval, SC_DEFAULT_HEARTBEAT_INTERVAL);

    /* Configurable limits defaults */
    ASSERT_INT_EQ(cfg->session_summary_threshold, SC_SESSION_SUMMARY_THRESHOLD);
    ASSERT_INT_EQ(cfg->session_keep_last, SC_SESSION_KEEP_LAST);
    ASSERT_INT_EQ(cfg->max_output_chars, SC_MAX_OUTPUT_CHARS);
    ASSERT_INT_EQ(cfg->max_fetch_chars, SC_MAX_FETCH_CHARS);
    ASSERT_INT_EQ(cfg->max_background_procs, SC_BG_MAX_PROCS);
    ASSERT_INT_EQ(cfg->summary_max_transcript, SC_SUMMARY_MAX_TRANSCRIPT);

    sc_config_free(cfg);
}

static void test_config_load(void)
{
    /* Create a temp config file */
    char tmppath[] = "/tmp/sc_test_config_XXXXXX";
    int fd = mkstemp(tmppath);
    ASSERT(fd >= 0, "mkstemp should succeed");

    const char *json_content =
        "{\n"
        "  \"agents\": {\n"
        "    \"defaults\": {\n"
        "      \"workspace\": \"/tmp/sc_test_workspace\",\n"
        "      \"model\": \"test-model\",\n"
        "      \"max_tokens\": 4096,\n"
        "      \"temperature\": 0.5,\n"
        "      \"max_tool_iterations\": 10\n"
        "    }\n"
        "  },\n"
        "  \"providers\": {\n"
        "    \"anthropic\": {\n"
        "      \"api_key\": \"test-key-123\"\n"
        "    }\n"
        "  },\n"
        "  \"channels\": {\n"
        "    \"telegram\": {\n"
        "      \"enabled\": true,\n"
        "      \"token\": \"bot-token-abc\",\n"
        "      \"allow_from\": [\"user1\", \"user2\"]\n"
        "    }\n"
        "  },\n"
        "  \"heartbeat\": {\n"
        "    \"enabled\": true,\n"
        "    \"interval\": 15\n"
        "  }\n"
        "}\n";

    write(fd, json_content, strlen(json_content));
    close(fd);

    sc_config_t *cfg = sc_config_load(tmppath);
    ASSERT_NOT_NULL(cfg);

    ASSERT_STR_EQ(cfg->workspace, "/tmp/sc_test_workspace");
    ASSERT_STR_EQ(cfg->model, "test-model");
    ASSERT_INT_EQ(cfg->max_tokens, 4096);
    ASSERT_INT_EQ(cfg->max_tool_iterations, 10);

    /* Provider */
    ASSERT_STR_EQ(cfg->anthropic.api_key, "test-key-123");

    /* Telegram */
    ASSERT_INT_EQ(cfg->telegram.enabled, 1);
    ASSERT_STR_EQ(cfg->telegram.token, "bot-token-abc");
    ASSERT_INT_EQ(cfg->telegram.allow_from_count, 2);
    ASSERT_STR_EQ(cfg->telegram.allow_from[0], "user1");
    ASSERT_STR_EQ(cfg->telegram.allow_from[1], "user2");

    /* Heartbeat */
    ASSERT_INT_EQ(cfg->heartbeat.enabled, 1);
    ASSERT_INT_EQ(cfg->heartbeat.interval, 15);

    sc_config_free(cfg);
    unlink(tmppath);
}

static void test_config_limits(void)
{
    /* Test loading configurable limits from JSON */
    char tmppath[] = "/tmp/sc_test_config_limits_XXXXXX";
    int fd = mkstemp(tmppath);
    ASSERT(fd >= 0, "mkstemp should succeed");

    const char *json_content =
        "{\n"
        "  \"agents\": {\n"
        "    \"defaults\": {\n"
        "      \"session_summary_threshold\": 40,\n"
        "      \"session_keep_last\": 8,\n"
        "      \"max_output_chars\": 5000,\n"
        "      \"max_fetch_chars\": 25000,\n"
        "      \"max_background_procs\": 4,\n"
        "      \"summary_max_transcript\": 2000\n"
        "    }\n"
        "  }\n"
        "}\n";

    write(fd, json_content, strlen(json_content));
    close(fd);

    sc_config_t *cfg = sc_config_load(tmppath);
    ASSERT_NOT_NULL(cfg);

    ASSERT_INT_EQ(cfg->session_summary_threshold, 40);
    ASSERT_INT_EQ(cfg->session_keep_last, 8);
    ASSERT_INT_EQ(cfg->max_output_chars, 5000);
    ASSERT_INT_EQ(cfg->max_fetch_chars, 25000);
    ASSERT_INT_EQ(cfg->max_background_procs, 4);
    ASSERT_INT_EQ(cfg->summary_max_transcript, 2000);

    sc_config_free(cfg);
    unlink(tmppath);
}

static void test_config_limits_env(void)
{
    /* Test env var overrides for configurable limits */
    char tmppath[] = "/tmp/sc_test_config_env_XXXXXX";
    int fd = mkstemp(tmppath);
    ASSERT(fd >= 0, "mkstemp should succeed");

    /* Minimal JSON so config loads successfully */
    const char *json_content = "{}\n";
    write(fd, json_content, strlen(json_content));
    close(fd);

    setenv("SMOLCLAW_AGENTS_DEFAULTS_MAX_OUTPUT_CHARS", "7777", 1);
    setenv("SMOLCLAW_AGENTS_DEFAULTS_SESSION_SUMMARY_THRESHOLD", "50", 1);

    sc_config_t *cfg = sc_config_load(tmppath);
    ASSERT_NOT_NULL(cfg);

    ASSERT_INT_EQ(cfg->max_output_chars, 7777);
    ASSERT_INT_EQ(cfg->session_summary_threshold, 50);
    /* Non-overridden fields should keep defaults */
    ASSERT_INT_EQ(cfg->session_keep_last, SC_SESSION_KEEP_LAST);

    sc_config_free(cfg);
    unlink(tmppath);

    unsetenv("SMOLCLAW_AGENTS_DEFAULTS_MAX_OUTPUT_CHARS");
    unsetenv("SMOLCLAW_AGENTS_DEFAULTS_SESSION_SUMMARY_THRESHOLD");
}

static void test_config_load_missing(void)
{
    /* Missing file should return defaults with env overrides */
    sc_config_t *cfg = sc_config_load("/tmp/nonexistent_sc_config.json");
    ASSERT_NOT_NULL(cfg);
    /* Should have default values */
    ASSERT_NOT_NULL(cfg->model);
    ASSERT_STR_EQ(cfg->model, SC_DEFAULT_MODEL);
    ASSERT_INT_EQ(cfg->max_tokens, SC_DEFAULT_MAX_TOKENS);
    sc_config_free(cfg);
}

static void test_config_load_corrupt(void)
{
    /* Corrupt JSON should return defaults */
    char tmppath[] = "/tmp/sc_test_config_corrupt_XXXXXX";
    int fd = mkstemp(tmppath);
    ASSERT(fd >= 0, "mkstemp should succeed");

    const char *bad_content = "THIS IS NOT JSON {{{";
    write(fd, bad_content, strlen(bad_content));
    close(fd);

    sc_config_t *cfg = sc_config_load(tmppath);
    ASSERT_NOT_NULL(cfg);
    /* Should have default values */
    ASSERT_NOT_NULL(cfg->model);
    ASSERT_STR_EQ(cfg->model, SC_DEFAULT_MODEL);
    ASSERT_INT_EQ(cfg->max_tokens, SC_DEFAULT_MAX_TOKENS);
    ASSERT_INT_EQ(cfg->max_tool_iterations, SC_DEFAULT_MAX_ITERATIONS);

    sc_config_free(cfg);
    unlink(tmppath);
}

static void test_config_backup(void)
{
    /* Create a config, save it, verify .bak is created on second save */
    char tmppath[] = "/tmp/sc_test_config_backup_XXXXXX";
    int fd = mkstemp(tmppath);
    ASSERT(fd >= 0, "mkstemp should succeed");

    const char *json_content =
        "{\n"
        "  \"agents\": {\n"
        "    \"defaults\": {\n"
        "      \"model\": \"original-model\"\n"
        "    }\n"
        "  }\n"
        "}\n";
    write(fd, json_content, strlen(json_content));
    close(fd);

    /* Load config */
    sc_config_t *cfg = sc_config_load(tmppath);
    ASSERT_NOT_NULL(cfg);
    ASSERT_STR_EQ(cfg->model, "original-model");

    /* Save config (this creates .bak of the original) */
    int ret = sc_config_save(tmppath, cfg);
    ASSERT_INT_EQ(ret, 0);

    /* Verify .bak file exists */
    char bakpath[256];
    snprintf(bakpath, sizeof(bakpath), "%s.bak", tmppath);
    FILE *bak = fopen(bakpath, "r");
    ASSERT_NOT_NULL(bak);
    /* .bak should contain the original content */
    char buf[1024] = {0};
    fread(buf, 1, sizeof(buf) - 1, bak);
    fclose(bak);
    ASSERT(strstr(buf, "original-model") != NULL,
           ".bak should contain original model");

    sc_config_free(cfg);
    unlink(tmppath);
    unlink(bakpath);
}

static void test_config_workspace_path(void)
{
    sc_config_t *cfg = sc_config_default();
    ASSERT_NOT_NULL(cfg);

    char *path = sc_config_workspace_path(cfg);
    ASSERT_NOT_NULL(path);
    /* Should be an absolute path after tilde expansion */
    ASSERT(path[0] == '/', "Workspace path should be absolute");
    free(path);

    sc_config_free(cfg);
}

/* Helper: write a temp config JSON and a temp secret file, load config */
static void write_tmp(const char *path, const char *content)
{
    FILE *f = fopen(path, "w");
    if (f) {
        fputs(content, f);
        fclose(f);
    }
}

static void test_config_file_ref(void)
{
    /* file:///path resolves to file contents */
    char secret_path[] = "/tmp/sc_test_secret_XXXXXX";
    int sfd = mkstemp(secret_path);
    ASSERT(sfd >= 0, "mkstemp secret");
    write(sfd, "my-secret-key-12345", 19);
    close(sfd);
    chmod(secret_path, 0600);

    char json[512];
    snprintf(json, sizeof(json),
        "{ \"providers\": { \"anthropic\": { \"api_key\": \"file://%s\" } } }",
        secret_path);

    char cfg_path[] = "/tmp/sc_test_cfg_fref_XXXXXX";
    int cfd = mkstemp(cfg_path);
    ASSERT(cfd >= 0, "mkstemp config");
    write(cfd, json, strlen(json));
    close(cfd);

    sc_config_t *cfg = sc_config_load(cfg_path);
    ASSERT_NOT_NULL(cfg);
    ASSERT_STR_EQ(cfg->anthropic.api_key, "my-secret-key-12345");

    sc_config_free(cfg);
    unlink(cfg_path);
    unlink(secret_path);
}

static void test_config_file_ref_at(void)
{
    /* @/path syntax works */
    char secret_path[] = "/tmp/sc_test_secret_at_XXXXXX";
    int sfd = mkstemp(secret_path);
    ASSERT(sfd >= 0, "mkstemp secret");
    write(sfd, "at-syntax-key-67890", 19);
    close(sfd);
    chmod(secret_path, 0600);

    char json[512];
    snprintf(json, sizeof(json),
        "{ \"providers\": { \"openai\": { \"api_key\": \"@%s\" } } }",
        secret_path);

    char cfg_path[] = "/tmp/sc_test_cfg_at_XXXXXX";
    int cfd = mkstemp(cfg_path);
    ASSERT(cfd >= 0, "mkstemp config");
    write(cfd, json, strlen(json));
    close(cfd);

    sc_config_t *cfg = sc_config_load(cfg_path);
    ASSERT_NOT_NULL(cfg);
    ASSERT_STR_EQ(cfg->openai.api_key, "at-syntax-key-67890");

    sc_config_free(cfg);
    unlink(cfg_path);
    unlink(secret_path);
}

static void test_config_file_ref_env(void)
{
    /* File ref in env var is resolved */
    char secret_path[] = "/tmp/sc_test_secret_env_XXXXXX";
    int sfd = mkstemp(secret_path);
    ASSERT(sfd >= 0, "mkstemp secret");
    write(sfd, "env-file-ref-key", 16);
    close(sfd);
    chmod(secret_path, 0600);

    char env_val[512];
    snprintf(env_val, sizeof(env_val), "file://%s", secret_path);
    setenv("SMOLCLAW_PROVIDERS_GROQ_API_KEY", env_val, 1);

    char cfg_path[] = "/tmp/sc_test_cfg_envref_XXXXXX";
    int cfd = mkstemp(cfg_path);
    ASSERT(cfd >= 0, "mkstemp config");
    write(cfd, "{}", 2);
    close(cfd);

    sc_config_t *cfg = sc_config_load(cfg_path);
    ASSERT_NOT_NULL(cfg);
    ASSERT_STR_EQ(cfg->groq.api_key, "env-file-ref-key");

    sc_config_free(cfg);
    unlink(cfg_path);
    unlink(secret_path);
    unsetenv("SMOLCLAW_PROVIDERS_GROQ_API_KEY");
}

static void test_config_file_ref_missing(void)
{
    /* Missing file leaves field as-is */
    const char *json =
        "{ \"providers\": { \"anthropic\": { "
        "\"api_key\": \"file:///tmp/sc_nonexistent_secret_file\" } } }";

    char cfg_path[] = "/tmp/sc_test_cfg_miss_XXXXXX";
    int cfd = mkstemp(cfg_path);
    ASSERT(cfd >= 0, "mkstemp config");
    write(cfd, json, strlen(json));
    close(cfd);

    sc_config_t *cfg = sc_config_load(cfg_path);
    ASSERT_NOT_NULL(cfg);
    /* Field should still hold the original file ref string */
    ASSERT_STR_EQ(cfg->anthropic.api_key,
                  "file:///tmp/sc_nonexistent_secret_file");

    sc_config_free(cfg);
    unlink(cfg_path);
}

static void test_config_file_ref_channel(void)
{
    /* Channel token fields resolve */
    char secret_path[] = "/tmp/sc_test_secret_chan_XXXXXX";
    int sfd = mkstemp(secret_path);
    ASSERT(sfd >= 0, "mkstemp secret");
    write(sfd, "bot-token-from-file", 19);
    close(sfd);
    chmod(secret_path, 0600);

    char json[512];
    snprintf(json, sizeof(json),
        "{ \"channels\": { \"telegram\": { \"enabled\": true, "
        "\"token\": \"file://%s\" } } }",
        secret_path);

    char cfg_path[] = "/tmp/sc_test_cfg_chan_XXXXXX";
    int cfd = mkstemp(cfg_path);
    ASSERT(cfd >= 0, "mkstemp config");
    write(cfd, json, strlen(json));
    close(cfd);

    sc_config_t *cfg = sc_config_load(cfg_path);
    ASSERT_NOT_NULL(cfg);
    ASSERT_STR_EQ(cfg->telegram.token, "bot-token-from-file");

    sc_config_free(cfg);
    unlink(cfg_path);
    unlink(secret_path);
}

static void test_config_file_ref_strip(void)
{
    /* Trailing \n and \r\n are stripped */
    char secret_path[] = "/tmp/sc_test_secret_strip_XXXXXX";
    int sfd = mkstemp(secret_path);
    ASSERT(sfd >= 0, "mkstemp secret");
    write(sfd, "clean-key\r\n\n", 12);
    close(sfd);
    chmod(secret_path, 0600);

    char json[512];
    snprintf(json, sizeof(json),
        "{ \"providers\": { \"deepseek\": { \"api_key\": \"file://%s\" } } }",
        secret_path);

    char cfg_path[] = "/tmp/sc_test_cfg_strip_XXXXXX";
    int cfd = mkstemp(cfg_path);
    ASSERT(cfd >= 0, "mkstemp config");
    write(cfd, json, strlen(json));
    close(cfd);

    sc_config_t *cfg = sc_config_load(cfg_path);
    ASSERT_NOT_NULL(cfg);
    ASSERT_STR_EQ(cfg->deepseek.api_key, "clean-key");

    sc_config_free(cfg);
    unlink(cfg_path);
    unlink(secret_path);
}

static void test_config_file_ref_nonsecret(void)
{
    /* Non-secret fields are NOT resolved */
    char secret_path[] = "/tmp/sc_test_secret_ns_XXXXXX";
    int sfd = mkstemp(secret_path);
    ASSERT(sfd >= 0, "mkstemp secret");
    write(sfd, "resolved-model", 14);
    close(sfd);
    chmod(secret_path, 0600);

    char json[512];
    snprintf(json, sizeof(json),
        "{ \"agents\": { \"defaults\": { "
        "\"model\": \"file://%s\", "
        "\"workspace\": \"@%s\" } } }",
        secret_path, secret_path);

    char cfg_path[] = "/tmp/sc_test_cfg_ns_XXXXXX";
    int cfd = mkstemp(cfg_path);
    ASSERT(cfd >= 0, "mkstemp config");
    write(cfd, json, strlen(json));
    close(cfd);

    sc_config_t *cfg = sc_config_load(cfg_path);
    ASSERT_NOT_NULL(cfg);
    /* model and workspace should keep the literal file ref string */
    char expected_model[512];
    snprintf(expected_model, sizeof(expected_model), "file://%s", secret_path);
    ASSERT_STR_EQ(cfg->model, expected_model);

    char expected_ws[512];
    snprintf(expected_ws, sizeof(expected_ws), "@%s", secret_path);
    ASSERT_STR_EQ(cfg->workspace, expected_ws);

    sc_config_free(cfg);
    unlink(cfg_path);
    unlink(secret_path);
}

static void test_config_file_ref_workspace_warn(void)
{
    /* Secret inside workspace triggers warning but still resolves */
    char ws_dir[] = "/tmp/sc_test_ws_XXXXXX";
    ASSERT(mkdtemp(ws_dir) != NULL, "mkdtemp workspace");

    char secret_path[512];
    snprintf(secret_path, sizeof(secret_path), "%s/my_secret", ws_dir);
    write_tmp(secret_path, "workspace-secret-key");
    chmod(secret_path, 0600);

    char json[1024];
    snprintf(json, sizeof(json),
        "{ \"agents\": { \"defaults\": { \"workspace\": \"%s\" } }, "
        "\"providers\": { \"gemini\": { \"api_key\": \"file://%s\" } } }",
        ws_dir, secret_path);

    char cfg_path[] = "/tmp/sc_test_cfg_wswarn_XXXXXX";
    int cfd = mkstemp(cfg_path);
    ASSERT(cfd >= 0, "mkstemp config");
    write(cfd, json, strlen(json));
    close(cfd);

    sc_config_t *cfg = sc_config_load(cfg_path);
    ASSERT_NOT_NULL(cfg);
    /* Should still resolve despite the warning */
    ASSERT_STR_EQ(cfg->gemini.api_key, "workspace-secret-key");

    sc_config_free(cfg);
    unlink(cfg_path);
    unlink(secret_path);
    rmdir(ws_dir);
}

int main(void)
{
    printf("test_config\n");

    RUN_TEST(test_config_default);
    RUN_TEST(test_config_load);
    RUN_TEST(test_config_limits);
    RUN_TEST(test_config_limits_env);
    RUN_TEST(test_config_load_missing);
    RUN_TEST(test_config_load_corrupt);
    RUN_TEST(test_config_backup);
    RUN_TEST(test_config_workspace_path);
    RUN_TEST(test_config_file_ref);
    RUN_TEST(test_config_file_ref_at);
    RUN_TEST(test_config_file_ref_env);
    RUN_TEST(test_config_file_ref_missing);
    RUN_TEST(test_config_file_ref_channel);
    RUN_TEST(test_config_file_ref_strip);
    RUN_TEST(test_config_file_ref_nonsecret);
    RUN_TEST(test_config_file_ref_workspace_warn);

    TEST_REPORT();
}
