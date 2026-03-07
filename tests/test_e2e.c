/*
 * smolclaw - E2E tests for CLI commands
 * Invokes the actual binary via popen() and checks output + exit code.
 */

#include "test_main.h"

#include <ftw.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

#define BIN "./build/smolclaw"

static char saved_home[PATH_MAX];
static char test_home[64];

/* Run command, capture merged stdout+stderr, return exit code */
static int run_cmd(const char *cmd, char *out, size_t out_sz)
{
    char full[1024];
    snprintf(full, sizeof(full), "%s 2>&1", cmd);

    FILE *fp = popen(full, "r");
    if (!fp) {
        out[0] = '\0';
        return -1;
    }

    size_t total = 0;
    while (total < out_sz - 1) {
        size_t n = fread(out + total, 1, out_sz - 1 - total, fp);
        if (n == 0) break;
        total += n;
    }
    out[total] = '\0';

    int status = pclose(fp);
    if (status == -1) return -1;
    return WEXITSTATUS(status);
}

static int nftw_remove_cb(const char *path, const struct stat *sb,
                           int typeflag, struct FTW *ftwbuf)
{
    (void)sb; (void)typeflag; (void)ftwbuf;
    remove(path);
    return 0;
}

static void setup_home(void)
{
    const char *h = getenv("HOME");
    if (h) strncpy(saved_home, h, sizeof(saved_home) - 1);
    else saved_home[0] = '\0';

    strcpy(test_home, "/tmp/sc_e2e_XXXXXX");
    char *d = mkdtemp(test_home);
    (void)d;
    setenv("HOME", test_home, 1);
}

static void teardown_home(void)
{
    if (saved_home[0])
        setenv("HOME", saved_home, 1);
    else
        unsetenv("HOME");

    nftw(test_home, nftw_remove_cb, 64, FTW_DEPTH | FTW_PHYS);
}

/* Helper: run onboard in the tmpdir (non-interactive, fresh HOME = no prompt) */
static void do_onboard(void)
{
    /* Create ~/.smolclaw/ dir — onboard expects it to exist */
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s/.smolclaw", test_home);
    mkdir(dir, 0755);

    char out[4096];
    run_cmd(BIN " onboard", out, sizeof(out));
}

/* ======================================================================
 * 1. version
 * ====================================================================== */

static void test_version_exit_code(void)
{
    char out[1024];
    int rc = run_cmd(BIN " version", out, sizeof(out));
    ASSERT_INT_EQ(rc, 0);
}

static void test_version_output(void)
{
    char out[1024];
    run_cmd(BIN " version", out, sizeof(out));
    ASSERT(strstr(out, "smolclaw") != NULL, "version output contains 'smolclaw'");
    /* Match a version-like pattern: digit.digit */
    int has_version = 0;
    for (const char *p = out; *p; p++) {
        if (*p >= '0' && *p <= '9' && *(p+1) == '.' && *(p+2) >= '0' && *(p+2) <= '9')
            { has_version = 1; break; }
    }
    ASSERT(has_version, "version output contains N.N pattern");
}

static void test_version_aliases(void)
{
    char out_v[1024], out_flag[1024], out_long[1024];
    run_cmd(BIN " version", out_v, sizeof(out_v));
    run_cmd(BIN " -v", out_flag, sizeof(out_flag));
    run_cmd(BIN " --version", out_long, sizeof(out_long));
    ASSERT_STR_EQ(out_v, out_flag);
    ASSERT_STR_EQ(out_v, out_long);
}

/* ======================================================================
 * 2. onboard
 * ====================================================================== */

static void test_onboard_fresh(void)
{
    setup_home();

    /* Create ~/.smolclaw/ dir — onboard expects it to exist */
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s/.smolclaw", test_home);
    mkdir(dir, 0755);

    char out[4096];
    int rc = run_cmd(BIN " onboard", out, sizeof(out));
    ASSERT_INT_EQ(rc, 0);
    ASSERT(strstr(out, "is ready") != NULL, "onboard says 'is ready'");

    /* Config file created */
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/.smolclaw/config.json", test_home);
    struct stat st;
    ASSERT(stat(path, &st) == 0, "config.json exists after onboard");

    /* Workspace dir created */
    snprintf(path, sizeof(path), "%s/.smolclaw/workspace", test_home);
    ASSERT(stat(path, &st) == 0 && S_ISDIR(st.st_mode),
           "workspace dir exists after onboard");

    teardown_home();
}

static void test_onboard_workspace_files(void)
{
    setup_home();
    do_onboard();

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/.smolclaw/workspace/AGENTS.md", test_home);
    struct stat st;
    ASSERT(stat(path, &st) == 0, "AGENTS.md exists in workspace");

    teardown_home();
}

/* ======================================================================
 * 3. doctor
 * ====================================================================== */

static void test_doctor_no_config(void)
{
    setup_home();

    char out[4096];
    run_cmd(BIN " doctor", out, sizeof(out));
    ASSERT(strstr(out, "[FAIL]") != NULL || strstr(out, "FAIL") != NULL,
           "doctor without config reports failure");

    teardown_home();
}

static void test_doctor_after_onboard(void)
{
    setup_home();
    do_onboard();

    char out[8192];
    run_cmd(BIN " doctor", out, sizeof(out));

    ASSERT(strstr(out, "PASS") != NULL, "doctor has at least one PASS");
    /* API key won't be set in default config */
    ASSERT(strstr(out, "FAIL") != NULL, "doctor has at least one FAIL (no API key)");
    /* Summary line */
    ASSERT(strstr(out, "passed") != NULL && strstr(out, "failed") != NULL,
           "doctor prints summary with passed/failed");

    teardown_home();
}

/* ======================================================================
 * 4. cost
 * ====================================================================== */

static void test_cost_no_config(void)
{
    setup_home();

    char out[4096];
    run_cmd(BIN " cost", out, sizeof(out));
    /* Config load falls through to defaults, no state file → no usage */
    ASSERT(strstr(out, "No token usage") != NULL ||
           strstr(out, "No cost data") != NULL,
           "cost without config shows no data");

    teardown_home();
}

static void test_cost_empty(void)
{
    setup_home();
    do_onboard();

    char out[4096];
    run_cmd(BIN " cost", out, sizeof(out));
    ASSERT(strstr(out, "No token usage") != NULL ||
           strstr(out, "No cost data") != NULL,
           "cost after onboard shows no data");

    teardown_home();
}

/* ======================================================================
 * 5. analytics (feature-gated)
 * ====================================================================== */

static void test_analytics_empty(void)
{
    setup_home();
    do_onboard();

    char out[4096];
    run_cmd(BIN " analytics summary", out, sizeof(out));

    /* If built without SC_ENABLE_ANALYTICS, it returns "Unknown command" — pass */
    if (strstr(out, "Unknown command") != NULL) {
        ASSERT(1, "analytics not compiled in — skip");
        teardown_home();
        return;
    }

    /* Empty DB: aggregate returns one row with 0 turns */
    ASSERT(strstr(out, "turns") != NULL,
           "analytics summary shows header");

    teardown_home();
}

/* ====================================================================== */

int main(void)
{
    printf("test_e2e\n");

    RUN_TEST(test_version_exit_code);
    RUN_TEST(test_version_output);
    RUN_TEST(test_version_aliases);
    RUN_TEST(test_onboard_fresh);
    RUN_TEST(test_onboard_workspace_files);
    RUN_TEST(test_doctor_no_config);
    RUN_TEST(test_doctor_after_onboard);
    RUN_TEST(test_cost_no_config);
    RUN_TEST(test_cost_empty);
    RUN_TEST(test_analytics_empty);

    TEST_REPORT();
}
