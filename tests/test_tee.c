/*
 * test_tee.c - Tests for tee-on-truncation
 */

#include "test_main.h"
#include "tee.h"

#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>

/* Helper: count files in directory */
static int count_files(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) return 0;
    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] != '.') count++;
    }
    closedir(d);
    return count;
}

/* Helper: remove directory contents */
static void clean_dir(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        unlink(path);
    }
    closedir(d);
}

static void test_tee_init(void)
{
    mkdir("/tmp/test_smolclaw_tee", 0755);

    sc_tee_config_t cfg = {0};
    int rc = sc_tee_init(&cfg, "/tmp/test_smolclaw_tee");
    ASSERT_INT_EQ(rc, 0);
    ASSERT_NOT_NULL(cfg.tee_dir);
    ASSERT(cfg.max_files == 50, "default max_files should be 50");
    ASSERT(cfg.max_file_size == 10 * 1024 * 1024, "default max_file_size should be 10MB");

    /* Directory should exist */
    struct stat st;
    ASSERT(stat(cfg.tee_dir, &st) == 0, "tee dir should exist");

    sc_tee_config_free(&cfg);
    rmdir("/tmp/test_smolclaw_tee/tee");
    rmdir("/tmp/test_smolclaw_tee");
}

static void test_tee_save(void)
{
    /* Setup */
    mkdir("/tmp/test_smolclaw_tee", 0755);
    sc_tee_config_t cfg = {0};
    sc_tee_init(&cfg, "/tmp/test_smolclaw_tee");
    clean_dir(cfg.tee_dir);

    /* Save some output */
    const char *output = "Hello, world! This is test output.\n";
    char *path = sc_tee_save(&cfg, output, strlen(output), "exec");
    ASSERT_NOT_NULL(path);
    ASSERT(strncmp(path, "tee/", 4) == 0, "path should start with tee/");
    ASSERT(strstr(path, "_exec.log") != NULL, "path should contain _exec.log");

    /* File should exist */
    char fullpath[512];
    snprintf(fullpath, sizeof(fullpath), "/tmp/test_smolclaw_tee/%s", path);
    struct stat st;
    ASSERT(stat(fullpath, &st) == 0, "tee file should exist");
    ASSERT(st.st_size == (off_t)strlen(output), "file size should match output size");

    free(path);

    /* Cleanup */
    clean_dir(cfg.tee_dir);
    rmdir(cfg.tee_dir);
    rmdir("/tmp/test_smolclaw_tee");
    sc_tee_config_free(&cfg);
}

static void test_tee_ring_buffer(void)
{
    mkdir("/tmp/test_smolclaw_tee_ring", 0755);
    sc_tee_config_t cfg = {0};
    cfg.max_files = 3;
    sc_tee_init(&cfg, "/tmp/test_smolclaw_tee_ring");
    clean_dir(cfg.tee_dir);

    /* Save 5 files — should keep only 3 */
    for (int i = 0; i < 5; i++) {
        char data[64];
        snprintf(data, sizeof(data), "output %d\n", i);
        char *path = sc_tee_save(&cfg, data, strlen(data), "test");
        free(path);
        /* Small delay so epoch differs */
        usleep(1100000); /* 1.1s to get different epoch seconds */
    }

    int file_count = count_files(cfg.tee_dir);
    ASSERT(file_count <= 3, "ring buffer should keep at most max_files");

    clean_dir(cfg.tee_dir);
    rmdir(cfg.tee_dir);
    rmdir("/tmp/test_smolclaw_tee_ring");
    sc_tee_config_free(&cfg);
}

static void test_tee_max_file_size(void)
{
    mkdir("/tmp/test_smolclaw_tee_size", 0755);
    sc_tee_config_t cfg = {0};
    cfg.max_file_size = 100;  /* 100 bytes cap */
    sc_tee_init(&cfg, "/tmp/test_smolclaw_tee_size");
    clean_dir(cfg.tee_dir);

    /* Generate output larger than cap */
    char big[256];
    memset(big, 'A', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';

    char *path = sc_tee_save(&cfg, big, strlen(big), "big");
    ASSERT_NOT_NULL(path);

    /* Check file was capped */
    char fullpath[512];
    snprintf(fullpath, sizeof(fullpath), "/tmp/test_smolclaw_tee_size/%s", path);
    struct stat st;
    ASSERT(stat(fullpath, &st) == 0, "file should exist");
    ASSERT(st.st_size <= 100, "file should be capped at max_file_size");

    free(path);
    clean_dir(cfg.tee_dir);
    rmdir(cfg.tee_dir);
    rmdir("/tmp/test_smolclaw_tee_size");
    sc_tee_config_free(&cfg);
}

static void test_tee_null_safety(void)
{
    /* NULL args should not crash */
    ASSERT_NULL(sc_tee_save(NULL, "data", 4, "test"));

    sc_tee_config_t cfg = {0};
    ASSERT_NULL(sc_tee_save(&cfg, "data", 4, "test")); /* tee_dir is NULL */

    sc_tee_config_free(NULL); /* should not crash */
}

int main(void)
{
    printf("test_tee\n");
    RUN_TEST(test_tee_init);
    RUN_TEST(test_tee_save);
    RUN_TEST(test_tee_ring_buffer);
    RUN_TEST(test_tee_max_file_size);
    RUN_TEST(test_tee_null_safety);
    TEST_REPORT();
}
