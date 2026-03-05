/*
 * tee.c - Tee-on-truncation: save full tool output to disk
 *
 * When shell/background output is truncated, the full output is saved
 * to {workspace}/tee/ so the LLM can read it later via read_file.
 */

#include "tee.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "util/str.h"
#include "logger.h"

#define LOG_TAG "tee"
#define TEE_DEFAULT_MAX_FILES    50
#define TEE_DEFAULT_MAX_FILE_SIZE (10 * 1024 * 1024)  /* 10 MB */

int sc_tee_init(sc_tee_config_t *cfg, const char *workspace)
{
    if (!cfg || !workspace) return -1;

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/tee", workspace);
    cfg->tee_dir = sc_strbuf_finish(&sb);

    if (cfg->max_files <= 0)
        cfg->max_files = TEE_DEFAULT_MAX_FILES;
    if (cfg->max_file_size == 0)
        cfg->max_file_size = TEE_DEFAULT_MAX_FILE_SIZE;

    mkdir(cfg->tee_dir, 0755);
    return 0;
}

/* Compare dirent names for sorting (oldest first by name, which is epoch-prefixed) */
static int cmp_dirent_name(const void *a, const void *b)
{
    const char *na = *(const char *const *)a;
    const char *nb = *(const char *const *)b;
    return strcmp(na, nb);
}

/* Ring-buffer cleanup: remove oldest files until count <= max_files - 1 */
static void tee_cleanup(const sc_tee_config_t *cfg)
{
    DIR *d = opendir(cfg->tee_dir);
    if (!d) return;

    /* Collect regular file names */
    char **names = NULL;
    int count = 0, cap = 0;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;

        if (count >= cap) {
            cap = cap ? cap * 2 : 64;
            names = realloc(names, (size_t)cap * sizeof(char *));
            if (!names) { closedir(d); return; }
        }
        names[count++] = sc_strdup(ent->d_name);
    }
    closedir(d);

    if (count < cfg->max_files) {
        for (int i = 0; i < count; i++) free(names[i]);
        free(names);
        return;
    }

    /* Sort by name (epoch prefix → chronological order) */
    qsort(names, (size_t)count, sizeof(char *), cmp_dirent_name);

    /* Remove oldest until we have room for one more */
    int to_remove = count - (cfg->max_files - 1);
    for (int i = 0; i < to_remove && i < count; i++) {
        sc_strbuf_t path;
        sc_strbuf_init(&path);
        sc_strbuf_appendf(&path, "%s/%s", cfg->tee_dir, names[i]);
        char *p = sc_strbuf_finish(&path);
        unlink(p);
        free(p);
        SC_LOG_DEBUG(LOG_TAG, "Cleaned up tee file: %s", names[i]);
    }

    for (int i = 0; i < count; i++) free(names[i]);
    free(names);
}

char *sc_tee_save(const sc_tee_config_t *cfg, const char *output,
                  size_t output_len, const char *tool_name)
{
    if (!cfg || !cfg->tee_dir || !output || output_len == 0) return NULL;

    /* Ring-buffer cleanup first */
    tee_cleanup(cfg);

    /* Generate filename: {epoch}_{tool_name}.log */
    long epoch = (long)time(NULL);
    const char *name = tool_name ? tool_name : "unknown";

    /* Sanitize tool name (replace non-alnum with _) */
    char safe_name[64];
    int j = 0;
    for (int i = 0; name[i] && j < 62; i++) {
        char c = name[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-') {
            safe_name[j++] = c;
        } else {
            safe_name[j++] = '_';
        }
    }
    safe_name[j] = '\0';

    sc_strbuf_t filename;
    sc_strbuf_init(&filename);
    sc_strbuf_appendf(&filename, "%ld_%s.log", epoch, safe_name);
    char *fname = sc_strbuf_finish(&filename);

    sc_strbuf_t fullpath;
    sc_strbuf_init(&fullpath);
    sc_strbuf_appendf(&fullpath, "%s/%s", cfg->tee_dir, fname);
    char *fpath = sc_strbuf_finish(&fullpath);

    /* Write output, capped at max_file_size */
    FILE *f = fopen(fpath, "w");
    if (!f) {
        SC_LOG_WARN(LOG_TAG, "Failed to create tee file: %s", fpath);
        free(fpath);
        free(fname);
        return NULL;
    }

    size_t write_len = output_len;
    if (write_len > cfg->max_file_size)
        write_len = cfg->max_file_size;

    fwrite(output, 1, write_len, f);
    fclose(f);

    SC_LOG_DEBUG(LOG_TAG, "Saved %zu bytes to tee/%s", write_len, fname);

    /* Return relative path */
    sc_strbuf_t rel;
    sc_strbuf_init(&rel);
    sc_strbuf_appendf(&rel, "tee/%s", fname);
    char *result = sc_strbuf_finish(&rel);

    free(fpath);
    free(fname);
    return result;
}

void sc_tee_config_free(sc_tee_config_t *cfg)
{
    if (!cfg) return;
    free(cfg->tee_dir);
    cfg->tee_dir = NULL;
}
