#include "state.h"
#include "logger.h"
#include "util/str.h"
#include "util/json_helpers.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#define LOG_TAG "state"

/* ---- Internal helpers ---- */

static char *state_dir_path(const char *workspace)
{
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/state", workspace);
    return sc_strbuf_finish(&sb);
}

static char *state_file_path(const char *workspace)
{
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/state/state.json", workspace);
    return sc_strbuf_finish(&sb);
}

static int save_state(sc_state_t *st)
{
    if (!st || !st->workspace) return -1;

    char *fpath = state_file_path(st->workspace);
    if (!fpath) return -1;

    cJSON *root = cJSON_CreateObject();
    if (!root) { free(fpath); return -1; }

    if (st->last_channel)
        cJSON_AddStringToObject(root, "last_channel", st->last_channel);
    cJSON_AddNumberToObject(root, "timestamp", (double)st->timestamp);

    int ret = sc_json_save_file(fpath, root);
    cJSON_Delete(root);
    free(fpath);
    return ret;
}

static void load_state(sc_state_t *st)
{
    if (!st || !st->workspace) return;

    char *fpath = state_file_path(st->workspace);
    if (!fpath) return;

    cJSON *root = sc_json_load_file(fpath);
    free(fpath);
    if (!root) return;

    st->last_channel = sc_strdup(sc_json_get_string(root, "last_channel", NULL));
    st->timestamp    = (long)sc_json_get_double(root, "timestamp", 0.0);

    cJSON_Delete(root);

    SC_LOG_DEBUG(LOG_TAG, "loaded state: last_channel=%s",
                 st->last_channel ? st->last_channel : "(none)");
}

/* ---- Public API ---- */

sc_state_t *sc_state_new(const char *workspace)
{
    sc_state_t *st = calloc(1, sizeof(*st));
    if (!st) return NULL;

    st->workspace = sc_strdup(workspace);

    /* Ensure state directory exists */
    char *dir = state_dir_path(workspace);
    if (dir) {
        mkdir(dir, 0755);
        free(dir);
    }

    load_state(st);
    return st;
}

void sc_state_free(sc_state_t *st)
{
    if (!st) return;
    free(st->workspace);
    free(st->last_channel);
    free(st);
}

const char *sc_state_get_last_channel(const sc_state_t *st)
{
    if (!st) return NULL;
    return st->last_channel;
}

int sc_state_set_last_channel(sc_state_t *st, const char *channel)
{
    if (!st) return -1;

    free(st->last_channel);
    st->last_channel = sc_strdup(channel);
    st->timestamp    = (long)time(NULL);

    return save_state(st);
}
