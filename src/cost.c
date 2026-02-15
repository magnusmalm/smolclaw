/*
 * cost.c - Token usage tracking
 *
 * Persists per-model token counts to {workspace}/state/costs.json.
 * Atomic writes via temp+rename.
 */

#include "cost.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util/str.h"
#include "util/json_helpers.h"
#include "logger.h"

#define COST_TAG "cost"

/* Load JSON from file, return NULL if missing or invalid */
static cJSON *load_json(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (len <= 0 || len > 1024 * 1024) {
        fclose(f);
        return NULL;
    }

    char *buf = malloc((size_t)len + 1);
    if (!buf) { fclose(f); return NULL; }

    size_t read_len = fread(buf, 1, (size_t)len, f);
    fclose(f);
    buf[read_len] = '\0';

    cJSON *json = cJSON_Parse(buf);
    free(buf);
    return json;
}

/* Save JSON atomically (temp+rename) */
static int save_json(const char *path, cJSON *data)
{
    char *json_str = cJSON_Print(data);
    if (!json_str) return -1;

    sc_strbuf_t tmp_sb;
    sc_strbuf_init(&tmp_sb);
    sc_strbuf_appendf(&tmp_sb, "%s.tmp", path);
    char *tmp_path = sc_strbuf_finish(&tmp_sb);

    FILE *f = fopen(tmp_path, "w");
    if (!f) {
        free(json_str);
        free(tmp_path);
        return -1;
    }

    size_t len = strlen(json_str);
    size_t written = fwrite(json_str, 1, len, f);
    fclose(f);
    free(json_str);

    if (written != len) {
        unlink(tmp_path);
        free(tmp_path);
        return -1;
    }

    chmod(tmp_path, 0600);
    int ret = rename(tmp_path, path);
    free(tmp_path);
    return ret;
}

static cJSON *init_empty_data(void)
{
    cJSON *data = cJSON_CreateObject();
    cJSON_AddObjectToObject(data, "models");
    cJSON_AddNumberToObject(data, "total_turns", 0);
    cJSON_AddNumberToObject(data, "total_prompt_tokens", 0);
    cJSON_AddNumberToObject(data, "total_completion_tokens", 0);
    return data;
}

sc_cost_tracker_t *sc_cost_tracker_new(const char *workspace)
{
    if (!workspace) return NULL;

    sc_cost_tracker_t *ct = calloc(1, sizeof(*ct));
    if (!ct) return NULL;

    /* Ensure state directory exists */
    sc_strbuf_t dir_sb;
    sc_strbuf_init(&dir_sb);
    sc_strbuf_appendf(&dir_sb, "%s/state", workspace);
    char *state_dir = sc_strbuf_finish(&dir_sb);
    mkdir(state_dir, 0755);
    free(state_dir);

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/state/costs.json", workspace);
    ct->state_path = sc_strbuf_finish(&sb);

    ct->data = load_json(ct->state_path);
    if (!ct->data)
        ct->data = init_empty_data();

    return ct;
}

void sc_cost_tracker_record(sc_cost_tracker_t *ct, const char *model,
                             const char *session_key,
                             int prompt_tokens, int completion_tokens)
{
    if (!ct || !ct->data || !model) return;
    if (prompt_tokens <= 0 && completion_tokens <= 0) return;

    (void)session_key; /* Reserved for per-session tracking */

    /* Get or create model entry */
    cJSON *models = cJSON_GetObjectItem(ct->data, "models");
    if (!models) {
        models = cJSON_AddObjectToObject(ct->data, "models");
    }

    cJSON *entry = cJSON_GetObjectItem(models, model);
    if (!entry) {
        entry = cJSON_CreateObject();
        cJSON_AddNumberToObject(entry, "prompt_tokens", 0);
        cJSON_AddNumberToObject(entry, "completion_tokens", 0);
        cJSON_AddNumberToObject(entry, "turns", 0);
        cJSON_AddItemToObject(models, model, entry);
    }

    /* Increment model counters */
    cJSON *pt = cJSON_GetObjectItem(entry, "prompt_tokens");
    cJSON *ct_field = cJSON_GetObjectItem(entry, "completion_tokens");
    cJSON *turns = cJSON_GetObjectItem(entry, "turns");

    if (pt) cJSON_SetNumberValue(pt, pt->valuedouble + prompt_tokens);
    if (ct_field) cJSON_SetNumberValue(ct_field, ct_field->valuedouble + completion_tokens);
    if (turns) cJSON_SetNumberValue(turns, turns->valuedouble + 1);

    /* Increment totals */
    cJSON *tt = cJSON_GetObjectItem(ct->data, "total_turns");
    cJSON *tpt = cJSON_GetObjectItem(ct->data, "total_prompt_tokens");
    cJSON *tct = cJSON_GetObjectItem(ct->data, "total_completion_tokens");

    if (tt) cJSON_SetNumberValue(tt, tt->valuedouble + 1);
    if (tpt) cJSON_SetNumberValue(tpt, tpt->valuedouble + prompt_tokens);
    if (tct) cJSON_SetNumberValue(tct, tct->valuedouble + completion_tokens);

    /* Save atomically */
    if (save_json(ct->state_path, ct->data) != 0)
        SC_LOG_WARN(COST_TAG, "Failed to save cost data");
}

void sc_cost_tracker_print_summary(sc_cost_tracker_t *ct)
{
    if (!ct || !ct->data) {
        printf("No cost data available.\n");
        return;
    }

    cJSON *models = cJSON_GetObjectItem(ct->data, "models");
    if (!models || !models->child) {
        printf("No token usage recorded yet.\n");
        return;
    }

    printf("%-40s %12s %12s %12s %6s\n",
           "Model", "Prompt", "Completion", "Total", "Turns");
    printf("%-40s %12s %12s %12s %6s\n",
           "----------------------------------------",
           "------------", "------------", "------------", "------");

    cJSON *entry;
    cJSON_ArrayForEach(entry, models) {
        const char *name = entry->string;
        double pt = sc_json_get_double(entry, "prompt_tokens", 0);
        double ct_val = sc_json_get_double(entry, "completion_tokens", 0);
        double turns = sc_json_get_double(entry, "turns", 0);

        printf("%-40s %12.0f %12.0f %12.0f %6.0f\n",
               name, pt, ct_val, pt + ct_val, turns);
    }

    printf("%-40s %12s %12s %12s %6s\n",
           "----------------------------------------",
           "------------", "------------", "------------", "------");

    double tpt = sc_json_get_double(ct->data, "total_prompt_tokens", 0);
    double tct = sc_json_get_double(ct->data, "total_completion_tokens", 0);
    double tt = sc_json_get_double(ct->data, "total_turns", 0);

    printf("%-40s %12.0f %12.0f %12.0f %6.0f\n",
           "TOTAL", tpt, tct, tpt + tct, tt);
}

void sc_cost_tracker_reset(sc_cost_tracker_t *ct)
{
    if (!ct) return;
    cJSON_Delete(ct->data);
    ct->data = init_empty_data();
    if (save_json(ct->state_path, ct->data) != 0)
        SC_LOG_WARN(COST_TAG, "Failed to save reset cost data");
    printf("Cost data reset.\n");
}

void sc_cost_tracker_free(sc_cost_tracker_t *ct)
{
    if (!ct) return;
    free(ct->state_path);
    cJSON_Delete(ct->data);
    free(ct);
}
