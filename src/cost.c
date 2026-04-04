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

#include "cJSON.h"

#define COST_TAG "cost"

/* ---------- Built-in pricing ($/M tokens) ---------- */

typedef struct {
    const char *prefix;  /* model name prefix to match */
    double prompt;       /* $/M input tokens */
    double completion;   /* $/M output tokens */
} sc_pricing_entry_t;

static const sc_pricing_entry_t DEFAULT_PRICING[] = {
    /* Anthropic */
    {"claude-opus-4",       15.0,   75.0},
    {"claude-sonnet-4",      3.0,   15.0},
    {"claude-haiku-4",       0.80,   4.0},
    /* OpenAI */
    {"gpt-4o",               2.50,  10.0},
    {"gpt-4.1",              2.0,    8.0},
    {"o3",                   2.50,  10.0},
    {"o4-mini",              1.10,   4.40},
    /* OpenRouter-prefixed models */
    {"z-ai/glm",             0.14,   0.14},
    {"moonshotai/kimi",      0.14,   0.28},
    {"deepseek",             0.27,   1.10},
    {"x-ai/grok",            3.0,   15.0},
    {"google/gemini",        1.25,   5.0},
    /* Raw model names (as returned by provider APIs) */
    {"gemini",               1.25,   5.0},
    {"glm",                  0.14,   0.14},
    {"kimi",                 0.14,   0.28},
    {"grok",                 3.0,   15.0},
    /* Sentinel */
    {NULL, 0, 0}
};

struct sc_cost_tracker {
    char *state_path;       /* {workspace}/state/costs.json */
    cJSON *data;            /* {"models":{...}, "total_turns":N} */
    cJSON *pricing_config;  /* borrowed from config, may be NULL */
};

/* Look up pricing rate for a model. Checks config overrides first,
 * then prefix-matches the built-in table. Returns {0,0} for local/unknown. */
static void
lookup_rate(const sc_cost_tracker_t *ct, const char *model,
            double *out_prompt, double *out_completion)
{
    *out_prompt = 0;
    *out_completion = 0;

    if (!model) return;

    /* Check config overrides first (exact match) */
    if (ct->pricing_config) {
        cJSON *entry = cJSON_GetObjectItem(ct->pricing_config, model);
        if (entry && cJSON_IsObject(entry)) {
            cJSON *p = cJSON_GetObjectItem(entry, "prompt");
            cJSON *c = cJSON_GetObjectItem(entry, "completion");
            if (p) *out_prompt = p->valuedouble;
            if (c) *out_completion = c->valuedouble;
            return;
        }
    }

    /* Prefix-match built-in table */
    for (int i = 0; DEFAULT_PRICING[i].prefix; i++) {
        if (strncmp(model, DEFAULT_PRICING[i].prefix,
                    strlen(DEFAULT_PRICING[i].prefix)) == 0) {
            *out_prompt = DEFAULT_PRICING[i].prompt;
            *out_completion = DEFAULT_PRICING[i].completion;
            return;
        }
    }
}

static double
compute_cost(double prompt_rate, double completion_rate,
             double prompt_tokens, double completion_tokens)
{
    return (prompt_tokens * prompt_rate + completion_tokens * completion_rate) / 1e6;
}

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
    if (written == len) {
        fflush(f);
        fsync(fileno(f));
    }
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

void sc_cost_tracker_set_pricing(sc_cost_tracker_t *ct, cJSON *overrides)
{
    if (ct) ct->pricing_config = overrides;
}

void sc_cost_tracker_record(sc_cost_tracker_t *ct, const char *model,
                             const char *session_key,
                             int prompt_tokens, int completion_tokens)
{
    if (!ct || !ct->data || !model) return;
    if (prompt_tokens <= 0 && completion_tokens <= 0) return;

    /* Per-session tracking */
    if (session_key && session_key[0]) {
        cJSON *sessions = cJSON_GetObjectItem(ct->data, "sessions");
        if (!sessions) {
            sessions = cJSON_AddObjectToObject(ct->data, "sessions");
        }
        cJSON *sess = cJSON_GetObjectItem(sessions, session_key);
        if (!sess) {
            sess = cJSON_CreateObject();
            cJSON_AddNumberToObject(sess, "prompt_tokens", 0);
            cJSON_AddNumberToObject(sess, "completion_tokens", 0);
            cJSON_AddNumberToObject(sess, "turns", 0);
            cJSON_AddItemToObject(sessions, session_key, sess);
        }
        cJSON *spt = cJSON_GetObjectItem(sess, "prompt_tokens");
        cJSON *sct = cJSON_GetObjectItem(sess, "completion_tokens");
        cJSON *st = cJSON_GetObjectItem(sess, "turns");
        if (spt) cJSON_SetNumberValue(spt, spt->valuedouble + prompt_tokens);
        if (sct) cJSON_SetNumberValue(sct, sct->valuedouble + completion_tokens);
        if (st) cJSON_SetNumberValue(st, st->valuedouble + 1);
    }

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

    /* Compute and store estimated cost per model */
    double prompt_rate, completion_rate;
    lookup_rate(ct, model, &prompt_rate, &completion_rate);

    if (prompt_rate > 0 || completion_rate > 0) {
        double model_pt = pt ? pt->valuedouble : 0;
        double model_ct = ct_field ? ct_field->valuedouble : 0;
        double model_cost = compute_cost(prompt_rate, completion_rate,
                                         model_pt, model_ct);
        cJSON *cost_field = cJSON_GetObjectItem(entry, "estimated_cost_usd");
        if (cost_field)
            cJSON_SetNumberValue(cost_field, model_cost);
        else
            cJSON_AddNumberToObject(entry, "estimated_cost_usd", model_cost);
    }

    /* Recompute total estimated cost across all models */
    double total_cost = 0;
    cJSON *m;
    cJSON_ArrayForEach(m, models) {
        cJSON *c = cJSON_GetObjectItem(m, "estimated_cost_usd");
        if (c) total_cost += c->valuedouble;
    }
    cJSON *tc_usd = cJSON_GetObjectItem(ct->data, "estimated_cost_usd");
    if (tc_usd)
        cJSON_SetNumberValue(tc_usd, total_cost);
    else
        cJSON_AddNumberToObject(ct->data, "estimated_cost_usd", total_cost);

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

    printf("%-32s %10s %10s %10s %5s %10s\n",
           "Model", "Prompt", "Compl.", "Total", "Turns", "Est. Cost");
    printf("%-32s %10s %10s %10s %5s %10s\n",
           "--------------------------------",
           "----------", "----------", "----------", "-----", "----------");

    double total_cost = 0;
    cJSON *entry;
    cJSON_ArrayForEach(entry, models) {
        const char *name = entry->string;
        double pt = sc_json_get_double(entry, "prompt_tokens", 0);
        double ct_val = sc_json_get_double(entry, "completion_tokens", 0);
        double turns = sc_json_get_double(entry, "turns", 0);

        /* Compute cost (live from rates, not just stored value) */
        double prompt_rate, completion_rate;
        lookup_rate(ct, name, &prompt_rate, &completion_rate);
        double cost = compute_cost(prompt_rate, completion_rate, pt, ct_val);
        total_cost += cost;

        char cost_str[16];
        if (cost > 0)
            snprintf(cost_str, sizeof(cost_str), "$%.4f", cost);
        else
            snprintf(cost_str, sizeof(cost_str), "$0.00");

        /* Truncate long model names */
        char short_name[33];
        if (strlen(name) > 32) {
            memcpy(short_name, name, 29);
            short_name[29] = '.';
            short_name[30] = '.';
            short_name[31] = '.';
            short_name[32] = '\0';
        } else {
            snprintf(short_name, sizeof(short_name), "%s", name);
        }

        printf("%-32s %10.0f %10.0f %10.0f %5.0f %10s\n",
               short_name, pt, ct_val, pt + ct_val, turns, cost_str);
    }

    printf("%-32s %10s %10s %10s %5s %10s\n",
           "--------------------------------",
           "----------", "----------", "----------", "-----", "----------");

    double tpt = sc_json_get_double(ct->data, "total_prompt_tokens", 0);
    double tct = sc_json_get_double(ct->data, "total_completion_tokens", 0);
    double tt = sc_json_get_double(ct->data, "total_turns", 0);

    char total_cost_str[16];
    snprintf(total_cost_str, sizeof(total_cost_str), "$%.4f", total_cost);

    printf("%-32s %10.0f %10.0f %10.0f %5.0f %10s\n",
           "TOTAL", tpt, tct, tpt + tct, tt, total_cost_str);
}

void sc_cost_tracker_print_sessions(sc_cost_tracker_t *ct)
{
    if (!ct || !ct->data) {
        printf("No cost data available.\n");
        return;
    }

    cJSON *sessions = cJSON_GetObjectItem(ct->data, "sessions");
    if (!sessions || !sessions->child) {
        printf("No per-session data recorded yet.\n");
        return;
    }

    printf("%-40s %10s %10s %10s %5s\n",
           "Session", "Prompt", "Compl.", "Total", "Turns");
    printf("%-40s %10s %10s %10s %5s\n",
           "----------------------------------------",
           "----------", "----------", "----------", "-----");

    cJSON *entry;
    cJSON_ArrayForEach(entry, sessions) {
        const char *key = entry->string;
        double pt = sc_json_get_double(entry, "prompt_tokens", 0);
        double ct_val = sc_json_get_double(entry, "completion_tokens", 0);
        double turns = sc_json_get_double(entry, "turns", 0);

        char short_key[41];
        if (strlen(key) > 40) {
            memcpy(short_key, key, 37);
            short_key[37] = '.';
            short_key[38] = '.';
            short_key[39] = '.';
            short_key[40] = '\0';
        } else {
            snprintf(short_key, sizeof(short_key), "%s", key);
        }

        printf("%-40s %10.0f %10.0f %10.0f %5.0f\n",
               short_key, pt, ct_val, pt + ct_val, turns);
    }
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
