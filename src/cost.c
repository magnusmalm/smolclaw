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
#include <time.h>
#include <unistd.h>

#include "util/str.h"
#include "util/json_helpers.h"
#include "logger.h"

#include "cJSON.h"

#define COST_TAG "cost"

/* ---------- Built-in pricing ($/M tokens) ----------
 *
 * Exact-name match only. Prefix matching previously caused gemini-2.5-flash
 * to be billed at gemini-pro rates (16x overestimate) and similar drift on
 * gpt-4.1-mini and grok-fast variants. Add an explicit row per model.
 *
 * Rates last verified: 2026-05-09. When adding a model, also bump the
 * verification date in the comment beside the row. Local-inference models
 * (ollama/..., lmstudio/..., vllm/...) are NOT listed here; lookup returns
 * 0/0 and that is correct — they cost $0.
 *
 * Override at runtime by setting agents.defaults.pricing_overrides in
 * config.json: {"my-model": {"prompt": 1.0, "completion": 5.0}}.
 */

typedef struct {
    const char *name;    /* exact model name (as reported by provider) */
    double prompt;       /* $/M input tokens */
    double completion;   /* $/M output tokens */
} sc_pricing_entry_t;

static const sc_pricing_entry_t DEFAULT_PRICING[] = {
    /* Anthropic — direct API.
     * Both dash and dot variants seen in the wild ("claude-sonnet-4-6" from
     * provider, "claude-sonnet-4.6" from older config templates). */
    {"claude-opus-4-7",                 15.0,   75.0},
    {"claude-opus-4-6",                 15.0,   75.0},
    {"claude-opus-4-5",                 15.0,   75.0},
    {"claude-sonnet-4-7",                3.0,   15.0},
    {"claude-sonnet-4-6",                3.0,   15.0},
    {"claude-sonnet-4.6",                3.0,   15.0},
    {"claude-sonnet-4-5",                3.0,   15.0},
    {"claude-haiku-4-5",                 1.0,    5.0},
    {"claude-haiku-4-5-20251001",        1.0,    5.0},
    {"claude-haiku-4.5",                 1.0,    5.0},
    /* OpenAI — direct API */
    {"gpt-4.1",                          2.0,    8.0},
    {"gpt-4.1-mini",                     0.40,   1.60},
    {"gpt-4.1-nano",                     0.10,   0.40},
    {"gpt-4o",                           2.50,  10.0},
    {"gpt-4o-mini",                      0.15,   0.60},
    {"o3",                               2.0,    8.0},
    {"o4-mini",                          1.10,   4.40},
    /* xAI — direct API */
    {"grok-4",                           3.0,   15.0},
    {"grok-4-1",                         3.0,   15.0},
    {"grok-4-1-fast-reasoning",          0.20,   0.50},
    {"grok-4-1-fast",                    0.20,   0.50},
    {"grok-4-fast-reasoning",            0.20,   0.50},
    {"grok-4-fast",                      0.20,   0.50},
    /* Google Gemini — direct API */
    {"gemini-2.5-flash",                 0.075,  0.30},
    {"gemini-2.5-pro",                   1.25,   5.0},
    {"gemini-3-flash-preview",           0.075,  0.30},
    {"gemini-3-pro-preview",             1.25,   5.0},
    /* OpenRouter passthrough — keep both raw and openrouter-prefixed forms */
    {"anthropic/claude-haiku-4-5",       1.0,    5.0},
    {"anthropic/claude-sonnet-4-6",      3.0,   15.0},
    {"openai/gpt-4.1-mini",              0.40,   1.60},
    {"x-ai/grok-4-1-fast-reasoning",     0.20,   0.50},
    {"google/gemini-2.5-flash",          0.075,  0.30},
    {"google/gemini-3-flash-preview",    0.075,  0.30},
    {"z-ai/glm-4.6",                     0.14,   0.14},
    {"z-ai/glm-5",                       0.14,   0.14},
    {"z-ai/glm-5.1",                     0.14,   0.14},
    {"glm-5",                            0.14,   0.14},
    {"glm-5.1",                          0.14,   0.14},
    {"moonshotai/kimi-k2",               0.14,   0.28},
    {"moonshotai/kimi-k2.5",             0.14,   0.28},
    {"deepseek/deepseek-chat",           0.27,   1.10},
    {"deepseek-chat",                    0.27,   1.10},
    {"deepseek/deepseek-v3.2",           0.27,   1.10},
    {"deepseek-v3.2",                    0.27,   1.10},
    /* Qwen — paid OpenRouter variants (the slash means cloud-hosted; the
     * "qwen3.5:9b"-style colon names are local-Ollama and stay zero). */
    {"qwen/qwen3-coder",                 0.30,   1.20},
    {"qwen/qwen3-coder-next",            0.30,   1.20},
    {"qwen/qwen3.6-plus",                0.40,   1.60},
    {"qwen/qwen3.6-plus:free",           0.0,    0.0},
    /* Sentinel */
    {NULL, 0, 0}
};

/* Models we treat as known-zero-cost and never warn about:
 *   - explicit local-inference prefixes
 *   - any name containing ':' (Ollama tag syntax: "qwen3.5:9b", "gemma4:31b").
 *     Cloud providers use '/' for namespacing, never ':', so ':' is a
 *     reliable local-inference marker.
 */
static const char *KNOWN_ZERO_COST_PREFIXES[] = {
    "ollama/", "lmstudio/", "vllm/", "local/", "tgi/", NULL
};

static int is_known_zero_cost(const char *model)
{
    if (!model) return 0;
    if (strchr(model, ':')) return 1;
    for (int i = 0; KNOWN_ZERO_COST_PREFIXES[i]; i++) {
        size_t plen = strlen(KNOWN_ZERO_COST_PREFIXES[i]);
        if (strncmp(model, KNOWN_ZERO_COST_PREFIXES[i], plen) == 0)
            return 1;
    }
    return 0;
}

struct sc_cost_tracker {
    char *state_path;       /* {workspace}/state/costs.json */
    cJSON *data;            /* {"models":{...}, "total_turns":N} */
    cJSON *pricing_config;  /* borrowed from config, may be NULL */
    cJSON *warned_models;   /* set of model names we've already warned about */
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

    /* Exact-match built-in table */
    for (int i = 0; DEFAULT_PRICING[i].name; i++) {
        if (strcmp(model, DEFAULT_PRICING[i].name) == 0) {
            *out_prompt = DEFAULT_PRICING[i].prompt;
            *out_completion = DEFAULT_PRICING[i].completion;
            return;
        }
    }
}

double
sc_cost_tracker_estimate(const sc_cost_tracker_t *ct, const char *model,
                          int prompt_tokens, int completion_tokens)
{
    sc_cost_tracker_t defaults_only = {0};
    double p = 0, c = 0;
    lookup_rate(ct ? ct : &defaults_only, model, &p, &c);
    return (prompt_tokens * p + completion_tokens * c) / 1e6;
}

/* Warn once per process per unknown model. Returns 1 if this is the first
 * sighting and a warning was emitted. Suppressed for known-zero-cost
 * (local-inference) prefixes. */
static int warn_unknown_model_once(sc_cost_tracker_t *ct, const char *model)
{
    if (!ct || !model) return 0;
    if (is_known_zero_cost(model)) return 0;

    if (!ct->warned_models)
        ct->warned_models = cJSON_CreateArray();

    int n = cJSON_GetArraySize(ct->warned_models);
    for (int i = 0; i < n; i++) {
        cJSON *e = cJSON_GetArrayItem(ct->warned_models, i);
        if (e && cJSON_IsString(e) && strcmp(e->valuestring, model) == 0)
            return 0;
    }
    cJSON_AddItemToArray(ct->warned_models, cJSON_CreateString(model));
    SC_LOG_WARN(COST_TAG,
        "no pricing entry for model '%s' — recording $0; "
        "add an exact entry to DEFAULT_PRICING in src/cost.c "
        "or set agents.defaults.pricing_overrides in config", model);
    return 1;
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

/* Stamp the top-level last_updated_ts to the current epoch second.
 * Consumers (smolswarm alert.c) treat a missing or stale value as
 * "cost data is not fresh; do not fire cost_high alarms on it." */
static void stamp_updated(cJSON *data)
{
    if (!data) return;
    long ts = (long)time(NULL);
    cJSON *e = cJSON_GetObjectItem(data, "last_updated_ts");
    if (e)
        cJSON_SetNumberValue(e, (double)ts);
    else
        cJSON_AddNumberToObject(data, "last_updated_ts", (double)ts);
}

static cJSON *init_empty_data(void)
{
    cJSON *data = cJSON_CreateObject();
    cJSON_AddObjectToObject(data, "models");
    cJSON_AddNumberToObject(data, "total_turns", 0);
    cJSON_AddNumberToObject(data, "total_prompt_tokens", 0);
    cJSON_AddNumberToObject(data, "total_completion_tokens", 0);
    /* Initialize to 0 so a never-recorded tracker reads as not-fresh. */
    cJSON_AddNumberToObject(data, "last_updated_ts", 0);
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
    sc_cost_tracker_record_actual(ct, model, session_key,
                                   prompt_tokens, completion_tokens, -1.0);
}

void sc_cost_tracker_record_actual(sc_cost_tracker_t *ct, const char *model,
                                    const char *session_key,
                                    int prompt_tokens, int completion_tokens,
                                    double actual_cost_usd)
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
    } else {
        warn_unknown_model_once(ct, model);
    }

    /* Provider-reported actual cost (OpenRouter usage.cost). Accumulated
     * separately so we can compare estimate vs truth. cost_source tracks
     * whether this model has ever seen an actual: "provider" if every
     * call had one, "estimated" if none have, "mixed" if some did. */
    if (actual_cost_usd >= 0) {
        cJSON *acu = cJSON_GetObjectItem(entry, "actual_cost_usd");
        if (acu)
            cJSON_SetNumberValue(acu, acu->valuedouble + actual_cost_usd);
        else
            cJSON_AddNumberToObject(entry, "actual_cost_usd", actual_cost_usd);

        cJSON *src = cJSON_GetObjectItem(entry, "cost_source");
        const char *cur = (src && cJSON_IsString(src)) ? src->valuestring : NULL;
        const char *next = (!cur || strcmp(cur, "estimated") == 0)
                           ? (cur ? "mixed" : "provider")
                           : cur;  /* already "provider" or "mixed" */
        if (src) cJSON_SetValuestring(src, next);
        else cJSON_AddStringToObject(entry, "cost_source", next);
    } else {
        cJSON *src = cJSON_GetObjectItem(entry, "cost_source");
        if (!src) {
            cJSON_AddStringToObject(entry, "cost_source", "estimated");
        } else if (cJSON_IsString(src) &&
                   strcmp(src->valuestring, "provider") == 0) {
            cJSON_SetValuestring(src, "mixed");
        }
    }

    stamp_updated(ct->data);

    /* Recompute totals across all models. Also surface actual_cost_usd at
     * the top level so smolswarm can compare cost_source="provider"/"mixed"
     * data against estimates without walking the per-model dict. */
    double total_estimate = 0;
    double total_actual = 0;
    int any_actual = 0;
    cJSON *m;
    cJSON_ArrayForEach(m, models) {
        cJSON *c = cJSON_GetObjectItem(m, "estimated_cost_usd");
        if (c) total_estimate += c->valuedouble;
        cJSON *a = cJSON_GetObjectItem(m, "actual_cost_usd");
        if (a) { total_actual += a->valuedouble; any_actual = 1; }
    }
    cJSON *tc_usd = cJSON_GetObjectItem(ct->data, "estimated_cost_usd");
    if (tc_usd)
        cJSON_SetNumberValue(tc_usd, total_estimate);
    else
        cJSON_AddNumberToObject(ct->data, "estimated_cost_usd", total_estimate);

    if (any_actual) {
        cJSON *ta = cJSON_GetObjectItem(ct->data, "actual_cost_usd");
        if (ta) cJSON_SetNumberValue(ta, total_actual);
        else cJSON_AddNumberToObject(ct->data, "actual_cost_usd", total_actual);
    }

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

/* Recompute estimated_cost_usd for every model entry against the current
 * pricing table. Use after editing DEFAULT_PRICING or pricing_overrides to
 * retroactively correct stale costs without waiting for new traffic. */
int sc_cost_tracker_recompute(sc_cost_tracker_t *ct)
{
    if (!ct || !ct->data) return -1;
    cJSON *models = cJSON_GetObjectItem(ct->data, "models");
    if (!models) return 0;

    int changed = 0;
    cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, models) {
        const char *name = entry->string;
        if (!name) continue;

        double prompt_rate = 0, completion_rate = 0;
        lookup_rate(ct, name, &prompt_rate, &completion_rate);

        cJSON *pt = cJSON_GetObjectItem(entry, "prompt_tokens");
        cJSON *cf = cJSON_GetObjectItem(entry, "completion_tokens");
        double model_pt = pt ? pt->valuedouble : 0;
        double model_ct = cf ? cf->valuedouble : 0;

        cJSON *cost_field = cJSON_GetObjectItem(entry, "estimated_cost_usd");
        if (prompt_rate <= 0 && completion_rate <= 0) {
            warn_unknown_model_once(ct, name);
            if (cost_field) {
                cJSON_DeleteItemFromObject(entry, "estimated_cost_usd");
                changed++;
            }
            continue;
        }

        double new_cost = compute_cost(prompt_rate, completion_rate,
                                        model_pt, model_ct);
        if (cost_field) {
            if (cost_field->valuedouble != new_cost) {
                cJSON_SetNumberValue(cost_field, new_cost);
                changed++;
            }
        } else {
            cJSON_AddNumberToObject(entry, "estimated_cost_usd", new_cost);
            changed++;
        }
    }

    /* Refresh the top-level estimated_cost_usd (sum of per-model costs).
     * smolswarm probes this single field via $.tokens.estimated_cost_usd;
     * leaving it stale was what kept the supervisor's frozen-cost alarm
     * firing after the rate-table fix. */
    double total_cost = 0;
    cJSON_ArrayForEach(entry, models) {
        cJSON *c = cJSON_GetObjectItem(entry, "estimated_cost_usd");
        if (c) total_cost += c->valuedouble;
    }
    cJSON *tc_usd = cJSON_GetObjectItem(ct->data, "estimated_cost_usd");
    if (tc_usd) {
        if (tc_usd->valuedouble != total_cost) {
            cJSON_SetNumberValue(tc_usd, total_cost);
            changed++;
        }
    } else {
        cJSON_AddNumberToObject(ct->data, "estimated_cost_usd", total_cost);
        changed++;
    }

    if (changed > 0) {
        stamp_updated(ct->data);
        if (save_json(ct->state_path, ct->data) != 0)
            SC_LOG_WARN(COST_TAG, "Failed to save recomputed cost data");
    }

    return changed;
}

void sc_cost_tracker_free(sc_cost_tracker_t *ct)
{
    if (!ct) return;
    free(ct->state_path);
    cJSON_Delete(ct->data);
    cJSON_Delete(ct->warned_models);
    free(ct);
}
