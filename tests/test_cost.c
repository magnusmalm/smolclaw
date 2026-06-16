/*
 * smolclaw - cost tracker tests
 *
 * Guards the rate table and freshness logic against silent regression.
 * Exists because a stale-and-wrong cost gauge masked an upstream provider
 * outage for 3+ days; the pricing table had inflated costs ~10x via greedy
 * prefix matching, and the gauge was both stuck and over-reported.
 */

#include "test_main.h"
#include "cost.h"
#include "cJSON.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

static char *make_tmp_workspace(void)
{
    static char tmpdir[256];
    snprintf(tmpdir, sizeof(tmpdir), "/tmp/smolclaw-test-cost-%d", getpid());
    char rmcmd[300];
    snprintf(rmcmd, sizeof(rmcmd), "rm -rf %s", tmpdir);
    if (system(rmcmd) != 0) { /* best effort */ }
    if (mkdir(tmpdir, 0755) != 0 && errno != EEXIST) return NULL;
    return tmpdir;
}

static cJSON *load_costs(const char *workspace)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/state/costs.json", workspace);
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        fclose(f); free(buf); return NULL;
    }
    buf[sz] = '\0';
    fclose(f);
    cJSON *j = cJSON_Parse(buf);
    free(buf);
    return j;
}

static double get_model_cost(cJSON *root, const char *model)
{
    cJSON *models = cJSON_GetObjectItem(root, "models");
    if (!models) return -1;
    cJSON *m = cJSON_GetObjectItem(models, model);
    if (!m) return -1;
    cJSON *c = cJSON_GetObjectItem(m, "estimated_cost_usd");
    return c ? c->valuedouble : -1;
}

/* Cloud models with known rates produce non-zero estimated_cost_usd. */
static void test_known_models_have_rates(void)
{
    char *ws = make_tmp_workspace();
    sc_cost_tracker_t *ct = sc_cost_tracker_new(ws);
    ASSERT_NOT_NULL(ct);

    /* Sample of models that MUST be in the table (cumulative cost > $0
     * historically across the fleet). If any of these reads as 0, either
     * the table was edited incorrectly or exact-match resolution broke. */
    const char *must_be_rated[] = {
        "claude-haiku-4-5",
        "claude-sonnet-4-6",
        "gpt-4.1-mini",
        "gemini-2.5-flash",
        "gemini-3-flash-preview",
        "grok-4-1-fast-reasoning",
        "z-ai/glm-5",
        "deepseek-v3.2",
        NULL
    };

    for (int i = 0; must_be_rated[i]; i++) {
        sc_cost_tracker_record(ct, must_be_rated[i], "s", 1000, 1000);
    }
    sc_cost_tracker_free(ct);

    cJSON *j = load_costs(ws);
    ASSERT_NOT_NULL(j);
    for (int i = 0; must_be_rated[i]; i++) {
        double c = get_model_cost(j, must_be_rated[i]);
        if (c <= 0) {
            fprintf(stderr, "  FAIL: model '%s' produced cost %.6f "
                    "(expected > 0; missing from DEFAULT_PRICING?)\n",
                    must_be_rated[i], c);
        }
        ASSERT(c > 0, must_be_rated[i]);
    }
    cJSON_Delete(j);
}

/* Local-inference models (Ollama tag syntax with ':') cost $0 and must
 * not get an estimated_cost_usd field added. */
static void test_local_models_zero_cost(void)
{
    char *ws = make_tmp_workspace();
    sc_cost_tracker_t *ct = sc_cost_tracker_new(ws);

    sc_cost_tracker_record(ct, "qwen3.5:9b", "s", 1000, 1000);
    sc_cost_tracker_record(ct, "ollama/llama3", "s", 1000, 1000);
    sc_cost_tracker_free(ct);

    cJSON *j = load_costs(ws);
    ASSERT_NOT_NULL(j);
    /* No estimated_cost_usd field => get_model_cost returns -1 */
    ASSERT_INT_EQ((int)get_model_cost(j, "qwen3.5:9b"), -1);
    ASSERT_INT_EQ((int)get_model_cost(j, "ollama/llama3"), -1);
    cJSON_Delete(j);
}

/* Calling record() with zero tokens must not write or stamp.
 * Failed LLM calls would otherwise spuriously refresh the timestamp. */
static void test_zero_tokens_no_op(void)
{
    char *ws = make_tmp_workspace();
    sc_cost_tracker_t *ct = sc_cost_tracker_new(ws);

    /* Force a baseline write so the file exists with a known ts. */
    sc_cost_tracker_record(ct, "claude-haiku-4-5", "s", 100, 100);
    sc_cost_tracker_free(ct);

    cJSON *j_before = load_costs(ws);
    cJSON *ts_before = cJSON_GetObjectItem(j_before, "last_updated_ts");
    long ts1 = ts_before ? (long)ts_before->valuedouble : 0;
    ASSERT(ts1 > 0, "baseline last_updated_ts > 0");
    cJSON_Delete(j_before);

    sleep(2);  /* ensure clock would tick if we did stamp */

    ct = sc_cost_tracker_new(ws);
    sc_cost_tracker_record(ct, "claude-haiku-4-5", "s", 0, 0);
    sc_cost_tracker_free(ct);

    cJSON *j_after = load_costs(ws);
    cJSON *ts_after = cJSON_GetObjectItem(j_after, "last_updated_ts");
    long ts2 = ts_after ? (long)ts_after->valuedouble : 0;
    ASSERT_INT_EQ((int)ts1, (int)ts2);
    cJSON_Delete(j_after);
}

/* Recompute updates the top-level estimated_cost_usd to the sum of
 * per-model costs. An external collector probes this single field;
 * per-model alone isn't enough. */
static void test_recompute_updates_top_level(void)
{
    char *ws = make_tmp_workspace();
    sc_cost_tracker_t *ct = sc_cost_tracker_new(ws);
    sc_cost_tracker_record(ct, "claude-haiku-4-5", "s", 1000, 1000);
    sc_cost_tracker_record(ct, "gpt-4.1-mini",     "s", 1000, 1000);

    /* Manually corrupt the top-level field, then recompute. */
    /* We have no public mutator, so cheat: re-create tracker after
     * editing the on-disk file. */
    sc_cost_tracker_free(ct);

    char path[512];
    snprintf(path, sizeof(path), "%s/state/costs.json", ws);
    cJSON *j = load_costs(ws);
    cJSON *tcu = cJSON_GetObjectItem(j, "estimated_cost_usd");
    ASSERT_NOT_NULL(tcu);
    cJSON_SetNumberValue(tcu, 9999.99);
    char *out = cJSON_Print(j);
    FILE *f = fopen(path, "w");
    fputs(out, f);
    fclose(f);
    free(out);
    cJSON_Delete(j);

    ct = sc_cost_tracker_new(ws);
    int n = sc_cost_tracker_recompute(ct);
    ASSERT(n >= 1, "recompute reports >=1 change");
    sc_cost_tracker_free(ct);

    cJSON *j2 = load_costs(ws);
    double tcu2 = cJSON_GetObjectItem(j2, "estimated_cost_usd")->valuedouble;
    /* claude-haiku-4-5 @ 1.0/5.0 + gpt-4.1-mini @ 0.40/1.60 over 1k+1k
     * each => 0.001 + 0.005 + 0.0004 + 0.0016 = 0.008 USD */
    ASSERT(tcu2 > 0.0079 && tcu2 < 0.0081, "top-level USD ~0.008");
    cJSON_Delete(j2);
}

/* Provider-reported actuals override estimates and tag cost_source.
 * A turn that mixes actual + estimate ends up "mixed". */
static void test_actual_cost_tracking(void)
{
    char *ws = make_tmp_workspace();
    sc_cost_tracker_t *ct = sc_cost_tracker_new(ws);

    /* OpenRouter-style call returns its own cost — record_actual stores it */
    sc_cost_tracker_record_actual(ct, "openai/gpt-4.1-mini", "s",
                                   1000, 1000, 0.0042);
    /* Native Anthropic call doesn't report cost — record (4-arg wrapper)
     * leaves cost_source = "estimated" for that model */
    sc_cost_tracker_record(ct, "claude-haiku-4-5", "s", 1000, 1000);
    /* Same OpenRouter model used again with provider-reported cost: stays "provider" */
    sc_cost_tracker_record_actual(ct, "openai/gpt-4.1-mini", "s",
                                   500, 500, 0.0021);
    sc_cost_tracker_free(ct);

    cJSON *j = load_costs(ws);
    ASSERT_NOT_NULL(j);

    cJSON *models = cJSON_GetObjectItem(j, "models");
    cJSON *m_or = cJSON_GetObjectItem(models, "openai/gpt-4.1-mini");
    cJSON *m_an = cJSON_GetObjectItem(models, "claude-haiku-4-5");
    ASSERT_NOT_NULL(m_or);
    ASSERT_NOT_NULL(m_an);

    cJSON *or_actual = cJSON_GetObjectItem(m_or, "actual_cost_usd");
    cJSON *or_src = cJSON_GetObjectItem(m_or, "cost_source");
    ASSERT_NOT_NULL(or_actual);
    /* 0.0042 + 0.0021 = 0.0063 */
    ASSERT(or_actual->valuedouble > 0.00629 && or_actual->valuedouble < 0.00631,
           "openrouter actual ~0.0063");
    ASSERT_STR_EQ(or_src->valuestring, "provider");

    cJSON *an_actual = cJSON_GetObjectItem(m_an, "actual_cost_usd");
    cJSON *an_src = cJSON_GetObjectItem(m_an, "cost_source");
    ASSERT_NULL(an_actual);  /* never reported, no field */
    ASSERT_STR_EQ(an_src->valuestring, "estimated");

    /* Top-level actual_cost_usd reflects sum of model actuals */
    cJSON *tcu_actual = cJSON_GetObjectItem(j, "actual_cost_usd");
    ASSERT_NOT_NULL(tcu_actual);
    ASSERT(tcu_actual->valuedouble > 0.00629 && tcu_actual->valuedouble < 0.00631,
           "top-level actual ~0.0063");

    cJSON_Delete(j);

    /* Now record a call against the same model WITHOUT actual cost
     * (e.g. provider failed to return usage.cost) — cost_source should
     * downgrade from "provider" to "mixed". */
    ct = sc_cost_tracker_new(ws);
    sc_cost_tracker_record(ct, "openai/gpt-4.1-mini", "s", 100, 100);
    sc_cost_tracker_free(ct);

    cJSON *j2 = load_costs(ws);
    cJSON *m_or2 = cJSON_GetObjectItem(cJSON_GetObjectItem(j2, "models"),
                                       "openai/gpt-4.1-mini");
    ASSERT_STR_EQ(cJSON_GetObjectItem(m_or2, "cost_source")->valuestring, "mixed");
    cJSON_Delete(j2);
}

int main(void)
{
    printf("Running cost tests:\n");
    RUN_TEST(test_known_models_have_rates);
    RUN_TEST(test_local_models_zero_cost);
    RUN_TEST(test_zero_tokens_no_op);
    RUN_TEST(test_recompute_updates_top_level);
    RUN_TEST(test_actual_cost_tracking);
    TEST_REPORT();
}
