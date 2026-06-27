/*
 * providers/moa.c - Mixture of Agents (MoA-lite) virtual provider (task 2.13)
 *
 * See docs/design/mixture-of-agents.md.
 */

#include "providers/moa.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "providers/factory.h"
#include "logger.h"
#include "util/str.h"

#define LOG_TAG "moa"

/* ---------------- message helpers ---------------- */

sc_llm_message_t *sc_msgs_reference_view(const sc_llm_message_t *msgs, int count,
                                         int *out_count)
{
    if (out_count) *out_count = 0;
    if (!msgs || count <= 0) return NULL;

    sc_llm_message_t *out = calloc((size_t)count, sizeof(*out));
    if (!out) return NULL;

    int n = 0;
    for (int i = 0; i < count; i++) {
        const char *role = msgs[i].role;
        if (!role) continue;
        if (strcmp(role, "system") == 0) continue;   /* no system prompt */
        if (strcmp(role, "tool") == 0) continue;      /* no tool rows */
        if (msgs[i].tool_call_id) continue;           /* tool result */
        const char *content = msgs[i].content;
        if (!content || !content[0]) continue;        /* skip tool-only turns */

        out[n].role = sc_strdup(role);
        out[n].content = sc_strdup(content);          /* text only, no tool_calls */
        n++;
    }

    if (out_count) *out_count = n;
    return out;
}

sc_llm_message_t *sc_msgs_inject_moa_refs(const sc_llm_message_t *msgs, int count,
                                          char *const *labels, char *const *texts,
                                          int ref_count, int *out_count)
{
    if (out_count) *out_count = 0;
    if (!msgs || count <= 0) return NULL;

    /* Build the injection block. */
    sc_strbuf_t inj;
    sc_strbuf_init(&inj);
    for (int i = 0; i < ref_count; i++) {
        sc_strbuf_appendf(&inj, "\n\n[MoA reference: %s]\n%s",
                          labels && labels[i] ? labels[i] : "?",
                          texts && texts[i] ? texts[i] : "");
    }
    char *injection = sc_strbuf_finish(&inj);

    /* Find the last user message. */
    int last_user = -1;
    for (int i = count - 1; i >= 0; i--) {
        if (msgs[i].role && strcmp(msgs[i].role, "user") == 0) { last_user = i; break; }
    }

    int total = (last_user >= 0) ? count : count + 1;
    sc_llm_message_t *out = calloc((size_t)total, sizeof(*out));
    if (!out) { free(injection); return NULL; }

    for (int i = 0; i < count; i++)
        out[i] = sc_llm_message_clone(&msgs[i]);

    if (last_user >= 0) {
        const char *old = out[last_user].content;
        size_t len = (old ? strlen(old) : 0) + strlen(injection) + 1;
        char *nc = malloc(len);
        if (nc) {
            snprintf(nc, len, "%s%s", old ? old : "", injection);
            free(out[last_user].content);
            out[last_user].content = nc;
        }
    } else {
        out[count] = sc_msg_user(injection);  /* synthetic trailing user turn */
    }

    free(injection);
    if (out_count) *out_count = total;
    return out;
}

int sc_moa_provider_is_local(const char *provider_name, const char *api_base)
{
    if (!provider_name) return 0;
    if (strcmp(provider_name, "ollama") == 0 || strcmp(provider_name, "vllm") == 0)
        return 1;
    /* Custom providers: loopback or RFC1918 api_base only. */
    if (api_base && api_base[0]) {
        if (strstr(api_base, "127.0.0.1") || strstr(api_base, "localhost") ||
            strstr(api_base, "://10.") || strstr(api_base, "://192.168.") ||
            strstr(api_base, "[::1]"))
            return 1;
        /* 172.16.0.0/12 (172.16 .. 172.31) */
        for (int o = 16; o <= 31; o++) {
            char pat[16];
            snprintf(pat, sizeof(pat), "://172.%d.", o);
            if (strstr(api_base, pat)) return 1;
        }
    }
    return 0;
}

/* ---------------- reference fan-out ---------------- */

typedef struct {
    const sc_moa_slot_t *slot;
    sc_llm_message_t *rview;
    int rview_count;
    double temp;
    int max_tokens;
    char *result;   /* owned text (always set after run) */
} ref_job_t;

static void *ref_thread(void *arg)
{
    ref_job_t *j = arg;
    if (!j->slot->provider) {
        j->result = sc_strdup("(reference unavailable)");
        return NULL;
    }
    cJSON *opt = cJSON_CreateObject();
    cJSON_AddNumberToObject(opt, "max_tokens", j->max_tokens);
    cJSON_AddNumberToObject(opt, "temperature", j->temp);
    sc_llm_response_t *r = j->slot->provider->chat(
        j->slot->provider, j->rview, j->rview_count, NULL, 0, j->slot->model, opt);
    cJSON_Delete(opt);

    if (r && r->http_status == 200 && r->content && r->content[0])
        j->result = sc_strdup(r->content);
    else
        j->result = sc_strdup("(reference failed)");
    if (r) sc_llm_response_free(r);
    return NULL;
}

sc_llm_response_t *sc_moa_run(const sc_moa_preset_t *preset,
                              sc_llm_message_t *msgs, int msg_count,
                              sc_tool_definition_t *tools, int tool_count,
                              cJSON *options,
                              sc_stream_cb stream_cb, void *stream_ctx)
{
    if (!preset || !preset->agg.provider) {
        SC_LOG_ERROR(LOG_TAG, "MoA preset has no usable aggregator");
        return NULL;
    }

    char *labels[SC_MOA_MAX_REFS] = {0};
    char *texts[SC_MOA_MAX_REFS]  = {0};
    int rc = 0;

    /* References run only when the preset is enabled. */
    if (preset->enabled && preset->ref_count > 0) {
        int rview_count = 0;
        sc_llm_message_t *rview = sc_msgs_reference_view(msgs, msg_count, &rview_count);

        ref_job_t jobs[SC_MOA_MAX_REFS] = {0};
        pthread_t tids[SC_MOA_MAX_REFS] = {0};
        int spawned[SC_MOA_MAX_REFS] = {0};

        for (int i = 0; i < preset->ref_count; i++) {
            jobs[i].slot = &preset->refs[i];
            jobs[i].rview = rview;
            jobs[i].rview_count = rview_count;
            jobs[i].temp = preset->ref_temp;
            jobs[i].max_tokens = preset->ref_max_tokens;
            if (pthread_create(&tids[i], NULL, ref_thread, &jobs[i]) == 0)
                spawned[i] = 1;
            else
                ref_thread(&jobs[i]);  /* run inline on spawn failure */
        }
        for (int i = 0; i < preset->ref_count; i++) {
            if (spawned[i]) pthread_join(tids[i], NULL);
            labels[rc] = sc_strdup(preset->refs[i].label);
            texts[rc] = jobs[i].result ? jobs[i].result : sc_strdup("(reference failed)");
            rc++;
        }

        sc_llm_message_array_free(rview, rview_count);
    }

    /* Build the aggregator message array (inject refs, or pass through). */
    int agg_count = 0;
    sc_llm_message_t *agg_msgs;
    if (rc > 0) {
        agg_msgs = sc_msgs_inject_moa_refs(msgs, msg_count, labels, texts, rc, &agg_count);
    } else {
        agg_msgs = calloc((size_t)msg_count, sizeof(*agg_msgs));
        if (agg_msgs) {
            for (int i = 0; i < msg_count; i++)
                agg_msgs[i] = sc_llm_message_clone(&msgs[i]);
            agg_count = msg_count;
        }
    }
    for (int i = 0; i < rc; i++) { free(labels[i]); free(texts[i]); }

    if (!agg_msgs) return NULL;

    /* Aggregator options inherit the turn's options; preset values override
     * temperature / max_tokens when set (> 0). */
    cJSON *aopts = options ? cJSON_Duplicate(options, 1) : cJSON_CreateObject();
    if (preset->agg_temp > 0) {
        cJSON_DeleteItemFromObject(aopts, "temperature");
        cJSON_AddNumberToObject(aopts, "temperature", preset->agg_temp);
    }
    if (preset->agg_max_tokens > 0) {
        cJSON_DeleteItemFromObject(aopts, "max_tokens");
        cJSON_AddNumberToObject(aopts, "max_tokens", preset->agg_max_tokens);
    }

    sc_provider_t *agg = preset->agg.provider;
    sc_llm_response_t *resp;
    if (stream_cb && agg->chat_stream)
        resp = agg->chat_stream(agg, agg_msgs, agg_count, tools, tool_count,
                                preset->agg.model, aopts, stream_cb, stream_ctx);
    else
        resp = agg->chat(agg, agg_msgs, agg_count, tools, tool_count,
                         preset->agg.model, aopts);

    cJSON_Delete(aopts);
    sc_llm_message_array_free(agg_msgs, agg_count);
    return resp;
}

/* ---------------- virtual provider ---------------- */

typedef struct {
    sc_moa_preset_t presets[SC_MOA_MAX_PRESETS];
    int preset_count;
    char *default_preset;
} moa_data_t;

static void slot_free(sc_moa_slot_t *s)
{
    if (s->provider && s->provider->destroy) s->provider->destroy(s->provider);
    free(s->model);
    free(s->label);
}

/* Resolve one config slot into a runtime slot (provider handle + bare model). */
static void resolve_slot(const sc_config_t *cfg, const sc_moa_slot_cfg_t *cs,
                         sc_moa_slot_t *out)
{
    if (!cs->provider || !cs->model) return;

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/%s", cs->provider, cs->model);
    char *routing = sc_strbuf_finish(&sb);

    out->provider = sc_provider_create_for_model(cfg, routing);
    out->model = sc_strdup(cs->model);
    out->label = routing;  /* "provider/model" — owned */
}

/* Validate + build one runtime preset. Returns 0 on success, -1 to skip. */
static int build_preset(const sc_config_t *cfg, const sc_moa_preset_cfg_t *pc,
                        sc_moa_preset_t *out)
{
    if (!pc->aggregator.provider) {
        SC_LOG_WARN(LOG_TAG, "preset '%s' has no aggregator; skipping", pc->name);
        return -1;
    }
    /* Block recursive MoA. */
    if (strcmp(pc->aggregator.provider, "moa") == 0) {
        SC_LOG_WARN(LOG_TAG, "preset '%s' aggregator is 'moa' (recursive); skipping",
                    pc->name);
        return -1;
    }
    /* local_only: every slot must be local. */
    if (pc->local_only) {
        if (!sc_moa_provider_is_local(pc->aggregator.provider, NULL)) {
            SC_LOG_WARN(LOG_TAG, "preset '%s' is local_only but aggregator '%s' is "
                        "not local; skipping", pc->name, pc->aggregator.provider);
            return -1;
        }
        for (int i = 0; i < pc->reference_count; i++) {
            if (pc->reference_models[i].provider &&
                !sc_moa_provider_is_local(pc->reference_models[i].provider, NULL)) {
                SC_LOG_WARN(LOG_TAG, "preset '%s' is local_only but reference '%s' is "
                            "not local; skipping", pc->name,
                            pc->reference_models[i].provider);
                return -1;
            }
            if (strcmp(pc->reference_models[i].provider ?
                       pc->reference_models[i].provider : "", "moa") == 0)
                return -1;  /* recursive reference */
        }
    }

    out->name = sc_strdup(pc->name);
    out->enabled = pc->enabled;
    out->local_only = pc->local_only;
    out->ref_temp = pc->reference_temperature;
    out->agg_temp = pc->aggregator_temperature;
    out->ref_max_tokens = pc->reference_max_tokens;
    out->agg_max_tokens = pc->aggregator_max_tokens;

    resolve_slot(cfg, &pc->aggregator, &out->agg);
    if (!out->agg.provider) {
        SC_LOG_WARN(LOG_TAG, "preset '%s' aggregator %s/%s failed to resolve; skipping",
                    pc->name, pc->aggregator.provider, pc->aggregator.model);
        free(out->name);
        slot_free(&out->agg);
        memset(out, 0, sizeof(*out));
        return -1;
    }

    for (int i = 0; i < pc->reference_count && i < SC_MOA_MAX_REFS; i++) {
        resolve_slot(cfg, &pc->reference_models[i], &out->refs[out->ref_count]);
        if (!out->refs[out->ref_count].provider)
            SC_LOG_WARN(LOG_TAG, "preset '%s' reference %s/%s failed to resolve; "
                        "it will report as failed at runtime", pc->name,
                        pc->reference_models[i].provider,
                        pc->reference_models[i].model);
        out->ref_count++;
    }
    return 0;
}

static const sc_moa_preset_t *find_preset(const moa_data_t *d, const char *name)
{
    if (!name || !name[0]) name = d->default_preset;
    if (!name && d->preset_count > 0) return &d->presets[0];
    for (int i = 0; i < d->preset_count; i++)
        if (d->presets[i].name && strcmp(d->presets[i].name, name) == 0)
            return &d->presets[i];
    return NULL;
}

/* Strip a leading "moa/" from a model string; empty → NULL (use default). */
static const char *preset_name_from_model(const char *model)
{
    if (!model || !model[0]) return NULL;
    if (strncmp(model, "moa/", 4) == 0) return model + 4;
    return model;
}

static sc_llm_response_t *moa_chat(sc_provider_t *self,
                                   sc_llm_message_t *msgs, int msg_count,
                                   sc_tool_definition_t *tools, int tool_count,
                                   const char *model, cJSON *options)
{
    moa_data_t *d = self->data;
    const sc_moa_preset_t *p = find_preset(d, preset_name_from_model(model));
    if (!p) {
        SC_LOG_ERROR(LOG_TAG, "no MoA preset '%s'", model ? model : "(default)");
        return NULL;
    }
    return sc_moa_run(p, msgs, msg_count, tools, tool_count, options, NULL, NULL);
}

static sc_llm_response_t *moa_chat_stream(sc_provider_t *self,
                                          sc_llm_message_t *msgs, int msg_count,
                                          sc_tool_definition_t *tools, int tool_count,
                                          const char *model, cJSON *options,
                                          sc_stream_cb stream_cb, void *stream_ctx)
{
    moa_data_t *d = self->data;
    const sc_moa_preset_t *p = find_preset(d, preset_name_from_model(model));
    if (!p) {
        SC_LOG_ERROR(LOG_TAG, "no MoA preset '%s'", model ? model : "(default)");
        return NULL;
    }
    return sc_moa_run(p, msgs, msg_count, tools, tool_count, options,
                      stream_cb, stream_ctx);
}

static const char *moa_get_default_model(sc_provider_t *self)
{
    moa_data_t *d = self->data;
    if (d->default_preset) return d->default_preset;
    return d->preset_count > 0 ? d->presets[0].name : "default";
}

static void moa_data_free(moa_data_t *d)
{
    if (!d) return;
    for (int i = 0; i < d->preset_count; i++) {
        free(d->presets[i].name);
        slot_free(&d->presets[i].agg);
        for (int j = 0; j < d->presets[i].ref_count; j++)
            slot_free(&d->presets[i].refs[j]);
    }
    free(d->default_preset);
    free(d);
}

static void moa_destroy(sc_provider_t *self)
{
    if (!self) return;
    moa_data_free(self->data);
    free(self);
}

/* MoA as a summary model is unsupported; NULL clone forces synchronous
 * summarization (see agent_session.c). */
static sc_provider_t *moa_clone(sc_provider_t *self) { (void)self; return NULL; }

sc_provider_t *sc_provider_moa_new(const sc_config_t *cfg, const char *default_preset)
{
    if (!cfg) return NULL;

    moa_data_t *d = calloc(1, sizeof(*d));
    if (!d) return NULL;

    const char *def = (default_preset && default_preset[0])
        ? preset_name_from_model(default_preset)
        : (cfg->moa.default_preset ? cfg->moa.default_preset : NULL);
    d->default_preset = def ? sc_strdup(def) : NULL;

    for (int i = 0; i < cfg->moa.preset_count && d->preset_count < SC_MOA_MAX_PRESETS; i++) {
        if (build_preset(cfg, &cfg->moa.presets[i], &d->presets[d->preset_count]) == 0)
            d->preset_count++;
    }

    if (d->preset_count == 0) {
        SC_LOG_ERROR(LOG_TAG, "no usable MoA presets configured");
        free(d->default_preset);
        free(d);
        return NULL;
    }

    sc_provider_t *p = calloc(1, sizeof(*p));
    if (!p) { moa_data_free(d); return NULL; }
    p->name = "moa";
    p->chat = moa_chat;
    p->chat_stream = moa_chat_stream;
    p->get_default_model = moa_get_default_model;
    p->destroy = moa_destroy;
    p->clone = moa_clone;
    p->data = d;

    SC_LOG_INFO(LOG_TAG, "MoA provider ready with %d preset(s), default '%s'",
                d->preset_count, d->default_preset ? d->default_preset : d->presets[0].name);
    return p;
}
