/*
 * doctor_local.c - Live provider capability probing (task 4.6)
 *
 * See doctor_local.h. The pure helpers and the provider-driven probe are kept
 * free of `sc_provider_create_for_model` / filesystem wiring so they can be
 * unit-tested with a mock provider and no network.
 */

#include "doctor_local.h"
#include "doctor.h"          /* DOC_PASS / DOC_FAIL */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>

#include "cJSON.h"
#include "constants.h"
#include "logger.h"
#include "util/str.h"
#include "providers/factory.h"
#include "sc_features.h"

#define TAG "doctor-local"

void sc_capability_report_free(sc_capability_report_t *r)
{
    if (!r) return;
    free(r->model);
    r->model = NULL;
}

/* ====================================================================== *
 *  Pure helpers                                                          *
 * ====================================================================== */

char *sc_capabilities_to_json(const sc_capability_report_t *r)
{
    if (!r) return NULL;
    cJSON *o = cJSON_CreateObject();
    if (!o) return NULL;
    cJSON_AddStringToObject(o, "model", r->model ? r->model : "");
    cJSON_AddNumberToObject(o, "chat", r->chat_ok);
    cJSON_AddNumberToObject(o, "stream", r->stream_ok);
    cJSON_AddNumberToObject(o, "tool_calls", r->tool_calls_ok);
    cJSON_AddNumberToObject(o, "json", r->json_ok);
    cJSON_AddNumberToObject(o, "checked_at", (double)r->checked_at);
    char *out = cJSON_PrintUnformatted(o);
    cJSON_Delete(o);
    return out;
}

/* Read an int field, defaulting when absent/non-numeric. */
static int cap_get_int(const cJSON *o, const char *key, int dflt)
{
    cJSON *v = cJSON_GetObjectItemCaseSensitive(o, key);
    return (v && cJSON_IsNumber(v)) ? v->valueint : dflt;
}

int sc_capabilities_from_json(const char *json, sc_capability_report_t *out)
{
    if (!json || !out) return 0;
    cJSON *o = cJSON_Parse(json);
    if (!o || !cJSON_IsObject(o)) { cJSON_Delete(o); return 0; }

    memset(out, 0, sizeof(*out));
    cJSON *m = cJSON_GetObjectItemCaseSensitive(o, "model");
    out->model = sc_strdup((m && cJSON_IsString(m)) ? m->valuestring : "");
    out->chat_ok       = cap_get_int(o, "chat", SC_CAP_NO);
    out->stream_ok     = cap_get_int(o, "stream", SC_CAP_NO);
    out->tool_calls_ok = cap_get_int(o, "tool_calls", SC_CAP_NO);
    out->json_ok       = cap_get_int(o, "json", SC_CAP_NO);
    out->checked_at    = (long)cap_get_int(o, "checked_at", 0);

    cJSON_Delete(o);
    return 1;
}

char *sc_capabilities_cache_path(const char *home, const char *model)
{
    if (!home || !home[0] || !model || !model[0]) return NULL;

    /* Sanitize the model into a safe filename component. */
    sc_strbuf_t name;
    sc_strbuf_init(&name);
    for (const char *p = model; *p; p++) {
        unsigned char c = (unsigned char)*p;
        char safe = (isalnum(c) || c == '.' || c == '_' || c == '-') ? (char)c : '_';
        sc_strbuf_appendf(&name, "%c", safe);
    }
    char *safe_model = sc_strbuf_finish(&name);
    if (!safe_model) return NULL;

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/capabilities/%s.json", home, safe_model);
    free(safe_model);
    return sc_strbuf_finish(&sb);
}

int sc_capabilities_response_is_json(const char *content)
{
    if (!content) return 0;

    /* Skip leading whitespace. */
    const char *s = content;
    while (*s && isspace((unsigned char)*s)) s++;
    if (!*s) return 0;

    char *dup = sc_strdup(s);
    if (!dup) return 0;

    /* Trim trailing whitespace. */
    size_t len = strlen(dup);
    while (len > 0 && isspace((unsigned char)dup[len - 1])) dup[--len] = '\0';

    char *body = dup;
    /* Strip a surrounding Markdown code fence: ```[lang]\n ... \n``` */
    if (strncmp(body, "```", 3) == 0) {
        char *nl = strchr(body, '\n');
        if (nl) body = nl + 1;
        size_t blen = strlen(body);
        if (blen >= 3 && strcmp(body + blen - 3, "```") == 0) {
            body[blen - 3] = '\0';
            /* Re-trim trailing whitespace before the fence. */
            blen = strlen(body);
            while (blen > 0 && isspace((unsigned char)body[blen - 1]))
                body[--blen] = '\0';
        }
    }

    cJSON *parsed = cJSON_Parse(body);
    int ok = parsed && (cJSON_IsObject(parsed) || cJSON_IsArray(parsed));
    cJSON_Delete(parsed);
    free(dup);
    return ok;
}

/* ====================================================================== *
 *  Provider-driven probe (mockable)                                      *
 * ====================================================================== */

/* One-shot chat helper: send a single user message (optionally with one tool),
 * return the response (caller frees) or NULL. */
static sc_llm_response_t *probe_chat(sc_provider_t *p, const char *model,
                                     const char *user_text,
                                     sc_tool_definition_t *tools, int tool_count)
{
    sc_llm_message_t msg = {
        .role = (char *)"user",
        .content = (char *)user_text,
        .tool_calls = NULL,
        .tool_call_count = 0,
        .tool_call_id = NULL,
    };
    cJSON *options = cJSON_CreateObject();
    if (options) cJSON_AddNumberToObject(options, "max_tokens", 64);
    sc_llm_response_t *resp =
        p->chat(p, &msg, 1, tools, tool_count, model, options);
    cJSON_Delete(options);
    return resp;
}

#if SC_ENABLE_STREAMING
typedef struct { int deltas; } stream_probe_ctx_t;

static void stream_probe_cb(const sc_stream_event_t *ev, void *ctx)
{
    stream_probe_ctx_t *s = ctx;
    if (ev && ev->type == SC_STREAM_TEXT) s->deltas++;
}
#endif

int sc_doctor_probe_provider(sc_provider_t *provider, const char *model,
                             sc_capability_report_t *out)
{
    if (!provider || !provider->chat || !out) return 0;
    memset(out, 0, sizeof(*out));
    out->model = sc_strdup(model ? model : "");
    out->checked_at = (long)time(NULL);
    out->stream_ok = SC_CAP_SKIPPED;

    /* 1. Basic chat round-trip. */
    sc_llm_response_t *r = probe_chat(provider, model, "Reply with exactly: OK",
                                      NULL, 0);
    out->chat_ok = (r && r->http_status == 200 && r->content && r->content[0])
                       ? SC_CAP_YES : SC_CAP_NO;
    sc_llm_response_free(r);

    /* 2. Tool calls — offer a trivial tool and ask the model to call it. */
    cJSON *params = cJSON_CreateObject();
    if (params) {
        cJSON_AddStringToObject(params, "type", "object");
        cJSON_AddItemToObject(params, "properties", cJSON_CreateObject());
    }
    sc_tool_definition_t tool = {
        .name = (char *)"ping",
        .description = (char *)"A diagnostic no-op tool. Call it to confirm "
                               "tool calling works.",
        .parameters = params,
    };
    r = probe_chat(provider, model, "Call the ping tool now.", &tool, 1);
    out->tool_calls_ok = (r && r->tool_call_count > 0) ? SC_CAP_YES : SC_CAP_NO;
    sc_llm_response_free(r);
    cJSON_Delete(params);

    /* 3. Inline JSON output. */
    r = probe_chat(provider, model,
                   "Respond with ONLY this JSON object and nothing else: "
                   "{\"ok\": true}", NULL, 0);
    out->json_ok = (r && sc_capabilities_response_is_json(r->content))
                       ? SC_CAP_YES : SC_CAP_NO;
    sc_llm_response_free(r);

    /* 4. Streaming (when compiled in and supported by the provider). */
#if SC_ENABLE_STREAMING
    if (provider->chat_stream) {
        stream_probe_ctx_t sctx = { .deltas = 0 };
        sc_llm_message_t msg = {
            .role = (char *)"user",
            .content = (char *)"Count to three.",
            .tool_calls = NULL, .tool_call_count = 0, .tool_call_id = NULL,
        };
        cJSON *options = cJSON_CreateObject();
        if (options) cJSON_AddNumberToObject(options, "max_tokens", 64);
        sc_llm_response_t *sr = provider->chat_stream(
            provider, &msg, 1, NULL, 0, model, options,
            stream_probe_cb, &sctx);
        cJSON_Delete(options);
        out->stream_ok = (sctx.deltas > 0) ? SC_CAP_YES : SC_CAP_NO;
        sc_llm_response_free(sr);
    }
#endif

    return out->chat_ok == SC_CAP_YES ? 1 : 0;
}

/* ====================================================================== *
 *  Live entry point                                                      *
 * ====================================================================== */

static const char *cap_str(int v)
{
    if (v == SC_CAP_YES) return "yes";
    if (v == SC_CAP_SKIPPED) return "skipped";
    return "no";
}

/* Persist the report under {home}/capabilities/<model>.json. Best-effort. */
static void cache_report(const sc_capability_report_t *rep)
{
    char *home = sc_get_home_dir();
    if (!home) return;

    sc_strbuf_t dir;
    sc_strbuf_init(&dir);
    sc_strbuf_appendf(&dir, "%s/capabilities", home);
    char *dir_path = sc_strbuf_finish(&dir);
    if (dir_path) {
        mkdir(dir_path, 0700); /* ignore EEXIST */
        free(dir_path);
    }

    char *path = sc_capabilities_cache_path(home, rep->model);
    free(home);
    if (!path) return;

    char *json = sc_capabilities_to_json(rep);
    if (json) {
        FILE *f = fopen(path, "w");
        if (f) {
            fputs(json, f);
            fclose(f);
            SC_LOG_DEBUG(TAG, "cached capabilities to %s", path);
        }
        free(json);
    }
    free(path);
}

int sc_doctor_local(const sc_config_t *cfg, const char *model)
{
    int pass = 0, fail = 0;
    printf("%s doctor --local\n\n", SC_NAME);

    if (!cfg) {
        DOC_FAIL(&fail, "Local probe: no config loaded");
        return 1;
    }

    const char *want = (model && model[0]) ? model : cfg->model;

    sc_provider_t *provider = want
        ? sc_provider_create_for_model(cfg, want)
        : sc_provider_create(cfg);
    if (!provider) {
        DOC_FAIL(&fail, "Local probe: could not create provider for model '%s'",
                 want ? want : "(default)");
        printf("\n  %d passed, %d failed\n", pass, fail);
        return 1;
    }

    /* `want` keeps its provider prefix for routing (create_for_model above),
     * but the model name sent to the API must be stripped — otherwise e.g.
     * `grok-sub/grok-4.3` reaches api.x.ai verbatim and 400s. */
    const char *probe_model = want ? sc_model_strip_prefix(want) : NULL;
    if (!probe_model || !probe_model[0])
        probe_model = provider->get_default_model(provider);

    printf("Probing model: %s\n\n", probe_model ? probe_model : "(unknown)");

    sc_capability_report_t rep;
    sc_doctor_probe_provider(provider, probe_model, &rep);
    if (provider->destroy) provider->destroy(provider);

    if (rep.chat_ok == SC_CAP_YES)
        DOC_PASS(&pass, "chat: %s", cap_str(rep.chat_ok));
    else
        DOC_FAIL(&fail, "chat: %s", cap_str(rep.chat_ok));

#if SC_ENABLE_STREAMING
    if (rep.stream_ok == SC_CAP_YES)
        DOC_PASS(&pass, "streaming: %s", cap_str(rep.stream_ok));
    else
        DOC_FAIL(&fail, "streaming: %s", cap_str(rep.stream_ok));
#endif

    if (rep.tool_calls_ok == SC_CAP_YES)
        DOC_PASS(&pass, "tool calls: %s", cap_str(rep.tool_calls_ok));
    else
        DOC_FAIL(&fail, "tool calls: %s", cap_str(rep.tool_calls_ok));

    if (rep.json_ok == SC_CAP_YES)
        DOC_PASS(&pass, "inline JSON: %s", cap_str(rep.json_ok));
    else
        DOC_FAIL(&fail, "inline JSON: %s", cap_str(rep.json_ok));

    cache_report(&rep);

    printf("\n  %d passed, %d failed\n", pass, fail);
    int rc = (rep.chat_ok == SC_CAP_YES) ? 0 : 1;
    sc_capability_report_free(&rep);
    return rc;
}
