/*
 * smolclaw - providers/http.c
 * OpenAI-compatible HTTP provider + provider type helpers
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <curl/curl.h>

#include "providers/http.h"
#include "providers/types.h"
#include "providers/provider_common.h"
#include "constants.h"
#include "util/str.h"
#include "util/json_helpers.h"
#include "sc_features.h"
#include "logger.h"
#include "cJSON.h"

#if SC_ENABLE_STREAMING
#include "util/sse.h"
#endif

#define LOG_TAG "http-provider"

/* ========================================================================
 * Provider type helpers (sc_llm_message, sc_llm_response, sc_tool_call, etc.)
 * ======================================================================== */

sc_llm_message_t sc_msg_system(const char *content)
{
    return (sc_llm_message_t){
        .role = sc_strdup("system"),
        .content = sc_strdup(content),
        .tool_calls = NULL,
        .tool_call_count = 0,
        .tool_call_id = NULL,
    };
}

sc_llm_message_t sc_msg_user(const char *content)
{
    return (sc_llm_message_t){
        .role = sc_strdup("user"),
        .content = sc_strdup(content),
        .tool_calls = NULL,
        .tool_call_count = 0,
        .tool_call_id = NULL,
    };
}

sc_llm_message_t sc_msg_assistant(const char *content)
{
    return (sc_llm_message_t){
        .role = sc_strdup("assistant"),
        .content = sc_strdup(content),
        .tool_calls = NULL,
        .tool_call_count = 0,
        .tool_call_id = NULL,
    };
}

sc_llm_message_t sc_msg_tool_result(const char *tool_call_id, const char *content)
{
    return (sc_llm_message_t){
        .role = sc_strdup("tool"),
        .content = sc_strdup(content),
        .tool_calls = NULL,
        .tool_call_count = 0,
        .tool_call_id = sc_strdup(tool_call_id),
    };
}

sc_llm_message_t sc_msg_assistant_with_tools(const char *content,
                                              sc_tool_call_t *calls, int count)
{
    sc_llm_message_t msg = {
        .role = sc_strdup("assistant"),
        .content = sc_strdup(content),
        .tool_calls = NULL,
        .tool_call_count = count,
        .tool_call_id = NULL,
    };

    if (count > 0 && calls) {
        msg.tool_calls = calloc((size_t)count, sizeof(sc_tool_call_t));
        if (!msg.tool_calls) { msg.tool_call_count = 0; return msg; }
        for (int i = 0; i < count; i++) {
            msg.tool_calls[i].id = sc_strdup(calls[i].id);
            msg.tool_calls[i].name = sc_strdup(calls[i].name);
            msg.tool_calls[i].arguments = calls[i].arguments
                ? cJSON_Duplicate(calls[i].arguments, 1) : NULL;
        }
    }

    return msg;
}

void sc_tool_call_free_fields(sc_tool_call_t *tc)
{
    if (!tc) return;
    free(tc->id);
    free(tc->name);
    cJSON_Delete(tc->arguments);
    tc->id = NULL;
    tc->name = NULL;
    tc->arguments = NULL;
}

void sc_llm_message_free_fields(sc_llm_message_t *msg)
{
    if (!msg) return;
    free(msg->role);
    free(msg->content);
    free(msg->tool_call_id);
    for (int i = 0; i < msg->tool_call_count; i++) {
        sc_tool_call_free_fields(&msg->tool_calls[i]);
    }
    free(msg->tool_calls);
    msg->role = NULL;
    msg->content = NULL;
    msg->tool_call_id = NULL;
    msg->tool_calls = NULL;
    msg->tool_call_count = 0;
}

void sc_llm_message_array_free(sc_llm_message_t *msgs, int count)
{
    if (!msgs) return;
    for (int i = 0; i < count; i++) {
        sc_llm_message_free_fields(&msgs[i]);
    }
    free(msgs);
}

sc_llm_message_t sc_llm_message_clone(const sc_llm_message_t *msg)
{
    sc_llm_message_t clone = {
        .role = sc_strdup(msg->role),
        .content = sc_strdup(msg->content),
        .tool_call_id = sc_strdup(msg->tool_call_id),
        .tool_calls = NULL,
        .tool_call_count = msg->tool_call_count,
    };

    if (msg->tool_call_count > 0 && msg->tool_calls) {
        clone.tool_calls = calloc((size_t)msg->tool_call_count,
                                  sizeof(sc_tool_call_t));
        if (!clone.tool_calls) { clone.tool_call_count = 0; return clone; }
        for (int i = 0; i < msg->tool_call_count; i++) {
            clone.tool_calls[i].id = sc_strdup(msg->tool_calls[i].id);
            clone.tool_calls[i].name = sc_strdup(msg->tool_calls[i].name);
            clone.tool_calls[i].arguments = msg->tool_calls[i].arguments
                ? cJSON_Duplicate(msg->tool_calls[i].arguments, 1) : NULL;
        }
    }

    return clone;
}

void sc_llm_response_free(sc_llm_response_t *resp)
{
    if (!resp) return;
    free(resp->content);
    for (int i = 0; i < resp->tool_call_count; i++) {
        sc_tool_call_free_fields(&resp->tool_calls[i]);
    }
    free(resp->tool_calls);
    free(resp->finish_reason);
    free(resp);
}

void sc_tool_definition_free(sc_tool_definition_t *def)
{
    if (!def) return;
    free(def->name);
    free(def->description);
    cJSON_Delete(def->parameters);
    def->name = NULL;
    def->description = NULL;
    def->parameters = NULL;
}

/* ========================================================================
 * HTTP provider internals
 * ======================================================================== */

typedef struct {
    char *api_key;
    char *api_base;
    char *proxy;
    CURL *curl;
} http_provider_data_t;


/* Build the JSON messages array for OpenAI format */
static cJSON *build_messages_json(sc_llm_message_t *msgs, int msg_count)
{
    cJSON *arr = cJSON_CreateArray();

    for (int i = 0; i < msg_count; i++) {
        sc_llm_message_t *m = &msgs[i];
        cJSON *msg_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(msg_obj, "role", m->role);

        if (m->content) {
            cJSON_AddStringToObject(msg_obj, "content", m->content);
        } else if (strcmp(m->role, "assistant") != 0) {
            cJSON_AddStringToObject(msg_obj, "content", "");
        }

        /* Assistant messages with tool calls */
        if (m->tool_call_count > 0 && m->tool_calls) {
            cJSON *tc_arr = cJSON_CreateArray();
            for (int j = 0; j < m->tool_call_count; j++) {
                sc_tool_call_t *tc = &m->tool_calls[j];
                cJSON *tc_obj = cJSON_CreateObject();
                cJSON_AddStringToObject(tc_obj, "id", tc->id ? tc->id : "");
                cJSON_AddStringToObject(tc_obj, "type", "function");

                cJSON *fn = cJSON_CreateObject();
                cJSON_AddStringToObject(fn, "name", tc->name ? tc->name : "");
                char *args_str = tc->arguments
                    ? cJSON_PrintUnformatted(tc->arguments) : sc_strdup("{}");
                cJSON_AddStringToObject(fn, "arguments", args_str);
                free(args_str);

                cJSON_AddItemToObject(tc_obj, "function", fn);
                cJSON_AddItemToArray(tc_arr, tc_obj);
            }
            cJSON_AddItemToObject(msg_obj, "tool_calls", tc_arr);
            /* OpenAI requires content to be null or present for assistant with tool_calls */
            if (!m->content) {
                cJSON_AddNullToObject(msg_obj, "content");
            }
        }

        /* Tool result messages carry tool_call_id */
        if (m->tool_call_id) {
            cJSON_AddStringToObject(msg_obj, "tool_call_id", m->tool_call_id);
        }

        cJSON_AddItemToArray(arr, msg_obj);
    }

    return arr;
}

/* Build tools array in OpenAI format */
static cJSON *build_tools_json(sc_tool_definition_t *tools, int tool_count)
{
    cJSON *arr = cJSON_CreateArray();

    for (int i = 0; i < tool_count; i++) {
        sc_tool_definition_t *t = &tools[i];
        cJSON *tool_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(tool_obj, "type", "function");

        cJSON *fn = cJSON_CreateObject();
        cJSON_AddStringToObject(fn, "name", t->name ? t->name : "");
        if (t->description) {
            cJSON_AddStringToObject(fn, "description", t->description);
        }
        if (t->parameters) {
            cJSON_AddItemToObject(fn, "parameters",
                                  cJSON_Duplicate(t->parameters, 1));
        }

        cJSON_AddItemToObject(tool_obj, "function", fn);
        cJSON_AddItemToArray(arr, tool_obj);
    }

    return arr;
}

/* Parse the OpenAI response body */
static sc_llm_response_t *parse_response(const char *body)
{
    cJSON *root = cJSON_Parse(body);
    if (!root) {
        SC_LOG_ERROR(LOG_TAG, "Failed to parse response JSON");
        return NULL;
    }

    sc_llm_response_t *resp = calloc(1, sizeof(sc_llm_response_t));

    cJSON *choices = sc_json_get_array(root, "choices");
    if (!choices || cJSON_GetArraySize(choices) == 0) {
        resp->content = sc_strdup("");
        resp->finish_reason = sc_strdup("stop");
        cJSON_Delete(root);
        return resp;
    }

    cJSON *choice0 = cJSON_GetArrayItem(choices, 0);
    cJSON *message = sc_json_get_object(choice0, "message");

    /* Content — some reasoning models (kimi, deepseek-r1) put the visible
     * response in "content" and internal chain-of-thought in "reasoning_content".
     * If "content" is null/empty, fall back to "reasoning_content" so the
     * caller gets *something* rather than a blank response. */
    const char *content = sc_json_get_string(message, "content", NULL);
    if (!content || !content[0])
        content = sc_json_get_string(message, "reasoning_content", NULL);
    resp->content = sc_strdup(content);

    /* Finish reason */
    const char *fr = sc_json_get_string(choice0, "finish_reason", "stop");
    resp->finish_reason = sc_strdup(fr);

    /* Tool calls */
    cJSON *tc_arr = sc_json_get_array(message, "tool_calls");
    if (tc_arr) {
        int tc_count = cJSON_GetArraySize(tc_arr);
        if (tc_count > 0) {
            resp->tool_calls = calloc((size_t)tc_count, sizeof(sc_tool_call_t));
            resp->tool_call_count = tc_count;

            for (int i = 0; i < tc_count; i++) {
                cJSON *tc_obj = cJSON_GetArrayItem(tc_arr, i);
                sc_tool_call_t *tc = &resp->tool_calls[i];

                tc->id = sc_strdup(sc_json_get_string(tc_obj, "id", ""));

                cJSON *fn = sc_json_get_object(tc_obj, "function");
                if (fn) {
                    tc->name = sc_strdup(sc_json_get_string(fn, "name", ""));
                    const char *args_str = sc_json_get_string(fn, "arguments", "{}");
                    tc->arguments = cJSON_Parse(args_str);
                    if (!tc->arguments) {
                        /* If args don't parse as JSON, wrap in {"raw": ...} */
                        tc->arguments = cJSON_CreateObject();
                        cJSON_AddStringToObject(tc->arguments, "raw", args_str);
                    }
                } else {
                    tc->name = sc_strdup("");
                    tc->arguments = cJSON_CreateObject();
                }
            }
        }
    }

    /* Usage */
    cJSON *usage = sc_json_get_object(root, "usage");
    if (usage) {
        resp->usage.prompt_tokens = sc_json_get_int(usage, "prompt_tokens", 0);
        resp->usage.completion_tokens = sc_json_get_int(usage, "completion_tokens", 0);
        resp->usage.total_tokens = sc_json_get_int(usage, "total_tokens", 0);
    }

    cJSON_Delete(root);
    return resp;
}

/* ========================================================================
 * Shared request helpers
 * ======================================================================== */

/* Build the common chat request body JSON */
static cJSON *build_chat_body(const char *model,
                               sc_llm_message_t *msgs, int msg_count,
                               sc_tool_definition_t *tools, int tool_count,
                               cJSON *options, int streaming)
{
    cJSON *body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "model", model ? model : "");
    if (streaming)
        cJSON_AddBoolToObject(body, "stream", 1);

    cJSON_AddItemToObject(body, "messages", build_messages_json(msgs, msg_count));

    if (tools && tool_count > 0) {
        cJSON_AddItemToObject(body, "tools", build_tools_json(tools, tool_count));
        cJSON_AddStringToObject(body, "tool_choice", "auto");
    }

    if (options) {
        int max_tokens = sc_json_get_int(options, "max_tokens", 0);
        if (max_tokens > 0)
            cJSON_AddNumberToObject(body, "max_tokens", max_tokens);
        double temp = sc_json_get_double(options, "temperature", -1.0);
        if (temp >= 0.0)
            cJSON_AddNumberToObject(body, "temperature", temp);
    }

    return body;
}

/* Build the chat/completions URL from api_base */
static char *build_chat_url(const char *api_base)
{
    sc_strbuf_t url_buf;
    sc_strbuf_init(&url_buf);
    sc_strbuf_append(&url_buf, api_base);
    sc_strbuf_append(&url_buf, "/chat/completions");
    return sc_strbuf_finish(&url_buf);
}

/* ========================================================================
 * NOTE: curl setup is now in provider_common.c (sc_provider_setup_curl)
 * ======================================================================== */

/* ========================================================================
 * HTTP provider vtable methods
 * ======================================================================== */

static sc_llm_response_t *http_chat(sc_provider_t *self,
                                     sc_llm_message_t *msgs, int msg_count,
                                     sc_tool_definition_t *tools, int tool_count,
                                     const char *model, cJSON *options)
{
    http_provider_data_t *d = self->data;

    if (!d->api_base || d->api_base[0] == '\0') {
        SC_LOG_ERROR(LOG_TAG, "API base not configured");
        return NULL;
    }

    cJSON *body = build_chat_body(model, msgs, msg_count, tools, tool_count,
                                   options, 0);
    char *body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);

    char *url = build_chat_url(d->api_base);
    SC_LOG_DEBUG(LOG_TAG, "POST %s", url);

    sc_strbuf_t response_buf;
    sc_strbuf_init(&response_buf);
    sc_header_ctx_t hdr_ctx = {0};

    struct curl_slist *headers = sc_provider_setup_curl(
        d->curl, url, d->api_key, "Authorization: Bearer ",
        body_str, d->proxy, &hdr_ctx,
        sc_curl_write_cb, &response_buf, 120L, NULL);

    CURLcode res = curl_easy_perform(d->curl);

    curl_slist_free_all(headers);
    free(url);

    if (res != CURLE_OK) {
        SC_LOG_ERROR(LOG_TAG, "curl request failed: %s", curl_easy_strerror(res));
        free(body_str);
        sc_strbuf_free(&response_buf);
        return sc_provider_make_error_response(0, 0);
    }

    long http_code = 0;
    curl_easy_getinfo(d->curl, CURLINFO_RESPONSE_CODE, &http_code);

    char *resp_body = sc_strbuf_finish(&response_buf);
    free(body_str);

    if (http_code != 200) {
        SC_LOG_ERROR(LOG_TAG, "API request failed (HTTP %ld): %.500s",
                     http_code, resp_body ? resp_body : "(empty)");
        free(resp_body);
        return sc_provider_make_error_response((int)http_code, hdr_ctx.retry_after);
    }

    sc_llm_response_t *result = parse_response(resp_body);
    free(resp_body);
    if (result) result->http_status = 200;
    return result;
}

#if SC_ENABLE_STREAMING
/* ========================================================================
 * Streaming implementation (SSE, OpenAI format)
 * ======================================================================== */

typedef struct {
    sc_strbuf_t content;
    sc_tool_call_t *tool_calls;
    int tool_call_count;
    int tool_call_cap;
    char *finish_reason;
    sc_stream_cb user_cb;
    void *user_ctx;
    /* Per-tool-call argument accumulation buffers */
    sc_strbuf_t *tool_arg_bufs;
    int tool_arg_buf_count;
    int tool_arg_buf_cap;
} http_stream_ctx_t;

static void http_stream_event(const char *data, void *ctx)
{
    http_stream_ctx_t *sc = ctx;

    if (strcmp(data, "[DONE]") == 0) return;

    cJSON *event = cJSON_Parse(data);
    if (!event) return;

    cJSON *choices = sc_json_get_array(event, "choices");
    if (!choices || cJSON_GetArraySize(choices) == 0) {
        cJSON_Delete(event);
        return;
    }

    cJSON *choice0 = cJSON_GetArrayItem(choices, 0);
    cJSON *delta = sc_json_get_object(choice0, "delta");

    if (delta) {
        /* Text content delta */
        const char *content = sc_json_get_string(delta, "content", NULL);
        if (content) {
            sc_strbuf_append(&sc->content, content);
            if (sc->user_cb) sc->user_cb(content, sc->user_ctx);
        }

        /* Tool call deltas */
        cJSON *tc_arr = sc_json_get_array(delta, "tool_calls");
        if (tc_arr) {
            int n = cJSON_GetArraySize(tc_arr);
            for (int i = 0; i < n; i++) {
                cJSON *tc_delta = cJSON_GetArrayItem(tc_arr, i);
                int idx = sc_json_get_int(tc_delta, "index", 0);

                /* Grow tool_calls array if needed */
                while (idx >= sc->tool_call_count) {
                    if (sc->tool_call_count >= sc->tool_call_cap) {
                        int new_cap = sc->tool_call_cap == 0 ? 4 : sc->tool_call_cap * 2;
                        sc_tool_call_t *new_tc = sc_safe_realloc(sc->tool_calls,
                            (size_t)new_cap * sizeof(sc_tool_call_t));
                        if (!new_tc) break;
                        sc->tool_calls = new_tc;
                        sc->tool_call_cap = new_cap;
                    }
                    sc_tool_call_t *tc = &sc->tool_calls[sc->tool_call_count];
                    tc->id = NULL;
                    tc->name = NULL;
                    tc->arguments = NULL;
                    sc->tool_call_count++;

                    /* Grow arg buf array */
                    if (sc->tool_arg_buf_count >= sc->tool_arg_buf_cap) {
                        int new_buf_cap = sc->tool_arg_buf_cap == 0 ? 4 : sc->tool_arg_buf_cap * 2;
                        sc_strbuf_t *new_bufs = sc_safe_realloc(sc->tool_arg_bufs,
                            (size_t)new_buf_cap * sizeof(sc_strbuf_t));
                        if (!new_bufs) break;
                        sc->tool_arg_bufs = new_bufs;
                        sc->tool_arg_buf_cap = new_buf_cap;
                    }
                    sc_strbuf_init(&sc->tool_arg_bufs[sc->tool_arg_buf_count]);
                    sc->tool_arg_buf_count++;
                }

                if (idx >= sc->tool_call_count) continue;
                sc_tool_call_t *tc = &sc->tool_calls[idx];

                const char *id = sc_json_get_string(tc_delta, "id", NULL);
                if (id && !tc->id) tc->id = sc_strdup(id);

                cJSON *fn = sc_json_get_object(tc_delta, "function");
                if (fn) {
                    const char *name = sc_json_get_string(fn, "name", NULL);
                    if (name && !tc->name) tc->name = sc_strdup(name);

                    const char *args = sc_json_get_string(fn, "arguments", NULL);
                    if (args && idx < sc->tool_arg_buf_count) {
                        sc_strbuf_append(&sc->tool_arg_bufs[idx], args);
                    }
                }
            }
        }
    }

    /* Finish reason */
    const char *fr = sc_json_get_string(choice0, "finish_reason", NULL);
    if (fr) {
        free(sc->finish_reason);
        sc->finish_reason = sc_strdup(fr);
    }

    cJSON_Delete(event);
}

/* curl write callback for SSE streaming */
static size_t curl_sse_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    sc_sse_parser_t *sse = userdata;
    if (nmemb > 0 && size > SIZE_MAX / nmemb) return 0;
    size_t total = size * nmemb;
    sc_sse_feed(sse, ptr, total);
    return total;
}

/* Free all resources in a stream context */
static void stream_ctx_cleanup(http_stream_ctx_t *sc)
{
    sc_strbuf_free(&sc->content);
    free(sc->finish_reason);
    for (int i = 0; i < sc->tool_call_count; i++)
        sc_tool_call_free_fields(&sc->tool_calls[i]);
    free(sc->tool_calls);
    for (int i = 0; i < sc->tool_arg_buf_count; i++)
        sc_strbuf_free(&sc->tool_arg_bufs[i]);
    free(sc->tool_arg_bufs);
}

static sc_llm_response_t *http_chat_stream(sc_provider_t *self,
                                            sc_llm_message_t *msgs, int msg_count,
                                            sc_tool_definition_t *tools, int tool_count,
                                            const char *model, cJSON *options,
                                            sc_stream_cb stream_cb, void *stream_ctx)
{
    http_provider_data_t *d = self->data;

    if (!d->api_base || d->api_base[0] == '\0') {
        SC_LOG_ERROR(LOG_TAG, "API base not configured");
        return NULL;
    }

    cJSON *body = build_chat_body(model, msgs, msg_count, tools, tool_count,
                                   options, 1);
    char *body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);

    char *url = build_chat_url(d->api_base);
    SC_LOG_DEBUG(LOG_TAG, "POST %s (streaming)", url);

    http_stream_ctx_t sc = {0};
    sc_strbuf_init(&sc.content);
    sc.user_cb = stream_cb;
    sc.user_ctx = stream_ctx;
    sc.finish_reason = sc_strdup("stop");

    sc_sse_parser_t sse;
    sc_sse_init(&sse, http_stream_event, &sc);

    sc_header_ctx_t stream_hdr = {0};

    struct curl_slist *headers = sc_provider_setup_curl(
        d->curl, url, d->api_key, "Authorization: Bearer ",
        body_str, d->proxy, &stream_hdr,
        curl_sse_write_cb, &sse, 300L, NULL);

    CURLcode res = curl_easy_perform(d->curl);

    curl_slist_free_all(headers);
    free(url);
    free(body_str);

    if (stream_cb) stream_cb(NULL, stream_ctx);

    if (res != CURLE_OK) {
        SC_LOG_ERROR(LOG_TAG, "curl streaming request failed: %s", curl_easy_strerror(res));
        sc_sse_free(&sse);
        stream_ctx_cleanup(&sc);
        return sc_provider_make_error_response(0, 0);
    }

    long http_code = 0;
    curl_easy_getinfo(d->curl, CURLINFO_RESPONSE_CODE, &http_code);

    sc_sse_free(&sse);

    if (http_code != 200) {
        char *content = sc_strbuf_finish(&sc.content);
        SC_LOG_ERROR(LOG_TAG, "Streaming API failed (HTTP %ld): %.500s",
                     http_code, content ? content : "(empty)");
        free(content);
        free(sc.finish_reason);
        for (int i = 0; i < sc.tool_call_count; i++)
            sc_tool_call_free_fields(&sc.tool_calls[i]);
        free(sc.tool_calls);
        for (int i = 0; i < sc.tool_arg_buf_count; i++)
            sc_strbuf_free(&sc.tool_arg_bufs[i]);
        free(sc.tool_arg_bufs);
        return sc_provider_make_error_response((int)http_code, stream_hdr.retry_after);
    }

    /* Finalize tool call arguments from accumulated buffers */
    for (int i = 0; i < sc.tool_call_count && i < sc.tool_arg_buf_count; i++) {
        char *args_str = sc_strbuf_finish(&sc.tool_arg_bufs[i]);
        if (args_str && args_str[0] != '\0') {
            sc.tool_calls[i].arguments = cJSON_Parse(args_str);
            if (!sc.tool_calls[i].arguments) {
                sc.tool_calls[i].arguments = cJSON_CreateObject();
                cJSON_AddStringToObject(sc.tool_calls[i].arguments, "raw", args_str);
            }
        } else if (!sc.tool_calls[i].arguments) {
            sc.tool_calls[i].arguments = cJSON_CreateObject();
        }
        free(args_str);
    }
    free(sc.tool_arg_bufs);

    sc_llm_response_t *resp = calloc(1, sizeof(*resp));
    resp->content = sc_strbuf_finish(&sc.content);
    resp->tool_calls = sc.tool_calls;
    resp->tool_call_count = sc.tool_call_count;
    resp->finish_reason = sc.finish_reason;
    resp->http_status = 200;

    return resp;
}
#endif /* SC_ENABLE_STREAMING */

static const char *http_get_default_model(sc_provider_t *self)
{
    (void)self;
    return "";
}

static sc_provider_t *http_clone(sc_provider_t *self)
{
    http_provider_data_t *d = self->data;
    return sc_provider_http_new(d->api_key, d->api_base, d->proxy);
}

static void http_destroy(sc_provider_t *self)
{
    if (!self) return;
    http_provider_data_t *d = self->data;
    if (d) {
        free(d->api_key);
        free(d->api_base);
        free(d->proxy);
        if (d->curl) curl_easy_cleanup(d->curl);
        free(d);
    }
    free(self);
}

/* ========================================================================
 * Public constructor
 * ======================================================================== */

sc_provider_t *sc_provider_http_new(const char *api_key, const char *api_base,
                                     const char *proxy)
{
    sc_provider_t *p = calloc(1, sizeof(sc_provider_t));
    http_provider_data_t *d = calloc(1, sizeof(http_provider_data_t));

    d->api_key = sc_strdup(api_key);

    if (api_base) {
        d->api_base = sc_strdup(api_base);
        sc_provider_trim_base_url(d->api_base);
    }

    d->proxy = sc_strdup(proxy);
    d->curl = sc_provider_init_curl();

    p->name = "http";
    p->chat = http_chat;
#if SC_ENABLE_STREAMING
    p->chat_stream = http_chat_stream;
#endif
    p->get_default_model = http_get_default_model;
    p->destroy = http_destroy;
    p->clone = http_clone;
    p->data = d;

    SC_LOG_INFO(LOG_TAG, "Created HTTP provider (base=%s)",
                d->api_base ? d->api_base : "(none)");

    return p;
}
