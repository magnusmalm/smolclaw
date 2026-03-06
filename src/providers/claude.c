/*
 * smolclaw - providers/claude.c
 * Anthropic Messages API provider (native format)
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <curl/curl.h>

#include "providers/claude.h"
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

#define LOG_TAG "claude-provider"
#define ANTHROPIC_VERSION "2023-06-01"

typedef struct {
    char *api_key;
    char *api_base;
    CURL *curl;
} claude_provider_data_t;


/* ========================================================================
 * Build request body in Anthropic Messages format
 * ======================================================================== */

/*
 * Build the system blocks array from system messages.
 * Returns a cJSON array of {"type":"text","text":"..."} blocks, or NULL if none.
 */
static cJSON *build_system_blocks(sc_llm_message_t *msgs, int msg_count)
{
    cJSON *sys_arr = NULL;

    for (int i = 0; i < msg_count; i++) {
        if (msgs[i].role && strcmp(msgs[i].role, "system") == 0 && msgs[i].content) {
            if (!sys_arr) sys_arr = cJSON_CreateArray();
            cJSON *block = cJSON_CreateObject();
            cJSON_AddStringToObject(block, "type", "text");
            cJSON_AddStringToObject(block, "text", msgs[i].content);
            cJSON_AddItemToArray(sys_arr, block);
        }
    }

    return sys_arr;
}

/*
 * Build a single user message content block for a tool result.
 * Returns: {"type":"tool_result","tool_use_id":"...","content":"..."}
 */
static cJSON *build_tool_result_block(const sc_llm_message_t *m)
{
    cJSON *block = cJSON_CreateObject();
    cJSON_AddStringToObject(block, "type", "tool_result");
    cJSON_AddStringToObject(block, "tool_use_id", m->tool_call_id ? m->tool_call_id : "");
    cJSON_AddStringToObject(block, "content", m->content ? m->content : "");
    return block;
}

/*
 * Build the messages array in Anthropic format.
 * System messages are excluded (handled separately).
 *
 * Mapping:
 *   user (no tool_call_id)   -> {"role":"user","content":[{"type":"text","text":"..."}]}
 *   user (with tool_call_id) -> {"role":"user","content":[{"type":"tool_result",...}]}
 *   tool                     -> {"role":"user","content":[{"type":"tool_result",...}]}
 *   assistant (no tools)     -> {"role":"assistant","content":[{"type":"text","text":"..."}]}
 *   assistant (with tools)   -> {"role":"assistant","content":[text_block?, tool_use_blocks...]}
 *
 * Consecutive same-role messages are merged into a single message with
 * multiple content blocks.
 */
static cJSON *build_messages_json(sc_llm_message_t *msgs, int msg_count)
{
    cJSON *arr = cJSON_CreateArray();
    cJSON *cur_msg = NULL;
    cJSON *cur_content = NULL;
    const char *cur_role = NULL;

    for (int i = 0; i < msg_count; i++) {
        sc_llm_message_t *m = &msgs[i];

        /* Skip system messages */
        if (m->role && strcmp(m->role, "system") == 0) continue;

        /* Determine the Anthropic role */
        const char *role;
        if (strcmp(m->role, "tool") == 0) {
            role = "user";
        } else {
            role = m->role; /* "user" or "assistant" */
        }

        /* If same role as current, merge into existing content array */
        if (cur_msg && cur_role && strcmp(cur_role, role) == 0) {
            /* Append blocks to existing content array */
        } else {
            /* Start new message */
            cur_msg = cJSON_CreateObject();
            cJSON_AddStringToObject(cur_msg, "role", role);
            cur_content = cJSON_CreateArray();
            cJSON_AddItemToObject(cur_msg, "content", cur_content);
            cJSON_AddItemToArray(arr, cur_msg);
            cur_role = role;
        }

        /* Build content blocks based on original role */
        if (strcmp(m->role, "tool") == 0 ||
            (strcmp(m->role, "user") == 0 && m->tool_call_id)) {
            /* Tool result */
            cJSON_AddItemToArray(cur_content, build_tool_result_block(m));
        } else if (strcmp(m->role, "assistant") == 0) {
            /* Assistant: text block + optional tool_use blocks */
            if (m->content && m->content[0] != '\0') {
                cJSON *text_block = cJSON_CreateObject();
                cJSON_AddStringToObject(text_block, "type", "text");
                cJSON_AddStringToObject(text_block, "text", m->content);
                cJSON_AddItemToArray(cur_content, text_block);
            }
            for (int j = 0; j < m->tool_call_count; j++) {
                sc_tool_call_t *tc = &m->tool_calls[j];
                cJSON *tu_block = cJSON_CreateObject();
                cJSON_AddStringToObject(tu_block, "type", "tool_use");
                cJSON_AddStringToObject(tu_block, "id", tc->id ? tc->id : "");
                cJSON_AddStringToObject(tu_block, "name", tc->name ? tc->name : "");
                if (tc->arguments) {
                    cJSON_AddItemToObject(tu_block, "input",
                                          cJSON_Duplicate(tc->arguments, 1));
                } else {
                    cJSON_AddItemToObject(tu_block, "input", cJSON_CreateObject());
                }
                cJSON_AddItemToArray(cur_content, tu_block);
            }
        } else {
            /* Regular user message: text block */
            cJSON *text_block = cJSON_CreateObject();
            cJSON_AddStringToObject(text_block, "type", "text");
            cJSON_AddStringToObject(text_block, "text", m->content ? m->content : "");
            cJSON_AddItemToArray(cur_content, text_block);
        }
    }

    return arr;
}

/* Build tools array in Anthropic format */
static cJSON *build_tools_json(sc_tool_definition_t *tools, int tool_count)
{
    cJSON *arr = cJSON_CreateArray();

    for (int i = 0; i < tool_count; i++) {
        sc_tool_definition_t *t = &tools[i];
        cJSON *tool_obj = cJSON_CreateObject();

        cJSON_AddStringToObject(tool_obj, "name", t->name ? t->name : "");
        if (t->description) {
            cJSON_AddStringToObject(tool_obj, "description", t->description);
        }

        /* input_schema from the parameters JSON Schema */
        if (t->parameters) {
            cJSON_AddItemToObject(tool_obj, "input_schema",
                                  cJSON_Duplicate(t->parameters, 1));
        } else {
            /* Minimal schema */
            cJSON *schema = cJSON_CreateObject();
            cJSON_AddStringToObject(schema, "type", "object");
            cJSON_AddItemToObject(schema, "properties", cJSON_CreateObject());
            cJSON_AddItemToObject(tool_obj, "input_schema", schema);
        }

        cJSON_AddItemToArray(arr, tool_obj);
    }

    return arr;
}

/* Parse Anthropic response */
static sc_llm_response_t *parse_response(const char *body)
{
    cJSON *root = cJSON_Parse(body);
    if (!root) {
        SC_LOG_ERROR(LOG_TAG, "Failed to parse response JSON");
        return NULL;
    }

    sc_llm_response_t *resp = calloc(1, sizeof(sc_llm_response_t));

    /* Parse content blocks */
    cJSON *content_arr = sc_json_get_array(root, "content");
    sc_strbuf_t text_buf;
    sc_strbuf_init(&text_buf);

    int tc_cap = 0;
    int tc_count = 0;
    sc_tool_call_t *tc_list = NULL;

    if (content_arr) {
        int n = cJSON_GetArraySize(content_arr);
        for (int i = 0; i < n; i++) {
            cJSON *block = cJSON_GetArrayItem(content_arr, i);
            const char *type = sc_json_get_string(block, "type", "");

            if (strcmp(type, "text") == 0) {
                const char *text = sc_json_get_string(block, "text", "");
                sc_strbuf_append(&text_buf, text);
            } else if (strcmp(type, "tool_use") == 0) {
                /* Grow tool_calls array if needed */
                if (tc_count >= tc_cap) {
                    int new_cap = tc_cap == 0 ? 4 : tc_cap * 2;
                    sc_tool_call_t *new_tc = sc_safe_realloc(tc_list,
                        (size_t)new_cap * sizeof(sc_tool_call_t));
                    if (!new_tc) break;
                    tc_list = new_tc;
                    tc_cap = new_cap;
                }
                sc_tool_call_t *tc = &tc_list[tc_count++];
                tc->id = sc_strdup(sc_json_get_string(block, "id", ""));
                tc->name = sc_strdup(sc_json_get_string(block, "name", ""));

                cJSON *input = sc_json_get_object(block, "input");
                if (input) {
                    tc->arguments = cJSON_Duplicate(input, 1);
                } else {
                    tc->arguments = cJSON_CreateObject();
                }
            }
        }
    }

    resp->content = sc_strbuf_finish(&text_buf);
    resp->tool_calls = tc_list;
    resp->tool_call_count = tc_count;

    /* Map stop_reason */
    const char *stop_reason = sc_json_get_string(root, "stop_reason", "end_turn");
    if (strcmp(stop_reason, "tool_use") == 0) {
        resp->finish_reason = sc_strdup("tool_calls");
    } else if (strcmp(stop_reason, "max_tokens") == 0) {
        resp->finish_reason = sc_strdup("length");
    } else {
        /* end_turn or anything else -> stop */
        resp->finish_reason = sc_strdup("stop");
    }

    /* Usage */
    cJSON *usage = sc_json_get_object(root, "usage");
    if (usage) {
        resp->usage.prompt_tokens = sc_json_get_int(usage, "input_tokens", 0);
        resp->usage.completion_tokens = sc_json_get_int(usage, "output_tokens", 0);
        resp->usage.total_tokens = resp->usage.prompt_tokens + resp->usage.completion_tokens;
    }

    cJSON_Delete(root);
    return resp;
}

/* ========================================================================
 * Claude provider vtable methods
 * ======================================================================== */

static sc_llm_response_t *claude_chat(sc_provider_t *self,
                                       sc_llm_message_t *msgs, int msg_count,
                                       sc_tool_definition_t *tools, int tool_count,
                                       const char *model, cJSON *options)
{
    claude_provider_data_t *d = self->data;

    if (!d->api_base || d->api_base[0] == '\0') {
        SC_LOG_ERROR(LOG_TAG, "API base not configured");
        return NULL;
    }

    /* Build request body */
    cJSON *body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "model", model ? model : "");

    /* System blocks */
    cJSON *sys_blocks = build_system_blocks(msgs, msg_count);
    if (sys_blocks) {
        cJSON_AddItemToObject(body, "system", sys_blocks);
    }

    /* Messages (excluding system) */
    cJSON_AddItemToObject(body, "messages",
                          build_messages_json(msgs, msg_count));

    /* max_tokens (required by Anthropic API) */
    int max_tokens = 4096;
    if (options) {
        int mt = sc_json_get_int(options, "max_tokens", 0);
        if (mt > 0) max_tokens = mt;
    }
    cJSON_AddNumberToObject(body, "max_tokens", max_tokens);

    /* temperature */
    if (options) {
        double temp = sc_json_get_double(options, "temperature", -1.0);
        if (temp >= 0.0) {
            cJSON_AddNumberToObject(body, "temperature", temp);
        }
    }

    /* Tools */
    if (tools && tool_count > 0) {
        cJSON_AddItemToObject(body, "tools",
                              build_tools_json(tools, tool_count));
    }

    char *body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);

    /* Build URL: {api_base}/messages */
    sc_strbuf_t url_buf;
    sc_strbuf_init(&url_buf);
    sc_strbuf_append(&url_buf, d->api_base);
    sc_strbuf_append(&url_buf, "/messages");
    char *url = sc_strbuf_finish(&url_buf);

    SC_LOG_DEBUG(LOG_TAG, "POST %s", url);

    /* Curl request */
    sc_strbuf_t response_buf;
    sc_strbuf_init(&response_buf);
    sc_header_ctx_t hdr_ctx = {0};

    const char *extra[] = { "anthropic-version: " ANTHROPIC_VERSION, NULL };
    struct curl_slist *headers = sc_provider_setup_curl(
        d->curl, url, d->api_key, "x-api-key: ",
        body_str, NULL, &hdr_ctx,
        sc_curl_write_cb, &response_buf, 120L, extra);

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
 * Streaming implementation (SSE)
 * ======================================================================== */

typedef struct {
    sc_strbuf_t content;      /* Accumulated text content */
    sc_tool_call_t *tool_calls;
    int tool_call_count;
    int tool_call_cap;
    char *finish_reason;
    sc_usage_info_t usage;
    sc_stream_cb user_cb;
    void *user_ctx;
    /* Track current tool input JSON accumulation */
    sc_strbuf_t tool_input_buf;
    int building_tool_input;
} claude_stream_ctx_t;

static void claude_stream_event(const char *data, void *ctx)
{
    claude_stream_ctx_t *sc = ctx;

    if (strcmp(data, "[DONE]") == 0) return;

    cJSON *event = cJSON_Parse(data);
    if (!event) return;

    const char *type = sc_json_get_string(event, "type", "");

    if (strcmp(type, "content_block_delta") == 0) {
        cJSON *delta = sc_json_get_object(event, "delta");
        if (delta) {
            const char *dtype = sc_json_get_string(delta, "type", "");
            if (strcmp(dtype, "text_delta") == 0) {
                const char *text = sc_json_get_string(delta, "text", "");
                sc_strbuf_append(&sc->content, text);
                if (sc->user_cb) sc->user_cb(text, sc->user_ctx);
            } else if (strcmp(dtype, "input_json_delta") == 0) {
                const char *partial = sc_json_get_string(delta, "partial_json", "");
                sc_strbuf_append(&sc->tool_input_buf, partial);
            }
        }
    } else if (strcmp(type, "content_block_start") == 0) {
        cJSON *cb = sc_json_get_object(event, "content_block");
        if (cb) {
            const char *cbtype = sc_json_get_string(cb, "type", "");
            if (strcmp(cbtype, "tool_use") == 0) {
                /* Start a new tool call */
                if (sc->tool_call_count >= sc->tool_call_cap) {
                    int new_cap = sc->tool_call_cap == 0 ? 4 : sc->tool_call_cap * 2;
                    sc_tool_call_t *new_tc = sc_safe_realloc(sc->tool_calls,
                        (size_t)new_cap * sizeof(sc_tool_call_t));
                    if (!new_tc) return;
                    sc->tool_calls = new_tc;
                    sc->tool_call_cap = new_cap;
                }
                sc_tool_call_t *tc = &sc->tool_calls[sc->tool_call_count++];
                tc->id = sc_strdup(sc_json_get_string(cb, "id", ""));
                tc->name = sc_strdup(sc_json_get_string(cb, "name", ""));
                tc->arguments = NULL;
                sc->building_tool_input = 1;
                sc->tool_input_buf.len = 0;
            }
        }
    } else if (strcmp(type, "content_block_stop") == 0) {
        if (sc->building_tool_input && sc->tool_call_count > 0) {
            /* Finalize tool input JSON */
            char *json_str = sc_strbuf_finish(&sc->tool_input_buf);
            sc_tool_call_t *tc = &sc->tool_calls[sc->tool_call_count - 1];
            tc->arguments = cJSON_Parse(json_str);
            if (!tc->arguments) tc->arguments = cJSON_CreateObject();
            free(json_str);
            sc_strbuf_init(&sc->tool_input_buf);
            sc->building_tool_input = 0;
        }
    } else if (strcmp(type, "message_delta") == 0) {
        cJSON *delta = sc_json_get_object(event, "delta");
        if (delta) {
            const char *sr = sc_json_get_string(delta, "stop_reason", NULL);
            if (sr) {
                free(sc->finish_reason);
                if (strcmp(sr, "tool_use") == 0)
                    sc->finish_reason = sc_strdup("tool_calls");
                else if (strcmp(sr, "max_tokens") == 0)
                    sc->finish_reason = sc_strdup("length");
                else
                    sc->finish_reason = sc_strdup("stop");
            }
        }
        cJSON *usage = sc_json_get_object(event, "usage");
        if (usage) {
            sc->usage.completion_tokens = sc_json_get_int(usage, "output_tokens", 0);
        }
    } else if (strcmp(type, "message_start") == 0) {
        cJSON *msg = sc_json_get_object(event, "message");
        if (msg) {
            cJSON *usage = sc_json_get_object(msg, "usage");
            if (usage) {
                sc->usage.prompt_tokens = sc_json_get_int(usage, "input_tokens", 0);
            }
        }
    }

    cJSON_Delete(event);
}

/* curl write callback for SSE streaming */
static size_t curl_stream_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    sc_sse_parser_t *sse = userdata;
    if (nmemb > 0 && size > SIZE_MAX / nmemb) return 0;
    size_t total = size * nmemb;
    sc_sse_feed(sse, ptr, total);
    return total;
}

static sc_llm_response_t *claude_chat_stream(sc_provider_t *self,
                                              sc_llm_message_t *msgs, int msg_count,
                                              sc_tool_definition_t *tools, int tool_count,
                                              const char *model, cJSON *options,
                                              sc_stream_cb stream_cb, void *stream_ctx)
{
    claude_provider_data_t *d = self->data;

    if (!d->api_base || d->api_base[0] == '\0') {
        SC_LOG_ERROR(LOG_TAG, "API base not configured");
        return NULL;
    }

    /* Build request body (same as non-streaming, plus stream:true) */
    cJSON *body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "model", model ? model : "");
    cJSON_AddBoolToObject(body, "stream", 1);

    cJSON *sys_blocks = build_system_blocks(msgs, msg_count);
    if (sys_blocks) cJSON_AddItemToObject(body, "system", sys_blocks);

    cJSON_AddItemToObject(body, "messages", build_messages_json(msgs, msg_count));

    int max_tokens = 4096;
    if (options) {
        int mt = sc_json_get_int(options, "max_tokens", 0);
        if (mt > 0) max_tokens = mt;
    }
    cJSON_AddNumberToObject(body, "max_tokens", max_tokens);

    if (options) {
        double temp = sc_json_get_double(options, "temperature", -1.0);
        if (temp >= 0.0) cJSON_AddNumberToObject(body, "temperature", temp);
    }

    if (tools && tool_count > 0) {
        cJSON_AddItemToObject(body, "tools", build_tools_json(tools, tool_count));
    }

    char *body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);

    sc_strbuf_t url_buf;
    sc_strbuf_init(&url_buf);
    sc_strbuf_append(&url_buf, d->api_base);
    sc_strbuf_append(&url_buf, "/messages");
    char *url = sc_strbuf_finish(&url_buf);

    SC_LOG_DEBUG(LOG_TAG, "POST %s (streaming)", url);

    /* Set up stream context */
    claude_stream_ctx_t sc = {0};
    sc_strbuf_init(&sc.content);
    sc_strbuf_init(&sc.tool_input_buf);
    sc.user_cb = stream_cb;
    sc.user_ctx = stream_ctx;
    sc.finish_reason = sc_strdup("stop");

    sc_sse_parser_t sse;
    sc_sse_init(&sse, claude_stream_event, &sc);

    sc_header_ctx_t stream_hdr = {0};

    const char *extra[] = { "anthropic-version: " ANTHROPIC_VERSION, NULL };
    struct curl_slist *headers = sc_provider_setup_curl(
        d->curl, url, d->api_key, "x-api-key: ",
        body_str, NULL, &stream_hdr,
        curl_stream_cb, &sse, 300L, extra);

    CURLcode res = curl_easy_perform(d->curl);

    curl_slist_free_all(headers);
    free(url);
    free(body_str);

    /* Signal end of stream */
    if (stream_cb) stream_cb(NULL, stream_ctx);

    if (res != CURLE_OK) {
        SC_LOG_ERROR(LOG_TAG, "curl streaming request failed: %s", curl_easy_strerror(res));
        sc_sse_free(&sse);
        sc_strbuf_free(&sc.content);
        sc_strbuf_free(&sc.tool_input_buf);
        free(sc.finish_reason);
        for (int i = 0; i < sc.tool_call_count; i++)
            sc_tool_call_free_fields(&sc.tool_calls[i]);
        free(sc.tool_calls);
        return sc_provider_make_error_response(0, 0);
    }

    long http_code = 0;
    curl_easy_getinfo(d->curl, CURLINFO_RESPONSE_CODE, &http_code);

    sc_sse_free(&sse);
    sc_strbuf_free(&sc.tool_input_buf);

    if (http_code != 200) {
        char *content = sc_strbuf_finish(&sc.content);
        SC_LOG_ERROR(LOG_TAG, "Streaming API failed (HTTP %ld): %.500s",
                     http_code, content ? content : "(empty)");
        free(content);
        free(sc.finish_reason);
        for (int i = 0; i < sc.tool_call_count; i++)
            sc_tool_call_free_fields(&sc.tool_calls[i]);
        free(sc.tool_calls);
        return sc_provider_make_error_response((int)http_code,
                                               stream_hdr.retry_after);
    }

    /* Build response */
    sc_llm_response_t *resp = calloc(1, sizeof(*resp));
    resp->content = sc_strbuf_finish(&sc.content);
    resp->tool_calls = sc.tool_calls;
    resp->tool_call_count = sc.tool_call_count;
    resp->finish_reason = sc.finish_reason;
    resp->usage = sc.usage;
    resp->usage.total_tokens = resp->usage.prompt_tokens + resp->usage.completion_tokens;
    resp->http_status = 200;

    return resp;
}
#endif /* SC_ENABLE_STREAMING */

static const char *claude_get_default_model(sc_provider_t *self)
{
    (void)self;
    return "claude-sonnet-4-5-20250929";
}

static sc_provider_t *claude_clone(sc_provider_t *self)
{
    claude_provider_data_t *d = self->data;
    return sc_provider_claude_new(d->api_key, d->api_base);
}

static void claude_destroy(sc_provider_t *self)
{
    if (!self) return;
    claude_provider_data_t *d = self->data;
    if (d) {
        free(d->api_key);
        free(d->api_base);
        if (d->curl) curl_easy_cleanup(d->curl);
        free(d);
    }
    free(self);
}

/* ========================================================================
 * Public constructor
 * ======================================================================== */

sc_provider_t *sc_provider_claude_new(const char *api_key, const char *api_base)
{
    sc_provider_t *p = calloc(1, sizeof(sc_provider_t));
    claude_provider_data_t *d = calloc(1, sizeof(claude_provider_data_t));

    d->api_key = sc_strdup(api_key);

    if (api_base) {
        d->api_base = sc_strdup(api_base);
        sc_provider_trim_base_url(d->api_base);
    }

    d->curl = sc_provider_init_curl();

    p->name = "claude";
    p->chat = claude_chat;
#if SC_ENABLE_STREAMING
    p->chat_stream = claude_chat_stream;
#endif
    p->get_default_model = claude_get_default_model;
    p->destroy = claude_destroy;
    p->clone = claude_clone;
    p->data = d;

    SC_LOG_INFO(LOG_TAG, "Created Claude provider (base=%s)",
                d->api_base ? d->api_base : "(none)");

    return p;
}
