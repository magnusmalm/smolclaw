/*
 * tools/delegate.c - Agent-to-agent task delegation tool
 *
 * POSTs tasks to other smolclaw agents via their Web channel
 * REST API (POST /api/message) and returns the response.
 * Targets are configured in config.json under delegation.targets.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tools/delegate.h"
#include "tools/types.h"
#include "memory.h"
#include "util/str.h"
#include "util/uuid.h"
#include "util/json_helpers.h"
#include "util/curl_common.h"
#include "logger.h"
#include "cJSON.h"

#include <curl/curl.h>

typedef struct {
    sc_delegate_target_t *targets;
    int target_count;
    char *workspace;  /* for logging delegation results to local memory */
} delegate_data_t;

/* ---------- curl write callback ---------- */

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} curl_buf_t;

#define DELEGATE_MAX_RESPONSE (512 * 1024) /* 512 KB */

static size_t curl_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    curl_buf_t *buf = userdata;
    if (nmemb > 0 && size > SIZE_MAX / nmemb) return 0;
    size_t total = size * nmemb;
    if (buf->len + total > DELEGATE_MAX_RESPONSE) return 0;

    if (buf->len + total >= buf->cap) {
        size_t new_cap = (buf->cap + total) * 2;
        char *tmp = realloc(buf->data, new_cap);
        if (!tmp) return 0;
        buf->data = tmp;
        buf->cap = new_cap;
    }

    memcpy(buf->data + buf->len, ptr, total);
    buf->len += total;
    buf->data[buf->len] = '\0';
    return total;
}

static void curl_buf_init(curl_buf_t *buf)
{
    buf->cap = 4096;
    buf->data = malloc(buf->cap);
    buf->len = 0;
    if (buf->data) buf->data[0] = '\0';
    else buf->cap = 0;
}

static void curl_buf_free(curl_buf_t *buf)
{
    free(buf->data);
    buf->data = NULL;
    buf->len = buf->cap = 0;
}

/* ---------- tool vtable ---------- */

static void delegate_destroy(sc_tool_t *self)
{
    if (!self) return;
    delegate_data_t *d = self->data;
    if (d) free(d->workspace);
    free(d);
    free(self);
}

static cJSON *delegate_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "object");

    cJSON *props = cJSON_AddObjectToObject(schema, "properties");

    cJSON *target = cJSON_AddObjectToObject(props, "target");
    cJSON_AddStringToObject(target, "type", "string");
    cJSON_AddStringToObject(target, "description",
        "Name of the target agent to delegate to (from config)");

    cJSON *task = cJSON_AddObjectToObject(props, "task");
    cJSON_AddStringToObject(task, "type", "string");
    cJSON_AddStringToObject(task, "description",
        "The task/message to send to the target agent");

    cJSON *session = cJSON_AddObjectToObject(props, "session");
    cJSON_AddStringToObject(session, "type", "string");
    cJSON_AddStringToObject(session, "description",
        "Optional session ID for conversation continuity");

    cJSON *action = cJSON_AddObjectToObject(props, "action");
    cJSON_AddStringToObject(action, "type", "string");
    cJSON_AddStringToObject(action, "description",
        "Optional action: 'memory_search' to search the target agent's "
        "memory index directly (task becomes the search query). "
        "Default is to send task as a message.");

    cJSON *req = cJSON_AddArrayToObject(schema, "required");
    cJSON_AddItemToArray(req, cJSON_CreateString("target"));
    cJSON_AddItemToArray(req, cJSON_CreateString("task"));
    return schema;
}

static sc_tool_result_t *delegate_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    delegate_data_t *d = self->data;

    const char *target_name = sc_json_get_string(args, "target", NULL);
    if (!target_name)
        return sc_tool_result_error("'target' is required");

    const char *task = sc_json_get_string(args, "task", NULL);
    if (!task)
        return sc_tool_result_error("'task' is required");

    const char *session = sc_json_get_string(args, "session", NULL);

    /* Look up target in configured targets */
    sc_delegate_target_t *tgt = NULL;
    for (int i = 0; i < d->target_count; i++) {
        if (strcmp(d->targets[i].name, target_name) == 0) {
            tgt = &d->targets[i];
            break;
        }
    }
    if (!tgt) {
        sc_strbuf_t sb;
        sc_strbuf_init(&sb);
        sc_strbuf_appendf(&sb, "Unknown delegation target '%s'. Available: ", target_name);
        for (int i = 0; i < d->target_count; i++) {
            if (i > 0) sc_strbuf_append(&sb, ", ");
            sc_strbuf_append(&sb, d->targets[i].name);
        }
        char *msg = sc_strbuf_finish(&sb);
        sc_tool_result_t *r = sc_tool_result_error(msg);
        free(msg);
        return r;
    }

    if (!tgt->url || !tgt->url[0])
        return sc_tool_result_error("Delegation target has no URL configured");

    /* Check for action dispatch */
    const char *action = sc_json_get_string(args, "action", NULL);

    /* memory_search: POST to /api/memory/search instead of /api/message */
    if (action && strcmp(action, "memory_search") == 0) {
        /* Derive search URL from target URL: replace /api/message with /api/memory/search */
        sc_strbuf_t url_sb;
        sc_strbuf_init(&url_sb);
        const char *api_msg = strstr(tgt->url, "/api/message");
        if (api_msg) {
            sc_strbuf_appendf(&url_sb, "%.*s/api/memory/search",
                              (int)(api_msg - tgt->url), tgt->url);
        } else {
            /* Fallback: append to base URL */
            sc_strbuf_appendf(&url_sb, "%s/api/memory/search", tgt->url);
        }
        char *search_url = sc_strbuf_finish(&url_sb);

        cJSON *body = cJSON_CreateObject();
        cJSON_AddStringToObject(body, "query", task);
        cJSON_AddNumberToObject(body, "max_results", 10);
        char *body_str = cJSON_PrintUnformatted(body);
        cJSON_Delete(body);

        SC_LOG_INFO("delegate", "Memory search on %s: %s", target_name, task);

        CURL *curl = sc_curl_init();
        if (!curl) {
            free(body_str);
            free(search_url);
            return sc_tool_result_error("Failed to initialize curl");
        }

        curl_buf_t buf;
        curl_buf_init(&buf);

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        if (tgt->bearer_token && tgt->bearer_token[0]) {
            sc_strbuf_t auth;
            sc_strbuf_init(&auth);
            sc_strbuf_appendf(&auth, "Authorization: Bearer %s", tgt->bearer_token);
            char *auth_str = sc_strbuf_finish(&auth);
            headers = curl_slist_append(headers, auth_str);
            free(auth_str);
        }

        curl_easy_setopt(curl, CURLOPT_URL, search_url);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body_str);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);

        CURLcode res = curl_easy_perform(curl);
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        free(body_str);
        free(search_url);

        if (res != CURLE_OK) {
            sc_strbuf_t err;
            sc_strbuf_init(&err);
            sc_strbuf_appendf(&err, "Memory search on %s failed: %s",
                              target_name, curl_easy_strerror(res));
            char *msg = sc_strbuf_finish(&err);
            curl_buf_free(&buf);
            sc_tool_result_t *r = sc_tool_result_error(msg);
            free(msg);
            return r;
        }

        sc_tool_result_t *result = buf.data && buf.len > 0
            ? sc_tool_result_new(buf.data)
            : sc_tool_result_new("No results");
        curl_buf_free(&buf);
        return result;
    }

    /* Build JSON body: {"message": "<task>", "session": "<session_or_uuid>"} */
    cJSON *body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "message", task);
    if (session && session[0]) {
        cJSON_AddStringToObject(body, "session", session);
    } else {
        char *uuid = sc_generate_id();
        cJSON_AddStringToObject(body, "session", uuid);
        free(uuid);
    }
    char *body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!body_str)
        return sc_tool_result_error("Failed to serialize request body");

    SC_LOG_INFO("delegate", "Delegating to %s at %s", target_name, tgt->url);

    /* Perform HTTP POST */
    CURL *curl = sc_curl_init();
    if (!curl) {
        free(body_str);
        return sc_tool_result_error("Failed to initialize curl");
    }

    curl_buf_t buf;
    curl_buf_init(&buf);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (tgt->bearer_token && tgt->bearer_token[0]) {
        sc_strbuf_t auth;
        sc_strbuf_init(&auth);
        sc_strbuf_appendf(&auth, "Authorization: Bearer %s", tgt->bearer_token);
        char *auth_str = sc_strbuf_finish(&auth);
        headers = curl_slist_append(headers, auth_str);
        free(auth_str);
    }

    curl_easy_setopt(curl, CURLOPT_URL, tgt->url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body_str);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)tgt->timeout_secs);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);

    CURLcode res = curl_easy_perform(curl);

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(body_str);

    if (res != CURLE_OK) {
        sc_strbuf_t err;
        sc_strbuf_init(&err);
        sc_strbuf_appendf(&err, "Delegation to %s failed: %s",
                          target_name, curl_easy_strerror(res));
        char *msg = sc_strbuf_finish(&err);
        curl_buf_free(&buf);
        sc_tool_result_t *r = sc_tool_result_error(msg);
        free(msg);
        return r;
    }

    if (http_code != 200) {
        sc_strbuf_t err;
        sc_strbuf_init(&err);
        sc_strbuf_appendf(&err, "Delegation to %s returned HTTP %ld",
                          target_name, http_code);
        if (buf.data && buf.len > 0) {
            sc_strbuf_appendf(&err, ": %.*s",
                              (int)(buf.len > 200 ? 200 : buf.len), buf.data);
        }
        char *msg = sc_strbuf_finish(&err);
        curl_buf_free(&buf);
        sc_tool_result_t *r = sc_tool_result_error(msg);
        free(msg);
        return r;
    }

    /* Parse response: try to extract {"response": "..."} */
    sc_tool_result_t *result = NULL;
    if (buf.data && buf.len > 0) {
        cJSON *resp = cJSON_Parse(buf.data);
        if (resp) {
            const char *response_text = sc_json_get_string(resp, "response", NULL);
            if (response_text) {
                result = sc_tool_result_new(response_text);
            } else {
                /* Return raw JSON if no "response" field */
                result = sc_tool_result_new(buf.data);
            }
            cJSON_Delete(resp);
        } else {
            result = sc_tool_result_new(buf.data);
        }
    } else {
        result = sc_tool_result_new("Delegation completed (empty response)");
    }

    curl_buf_free(&buf);
    SC_LOG_INFO("delegate", "Delegation to %s completed (HTTP %ld)", target_name, http_code);

    /* Log delegation result to local daily notes */
    if (d->workspace && result && result->for_llm) {
        sc_memory_t *mem = sc_memory_new(d->workspace);
        if (mem) {
            /* Truncate result preview for the memory entry */
            const char *preview = result->for_llm;
            size_t plen = strlen(preview);
            char truncated[256];
            if (plen > 200) {
                snprintf(truncated, sizeof(truncated), "%.200s...", preview);
                preview = truncated;
            }
            sc_strbuf_t entry;
            sc_strbuf_init(&entry);
            sc_strbuf_appendf(&entry,
                "[delegation] Delegated to **%s**: %.*s → %s",
                target_name,
                (int)(strlen(task) > 120 ? 120 : strlen(task)), task,
                preview);
            char *text = sc_strbuf_finish(&entry);
            sc_memory_append_today(mem, text);
            free(text);
            sc_memory_free(mem);
        }
    }

    return result;
}

sc_tool_t *sc_tool_delegate_new(sc_delegation_config_t *cfg, const char *workspace)
{
    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    delegate_data_t *d = calloc(1, sizeof(*d));
    if (!d) { free(t); return NULL; }
    d->targets = cfg->targets;
    d->target_count = cfg->target_count;
    d->workspace = sc_strdup(workspace);

    t->name = "delegate";
    t->description = "Delegate a task to another agent. Sends the task to the "
                     "target agent's REST API and returns their response. Use "
                     "this to route tasks to agents with specialized capabilities.";
    t->parameters = delegate_parameters;
    t->execute = delegate_execute;
    t->destroy = delegate_destroy;
    t->data = d;
    return t;
}
