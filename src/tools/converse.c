/*
 * tools/converse.c - Multi-turn agent-to-agent dialogue tool
 *
 * Facilitates a structured debate between two remote agents.
 * Alternates messages for N rounds with session continuity,
 * then returns the full transcript to the calling agent.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tools/converse.h"
#include "tools/types.h"
#include "memory.h"
#include "util/str.h"
#include "util/uuid.h"
#include "util/json_helpers.h"
#include "util/curl_common.h"
#include "logger.h"
#include "cJSON.h"

#include <curl/curl.h>

#define CONVERSE_TAG      "converse"
#define MAX_ROUNDS        10
#define DEFAULT_ROUNDS    3
#define MAX_RESPONSE      (512 * 1024)

typedef struct {
    sc_delegate_target_t *targets;
    int target_count;
    char *workspace;
} converse_data_t;

/* ---------- curl write callback ---------- */

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} curl_buf_t;

static size_t curl_write_cb(void *ptr, size_t size, size_t nmemb, void *ud)
{
    curl_buf_t *buf = ud;
    if (nmemb > 0 && size > SIZE_MAX / nmemb) return 0;
    size_t total = size * nmemb;
    if (buf->len + total > MAX_RESPONSE) return 0;

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

/* ---------- send one message to a target ---------- */

/*
 * POST {"message": msg, "session": session} to target's URL.
 * Returns malloc'd response text or NULL on error.
 * On error, *err is set to a malloc'd error string.
 */
static char *send_message(const sc_delegate_target_t *tgt,
                           const char *msg, const char *session,
                           char **err)
{
    *err = NULL;

    cJSON *body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "message", msg);
    cJSON_AddStringToObject(body, "session", session);
    char *body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!body_str) {
        *err = sc_strdup("Failed to serialize request");
        return NULL;
    }

    CURL *curl = sc_curl_init();
    if (!curl) {
        free(body_str);
        *err = sc_strdup("Failed to initialize curl");
        return NULL;
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
        sc_strbuf_t sb;
        sc_strbuf_init(&sb);
        sc_strbuf_appendf(&sb, "HTTP request failed: %s", curl_easy_strerror(res));
        *err = sc_strbuf_finish(&sb);
        curl_buf_free(&buf);
        return NULL;
    }

    if (http_code != 200) {
        sc_strbuf_t sb;
        sc_strbuf_init(&sb);
        sc_strbuf_appendf(&sb, "HTTP %ld", http_code);
        if (buf.data && buf.len > 0)
            sc_strbuf_appendf(&sb, ": %.*s",
                              (int)(buf.len > 200 ? 200 : buf.len), buf.data);
        *err = sc_strbuf_finish(&sb);
        curl_buf_free(&buf);
        return NULL;
    }

    /* Extract response text */
    char *result = NULL;
    if (buf.data && buf.len > 0) {
        cJSON *resp = cJSON_Parse(buf.data);
        if (resp) {
            const char *text = sc_json_get_string(resp, "response", NULL);
            result = sc_strdup(text ? text : buf.data);
            cJSON_Delete(resp);
        } else {
            result = sc_strdup(buf.data);
        }
    }

    curl_buf_free(&buf);
    return result;
}

/* ---------- tool vtable ---------- */

static void converse_destroy(sc_tool_t *self)
{
    if (!self) return;
    converse_data_t *d = self->data;
    if (d) free(d->workspace);
    free(d);
    free(self);
}

static cJSON *converse_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "object");

    cJSON *props = cJSON_AddObjectToObject(schema, "properties");

    cJSON *a = cJSON_AddObjectToObject(props, "agent_a");
    cJSON_AddStringToObject(a, "type", "string");
    cJSON_AddStringToObject(a, "description",
        "Name of the first agent (from delegation targets)");

    cJSON *b = cJSON_AddObjectToObject(props, "agent_b");
    cJSON_AddStringToObject(b, "type", "string");
    cJSON_AddStringToObject(b, "description",
        "Name of the second agent (from delegation targets)");

    cJSON *topic = cJSON_AddObjectToObject(props, "topic");
    cJSON_AddStringToObject(topic, "type", "string");
    cJSON_AddStringToObject(topic, "description",
        "The topic or question for both agents to discuss");

    cJSON *rounds = cJSON_AddObjectToObject(props, "rounds");
    cJSON_AddStringToObject(rounds, "type", "integer");
    cJSON_AddStringToObject(rounds, "description",
        "Number of exchanges (default 3, max 10). Each exchange is "
        "one message from each agent.");

    cJSON *req = cJSON_AddArrayToObject(schema, "required");
    cJSON_AddItemToArray(req, cJSON_CreateString("agent_a"));
    cJSON_AddItemToArray(req, cJSON_CreateString("agent_b"));
    cJSON_AddItemToArray(req, cJSON_CreateString("topic"));
    return schema;
}

static sc_delegate_target_t *find_target(converse_data_t *d, const char *name)
{
    for (int i = 0; i < d->target_count; i++)
        if (strcmp(d->targets[i].name, name) == 0)
            return &d->targets[i];
    return NULL;
}

static sc_tool_result_t *converse_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    converse_data_t *d = self->data;

    const char *name_a = sc_json_get_string(args, "agent_a", NULL);
    const char *name_b = sc_json_get_string(args, "agent_b", NULL);
    const char *topic  = sc_json_get_string(args, "topic", NULL);
    if (!name_a || !name_b || !topic)
        return sc_tool_result_error("'agent_a', 'agent_b', and 'topic' are required");

    int rounds = sc_json_get_int(args, "rounds", DEFAULT_ROUNDS);
    if (rounds < 1) rounds = 1;
    if (rounds > MAX_ROUNDS) rounds = MAX_ROUNDS;

    sc_delegate_target_t *tgt_a = find_target(d, name_a);
    sc_delegate_target_t *tgt_b = find_target(d, name_b);
    if (!tgt_a || !tgt_b) {
        sc_strbuf_t sb;
        sc_strbuf_init(&sb);
        sc_strbuf_appendf(&sb, "Unknown agent(s): ");
        if (!tgt_a) sc_strbuf_appendf(&sb, "'%s' ", name_a);
        if (!tgt_b) sc_strbuf_appendf(&sb, "'%s' ", name_b);
        sc_strbuf_append(&sb, "— available: ");
        for (int i = 0; i < d->target_count; i++) {
            if (i > 0) sc_strbuf_append(&sb, ", ");
            sc_strbuf_append(&sb, d->targets[i].name);
        }
        char *msg = sc_strbuf_finish(&sb);
        sc_tool_result_t *r = sc_tool_result_error(msg);
        free(msg);
        return r;
    }

    /* Generate session IDs for continuity */
    char *sess_a = sc_generate_id();
    char *sess_b = sc_generate_id();
    if (!sess_a || !sess_b) {
        free(sess_a);
        free(sess_b);
        return sc_tool_result_error("Failed to generate session IDs");
    }

    SC_LOG_INFO(CONVERSE_TAG, "Starting %d-round dialogue: %s <-> %s on '%.*s'",
                rounds, name_a, name_b,
                (int)(strlen(topic) > 80 ? 80 : strlen(topic)), topic);

    sc_strbuf_t transcript;
    sc_strbuf_init(&transcript);
    sc_strbuf_appendf(&transcript, "## Dialogue: %s <-> %s\n**Topic:** %s\n\n",
                      name_a, name_b, topic);

    char *last_response = NULL;
    int ok = 1;

    for (int round = 1; round <= rounds && ok; round++) {
        /* --- Agent A's turn --- */
        sc_strbuf_t prompt_a;
        sc_strbuf_init(&prompt_a);
        if (round == 1) {
            sc_strbuf_appendf(&prompt_a,
                "You are in a dialogue with %s about: %s\n\n"
                "State your position concisely.", name_b, topic);
        } else {
            sc_strbuf_appendf(&prompt_a,
                "%s responded:\n%s\n\n"
                "Address their points and advance your position.",
                name_b, last_response ? last_response : "(no response)");
        }
        char *msg_a = sc_strbuf_finish(&prompt_a);

        SC_LOG_INFO(CONVERSE_TAG, "Round %d/%d: %s", round, rounds, name_a);
        char *err = NULL;
        char *resp_a = send_message(tgt_a, msg_a, sess_a, &err);
        free(msg_a);

        if (!resp_a) {
            sc_strbuf_appendf(&transcript, "**[Round %d aborted]** %s error: %s\n",
                              round, name_a, err ? err : "unknown");
            free(err);
            ok = 0;
            break;
        }

        sc_strbuf_appendf(&transcript, "### Round %d\n\n**%s:**\n%s\n\n",
                          round, name_a, resp_a);
        free(last_response);
        last_response = resp_a;

        /* --- Agent B's turn --- */
        sc_strbuf_t prompt_b;
        sc_strbuf_init(&prompt_b);
        if (round == 1) {
            sc_strbuf_appendf(&prompt_b,
                "You are in a dialogue with %s about: %s\n\n"
                "%s said:\n%s\n\n"
                "Respond with your perspective. Challenge or build on their points.",
                name_a, topic, name_a, last_response);
        } else {
            sc_strbuf_appendf(&prompt_b,
                "%s responded:\n%s\n\n"
                "Address their points and advance your position.",
                name_a, last_response);
        }
        char *msg_b = sc_strbuf_finish(&prompt_b);

        SC_LOG_INFO(CONVERSE_TAG, "Round %d/%d: %s", round, rounds, name_b);
        char *resp_b = send_message(tgt_b, msg_b, sess_b, &err);
        free(msg_b);

        if (!resp_b) {
            sc_strbuf_appendf(&transcript, "**[Round %d aborted]** %s error: %s\n",
                              round, name_b, err ? err : "unknown");
            free(err);
            ok = 0;
            break;
        }

        sc_strbuf_appendf(&transcript, "**%s:**\n%s\n\n", name_b, resp_b);
        free(last_response);
        last_response = resp_b;
    }

    free(last_response);
    free(sess_a);
    free(sess_b);

    char *text = sc_strbuf_finish(&transcript);
    sc_tool_result_t *result = sc_tool_result_new(text);

    /* Log dialogue summary to memory */
    if (d->workspace) {
        sc_memory_t *mem = sc_memory_new(d->workspace);
        if (mem) {
            sc_strbuf_t entry;
            sc_strbuf_init(&entry);
            sc_strbuf_appendf(&entry,
                "[converse] %s <-> %s (%d rounds) on: %.*s — %s",
                name_a, name_b, rounds,
                (int)(strlen(topic) > 100 ? 100 : strlen(topic)), topic,
                ok ? "completed" : "aborted");
            char *log = sc_strbuf_finish(&entry);
            sc_memory_append_today(mem, log);
            free(log);
            sc_memory_free(mem);
        }
    }

    free(text);
    SC_LOG_INFO(CONVERSE_TAG, "Dialogue %s <-> %s %s after %d rounds",
                name_a, name_b, ok ? "completed" : "aborted", rounds);
    return result;
}

sc_tool_t *sc_tool_converse_new(sc_delegation_config_t *cfg,
                                 const char *workspace)
{
    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    converse_data_t *d = calloc(1, sizeof(*d));
    if (!d) { free(t); return NULL; }
    d->targets = cfg->targets;
    d->target_count = cfg->target_count;
    d->workspace = sc_strdup(workspace);

    t->name = "converse";
    t->description = "Start a multi-turn dialogue between two agents. Both agents "
                     "debate the topic for the specified number of rounds, building "
                     "on each other's responses. Returns the full transcript. Use "
                     "this when a topic benefits from multiple perspectives or "
                     "iterative refinement between specialists.";
    t->parameters = converse_parameters;
    t->execute = converse_execute;
    t->destroy = converse_destroy;
    t->data = d;
    return t;
}
