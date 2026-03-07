#include "session.h"
#include "logger.h"
#include "util/str.h"
#include "util/json_helpers.h"
#include "util/secrets.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>

#define LOG_TAG "session"
#define INITIAL_MSG_CAP  16
#define INITIAL_SESS_CAP 8

struct sc_session {
    char *key;
    sc_llm_message_t *messages;
    int message_count;
    int message_cap;
    char *summary;
    long created;  /* unix timestamp */
    long updated;
};

struct sc_session_manager {
    sc_session_t **sessions;
    int count;
    int cap;
    char *storage_dir;
};

/* ---- Internal helpers ---- */

static sc_session_t *session_create(const char *key)
{
    sc_session_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;

    s->key         = sc_strdup(key);
    s->messages    = calloc(INITIAL_MSG_CAP, sizeof(sc_llm_message_t));
    s->message_cap = INITIAL_MSG_CAP;
    s->created     = (long)time(NULL);
    s->updated     = s->created;

    return s;
}

static void session_free(sc_session_t *s)
{
    if (!s) return;
    free(s->key);
    for (int i = 0; i < s->message_count; i++) {
        sc_llm_message_free_fields(&s->messages[i]);
    }
    free(s->messages);
    free(s->summary);
    free(s);
}

static int session_ensure_cap(sc_session_t *s)
{
    if (s->message_count < s->message_cap) return 0;
    int new_cap = s->message_cap * 2;
    sc_llm_message_t *new_msgs = sc_safe_realloc(s->messages,
                                          (size_t)new_cap * sizeof(sc_llm_message_t));
    if (!new_msgs) return -1;
    s->messages    = new_msgs;
    s->message_cap = new_cap;
    return 0;
}

static sc_session_t *find_session(sc_session_manager_t *sm, const char *key)
{
    for (int i = 0; i < sm->count; i++) {
        if (strcmp(sm->sessions[i]->key, key) == 0)
            return sm->sessions[i];
    }
    return NULL;
}

static int manager_add_session(sc_session_manager_t *sm, sc_session_t *s)
{
    if (sm->count >= sm->cap) {
        int new_cap = sm->cap * 2;
        sc_session_t **new_arr = sc_safe_realloc(sm->sessions,
                                          (size_t)new_cap * sizeof(sc_session_t *));
        if (!new_arr) return -1;
        sm->sessions = new_arr;
        sm->cap      = new_cap;
    }
    sm->sessions[sm->count++] = s;
    return 0;
}

/* ---- Serialization helpers ---- */

static cJSON *message_to_json(const sc_llm_message_t *msg)
{
    cJSON *obj = cJSON_CreateObject();
    if (!obj) return NULL;

    if (msg->role)    cJSON_AddStringToObject(obj, "role", msg->role);
    if (msg->content) cJSON_AddStringToObject(obj, "content", msg->content);

    if (msg->tool_call_id)
        cJSON_AddStringToObject(obj, "tool_call_id", msg->tool_call_id);

    if (msg->tool_calls && msg->tool_call_count > 0) {
        cJSON *calls = cJSON_AddArrayToObject(obj, "tool_calls");
        for (int i = 0; i < msg->tool_call_count; i++) {
            cJSON *tc = cJSON_CreateObject();
            if (msg->tool_calls[i].id)
                cJSON_AddStringToObject(tc, "id", msg->tool_calls[i].id);
            if (msg->tool_calls[i].name)
                cJSON_AddStringToObject(tc, "name", msg->tool_calls[i].name);
            if (msg->tool_calls[i].arguments)
                cJSON_AddItemToObject(tc, "arguments",
                                      cJSON_Duplicate(msg->tool_calls[i].arguments, 1));
            cJSON_AddItemToArray(calls, tc);
        }
    }

    return obj;
}

static sc_llm_message_t message_from_json(const cJSON *obj)
{
    sc_llm_message_t msg = {0};

    msg.role    = sc_strdup(sc_json_get_string(obj, "role", NULL));
    msg.content = sc_strdup(sc_json_get_string(obj, "content", NULL));
    msg.tool_call_id = sc_strdup(sc_json_get_string(obj, "tool_call_id", NULL));

    const cJSON *calls = sc_json_get_array(obj, "tool_calls");
    if (calls) {
        int n = cJSON_GetArraySize(calls);
        if (n > 0) {
            msg.tool_calls = calloc((size_t)n, sizeof(sc_tool_call_t));
            if (msg.tool_calls) {
                msg.tool_call_count = 0;
                const cJSON *tc;
                cJSON_ArrayForEach(tc, calls) {
                    sc_tool_call_t *c = &msg.tool_calls[msg.tool_call_count++];
                    c->id   = sc_strdup(sc_json_get_string(tc, "id", NULL));
                    c->name = sc_strdup(sc_json_get_string(tc, "name", NULL));
                    const cJSON *args = cJSON_GetObjectItem(tc, "arguments");
                    c->arguments = args ? cJSON_Duplicate(args, 1) : NULL;
                }
            }
        }
    }

    return msg;
}

static cJSON *session_to_json(const sc_session_t *s)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    cJSON_AddStringToObject(root, "key", s->key);
    if (s->summary)
        cJSON_AddStringToObject(root, "summary", s->summary);
    cJSON_AddNumberToObject(root, "created", (double)s->created);
    cJSON_AddNumberToObject(root, "updated", (double)s->updated);

    cJSON *msgs = cJSON_AddArrayToObject(root, "messages");
    for (int i = 0; i < s->message_count; i++) {
        cJSON_AddItemToArray(msgs, message_to_json(&s->messages[i]));
    }

    return root;
}

static sc_session_t *session_from_json(const cJSON *root)
{
    const char *key = sc_json_get_string(root, "key", NULL);
    if (!key) return NULL;

    sc_session_t *s = session_create(key);
    if (!s) return NULL;

    free(s->summary);
    s->summary = sc_strdup(sc_json_get_string(root, "summary", NULL));
    s->created = (long)sc_json_get_double(root, "created", (double)s->created);
    s->updated = (long)sc_json_get_double(root, "updated", (double)s->updated);

    const cJSON *msgs = sc_json_get_array(root, "messages");
    if (msgs) {
        const cJSON *item;
        cJSON_ArrayForEach(item, msgs) {
            if (session_ensure_cap(s) != 0) break;
            s->messages[s->message_count++] = message_from_json(item);
        }
    }

    return s;
}

/* ---- Load sessions from directory ---- */

static void load_sessions(sc_session_manager_t *sm)
{
    DIR *dir = opendir(sm->storage_dir);
    if (!dir) return;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        size_t len = strlen(ent->d_name);
        if (len < 6 || strcmp(ent->d_name + len - 5, ".json") != 0)
            continue;

        sc_strbuf_t path;
        sc_strbuf_init(&path);
        sc_strbuf_appendf(&path, "%s/%s", sm->storage_dir, ent->d_name);
        char *fpath = sc_strbuf_finish(&path);

        cJSON *root = sc_json_load_file(fpath);
        free(fpath);
        if (!root) continue;

        sc_session_t *s = session_from_json(root);
        cJSON_Delete(root);
        if (s) {
            /* Only add if not already present */
            if (!find_session(sm, s->key)) {
                manager_add_session(sm, s);
            } else {
                session_free(s);
            }
        }
    }

    closedir(dir);
}

/* ---- Public API ---- */

sc_session_manager_t *sc_session_manager_new(const char *storage_dir)
{
    sc_session_manager_t *sm = calloc(1, sizeof(*sm));
    if (!sm) return NULL;

    sm->sessions    = calloc(INITIAL_SESS_CAP, sizeof(sc_session_t *));
    sm->cap         = INITIAL_SESS_CAP;
    sm->storage_dir = sc_strdup(storage_dir);

    if (storage_dir) {
        /* Ensure directory exists (owner-only access) */
        mkdir(sm->storage_dir, 0700);
        load_sessions(sm);
    }

    SC_LOG_DEBUG(LOG_TAG, "session manager created (storage=%s, loaded=%d)",
                 storage_dir ? storage_dir : "(none)", sm->count);
    return sm;
}

void sc_session_manager_free(sc_session_manager_t *sm)
{
    if (!sm) return;
    for (int i = 0; i < sm->count; i++) {
        session_free(sm->sessions[i]);
    }
    free(sm->sessions);
    free(sm->storage_dir);
    free(sm);
}

#define SC_MAX_SESSION_KEY_LEN 128

sc_session_t *sc_session_get_or_create(sc_session_manager_t *sm, const char *key)
{
    if (!sm || !key) return NULL;
    if (strlen(key) > SC_MAX_SESSION_KEY_LEN) {
        SC_LOG_WARN(LOG_TAG, "session key too long (%zu chars), rejecting",
                    strlen(key));
        return NULL;
    }

    sc_session_t *s = find_session(sm, key);
    if (s) return s;

    s = session_create(key);
    if (!s) return NULL;

    manager_add_session(sm, s);
    SC_LOG_DEBUG(LOG_TAG, "created session: %s", key);
    return s;
}

void sc_session_add_message(sc_session_manager_t *sm, const char *key,
                            const char *role, const char *content)
{
    sc_session_t *s = sc_session_get_or_create(sm, key);
    if (!s) return;

    if (session_ensure_cap(s) != 0) return;
    sc_llm_message_t *msg = &s->messages[s->message_count++];
    memset(msg, 0, sizeof(*msg));
    msg->role = sc_strdup(role);

    /* Redact secrets in assistant messages before persisting to disk */
    if (role && strcmp(role, "assistant") == 0 && content) {
        char *redacted = sc_redact_secrets(content);
        msg->content = redacted ? redacted : sc_strdup(content);
    } else {
        msg->content = sc_strdup(content);
    }
    s->updated = (long)time(NULL);
}

void sc_session_add_full_message(sc_session_manager_t *sm, const char *key,
                                  const sc_llm_message_t *msg)
{
    sc_session_t *s = sc_session_get_or_create(sm, key);
    if (!s) return;

    if (session_ensure_cap(s) != 0) return;
    s->messages[s->message_count++] = sc_llm_message_clone(msg);
    s->updated = (long)time(NULL);
}

sc_llm_message_t *sc_session_get_history(sc_session_manager_t *sm, const char *key,
                                          int *out_count)
{
    if (out_count) *out_count = 0;
    if (!sm || !key) return NULL;

    sc_session_t *s = find_session(sm, key);
    if (!s) return NULL;

    if (out_count) *out_count = s->message_count;
    return s->messages;
}

const char *sc_session_get_summary(sc_session_manager_t *sm, const char *key)
{
    if (!sm || !key) return NULL;
    sc_session_t *s = find_session(sm, key);
    return s ? s->summary : NULL;
}

void sc_session_set_summary(sc_session_manager_t *sm, const char *key,
                            const char *summary)
{
    sc_session_t *s = sc_session_get_or_create(sm, key);
    if (!s) return;

    free(s->summary);
    s->summary = sc_strdup(summary);
    s->updated = (long)time(NULL);
}

void sc_session_truncate(sc_session_manager_t *sm, const char *key, int keep_last)
{
    if (!sm || !key) return;

    sc_session_t *s = find_session(sm, key);
    if (!s) return;

    if (keep_last <= 0) {
        for (int i = 0; i < s->message_count; i++)
            sc_llm_message_free_fields(&s->messages[i]);
        s->message_count = 0;
        s->updated = (long)time(NULL);
        return;
    }

    if (s->message_count <= keep_last) return;

    int to_remove = s->message_count - keep_last;
    for (int i = 0; i < to_remove; i++) {
        sc_llm_message_free_fields(&s->messages[i]);
    }

    memmove(s->messages, s->messages + to_remove,
            (size_t)keep_last * sizeof(sc_llm_message_t));
    s->message_count = keep_last;
    s->updated = (long)time(NULL);
}

int sc_session_save(sc_session_manager_t *sm, const char *key)
{
    if (!sm || !key || !sm->storage_dir) return -1;

    sc_session_t *s = find_session(sm, key);
    if (!s) return -1;

    char *safe_name = sc_sanitize_filename(key);
    if (!safe_name) return -1;

    sc_strbuf_t path;
    sc_strbuf_init(&path);
    sc_strbuf_appendf(&path, "%s/%s.json", sm->storage_dir, safe_name);
    char *fpath = sc_strbuf_finish(&path);
    free(safe_name);

    cJSON *json = session_to_json(s);
    if (!json) {
        free(fpath);
        return -1;
    }

    int ret = sc_json_save_file(fpath, json);
    cJSON_Delete(json);
    free(fpath);

    if (ret == 0) {
        SC_LOG_DEBUG(LOG_TAG, "saved session: %s", key);
    } else {
        SC_LOG_ERROR(LOG_TAG, "failed to save session: %s", key);
    }

    return ret;
}
