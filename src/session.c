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
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#define LOG_TAG "session"
#define INITIAL_NODE_CAP  16
#define INITIAL_SESS_CAP  8

/* ---------- Tree node ---------- */

typedef struct {
    int id;              /* unique within session, 0-based sequential */
    int parent_id;       /* -1 for root */
    sc_llm_message_t msg;
    long timestamp;
} sc_session_node_t;

/* ---------- Session ---------- */

struct sc_session {
    char *key;
    char *summary;
    long created;
    long updated;

    /* Tree storage (all nodes, indexed by id) */
    sc_session_node_t *nodes;
    int node_count;
    int node_cap;

    /* Active branch state */
    int active_leaf;     /* node id of current leaf, -1 if empty */

    /* Cached linear branch (root → active_leaf path) */
    sc_llm_message_t *branch;   /* cloned messages, owned */
    int branch_count;
    int branch_dirty;           /* 1 = needs rebuild */
};

/* ---------- Session manager ---------- */

struct sc_session_manager {
    sc_session_t **sessions;
    int count;
    int cap;
    char *storage_dir;
    sc_session_t *last_session;
};

/* ---------- Internal helpers ---------- */

static sc_session_t *session_create(const char *key)
{
    sc_session_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;

    s->key = sc_strdup(key);
    s->nodes = calloc(INITIAL_NODE_CAP, sizeof(sc_session_node_t));
    if (!s->nodes) { free(s->key); free(s); return NULL; }
    s->node_cap = INITIAL_NODE_CAP;
    s->active_leaf = -1;
    s->branch_dirty = 1;
    s->created = (long)time(NULL);
    s->updated = s->created;

    return s;
}

static void session_free(sc_session_t *s)
{
    if (!s) return;
    free(s->key);
    free(s->summary);
    for (int i = 0; i < s->node_count; i++)
        sc_llm_message_free_fields(&s->nodes[i].msg);
    free(s->nodes);
    /* Free cached branch */
    for (int i = 0; i < s->branch_count; i++)
        sc_llm_message_free_fields(&s->branch[i]);
    free(s->branch);
    free(s);
}

static int session_ensure_node_cap(sc_session_t *s)
{
    if (s->node_count < s->node_cap) return 0;
    int new_cap = s->node_cap * 2;
    sc_session_node_t *new_nodes = sc_safe_realloc(s->nodes,
        (size_t)new_cap * sizeof(sc_session_node_t));
    if (!new_nodes) return -1;
    s->nodes = new_nodes;
    s->node_cap = new_cap;
    return 0;
}

/* Rebuild the cached branch (path from root to active_leaf) */
static void rebuild_branch(sc_session_t *s)
{
    /* Free old cache */
    for (int i = 0; i < s->branch_count; i++)
        sc_llm_message_free_fields(&s->branch[i]);
    free(s->branch);
    s->branch = NULL;
    s->branch_count = 0;

    if (s->active_leaf < 0 || s->node_count == 0) {
        s->branch_dirty = 0;
        return;
    }

    /* Walk from active_leaf to root, collecting node indices */
    int path[4096]; /* max depth */
    int depth = 0;
    int cur = s->active_leaf;
    while (cur >= 0 && cur < s->node_count && depth < 4096) {
        path[depth++] = cur;
        cur = s->nodes[cur].parent_id;
    }

    /* Reverse into root→leaf order and clone messages */
    s->branch = calloc((size_t)depth, sizeof(sc_llm_message_t));
    if (!s->branch) {
        s->branch_dirty = 0;
        return;
    }
    s->branch_count = depth;
    for (int i = 0; i < depth; i++) {
        s->branch[i] = sc_llm_message_clone(&s->nodes[path[depth - 1 - i]].msg);
    }

    s->branch_dirty = 0;
}

static sc_session_t *find_session(sc_session_manager_t *sm, const char *key)
{
    if (sm->last_session && strcmp(sm->last_session->key, key) == 0)
        return sm->last_session;

    for (int i = 0; i < sm->count; i++) {
        if (strcmp(sm->sessions[i]->key, key) == 0) {
            sm->last_session = sm->sessions[i];
            return sm->sessions[i];
        }
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
        sm->cap = new_cap;
    }
    sm->sessions[sm->count++] = s;
    return 0;
}

/* ---------- Serialization: JSONL tree ---------- */

static cJSON *node_to_json(const sc_session_node_t *node)
{
    cJSON *obj = cJSON_CreateObject();
    if (!obj) return NULL;

    cJSON_AddStringToObject(obj, "type", "message");
    cJSON_AddNumberToObject(obj, "id", node->id);
    cJSON_AddNumberToObject(obj, "parent_id", node->parent_id);
    cJSON_AddNumberToObject(obj, "timestamp", (double)node->timestamp);

    const sc_llm_message_t *msg = &node->msg;
    if (msg->role)    cJSON_AddStringToObject(obj, "role", msg->role);
    if (msg->content) cJSON_AddStringToObject(obj, "content", msg->content);
    if (msg->thinking) cJSON_AddStringToObject(obj, "thinking", msg->thinking);
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

static sc_session_node_t node_from_json(const cJSON *obj)
{
    sc_session_node_t node = {0};
    node.id = sc_json_get_int(obj, "id", 0);
    node.parent_id = sc_json_get_int(obj, "parent_id", -1);
    node.timestamp = (long)sc_json_get_double(obj, "timestamp", 0);

    node.msg.role = sc_strdup(sc_json_get_string(obj, "role", NULL));
    node.msg.content = sc_strdup(sc_json_get_string(obj, "content", NULL));
    node.msg.thinking = sc_strdup(sc_json_get_string(obj, "thinking", NULL));
    node.msg.tool_call_id = sc_strdup(sc_json_get_string(obj, "tool_call_id", NULL));

    const cJSON *calls = sc_json_get_array(obj, "tool_calls");
    if (calls) {
        int n = cJSON_GetArraySize(calls);
        if (n > 0) {
            node.msg.tool_calls = calloc((size_t)n, sizeof(sc_tool_call_t));
            if (node.msg.tool_calls) {
                const cJSON *tc;
                cJSON_ArrayForEach(tc, calls) {
                    sc_tool_call_t *c = &node.msg.tool_calls[node.msg.tool_call_count++];
                    c->id = sc_strdup(sc_json_get_string(tc, "id", NULL));
                    c->name = sc_strdup(sc_json_get_string(tc, "name", NULL));
                    const cJSON *args = cJSON_GetObjectItem(tc, "arguments");
                    c->arguments = args ? cJSON_Duplicate(args, 1) : NULL;
                }
            }
        }
    }

    return node;
}

/* Write session as JSONL: header line + one line per node */
static int session_write_jsonl(const sc_session_t *s, const char *path)
{
    /* Atomic write: temp file + fsync + rename to prevent corruption
     * on disk full or crash during write */
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);

    FILE *f = fopen(tmp, "w");
    if (!f) {
        SC_LOG_ERROR(LOG_TAG, "Failed to open %s for writing: %s", tmp, strerror(errno));
        return -1;
    }

    int ok = 1;

    /* Header line: metadata */
    cJSON *hdr = cJSON_CreateObject();
    cJSON_AddStringToObject(hdr, "type", "header");
    cJSON_AddStringToObject(hdr, "key", s->key);
    if (s->summary) cJSON_AddStringToObject(hdr, "summary", s->summary);
    cJSON_AddNumberToObject(hdr, "created", (double)s->created);
    cJSON_AddNumberToObject(hdr, "updated", (double)s->updated);
    cJSON_AddNumberToObject(hdr, "active_leaf", s->active_leaf);
    char *line = cJSON_PrintUnformatted(hdr);
    cJSON_Delete(hdr);
    if (line) { if (fprintf(f, "%s\n", line) < 0) ok = 0; free(line); }

    /* One line per node */
    for (int i = 0; i < s->node_count && ok; i++) {
        cJSON *nj = node_to_json(&s->nodes[i]);
        if (nj) {
            line = cJSON_PrintUnformatted(nj);
            cJSON_Delete(nj);
            if (line) { if (fprintf(f, "%s\n", line) < 0) ok = 0; free(line); }
        }
    }

    if (ok) ok = (fflush(f) == 0);
    if (ok) ok = (fsync(fileno(f)) == 0);
    fclose(f);

    if (!ok) {
        SC_LOG_ERROR(LOG_TAG, "Write error for session %s, keeping old file", s->key);
        unlink(tmp);
        return -1;
    }

    if (rename(tmp, path) != 0) {
        SC_LOG_ERROR(LOG_TAG, "Failed to rename %s -> %s: %s", tmp, path, strerror(errno));
        unlink(tmp);
        return -1;
    }

    return 0;
}

/* Read session from JSONL file */
static sc_session_t *session_read_jsonl(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return NULL;

    sc_session_t *s = NULL;
    char *buf = malloc(65536);
    if (!buf) { fclose(f); return NULL; }

    while (fgets(buf, 65536, f)) {
        /* Strip trailing newline */
        size_t len = strlen(buf);
        while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r'))
            buf[--len] = '\0';
        if (len == 0) continue;

        cJSON *obj = cJSON_Parse(buf);
        if (!obj) continue;

        const char *type = sc_json_get_string(obj, "type", "");

        if (strcmp(type, "header") == 0) {
            const char *key = sc_json_get_string(obj, "key", NULL);
            if (!key) { cJSON_Delete(obj); continue; }
            s = session_create(key);
            if (!s) { cJSON_Delete(obj); break; }
            free(s->summary);
            s->summary = sc_strdup(sc_json_get_string(obj, "summary", NULL));
            s->created = (long)sc_json_get_double(obj, "created", (double)s->created);
            s->updated = (long)sc_json_get_double(obj, "updated", (double)s->updated);
            s->active_leaf = sc_json_get_int(obj, "active_leaf", -1);
        } else if (strcmp(type, "message") == 0 && s) {
            if (session_ensure_node_cap(s) == 0) {
                s->nodes[s->node_count++] = node_from_json(obj);
            }
        }

        cJSON_Delete(obj);
    }

    fclose(f);

    if (s) {
        /* Validate active_leaf */
        if (s->active_leaf < 0 || s->active_leaf >= s->node_count) {
            /* Default to last node */
            s->active_leaf = s->node_count > 0 ? s->node_count - 1 : -1;
        }
        s->branch_dirty = 1;
    }

    free(buf);
    return s;
}

/* Migrate legacy JSON session to tree format */
static sc_session_t *session_from_legacy_json(const cJSON *root)
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
        int id = 0;
        const cJSON *item;
        cJSON_ArrayForEach(item, msgs) {
            if (session_ensure_node_cap(s) != 0) break;
            sc_session_node_t *node = &s->nodes[s->node_count++];
            memset(node, 0, sizeof(*node));
            node->id = id;
            node->parent_id = id > 0 ? id - 1 : -1;
            node->timestamp = s->updated;

            /* Parse message fields — use memset above to zero all fields
             * so any missing fields (like thinking) are safely NULL */
            node->msg.role = sc_strdup(sc_json_get_string(item, "role", NULL));
            node->msg.content = sc_strdup(sc_json_get_string(item, "content", NULL));
            node->msg.thinking = sc_strdup(sc_json_get_string(item, "thinking", NULL));
            node->msg.tool_call_id = sc_strdup(sc_json_get_string(item, "tool_call_id", NULL));

            const cJSON *calls = sc_json_get_array(item, "tool_calls");
            if (calls) {
                int n = cJSON_GetArraySize(calls);
                if (n > 0) {
                    node->msg.tool_calls = calloc((size_t)n, sizeof(sc_tool_call_t));
                    if (node->msg.tool_calls) {
                        const cJSON *tc;
                        cJSON_ArrayForEach(tc, calls) {
                            sc_tool_call_t *c = &node->msg.tool_calls[node->msg.tool_call_count++];
                            c->id = sc_strdup(sc_json_get_string(tc, "id", NULL));
                            c->name = sc_strdup(sc_json_get_string(tc, "name", NULL));
                            const cJSON *args = cJSON_GetObjectItem(tc, "arguments");
                            c->arguments = args ? cJSON_Duplicate(args, 1) : NULL;
                        }
                    }
                }
            }

            id++;
        }
    }

    s->active_leaf = s->node_count > 0 ? s->node_count - 1 : -1;
    s->branch_dirty = 1;
    return s;
}

/* ---------- Load sessions from directory ---------- */

static void load_sessions(sc_session_manager_t *sm)
{
    DIR *dir = opendir(sm->storage_dir);
    if (!dir) return;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        size_t len = strlen(ent->d_name);

        sc_strbuf_t path;
        sc_strbuf_init(&path);
        sc_strbuf_appendf(&path, "%s/%s", sm->storage_dir, ent->d_name);
        char *fpath = sc_strbuf_finish(&path);

        sc_session_t *s = NULL;

        if (len > 6 && strcmp(ent->d_name + len - 6, ".jsonl") == 0) {
            /* New JSONL tree format */
            s = session_read_jsonl(fpath);
        } else if (len > 5 && strcmp(ent->d_name + len - 5, ".json") == 0) {
            /* Legacy JSON format — migrate */
            cJSON *root = sc_json_load_file(fpath);
            if (root) {
                /* Validate minimal structure before migration */
                const char *jkey = sc_json_get_string(root, "key", NULL);
                const cJSON *jmsgs = cJSON_GetObjectItem(root, "messages");
                if (jkey && jmsgs && cJSON_IsArray(jmsgs)) {
                    s = session_from_legacy_json(root);
                    if (s) {
                        SC_LOG_INFO(LOG_TAG, "Migrated legacy session: %s", s->key);
                    }
                } else {
                    SC_LOG_WARN(LOG_TAG, "Skipping malformed legacy session: %s",
                                ent->d_name);
                }
                cJSON_Delete(root);
            }
        }

        free(fpath);

        if (s) {
            if (!find_session(sm, s->key)) {
                manager_add_session(sm, s);
            } else {
                session_free(s);
            }
        }
    }

    closedir(dir);
}

/* ---------- Public API ---------- */

#define SC_MAX_SESSION_KEY_LEN 128

sc_session_manager_t *sc_session_manager_new(const char *storage_dir)
{
    sc_session_manager_t *sm = calloc(1, sizeof(*sm));
    if (!sm) return NULL;

    sm->sessions = calloc(INITIAL_SESS_CAP, sizeof(sc_session_t *));
    sm->cap = INITIAL_SESS_CAP;
    sm->storage_dir = sc_strdup(storage_dir);

    if (storage_dir) {
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
    for (int i = 0; i < sm->count; i++)
        session_free(sm->sessions[i]);
    free(sm->sessions);
    free(sm->storage_dir);
    free(sm);
}

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

/* Append a node to the tree, parented to active_leaf */
static int session_append_node(sc_session_t *s, const sc_llm_message_t *msg)
{
    if (session_ensure_node_cap(s) != 0) return -1;

    sc_session_node_t *node = &s->nodes[s->node_count];
    node->id = s->node_count;
    node->parent_id = s->active_leaf;
    node->timestamp = (long)time(NULL);
    node->msg = sc_llm_message_clone(msg);

    s->node_count++;
    s->active_leaf = node->id;
    s->branch_dirty = 1;
    s->updated = node->timestamp;
    return 0;
}

void sc_session_add_message(sc_session_manager_t *sm, const char *key,
                            const char *role, const char *content)
{
    sc_session_t *s = sc_session_get_or_create(sm, key);
    if (!s) return;

    sc_llm_message_t msg = {0};
    msg.role = (char *)role;     /* borrowed for append */

    if (role && strcmp(role, "assistant") == 0 && content) {
        char *redacted = sc_redact_secrets(content);
        msg.content = redacted ? redacted : sc_strdup(content);
        session_append_node(s, &msg);
        free(msg.content);
    } else {
        msg.content = (char *)content;
        session_append_node(s, &msg);
    }
}

void sc_session_add_full_message(sc_session_manager_t *sm, const char *key,
                                  const sc_llm_message_t *msg)
{
    sc_session_t *s = sc_session_get_or_create(sm, key);
    if (!s) return;
    session_append_node(s, msg);
}

sc_llm_message_t *sc_session_get_history(sc_session_manager_t *sm, const char *key,
                                          int *out_count)
{
    if (out_count) *out_count = 0;
    if (!sm || !key) return NULL;

    sc_session_t *s = find_session(sm, key);
    if (!s) return NULL;

    if (s->branch_dirty)
        rebuild_branch(s);

    if (out_count) *out_count = s->branch_count;
    return s->branch;
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
        /* Clear all nodes */
        for (int i = 0; i < s->node_count; i++)
            sc_llm_message_free_fields(&s->nodes[i].msg);
        s->node_count = 0;
        s->active_leaf = -1;
        s->branch_dirty = 1;
        s->updated = (long)time(NULL);
        return;
    }

    /* Rebuild branch to know which nodes are on the active path */
    if (s->branch_dirty)
        rebuild_branch(s);

    if (s->branch_count <= keep_last) return;

    /* We need to keep the last keep_last nodes on the active branch.
     * Strategy: rebuild the tree with only those nodes. */
    int path[4096];
    int depth = 0;
    int cur = s->active_leaf;
    while (cur >= 0 && cur < s->node_count && depth < 4096) {
        path[depth++] = cur;
        cur = s->nodes[cur].parent_id;
    }

    /* path is leaf→root. We want to keep the last keep_last (closest to leaf). */
    int to_keep = keep_last < depth ? keep_last : depth;

    /* Build new node array from the kept path */
    sc_session_node_t *new_nodes = calloc((size_t)to_keep, sizeof(sc_session_node_t));
    if (!new_nodes) return;

    for (int i = 0; i < to_keep; i++) {
        int src_idx = path[to_keep - 1 - i]; /* root-first order */
        new_nodes[i].msg = s->nodes[src_idx].msg;
        /* Zero out source so we don't double-free */
        memset(&s->nodes[src_idx].msg, 0, sizeof(sc_llm_message_t));
        new_nodes[i].id = i;
        new_nodes[i].parent_id = i > 0 ? i - 1 : -1;
        new_nodes[i].timestamp = s->nodes[src_idx].timestamp;
    }

    /* Free all old nodes (messages already zeroed for kept ones) */
    for (int i = 0; i < s->node_count; i++)
        sc_llm_message_free_fields(&s->nodes[i].msg);
    free(s->nodes);

    s->nodes = new_nodes;
    s->node_count = to_keep;
    s->node_cap = to_keep;
    s->active_leaf = to_keep - 1;
    s->branch_dirty = 1;
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
    sc_strbuf_appendf(&path, "%s/%s.jsonl", sm->storage_dir, safe_name);
    char *fpath = sc_strbuf_finish(&path);
    free(safe_name);

    int ret = session_write_jsonl(s, fpath);
    free(fpath);

    if (ret == 0) {
        SC_LOG_DEBUG(LOG_TAG, "saved session: %s", key);
    } else {
        SC_LOG_ERROR(LOG_TAG, "failed to save session: %s", key);
    }

    return ret;
}

int sc_session_reset(sc_session_manager_t *sm, const char *key)
{
    if (!sm || !key) return -1;

    sc_session_t *s = find_session(sm, key);
    if (!s) return 0;  /* nothing stored → already "reset" */

    for (int i = 0; i < s->node_count; i++)
        sc_llm_message_free_fields(&s->nodes[i].msg);
    s->node_count = 0;
    s->active_leaf = -1;

    free(s->branch);
    s->branch = NULL;
    s->branch_count = 0;
    s->branch_dirty = 1;

    free(s->summary);
    s->summary = NULL;

    s->updated = (long)time(NULL);

    /* Persist the cleared session so a gateway restart doesn't resurrect it. */
    if (sm->storage_dir)
        return sc_session_save(sm, key);
    return 0;
}

long sc_session_get_updated(sc_session_manager_t *sm, const char *key)
{
    if (!sm || !key) return 0;
    sc_session_t *s = find_session(sm, key);
    return s ? s->updated : 0;
}

int sc_session_reset_due(int mode, int daily_reset_hour, int idle_minutes,
                         long last_updated, long now)
{
    if (mode == SC_SESSION_RESET_NONE || last_updated <= 0 || now <= last_updated)
        return 0;

    int idle  = (mode == SC_SESSION_RESET_IDLE  || mode == SC_SESSION_RESET_BOTH);
    int daily = (mode == SC_SESSION_RESET_DAILY || mode == SC_SESSION_RESET_BOTH);

    if (idle && idle_minutes > 0 &&
        (now - last_updated) >= (long)idle_minutes * 60)
        return 1;

    if (daily) {
        if (daily_reset_hour < 0 || daily_reset_hour > 23) daily_reset_hour = 4;
        /* Most recent local-time daily boundary at or before `now`. */
        time_t nt = (time_t)now;
        struct tm tmv;
        localtime_r(&nt, &tmv);
        tmv.tm_hour = daily_reset_hour;
        tmv.tm_min = 0;
        tmv.tm_sec = 0;
        long boundary = (long)mktime(&tmv);
        if (boundary > now) boundary -= 86400;  /* today's hour not reached yet */
        /* A daily boundary fell between last activity and now. */
        if (last_updated < boundary) return 1;
    }
    return 0;
}

int sc_session_force_prune_due(int count, int summary_threshold)
{
    if (summary_threshold <= 0) return 0;  /* summarization disabled */
    return count >= summary_threshold * SC_SESSION_FORCE_PRUNE_MULT;
}

int sc_session_branch(sc_session_manager_t *sm, const char *key, int node_id)
{
    if (!sm || !key) return -1;

    sc_session_t *s = find_session(sm, key);
    if (!s) return -1;

    if (node_id < 0 || node_id >= s->node_count) return -1;

    s->active_leaf = node_id;
    s->branch_dirty = 1;
    s->updated = (long)time(NULL);

    SC_LOG_INFO(LOG_TAG, "Session %s branched to node %d", key, node_id);
    return 0;
}

int sc_session_branch_count(sc_session_manager_t *sm, const char *key)
{
    if (!sm || !key) return 0;

    sc_session_t *s = find_session(sm, key);
    if (!s || s->node_count == 0) return 0;

    /* A leaf node is one that no other node has as parent_id */
    int leaves = 0;
    for (int i = 0; i < s->node_count; i++) {
        int is_parent = 0;
        for (int j = 0; j < s->node_count; j++) {
            if (s->nodes[j].parent_id == s->nodes[i].id) {
                is_parent = 1;
                break;
            }
        }
        if (!is_parent) leaves++;
    }
    return leaves;
}

int sc_session_active_leaf(sc_session_manager_t *sm, const char *key)
{
    if (!sm || !key) return -1;

    sc_session_t *s = find_session(sm, key);
    return s ? s->active_leaf : -1;
}
