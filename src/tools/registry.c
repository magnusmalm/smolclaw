/*
 * tools/registry.c - Tool registry and tool result types
 *
 * Manages a dynamic array of tools. Provides result constructors,
 * tool lookup, execution with timing, and conversion to provider definitions.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#include "tools/registry.h"
#include "tools/types.h"
#include "tools/schema_validate.h"
#include "constants_limits.h"
#include "providers/types.h"
#include "audit.h"
#include "util/str.h"
#include "logger.h"

/* Read current VmRSS from /proc/self/status in KB. Returns 0 on failure. */
static long read_rss_kb(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[256];
    long rss = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            rss = strtol(line + 6, NULL, 10);
            break;
        }
    }
    fclose(f);
    return rss;
}

/* ---------- Tool result constructors ---------- */

sc_tool_result_t *sc_tool_result_new(const char *for_llm)
{
    sc_tool_result_t *r = calloc(1, sizeof(*r));
    if (!r) return NULL;
    r->for_llm = sc_sanitize_tool_output(for_llm);
    return r;
}

sc_tool_result_t *sc_tool_result_silent(const char *for_llm)
{
    sc_tool_result_t *r = calloc(1, sizeof(*r));
    if (!r) return NULL;
    r->for_llm = sc_sanitize_tool_output(for_llm);
    r->silent = 1;
    return r;
}

sc_tool_result_t *sc_tool_result_error(const char *message)
{
    sc_tool_result_t *r = calloc(1, sizeof(*r));
    if (!r) return NULL;
    r->for_llm = sc_sanitize_tool_output(message);
    r->is_error = 1;
    return r;
}

sc_tool_result_t *sc_tool_result_user(const char *content)
{
    sc_tool_result_t *r = calloc(1, sizeof(*r));
    if (!r) return NULL;
    r->for_llm = sc_sanitize_tool_output(content);
    r->for_user = sc_strdup(content);  /* user sees raw output */
    return r;
}

sc_tool_result_t *sc_tool_result_async(const char *for_llm)
{
    sc_tool_result_t *r = calloc(1, sizeof(*r));
    if (!r) return NULL;
    r->for_llm = sc_sanitize_tool_output(for_llm);
    r->async = 1;
    return r;
}

void sc_tool_result_free(sc_tool_result_t *r)
{
    if (!r) return;
    free(r->for_llm);
    free(r->for_user);
    free(r);
}

/* ---------- Registry ---------- */

#define INITIAL_CAP 8

sc_tool_registry_t *sc_tool_registry_new(void)
{
    sc_tool_registry_t *reg = calloc(1, sizeof(*reg));
    if (!reg) return NULL;
    reg->tools = calloc(INITIAL_CAP, sizeof(sc_tool_t *));
    if (!reg->tools) { free(reg); return NULL; }
    reg->cap = INITIAL_CAP;
    return reg;
}

void sc_tool_registry_free(sc_tool_registry_t *reg)
{
    if (!reg) return;
    for (int i = 0; i < reg->count; i++) {
        if (reg->tools[i] && reg->tools[i]->destroy)
            reg->tools[i]->destroy(reg->tools[i]);
    }
    free(reg->tools);
    for (int i = 0; i < reg->allowed_count; i++)
        free(reg->allowed_tools[i]);
    free(reg->allowed_tools);
    free(reg->pre_hooks);
    free(reg->post_hooks);
    free(reg->workspace);
    for (int i = 0; i < reg->discovered_count; i++)
        free(reg->discovered_tools[i]);
    free(reg->discovered_tools);
    free(reg);
}

void sc_tool_registry_set_confirm(sc_tool_registry_t *reg,
    int (*cb)(const char *, const char *, void *), void *ctx)
{
    if (!reg) return;
    reg->confirm_cb = cb;
    reg->confirm_ctx = ctx;
}

void sc_tool_registry_add_pre_hook(sc_tool_registry_t *reg, const char *name,
                                    sc_pre_tool_fn fn, void *userdata)
{
    if (!reg || !fn) return;
    if (reg->pre_hook_count >= reg->pre_hook_cap) {
        int new_cap = reg->pre_hook_cap ? reg->pre_hook_cap * 2 : 4;
        sc_pre_tool_hook_t *new_arr = realloc(reg->pre_hooks,
            (size_t)new_cap * sizeof(sc_pre_tool_hook_t));
        if (!new_arr) return;
        reg->pre_hooks = new_arr;
        reg->pre_hook_cap = new_cap;
    }
    sc_pre_tool_hook_t *h = &reg->pre_hooks[reg->pre_hook_count++];
    h->fn = fn;
    h->userdata = userdata;
    h->name = name ? name : "unnamed";
}

void sc_tool_registry_add_post_hook(sc_tool_registry_t *reg, const char *name,
                                     sc_post_tool_fn fn, void *userdata)
{
    if (!reg || !fn) return;
    if (reg->post_hook_count >= reg->post_hook_cap) {
        int new_cap = reg->post_hook_cap ? reg->post_hook_cap * 2 : 4;
        sc_post_tool_hook_t *new_arr = realloc(reg->post_hooks,
            (size_t)new_cap * sizeof(sc_post_tool_hook_t));
        if (!new_arr) return;
        reg->post_hooks = new_arr;
        reg->post_hook_cap = new_cap;
    }
    sc_post_tool_hook_t *h = &reg->post_hooks[reg->post_hook_count++];
    h->fn = fn;
    h->userdata = userdata;
    h->name = name ? name : "unnamed";
}

void sc_tool_registry_set_allowed(sc_tool_registry_t *reg,
    char **tools, int count)
{
    if (!reg) return;
    /* Free old */
    for (int i = 0; i < reg->allowed_count; i++)
        free(reg->allowed_tools[i]);
    free(reg->allowed_tools);
    /* Copy new */
    if (tools && count > 0) {
        reg->allowed_tools = calloc((size_t)count, sizeof(char *));
        if (reg->allowed_tools) {
            for (int i = 0; i < count; i++)
                reg->allowed_tools[i] = sc_strdup(tools[i]);
            reg->allowed_count = count;
        } else {
            reg->allowed_count = 0;
        }
    } else {
        reg->allowed_tools = NULL;
        reg->allowed_count = 0;
    }
}

void sc_tool_registry_set_workspace(sc_tool_registry_t *reg, const char *workspace)
{
    if (!reg || !workspace) return;
    free(reg->workspace);
    reg->workspace = sc_strdup(workspace);
    for (int i = 0; i < reg->count; i++) {
        if (reg->tools[i]->set_workspace)
            reg->tools[i]->set_workspace(reg->tools[i], workspace);
    }
}

void sc_tool_registry_set_result_limits(sc_tool_registry_t *reg,
                                        int max_chars, int preview_chars)
{
    if (!reg) return;
    reg->max_result_chars = max_chars;
    reg->result_preview_chars = preview_chars;
}

int sc_tool_registry_is_allowed(sc_tool_registry_t *reg, const char *name)
{
    if (!reg || !name) return 0;
    /* Per-turn denylist (isolated sessions) overrides everything */
    for (int i = 0; i < reg->denied_count; i++) {
        if (reg->denied_tools && reg->denied_tools[i] &&
            strcmp(reg->denied_tools[i], name) == 0)
            return 0;
    }
    if (!reg->allowed_tools || reg->allowed_count == 0) return 1;
    for (int i = 0; i < reg->allowed_count; i++) {
        if (reg->allowed_tools[i] && strcmp(reg->allowed_tools[i], name) == 0)
            return 1;
    }
    return 0;
}

void sc_tool_registry_set_denied(sc_tool_registry_t *reg,
                                  const char **tools, int count)
{
    if (!reg) return;
    reg->denied_tools = tools;
    reg->denied_count = (tools && count > 0) ? count : 0;
}

void sc_tool_registry_register(sc_tool_registry_t *reg, sc_tool_t *tool)
{
    if (!reg || !tool) return;

    if (reg->count >= reg->cap) {
        int new_cap = reg->cap * 2;
        sc_tool_t **tmp = realloc(reg->tools, (size_t)new_cap * sizeof(sc_tool_t *));
        if (!tmp) return;
        reg->tools = tmp;
        reg->cap = new_cap;
    }
    reg->tools[reg->count++] = tool;
}

sc_tool_t *sc_tool_registry_get(sc_tool_registry_t *reg, const char *name)
{
    if (!reg || !name) return NULL;
    for (int i = 0; i < reg->count; i++) {
        if (reg->tools[i] && strcmp(reg->tools[i]->name, name) == 0)
            return reg->tools[i];
    }
    return NULL;
}

sc_tool_result_t *sc_tool_registry_execute(sc_tool_registry_t *reg,
                                            const char *name, cJSON *args,
                                            const char *channel, const char *chat_id,
                                            void *ctx)
{
    if (!reg || !name)
        return sc_tool_result_error("invalid registry or tool name");

    SC_LOG_INFO("tool", "Tool execution started: %s", name);

    /* Allowlist check */
    if (!sc_tool_registry_is_allowed(reg, name)) {
        SC_LOG_WARN("tool", "Tool blocked by allowlist: %s", name);
        sc_audit_log(name, "(blocked by allowlist)", 1, 0);
        return sc_tool_result_error("tool not available");
    }

    sc_tool_t *tool = sc_tool_registry_get(reg, name);
    if (!tool) {
        SC_LOG_ERROR("tool", "Tool not found: %s", name);
        return sc_tool_result_error("tool not found");
    }

    /* Confirmation check */
    if (tool->needs_confirm) {
        if (!reg->confirm_cb) {
            SC_LOG_WARN("tool", "Tool requires confirmation but no handler: %s", name);
            sc_audit_log(name, "(denied: no confirm handler)", 1, 0);
            return sc_tool_result_error("tool requires confirmation (not available in this mode)");
        }
        /* Build args summary for the prompt */
        char *args_preview = NULL;
        if (args) {
            args_preview = cJSON_PrintUnformatted(args);
        }
        int approved = reg->confirm_cb(name, args_preview ? args_preview : "", reg->confirm_ctx);
        if (!approved) {
            SC_LOG_INFO("tool", "Tool denied by user: %s", name);
            sc_audit_log(name, args_preview ? args_preview : "", 1, 0);
            free(args_preview);
            return sc_tool_result_error("tool execution denied by user");
        }
        free(args_preview);
    }

    /* Reject oversized arguments (prevent DoS via huge LLM output) */
    if (args) {
        char *raw = cJSON_PrintUnformatted(args);
        if (raw) {
            size_t arg_len = strlen(raw);
            free(raw);
            if (arg_len > 256 * 1024) {  /* 256 KB max */
                SC_LOG_WARN("tool", "Tool %s: args too large (%zu bytes)", name, arg_len);
                return sc_tool_result_error("tool arguments too large");
            }
        }
    }

    /* Validate arguments against tool's JSON Schema */
    if (tool->parameters) {
        cJSON *schema = tool->parameters(tool);
        if (schema) {
            sc_schema_result_t vr = sc_schema_validate(schema, args);
            cJSON_Delete(schema);
            if (!vr.valid) {
                SC_LOG_WARN("tool", "Schema validation failed for %s: %s",
                            name, vr.error);
                return sc_tool_result_error(vr.error);
            }
        }
    }

    /* Pre-tool hooks: return non-zero to block execution */
    for (int i = 0; i < reg->pre_hook_count; i++) {
        int rc = reg->pre_hooks[i].fn(name, args, channel, chat_id,
                                       reg->pre_hooks[i].userdata);
        if (rc != 0) {
            SC_LOG_INFO("tool", "Tool %s blocked by pre-hook '%s' (rc=%d)",
                        name, reg->pre_hooks[i].name, rc);
            sc_audit_log(name, "(blocked by pre-hook)", 1, 0);
            return sc_tool_result_error("tool execution blocked by hook");
        }
    }

    /* Set context if supported */
    if (tool->set_context && channel && chat_id)
        tool->set_context(tool, channel, chat_id);

    long rss_before = read_rss_kb();
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    sc_tool_result_t *result = tool->execute(tool, args, ctx);

    clock_gettime(CLOCK_MONOTONIC, &end);
    long ms = (end.tv_sec - start.tv_sec) * 1000
            + (end.tv_nsec - start.tv_nsec) / 1000000;
    long rss_after = read_rss_kb();
    long rss_delta = rss_after - rss_before;

    if (!result) {
        SC_LOG_ERROR("tool", "Tool %s returned NULL result", name);
        return sc_tool_result_error("tool returned no result");
    }

    /* Post-tool hooks: can modify result in-place */
    for (int i = 0; i < reg->post_hook_count; i++) {
        reg->post_hooks[i].fn(name, result, channel, chat_id,
                               reg->post_hooks[i].userdata);
    }

    /* Persist oversized output to disk before sanitization truncates it.
     * The LLM gets a preview + file path it can read with file_read.
     * Thresholds are configurable (config: max_tool_result_chars /
     * tool_result_preview_chars); <=0 falls back to the built-in defaults. */
    int persist_threshold = reg->max_result_chars > 0
        ? reg->max_result_chars : SC_DEFAULT_MAX_TOOL_RESULT_CHARS;
    int preview_size = reg->result_preview_chars > 0
        ? reg->result_preview_chars : SC_DEFAULT_TOOL_RESULT_PREVIEW_CHARS;
    if (!result->is_error && result->for_llm && reg->workspace &&
        strlen(result->for_llm) > (size_t)persist_threshold) {
        size_t full_len = strlen(result->for_llm);

        /* Ensure tool_outputs directory exists */
        char dir[512];
        snprintf(dir, sizeof(dir), "%s/tool_outputs", reg->workspace);
        mkdir(dir, 0755);

        /* Write full output to file */
        char path[512];
        snprintf(path, sizeof(path), "%s/%s_%ld.txt", dir, name, (long)time(NULL));
        FILE *f = fopen(path, "w");
        if (f) {
            fwrite(result->for_llm, 1, full_len, f);
            fclose(f);

            /* Replace for_llm with preview + path reference */
            sc_strbuf_t buf;
            sc_strbuf_init(&buf);
            sc_strbuf_appendf(&buf,
                "[Truncated: %zu chars. Full output saved to %s. "
                "Use file_read to access specific sections.]\n",
                full_len, path);
            sc_strbuf_appendf(&buf, "%.*s",
                              preview_size, result->for_llm);
            sc_strbuf_append(&buf, "\n...");
            free(result->for_llm);
            result->for_llm = sc_strbuf_finish(&buf);

            SC_LOG_INFO("tool", "Persisted oversized output (%zu bytes) to %s",
                        full_len, path);
        }
    }

    if (result->is_error) {
        SC_LOG_ERROR("tool", "Tool %s failed (%ldms, rss%+ldKB): %s",
                     name, ms, rss_delta,
                     result->for_llm ? result->for_llm : "(null)");
    } else if (result->async) {
        SC_LOG_INFO("tool", "Tool %s started async (%ldms)", name, ms);
    } else {
        SC_LOG_INFO("tool", "Tool %s completed (%ldms, rss%+ldKB, result_len=%zu)",
                    name, ms, rss_delta,
                    result->for_llm ? strlen(result->for_llm) : 0);
    }

    /* Audit log: extract summary from args (first string value, or dump) */
    const char *summary = NULL;
    char *summary_alloc = NULL;
    if (args) {
        cJSON *child = args->child;
        while (child) {
            if (cJSON_IsString(child) && child->valuestring) {
                summary = child->valuestring;
                break;
            }
            child = child->next;
        }
        if (!summary) {
            summary_alloc = cJSON_PrintUnformatted(args);
            summary = summary_alloc;
        }
    }
    sc_audit_log_rss(name, summary, result->is_error, ms, rss_delta);
    free(summary_alloc);

    return result;
}

sc_tool_definition_t *sc_tool_registry_to_defs(sc_tool_registry_t *reg, int *out_count)
{
    return sc_tool_registry_to_defs_filtered(reg, out_count, NULL, 0);
}

static int is_in_channel_list(const char *name, char **list, int count)
{
    for (int i = 0; i < count; i++) {
        if (list[i] && strcmp(list[i], name) == 0)
            return 1;
    }
    return 0;
}

sc_tool_definition_t *sc_tool_registry_to_defs_filtered(
    sc_tool_registry_t *reg, int *out_count,
    char **channel_tools, int channel_tool_count)
{
    if (!reg || !out_count) return NULL;
    *out_count = 0;

    if (reg->count == 0) return NULL;

    sc_tool_definition_t *defs = calloc((size_t)reg->count, sizeof(sc_tool_definition_t));
    if (!defs) return NULL;

    int n = 0;
    for (int i = 0; i < reg->count; i++) {
        sc_tool_t *t = reg->tools[i];
        if (!sc_tool_registry_is_allowed(reg, t->name))
            continue;
        /* Apply per-channel filter if set */
        if (channel_tools && channel_tool_count > 0 &&
            !is_in_channel_list(t->name, channel_tools, channel_tool_count))
            continue;
        /* Skip deferred tools unless they've been discovered via tool_search */
        if (t->deferred && !sc_tool_registry_is_discovered(reg, t->name))
            continue;
        defs[n].name = sc_strdup(t->name);
        defs[n].description = sc_strdup(t->description);
        defs[n].parameters = t->parameters ? t->parameters(t) : NULL;
        n++;
    }

    *out_count = n;
    return defs;
}

void sc_tool_definitions_free(sc_tool_definition_t *defs, int count)
{
    if (!defs) return;
    for (int i = 0; i < count; i++) {
        free(defs[i].name);
        free(defs[i].description);
        if (defs[i].parameters)
            cJSON_Delete(defs[i].parameters);
    }
    free(defs);
}

char *sc_tool_registry_get_summaries(sc_tool_registry_t *reg)
{
    if (!reg) return sc_strdup("");

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);

    for (int i = 0; i < reg->count; i++) {
        sc_tool_t *t = reg->tools[i];
        if (!sc_tool_registry_is_allowed(reg, t->name))
            continue;
        sc_strbuf_appendf(&sb, "- `%s` - %s\n", t->name, t->description);
    }

    return sc_strbuf_finish(&sb);
}

int sc_tool_registry_count(sc_tool_registry_t *reg)
{
    return reg ? reg->count : 0;
}

/* --- Deferred tool discovery --- */

void sc_tool_registry_mark_discovered(sc_tool_registry_t *reg, const char *name)
{
    if (!reg || !name) return;
    /* Already discovered? */
    if (sc_tool_registry_is_discovered(reg, name)) return;

    if (reg->discovered_count >= reg->discovered_cap) {
        int new_cap = reg->discovered_cap ? reg->discovered_cap * 2 : 8;
        char **new_arr = realloc(reg->discovered_tools,
                                  (size_t)new_cap * sizeof(char *));
        if (!new_arr) return;
        reg->discovered_tools = new_arr;
        reg->discovered_cap = new_cap;
    }
    reg->discovered_tools[reg->discovered_count++] = sc_strdup(name);
}

int sc_tool_registry_is_discovered(sc_tool_registry_t *reg, const char *name)
{
    if (!reg || !name) return 0;
    for (int i = 0; i < reg->discovered_count; i++) {
        if (strcmp(reg->discovered_tools[i], name) == 0)
            return 1;
    }
    return 0;
}

void sc_tool_registry_clear_discovered(sc_tool_registry_t *reg)
{
    if (!reg) return;
    for (int i = 0; i < reg->discovered_count; i++)
        free(reg->discovered_tools[i]);
    reg->discovered_count = 0;
}

char *sc_tool_registry_deferred_listing(sc_tool_registry_t *reg)
{
    if (!reg) return NULL;

    int has_deferred = 0;
    for (int i = 0; i < reg->count; i++) {
        if (reg->tools[i]->deferred && sc_tool_registry_is_allowed(reg, reg->tools[i]->name)
            && !sc_tool_registry_is_discovered(reg, reg->tools[i]->name)) {
            has_deferred = 1;
            break;
        }
    }
    if (!has_deferred) return NULL;

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_append(&sb,
        "\nThe following deferred tools are available via the tool_search tool. "
        "Use tool_search to fetch their full schemas before calling them:\n");

    for (int i = 0; i < reg->count; i++) {
        sc_tool_t *t = reg->tools[i];
        if (!t->deferred) continue;
        if (!sc_tool_registry_is_allowed(reg, t->name)) continue;
        if (sc_tool_registry_is_discovered(reg, t->name)) continue;
        /* Truncate description to ~100 chars for compact listing */
        if (t->description) {
            char desc[104];
            snprintf(desc, sizeof(desc), "%.100s", t->description);
            sc_strbuf_appendf(&sb, "- %s — %s\n", t->name, desc);
        } else {
            sc_strbuf_appendf(&sb, "- %s\n", t->name);
        }
    }

    return sc_strbuf_finish(&sb);
}
