/*
 * tools/registry.c - Tool registry and tool result types
 *
 * Manages a dynamic array of tools. Provides result constructors,
 * tool lookup, execution with timing, and conversion to provider definitions.
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "tools/registry.h"
#include "tools/types.h"
#include "providers/types.h"
#include "audit.h"
#include "util/str.h"
#include "logger.h"

/* ---------- Tool result constructors ---------- */

sc_tool_result_t *sc_tool_result_new(const char *for_llm)
{
    sc_tool_result_t *r = calloc(1, sizeof(*r));
    if (!r) return NULL;
    r->for_llm = sc_strdup(for_llm);
    return r;
}

sc_tool_result_t *sc_tool_result_silent(const char *for_llm)
{
    sc_tool_result_t *r = calloc(1, sizeof(*r));
    if (!r) return NULL;
    r->for_llm = sc_strdup(for_llm);
    r->silent = 1;
    return r;
}

sc_tool_result_t *sc_tool_result_error(const char *message)
{
    sc_tool_result_t *r = calloc(1, sizeof(*r));
    if (!r) return NULL;
    r->for_llm = sc_strdup(message);
    r->is_error = 1;
    return r;
}

sc_tool_result_t *sc_tool_result_user(const char *content)
{
    sc_tool_result_t *r = calloc(1, sizeof(*r));
    if (!r) return NULL;
    r->for_llm = sc_strdup(content);
    r->for_user = sc_strdup(content);
    return r;
}

sc_tool_result_t *sc_tool_result_async(const char *for_llm)
{
    sc_tool_result_t *r = calloc(1, sizeof(*r));
    if (!r) return NULL;
    r->for_llm = sc_strdup(for_llm);
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
    free(reg);
}

void sc_tool_registry_set_confirm(sc_tool_registry_t *reg,
    int (*cb)(const char *, const char *, void *), void *ctx)
{
    if (!reg) return;
    reg->confirm_cb = cb;
    reg->confirm_ctx = ctx;
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

int sc_tool_registry_is_allowed(sc_tool_registry_t *reg, const char *name)
{
    if (!reg || !name) return 0;
    if (!reg->allowed_tools || reg->allowed_count == 0) return 1;
    for (int i = 0; i < reg->allowed_count; i++) {
        if (reg->allowed_tools[i] && strcmp(reg->allowed_tools[i], name) == 0)
            return 1;
    }
    return 0;
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

    /* Set context if supported */
    if (tool->set_context && channel && chat_id)
        tool->set_context(tool, channel, chat_id);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    sc_tool_result_t *result = tool->execute(tool, args, ctx);

    clock_gettime(CLOCK_MONOTONIC, &end);
    long ms = (end.tv_sec - start.tv_sec) * 1000
            + (end.tv_nsec - start.tv_nsec) / 1000000;

    if (!result) {
        SC_LOG_ERROR("tool", "Tool %s returned NULL result", name);
        return sc_tool_result_error("tool returned no result");
    }

    if (result->is_error) {
        SC_LOG_ERROR("tool", "Tool %s failed (%ldms): %s",
                     name, ms, result->for_llm ? result->for_llm : "(null)");
    } else if (result->async) {
        SC_LOG_INFO("tool", "Tool %s started async (%ldms)", name, ms);
    } else {
        SC_LOG_INFO("tool", "Tool %s completed (%ldms, result_len=%zu)",
                    name, ms,
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
    sc_audit_log(name, summary, result->is_error, ms);
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
