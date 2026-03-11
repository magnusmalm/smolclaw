/*
 * tools/memory_tools.c - Memory management tools
 *
 * Three tools for LLM-driven memory management:
 *   memory_read  — read long-term memory and/or recent daily notes
 *   memory_write — overwrite MEMORY.md (destructive, needs_confirm)
 *   memory_log   — append to today's daily note (additive, no confirm)
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "tools/memory_tools.h"
#include "tools/types.h"
#include "memory.h"
#include "util/str.h"
#include "util/json_helpers.h"
#include "util/prompt_guard.h"
#include "logger.h"
#include "cJSON.h"

/* ---------- Common ---------- */

typedef struct {
    sc_memory_t *mem;
} mem_tool_data_t;

static void mem_tool_destroy(sc_tool_t *self)
{
    if (!self) return;
    mem_tool_data_t *d = self->data;
    if (d) {
        sc_memory_free(d->mem);
        free(d);
    }
    free(self);
}

static mem_tool_data_t *mem_data_new(const char *workspace)
{
    mem_tool_data_t *d = calloc(1, sizeof(*d));
    if (!d) return NULL;
    d->mem = sc_memory_new(workspace);
    if (!d->mem) { free(d); return NULL; }
    return d;
}

/* ---------- memory_read ---------- */

static cJSON *memory_read_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = sc_schema_new();
    sc_schema_add_string(schema, "section",
        "Which section to read: \"all\" (default), \"long_term\", or \"recent\"", 0);
    return schema;
}

static sc_tool_result_t *memory_read_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    mem_tool_data_t *d = self->data;
    if (!d || !d->mem)
        return sc_tool_result_error("memory tool not initialized");

    const char *section = sc_json_get_string(args, "section", "all");

    int want_long_term = (strcmp(section, "all") == 0 ||
                          strcmp(section, "long_term") == 0);
    int want_recent    = (strcmp(section, "all") == 0 ||
                          strcmp(section, "recent") == 0);

    char *long_term = NULL;
    char *recent = NULL;

    if (want_long_term)
        long_term = sc_memory_read_long_term(d->mem);
    if (want_recent)
        recent = sc_memory_get_recent_notes(d->mem, 7);

    if (!long_term && !recent)
        return sc_tool_result_new("No memory stored yet.");

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);

    int had_long_term = (long_term != NULL);
    if (long_term) {
        sc_strbuf_append(&sb, "## Long-term Memory\n\n");
        sc_strbuf_append(&sb, long_term);
        free(long_term);
        long_term = NULL;
    }

    if (recent) {
        if (had_long_term)
            sc_strbuf_append(&sb, "\n\n---\n\n");
        sc_strbuf_append(&sb, "## Recent Daily Notes (last 7 days)\n\n");
        sc_strbuf_append(&sb, recent);
        free(recent);
    }

    char *result = sc_strbuf_finish(&sb);
    sc_tool_result_t *r = sc_tool_result_new(result);
    free(result);
    return r;
}

sc_tool_t *sc_tool_memory_read_new(const char *workspace)
{
    mem_tool_data_t *d = mem_data_new(workspace);
    if (!d) return NULL;
    return sc_tool_new_simple("memory_read",
        "Read the agent's long-term memory (MEMORY.md) and/or "
        "recent daily notes. Use to recall previously stored facts, "
        "user preferences, and observations.",
        memory_read_parameters, memory_read_execute, mem_tool_destroy, 0, d);
}

/* ---------- memory_write ---------- */

static cJSON *memory_write_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = sc_schema_new();
    sc_schema_add_string(schema, "content",
        "The complete content to write to long-term memory (MEMORY.md). "
        "This replaces the entire file.", 1);
    return schema;
}

static sc_tool_result_t *memory_write_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    mem_tool_data_t *d = self->data;
    if (!d || !d->mem)
        return sc_tool_result_error("memory tool not initialized");

    const char *content = sc_json_get_string(args, "content", NULL);
    if (!content)
        return sc_tool_result_error("content is required");

    /* Block prompt injection in memory content */
    if (sc_prompt_guard_scan_high(content)) {
        SC_LOG_WARN("memory", "Blocked memory_write: prompt injection detected");
        return sc_tool_result_error(
            "Content rejected: suspected prompt injection pattern detected.");
    }

    int rc = sc_memory_write_long_term(d->mem, content);
    if (rc != 0)
        return sc_tool_result_error("Failed to write long-term memory");

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "Memory updated (%d bytes).", (int)strlen(content));
    char *msg = sc_strbuf_finish(&sb);
    sc_tool_result_t *r = sc_tool_result_new(msg);
    free(msg);
    return r;
}

sc_tool_t *sc_tool_memory_write_new(const char *workspace)
{
    mem_tool_data_t *d = mem_data_new(workspace);
    if (!d) return NULL;
    return sc_tool_new_simple("memory_write",
        "Overwrite the agent's long-term memory (MEMORY.md). "
        "Use to update or restructure stored knowledge. "
        "Replaces the entire file — read first to preserve existing content.",
        memory_write_parameters, memory_write_execute, mem_tool_destroy, 1, d);
}

/* ---------- memory_log ---------- */

static cJSON *memory_log_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = sc_schema_new();
    sc_schema_add_string(schema, "content",
        "The observation or fact to log. Will be appended as a bullet point "
        "to today's daily note.", 1);
    return schema;
}

static sc_tool_result_t *memory_log_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    mem_tool_data_t *d = self->data;
    if (!d || !d->mem)
        return sc_tool_result_error("memory tool not initialized");

    const char *content = sc_json_get_string(args, "content", NULL);
    if (!content)
        return sc_tool_result_error("content is required");

    /* Block prompt injection in memory content */
    if (sc_prompt_guard_scan_high(content)) {
        SC_LOG_WARN("memory", "Blocked memory_log: prompt injection detected");
        return sc_tool_result_error(
            "Content rejected: suspected prompt injection pattern detected.");
    }

    /* Format as bullet point */
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "- %s", content);
    char *entry = sc_strbuf_finish(&sb);

    int rc = sc_memory_append_today(d->mem, entry);
    free(entry);

    if (rc != 0)
        return sc_tool_result_error("Failed to write daily note");

    return sc_tool_result_new("Logged to daily notes.");
}

sc_tool_t *sc_tool_memory_log_new(const char *workspace)
{
    mem_tool_data_t *d = mem_data_new(workspace);
    if (!d) return NULL;
    return sc_tool_new_simple("memory_log",
        "Append an observation or fact to today's daily note. "
        "Use to record things worth remembering: user preferences, "
        "project decisions, recurring patterns, important context.",
        memory_log_parameters, memory_log_execute, mem_tool_destroy, 0, d);
}

/* ---------- Index callback wiring ---------- */

void sc_tool_memory_set_index_cb(sc_tool_t *tool, sc_memory_index_cb cb,
                                  void *ctx)
{
    if (!tool || !tool->data) return;
    mem_tool_data_t *d = tool->data;
    sc_memory_set_index_cb(d->mem, cb, ctx);
}
