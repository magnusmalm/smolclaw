/*
 * tools/scratchpad.c - Persistent working notes tool
 *
 * The "note" tool writes to {workspace}/state/scratchpad.md.
 * This file is read and injected into the system prompt on every
 * LLM call, making it survive context compaction.  Agents use it
 * to track working state: files modified, git operations performed,
 * current plan, key decisions made during multi-step tasks.
 *
 * Semantics: each call overwrites the scratchpad entirely.
 * The agent is responsible for including previous content if needed.
 * Max size: 2048 bytes.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "tools/scratchpad.h"
#include "tools/types.h"
#include "util/str.h"
#include "util/json_helpers.h"
#include "util/prompt_guard.h"
#include "logger.h"
#include "cJSON.h"

#define SCRATCHPAD_MAX_BYTES 2048
#define SCRATCHPAD_FILE      "state/scratchpad.md"
#define TAG                  "scratchpad"

typedef struct {
    char *path;  /* {workspace}/state/scratchpad.md */
} scratchpad_data_t;

static void scratchpad_destroy(sc_tool_t *self)
{
    if (!self) return;
    scratchpad_data_t *d = self->data;
    if (d) {
        free(d->path);
        free(d);
    }
    free(self);
}

static cJSON *scratchpad_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = sc_schema_new();
    sc_schema_add_string(schema, "content",
        "Complete scratchpad content (overwrites previous). "
        "Max 2048 bytes. Record: files modified, git state, "
        "current plan, key decisions.", 1);
    return schema;
}

static sc_tool_result_t *scratchpad_execute(sc_tool_t *self, cJSON *args,
                                             void *ctx)
{
    (void)ctx;
    scratchpad_data_t *d = self->data;
    if (!d || !d->path)
        return sc_tool_result_error("scratchpad tool not initialized");

    const char *content = sc_json_get_string(args, "content", NULL);
    if (!content || !content[0])
        return sc_tool_result_error("content is required");

    size_t len = strlen(content);
    if (len > SCRATCHPAD_MAX_BYTES) {
        char msg[128];
        snprintf(msg, sizeof(msg),
                 "Content too large (%zu bytes, max %d)",
                 len, SCRATCHPAD_MAX_BYTES);
        return sc_tool_result_error(msg);
    }

    /* Prompt injection guard */
    if (sc_prompt_guard_scan(content)) {
        SC_LOG_WARN(TAG, "Prompt injection detected in scratchpad content");
        return sc_tool_result_error(
            "Content blocked by prompt injection guard");
    }

    /* Atomic write: temp file + rename */
    char tmp_path[1024];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", d->path);

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        SC_LOG_WARN(TAG, "Failed to open %s: %s", tmp_path, strerror(errno));
        return sc_tool_result_error("Failed to write scratchpad");
    }

    ssize_t written = write(fd, content, len);
    fsync(fd);
    close(fd);

    if (written != (ssize_t)len) {
        unlink(tmp_path);
        return sc_tool_result_error("Failed to write scratchpad");
    }

    if (rename(tmp_path, d->path) != 0) {
        SC_LOG_WARN(TAG, "Failed to rename %s -> %s: %s",
                    tmp_path, d->path, strerror(errno));
        unlink(tmp_path);
        return sc_tool_result_error("Failed to write scratchpad");
    }

    SC_LOG_INFO(TAG, "Scratchpad updated (%zu bytes)", len);

    char result[64];
    snprintf(result, sizeof(result), "Scratchpad updated (%zu bytes).", len);
    return sc_tool_result_silent(result);
}

sc_tool_t *sc_tool_scratchpad_new(const char *workspace)
{
    if (!workspace) return NULL;

    scratchpad_data_t *d = calloc(1, sizeof(*d));
    if (!d) return NULL;

    if (asprintf(&d->path, "%s/" SCRATCHPAD_FILE, workspace) < 0) {
        free(d);
        return NULL;
    }

    sc_tool_t *tool = calloc(1, sizeof(*tool));
    if (!tool) {
        free(d->path);
        free(d);
        return NULL;
    }

    tool->name = "note";
    tool->description =
        "Write persistent working notes that survive context compaction. "
        "Use to record: files modified, git operations performed, current "
        "step in workflow, key decisions. Overwrites previous content — "
        "include prior notes if you want to keep them. Max 2048 bytes. "
        "For durable long-term facts, use memory_log instead.";
    tool->parameters = scratchpad_parameters;
    tool->execute = scratchpad_execute;
    tool->destroy = scratchpad_destroy;
    tool->needs_confirm = 0;
    tool->data = d;

    return tool;
}
