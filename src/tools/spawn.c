/*
 * tools/spawn.c - Subagent spawning tool
 *
 * Lets the LLM spawn a background agent to handle a task on a
 * separate session. The subagent shares the same provider and tools
 * but operates on its own session key, returning the result to the
 * parent agent's context.
 */

#include <stdlib.h>
#include <string.h>

#include "tools/spawn.h"
#include "tools/types.h"
#include "agent.h"
#include "constants.h"
#include "util/str.h"
#include "util/uuid.h"
#include "util/json_helpers.h"
#include "logger.h"
#include "cJSON.h"

typedef struct {
    sc_agent_t *parent;
} spawn_data_t;

static void spawn_destroy(sc_tool_t *self)
{
    if (!self) return;
    free(self->data);
    free(self);
}

static cJSON *spawn_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "object");

    cJSON *props = cJSON_AddObjectToObject(schema, "properties");

    cJSON *prompt = cJSON_AddObjectToObject(props, "prompt");
    cJSON_AddStringToObject(prompt, "type", "string");
    cJSON_AddStringToObject(prompt, "description",
        "The task/prompt for the subagent to process");

    cJSON *name = cJSON_AddObjectToObject(props, "name");
    cJSON_AddStringToObject(name, "type", "string");
    cJSON_AddStringToObject(name, "description",
        "Optional short name for the subagent task (for logging)");

    cJSON *req = cJSON_AddArrayToObject(schema, "required");
    cJSON_AddItemToArray(req, cJSON_CreateString("prompt"));
    return schema;
}

static _Thread_local int spawn_depth = 0;

static sc_tool_result_t *spawn_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    spawn_data_t *d = self->data;

    if (!d->parent) return sc_tool_result_error("No parent agent available");

    if (spawn_depth >= SC_MAX_SPAWN_DEPTH)
        return sc_tool_result_error("spawn depth limit reached");

    const char *prompt = sc_json_get_string(args, "prompt", NULL);
    if (!prompt) return sc_tool_result_error("'prompt' is required");

    const char *name = sc_json_get_string(args, "name", "subagent");

    /* Generate a unique session key for this subagent */
    char *uuid = sc_generate_id();
    sc_strbuf_t sk;
    sc_strbuf_init(&sk);
    sc_strbuf_appendf(&sk, "spawn:%s:%s", name, uuid);
    char *session_key = sc_strbuf_finish(&sk);
    free(uuid);

    SC_LOG_INFO("spawn", "Spawning subagent '%s' (session=%s)", name, session_key);

    /* Process the prompt synchronously using the parent agent's provider/tools.
     * This is a blocking call — the subagent runs in the same thread. */
    spawn_depth++;
    char *result = sc_agent_process_direct(d->parent, prompt, session_key);
    spawn_depth--;

    free(session_key);

    if (!result || result[0] == '\0') {
        free(result);
        return sc_tool_result_new("Subagent completed but produced no output.");
    }

    /* Truncate long results */
    size_t len = strlen(result);
    if (len > SC_MAX_OUTPUT_CHARS) {
        result[SC_MAX_OUTPUT_CHARS] = '\0';
    }

    sc_tool_result_t *r = sc_tool_result_new(result);
    free(result);
    return r;
}

sc_tool_t *sc_tool_spawn_new(sc_agent_t *parent_agent)
{
    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    spawn_data_t *d = calloc(1, sizeof(*d));
    if (!d) { free(t); return NULL; }
    d->parent = parent_agent;

    t->name = "spawn";
    t->description = "Spawn a subagent to handle a task independently. "
                     "The subagent processes the given prompt on a separate session "
                     "and returns its result. Use for parallel or background work.";
    t->parameters = spawn_parameters;
    t->execute = spawn_execute;
    t->destroy = spawn_destroy;
    t->data = d;
    return t;
}
