/*
 * tools/skill_tool.c - Skill invocation tool
 *
 * Allows the LLM to invoke user-defined skills by name.
 * Inline skills expand the prompt as a tool result.
 * Fork skills spawn a subagent with the skill content as prompt.
 */

#include <stdlib.h>
#include <string.h>

#include "tools/skill_tool.h"
#include "tools/types.h"
#include "skill.h"
#include "agent.h"
#include "util/str.h"
#include "logger.h"
#include "cJSON.h"

#define LOG_TAG "skill_tool"

typedef struct {
    sc_skill_registry_t *skills;
    sc_agent_t *agent;
} skill_tool_data_t;

static void skill_destroy(sc_tool_t *self)
{
    if (!self) return;
    free(self->data);
    free(self);
}

static cJSON *skill_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "object");

    cJSON *props = cJSON_AddObjectToObject(schema, "properties");

    cJSON *name = cJSON_AddObjectToObject(props, "skill");
    cJSON_AddStringToObject(name, "type", "string");
    cJSON_AddStringToObject(name, "description",
        "Name of the skill to invoke.");

    cJSON *args = cJSON_AddObjectToObject(props, "args");
    cJSON_AddStringToObject(args, "type", "string");
    cJSON_AddStringToObject(args, "description",
        "Arguments to pass to the skill (substituted for $ARGUMENTS).");

    cJSON *req = cJSON_AddArrayToObject(schema, "required");
    cJSON_AddItemToArray(req, cJSON_CreateString("skill"));
    return schema;
}

static sc_tool_result_t *skill_execute(sc_tool_t *self, cJSON *args_json,
                                        void *ctx)
{
    (void)ctx;
    skill_tool_data_t *d = self->data;

    const char *name = NULL;
    cJSON *n = cJSON_GetObjectItem(args_json, "skill");
    if (n && cJSON_IsString(n)) name = n->valuestring;
    if (!name || !name[0])
        return sc_tool_result_error("'skill' is required.");

    const char *args = NULL;
    cJSON *a = cJSON_GetObjectItem(args_json, "args");
    if (a && cJSON_IsString(a)) args = a->valuestring;

    sc_skill_t *skill = sc_skill_registry_find(d->skills, name);
    if (!skill)
        return sc_tool_result_error("Skill not found. Check available skills.");

    if (skill->disable_model)
        return sc_tool_result_error("This skill is user-only (not model-invocable).");

    SC_LOG_INFO(LOG_TAG, "Invoking skill: %s (args=%s)", name,
                args ? args : "(none)");

    char *expanded = sc_skill_expand(skill, args ? args : "");
    if (!expanded)
        return sc_tool_result_error("Failed to load skill content.");

    /* Fork mode: spawn subagent with skill as prompt */
    if (skill->context && strcmp(skill->context, "fork") == 0) {
        if (!d->agent) {
            free(expanded);
            return sc_tool_result_error("Fork mode requires agent context.");
        }
        char *result = sc_agent_process_direct(d->agent, expanded, NULL);
        free(expanded);
        if (!result || result[0] == '\0') {
            free(result);
            return sc_tool_result_new("Skill completed (no output).");
        }
        sc_tool_result_t *r = sc_tool_result_new(result);
        free(result);
        return r;
    }

    /* Inline mode: return expanded prompt as tool result */
    sc_tool_result_t *r = sc_tool_result_new(expanded);
    free(expanded);
    return r;
}

sc_tool_t *sc_tool_skill_new(sc_skill_registry_t *skills, sc_agent_t *agent)
{
    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    skill_tool_data_t *d = calloc(1, sizeof(*d));
    if (!d) { free(t); return NULL; }
    d->skills = skills;
    d->agent = agent;

    t->name = "skill";
    t->description =
        "Invoke a user-defined skill by name. Skills are prompt templates "
        "that provide structured workflows for common tasks. "
        "Check the Available Skills section in the system prompt for options.";
    t->parameters = skill_parameters;
    t->execute = skill_execute;
    t->destroy = skill_destroy;
    t->data = d;
    return t;
}
