/*
 * smolclaw - prompt prefix warmup (Phase 1.8)
 */
#include "providers/warmup.h"
#include "agent.h"
#include "logger.h"
#include "cJSON.h"

#include <stdint.h>
#include <string.h>

static uint32_t fnv1a(const char *s)
{
    uint32_t h = 2166136261u;
    for (; s && *s; s++) {
        h ^= (unsigned char)*s;
        h *= 16777619u;
    }
    return h;
}

static int provider_allowed(struct sc_agent *agent, const char *name)
{
    if (!name) return 0;
    for (int i = 0; i < agent->warmup_provider_count; i++)
        if (agent->warmup_providers[i] &&
            strcmp(agent->warmup_providers[i], name) == 0)
            return 1;
    return 0;
}

int sc_warmup_maybe(struct sc_agent *agent, sc_provider_t *provider,
                    const char *model, sc_llm_message_t *msgs, int msg_count,
                    sc_tool_definition_t *tools, int tool_count)
{
    if (!agent || !agent->warmup || !provider || !provider->chat)
        return 0;
    if (!provider_allowed(agent, provider->name))
        return 0;

    /* Fingerprint the prefix that the real call will use. */
    uint32_t fp = fnv1a(provider->name);
    fp = fp * 16777619u ^ fnv1a(model ? model : "");
    if (msg_count > 0 && msgs[0].content)
        fp = fp * 16777619u ^ fnv1a(msgs[0].content);
    for (int i = 0; i < tool_count; i++)
        fp = fp * 16777619u ^ fnv1a(tools[i].name ? tools[i].name : "");

    if (fp == agent->last_warmup_fingerprint)
        return 0;  /* unchanged — already primed */

    cJSON *opts = cJSON_CreateObject();
    cJSON_AddNumberToObject(opts, "max_tokens", 1);
    cJSON_AddNumberToObject(opts, "temperature", 0);
    sc_llm_response_t *resp = provider->chat(provider, msgs, msg_count,
                                             tools, tool_count, model, opts);
    cJSON_Delete(opts);
    if (resp) sc_llm_response_free(resp);

    agent->last_warmup_fingerprint = fp;
    SC_LOG_DEBUG("agent", "Prompt warmup sent (provider=%s model=%s)",
                 provider->name, model ? model : "");
    return 1;
}
