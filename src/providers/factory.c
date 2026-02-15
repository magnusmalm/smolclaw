/*
 * smolclaw - providers/factory.c
 * Provider factory: create the right provider from config
 */

#include <stdlib.h>
#include <string.h>
#include <strings.h> /* strcasecmp */
#include <stddef.h>  /* offsetof */

#include "providers/factory.h"
#include "providers/http.h"
#include "providers/claude.h"
#include "config.h"
#include "logger.h"

#define LOG_TAG "provider-factory"

/* Check if a string contains a substring (case-insensitive) */
static int contains_ci(const char *haystack, const char *needle)
{
    if (!haystack || !needle) return 0;
    size_t hlen = strlen(haystack);
    size_t nlen = strlen(needle);
    if (nlen > hlen) return 0;
    for (size_t i = 0; i <= hlen - nlen; i++) {
        if (strncasecmp(haystack + i, needle, nlen) == 0) return 1;
    }
    return 0;
}

/* Provider lookup table — single source of truth for routing */
typedef struct {
    const char *names[3];        /* Name + alias(es), NULL-terminated */
    const char *default_base;    /* Default base URL (NULL = none) */
    size_t cfg_offset;           /* offsetof(sc_config_t, <provider_config>) */
    int use_claude;
    int allow_no_key;
    const char *model_hints[7];  /* Substrings for model-name auto-detect */
} provider_entry_t;

#define PROVIDER_COUNT 10

/* Order matters for model_hints matching (first match wins) */
static const provider_entry_t provider_table[PROVIDER_COUNT] = {
    { {"anthropic", "claude"}, "https://api.anthropic.com/v1",
      offsetof(sc_config_t, anthropic), 1, 0, {"claude"} },
    { {"openai", "gpt"}, "https://api.openai.com/v1",
      offsetof(sc_config_t, openai), 0, 0, {"gpt", "o1"} },
    { {"openrouter"}, "https://openrouter.ai/api/v1",
      offsetof(sc_config_t, openrouter), 0, 0, {NULL} },
    { {"groq"}, "https://api.groq.com/openai/v1",
      offsetof(sc_config_t, groq), 0, 0, {"groq"} },
    { {"zhipu", "glm"}, "https://open.bigmodel.cn/api/paas/v4",
      offsetof(sc_config_t, zhipu), 0, 0, {"glm", "zhipu"} },
    { {"gemini", "google"}, "https://generativelanguage.googleapis.com/v1beta",
      offsetof(sc_config_t, gemini), 0, 0, {"gemini"} },
    { {"vllm"}, NULL,
      offsetof(sc_config_t, vllm), 0, 0, {NULL} },
    { {"deepseek"}, "https://api.deepseek.com/v1",
      offsetof(sc_config_t, deepseek), 0, 0, {"deepseek"} },
    { {"xai", "grok"}, "https://api.x.ai/v1",
      offsetof(sc_config_t, xai), 0, 0, {"grok"} },
    { {"ollama"}, "http://localhost:11434/v1",
      offsetof(sc_config_t, ollama), 0, 1,
      {"llama", "mistral", "qwen", "phi", "codellama", "gemma"} },
};

/* Resolve fields from a table entry */
static void resolve_from_entry(const sc_config_t *cfg, const provider_entry_t *e,
                                const char **api_key, const char **api_base,
                                const char **proxy, int *use_claude,
                                int *allow_no_key)
{
    const sc_provider_config_t *pc =
        (const sc_provider_config_t *)((const char *)cfg + e->cfg_offset);
    *api_key = pc->api_key;
    *api_base = pc->api_base;
    *proxy = pc->proxy;
    if (!*api_base || (*api_base)[0] == '\0')
        *api_base = e->default_base;
    *use_claude = e->use_claude;
    if (e->allow_no_key && allow_no_key) *allow_no_key = 1;
}

/* Resolve credentials for an explicit provider name.
 * Returns 1 if resolved, 0 otherwise. */
static int resolve_by_provider_name(const sc_config_t *cfg,
                                    const char *provider_name,
                                    const char **api_key, const char **api_base,
                                    const char **proxy, int *use_claude,
                                    int *allow_no_key)
{
    if (!provider_name || provider_name[0] == '\0') return 0;

    for (int i = 0; i < PROVIDER_COUNT; i++) {
        for (int j = 0; provider_table[i].names[j]; j++) {
            if (strcasecmp(provider_name, provider_table[i].names[j]) == 0) {
                resolve_from_entry(cfg, &provider_table[i], api_key, api_base,
                                    proxy, use_claude, allow_no_key);
                return 1;
            }
        }
    }
    return 0;
}

/* Resolve credentials by detecting provider from model name.
 * Returns 1 if resolved, 0 otherwise. */
static int resolve_by_model_name(const sc_config_t *cfg, const char *model,
                                 const char **api_key, const char **api_base,
                                 const char **proxy, int *use_claude,
                                 int *allow_no_key)
{
    if (!model || model[0] == '\0') return 0;

    for (int i = 0; i < PROVIDER_COUNT; i++) {
        const provider_entry_t *e = &provider_table[i];
        if (!e->model_hints[0]) continue;

        /* Check if any hint substring matches */
        int matched = 0;
        for (int j = 0; e->model_hints[j]; j++) {
            if (contains_ci(model, e->model_hints[j])) {
                matched = 1;
                break;
            }
        }
        if (!matched) continue;

        /* Hint matched — check if provider is configured */
        const sc_provider_config_t *pc =
            (const sc_provider_config_t *)((const char *)cfg + e->cfg_offset);
        int available = e->allow_no_key
            ? (pc->api_base && pc->api_base[0] != '\0')
            : (pc->api_key && pc->api_key[0] != '\0');
        if (available) {
            resolve_from_entry(cfg, e, api_key, api_base, proxy,
                                use_claude, allow_no_key);
            return 1;
        }
        break; /* Matched but not configured — fall through to openrouter */
    }

    /* Last resort: try openrouter if available */
    if (cfg->openrouter.api_key && cfg->openrouter.api_key[0] != '\0') {
        resolve_by_provider_name(cfg, "openrouter", api_key, api_base, proxy,
                                  use_claude, allow_no_key);
        SC_LOG_INFO(LOG_TAG, "Falling back to OpenRouter for model '%s'", model);
        return 1;
    }

    return 0;
}

/* Create a provider instance from resolved credentials */
static sc_provider_t *create_provider_instance(const char *api_key,
                                               const char *api_base,
                                               const char *proxy,
                                               int use_claude,
                                               const char *model,
                                               int allow_no_key)
{
    if (!allow_no_key && (!api_key || api_key[0] == '\0')) {
        SC_LOG_ERROR(LOG_TAG, "No API key configured for model '%s'",
                     model ? model : "(none)");
        return NULL;
    }
    if (!api_base || api_base[0] == '\0') {
        SC_LOG_ERROR(LOG_TAG, "No API base configured for model '%s'",
                     model ? model : "(none)");
        return NULL;
    }

    if (use_claude) {
        SC_LOG_INFO(LOG_TAG, "Using Claude (Anthropic) provider for model '%s'",
                    model ? model : "(default)");
        return sc_provider_claude_new(api_key, api_base);
    }

    SC_LOG_INFO(LOG_TAG, "Using HTTP (OpenAI-compat) provider for model '%s' (base=%s)",
                model ? model : "(default)", api_base);
    return sc_provider_http_new(api_key, api_base, proxy);
}

const char *sc_model_strip_prefix(const char *model)
{
    if (!model) return model;
    const char *slash = strchr(model, '/');
    if (!slash || slash == model) return model;

    size_t prefix_len = (size_t)(slash - model);
    for (int i = 0; i < PROVIDER_COUNT; i++) {
        for (int j = 0; provider_table[i].names[j]; j++) {
            if (strlen(provider_table[i].names[j]) == prefix_len &&
                strncasecmp(model, provider_table[i].names[j], prefix_len) == 0) {
                return slash + 1;
            }
        }
    }
    return model;
}

sc_provider_t *sc_provider_create(const sc_config_t *cfg)
{
    if (!cfg) {
        SC_LOG_ERROR(LOG_TAG, "NULL config");
        return NULL;
    }

    const char *provider_name = cfg->provider;
    const char *model = cfg->model;

    const char *api_key = NULL;
    const char *api_base = NULL;
    const char *proxy = NULL;
    int use_claude = 0;
    int allow_no_key = 0;

    /* 1. Explicit provider name from config */
    if (provider_name && provider_name[0] != '\0') {
        if (!resolve_by_provider_name(cfg, provider_name,
                                      &api_key, &api_base, &proxy, &use_claude,
                                      &allow_no_key)) {
            SC_LOG_WARN(LOG_TAG, "Unknown provider name '%s', trying as HTTP",
                        provider_name);
        }
    }

    /* 2. Check for "provider/model" prefix syntax in model name
     *    (e.g. "openrouter/qwen/qwen3-8b" → provider "openrouter") */
    if (!api_key && !api_base && model) {
        const char *slash = strchr(model, '/');
        if (slash && slash != model) {
            size_t prefix_len = (size_t)(slash - model);
            char *prefix = malloc(prefix_len + 1);
            if (prefix) {
                memcpy(prefix, model, prefix_len);
                prefix[prefix_len] = '\0';
                resolve_by_provider_name(cfg, prefix,
                                         &api_key, &api_base, &proxy, &use_claude,
                                         &allow_no_key);
                free(prefix);
            }
        }
    }

    /* 3. Fallback: detect from model name */
    if (!api_key && !api_base) {
        resolve_by_model_name(cfg, model, &api_key, &api_base, &proxy, &use_claude,
                              &allow_no_key);
    }

    /* 3. Validate and create */
    if (!allow_no_key && (!api_key || api_key[0] == '\0')) {
        SC_LOG_ERROR(LOG_TAG, "No API key configured (provider=%s, model=%s)",
                     provider_name ? provider_name : "(auto)",
                     model ? model : "(none)");
        return NULL;
    }

    if (!api_base || api_base[0] == '\0') {
        SC_LOG_ERROR(LOG_TAG, "No API base configured (provider=%s, model=%s)",
                     provider_name ? provider_name : "(auto)",
                     model ? model : "(none)");
        return NULL;
    }

    return create_provider_instance(api_key, api_base, proxy, use_claude, model,
                                    allow_no_key);
}

sc_provider_t *sc_provider_create_for_model(const sc_config_t *cfg, const char *model)
{
    if (!cfg || !model || model[0] == '\0') {
        SC_LOG_ERROR(LOG_TAG, "Invalid args for create_for_model");
        return NULL;
    }

    const char *api_key = NULL;
    const char *api_base = NULL;
    const char *proxy = NULL;
    int use_claude = 0;
    int allow_no_key = 0;

    /* Check for "provider/model" prefix syntax (e.g. "groq/llama-3.3-70b") */
    const char *slash = strchr(model, '/');
    if (slash && slash != model) {
        size_t prefix_len = (size_t)(slash - model);
        char *prefix = malloc(prefix_len + 1);
        if (prefix) {
            memcpy(prefix, model, prefix_len);
            prefix[prefix_len] = '\0';
            resolve_by_provider_name(cfg, prefix,
                                     &api_key, &api_base, &proxy, &use_claude,
                                     &allow_no_key);
            free(prefix);
        }
    }

    /* Fall back to model-name detection */
    if (!api_key && !api_base) {
        resolve_by_model_name(cfg, model, &api_key, &api_base, &proxy, &use_claude,
                              &allow_no_key);
    }

    return create_provider_instance(api_key, api_base, proxy, use_claude, model,
                                    allow_no_key);
}
