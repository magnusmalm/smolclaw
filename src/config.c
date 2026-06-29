#include "config.h"
#include "audit.h"
#include "constants.h"
#include "logger.h"
#include "util/str.h"
#include "util/json_helpers.h"

#include "sc_features.h"
#if SC_ENABLE_VAULT
#include "util/vault.h"
#include <openssl/crypto.h>
#endif

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define LOG_TAG "config"

/* Helper: override a string field only if JSON key is present */
static void override_str_field(char **field, const cJSON *obj, const char *key)
{
    const char *val = sc_json_get_string(obj, key, NULL);
    if (val) {
        free(*field);
        *field = sc_strdup(val);
    }
}

static void parse_provider(const cJSON *obj, const char *name,
                           sc_provider_config_t *out)
{
    const cJSON *p = sc_json_get_object(obj, name);
    if (!p) return;
    override_str_field(&out->api_key,  p, "api_key");
    override_str_field(&out->api_base, p, "api_base");
    override_str_field(&out->proxy,    p, "proxy");
}

/* Helper: free a provider config */
static void free_provider(sc_provider_config_t *p)
{
    free(p->api_key);
    free(p->api_base);
    free(p->proxy);
}

/* Map an approval-policy name to its int (sc_approval_policy_t). */
static int parse_approval_policy(const char *s, int dflt)
{
    if (!s) return dflt;
    if (strcmp(s, "always") == 0)         return 1;
    if (strcmp(s, "never") == 0)          return 2;
    if (strcmp(s, "dangerous-only") == 0) return 0;
    return dflt;
}

void sc_config_apply_operator_mode(sc_config_t *cfg, const char *mode)
{
    if (!cfg || !mode || strcmp(mode, "custom") == 0) return;

    int clamp = 0;
    if (strcmp(mode, "explore") == 0)      { cfg->approval_policy = 0; clamp = 15; }
    else if (strcmp(mode, "edit") == 0)    { cfg->approval_policy = 0; clamp = 25; }
    else if (strcmp(mode, "review") == 0)  { cfg->approval_policy = 1; clamp = 15; }
    else if (strcmp(mode, "ship") == 0)    { cfg->approval_policy = 2; clamp = 50; }
    else return;  /* unknown mode → no-op */

    if (clamp > 0 &&
        (cfg->max_tool_iterations <= 0 || cfg->max_tool_iterations > clamp))
        cfg->max_tool_iterations = clamp;
}

#if SC_ENABLE_MOA
static void parse_moa_slot(const cJSON *obj, sc_moa_slot_cfg_t *slot)
{
    if (!obj) return;
    slot->provider = sc_strdup(sc_json_get_string(obj, "provider", NULL));
    slot->model    = sc_strdup(sc_json_get_string(obj, "model", NULL));
}

/* Parse the top-level "moa" section into cfg->moa (task 2.13). */
static void parse_moa(sc_config_t *cfg, const cJSON *root)
{
    const cJSON *moa = sc_json_get_object(root, "moa");
    if (!moa) return;

    cfg->moa.default_preset =
        sc_strdup(sc_json_get_string(moa, "default_preset", NULL));

    const cJSON *presets = sc_json_get_object(moa, "presets");
    if (!presets) return;

    cJSON *p;
    cJSON_ArrayForEach(p, (cJSON *)presets) {
        if (!p->string) continue;
        if (cfg->moa.preset_count >= SC_MOA_MAX_PRESETS) break;

        sc_moa_preset_cfg_t *pr = &cfg->moa.presets[cfg->moa.preset_count];
        pr->name                  = sc_strdup(p->string);
        pr->enabled               = sc_json_get_bool(p, "enabled", 1);
        pr->local_only            = sc_json_get_bool(p, "local_only", 0);
        pr->reference_temperature = sc_json_get_double(p, "reference_temperature", 0.6);
        pr->aggregator_temperature= sc_json_get_double(p, "aggregator_temperature", 0);
        pr->reference_max_tokens  = sc_json_get_int(p, "reference_max_tokens", 1024);
        pr->aggregator_max_tokens = sc_json_get_int(p, "aggregator_max_tokens", 0);

        parse_moa_slot(sc_json_get_object(p, "aggregator"), &pr->aggregator);

        const cJSON *refs = sc_json_get_array(p, "reference_models");
        if (refs) {
            cJSON *r;
            cJSON_ArrayForEach(r, (cJSON *)refs) {
                if (pr->reference_count >= SC_MOA_MAX_REFS) break;
                parse_moa_slot(r, &pr->reference_models[pr->reference_count++]);
            }
        }
        cfg->moa.preset_count++;
    }
}
#endif /* SC_ENABLE_MOA */

/* Helper: serialize a provider section to JSON */
static void provider_to_json(cJSON *parent, const char *name,
                             const sc_provider_config_t *p)
{
    cJSON *obj = cJSON_CreateObject();
    if (p->api_key)  cJSON_AddStringToObject(obj, "api_key",  p->api_key);
    if (p->api_base) cJSON_AddStringToObject(obj, "api_base", p->api_base);
    if (p->proxy)    cJSON_AddStringToObject(obj, "proxy",    p->proxy);
    cJSON_AddItemToObject(parent, name, obj);
}

/* Helper: apply env var override (string) */
static void env_override_str(char **field, const char *var)
{
    const char *val = getenv(var);
    if (val) {
        free(*field);
        *field = sc_strdup(val);
    }
}

/* Helper: apply env var override (int) */
static void env_override_int(int *field, const char *var)
{
    const char *val = getenv(var);
    if (val) {
        char *end;
        long v = strtol(val, &end, 10);
        if (end != val && *end == '\0' && v >= INT_MIN && v <= INT_MAX)
            *field = (int)v;
        else
            SC_LOG_WARN(LOG_TAG, "invalid integer for %s: '%s'", var, val);
    }
}

/* Helper: apply env var override (double) */
static void env_override_double(double *field, const char *var)
{
    const char *val = getenv(var);
    if (val) {
        char *end;
        double v = strtod(val, &end);
        if (end != val && *end == '\0')
            *field = v;
        else
            SC_LOG_WARN(LOG_TAG, "invalid number for %s: '%s'", var, val);
    }
}

/* Helper: apply env var override (bool as int) */
static void env_override_bool(int *field, const char *var)
{
    const char *val = getenv(var);
    if (val) {
        *field = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
    }
}

/*
 * Resolve a file reference: file:///path or @/path.
 * Returns malloc'd string on success, NULL on failure.
 * workspace (expanded, absolute) is used for advisory warnings only.
 */
static char *sc_resolve_file_ref(const char *value, const char *workspace)
{
    if (!value) return NULL;

    const char *path = NULL;
    if (strncmp(value, "file://", 7) == 0)
        path = value + 7;
    else if (value[0] == '@' && value[1] == '/')
        path = value + 1;
    else
        return NULL;

    /* Require absolute path */
    if (path[0] != '/') {
        SC_LOG_WARN(LOG_TAG, "file ref must be absolute path: %s", value);
        return NULL;
    }

    /* Advisory warnings for agent-accessible locations */
    if (workspace && workspace[0] &&
        strncmp(path, workspace, strlen(workspace)) == 0) {
        SC_LOG_WARN(LOG_TAG, "secret file is inside workspace (%s) — "
                    "agent tools can read it, exposing the secret to the LLM",
                    path);
    }
    char *smolclaw_dir = sc_get_home_dir();
    if (smolclaw_dir) {
        size_t dir_len = strlen(smolclaw_dir);
        /* Append trailing slash for prefix check */
        char *dir_slash = malloc(dir_len + 2);
        if (dir_slash) {
            snprintf(dir_slash, dir_len + 2, "%s/", smolclaw_dir);
            if (strncmp(path, dir_slash, strlen(dir_slash)) == 0) {
                SC_LOG_WARN(LOG_TAG, "secret file is inside %s (%s) — "
                            "agent reads memory/sessions from here",
                            smolclaw_dir, path);
            }
            free(dir_slash);
        }
        free(smolclaw_dir);
    }
    if (strncmp(path, "/proc", 5) == 0 || strncmp(path, "/sys", 4) == 0 ||
        strncmp(path, "/dev", 4) == 0) {
        SC_LOG_WARN(LOG_TAG, "secret file under /proc, /sys, or /dev: %s",
                    path);
    }

    /* Read the file */
    FILE *f = fopen(path, "r");
    if (!f) {
        SC_LOG_WARN(LOG_TAG, "cannot open secret file %s: %s",
                    path, strerror(errno));
        return NULL;
    }

    /* Check permissions */
    struct stat st;
    if (fstat(fileno(f), &st) == 0 && (st.st_mode & 0077) != 0) {
        SC_LOG_WARN(LOG_TAG, "secret file %s has open permissions "
                    "(mode %04o) — recommend 0600", path,
                    (unsigned)(st.st_mode & 07777));
    }

    /* Check size */
    if (fstat(fileno(f), &st) == 0 &&
        st.st_size > SC_MAX_SECRET_FILE_SIZE) {
        SC_LOG_WARN(LOG_TAG, "secret file %s too large (%ld bytes, "
                    "max %d)", path, (long)st.st_size,
                    SC_MAX_SECRET_FILE_SIZE);
        fclose(f);
        return NULL;
    }

    char buf[SC_MAX_SECRET_FILE_SIZE + 1];
    size_t n = fread(buf, 1, SC_MAX_SECRET_FILE_SIZE, f);
    fclose(f);
    buf[n] = '\0';

    /* Strip trailing newlines */
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) {
        buf[--n] = '\0';
    }

    if (n == 0) {
        SC_LOG_WARN(LOG_TAG, "secret file %s is empty", path);
        return NULL;
    }

    return sc_strdup(buf);
}

/* Resolve a single secret field if it contains a file reference */
static void resolve_secret_field(char **field, const char *workspace)
{
    if (!field || !*field) return;
    char *resolved = sc_resolve_file_ref(*field, workspace);
    if (resolved) {
        free(*field);
        *field = resolved;
    }
}

/* Resolve file references in all secret fields */
static void resolve_secret_refs(sc_config_t *cfg)
{
    char *ws = sc_config_workspace_path(cfg);

    /* Provider API keys (10 providers) */
    resolve_secret_field(&cfg->anthropic.api_key,  ws);
    resolve_secret_field(&cfg->openai.api_key,     ws);
    resolve_secret_field(&cfg->openrouter.api_key, ws);
    resolve_secret_field(&cfg->groq.api_key,       ws);
    resolve_secret_field(&cfg->zhipu.api_key,      ws);
    resolve_secret_field(&cfg->vllm.api_key,       ws);
    resolve_secret_field(&cfg->gemini.api_key,     ws);
    resolve_secret_field(&cfg->deepseek.api_key,   ws);
    resolve_secret_field(&cfg->ollama.api_key,     ws);
    resolve_secret_field(&cfg->xai.api_key,        ws);

    /* Channel tokens/passwords */
    resolve_secret_field(&cfg->telegram.token,     ws);
    resolve_secret_field(&cfg->discord.token,      ws);
    resolve_secret_field(&cfg->irc.password,       ws);
    resolve_secret_field(&cfg->slack.bot_token,    ws);
    resolve_secret_field(&cfg->slack.app_token,    ws);
    resolve_secret_field(&cfg->web.bearer_token,   ws);

    /* Tool API keys */
    resolve_secret_field(&cfg->web_tools.brave_api_key, ws);
    resolve_secret_field(&cfg->gitea.token, ws);

    free(ws);
}

#if SC_ENABLE_VAULT
/* Check if any field has a vault:// reference */
static int has_vault_refs(const sc_config_t *cfg)
{
    const char *fields[] = {
        cfg->anthropic.api_key, cfg->openai.api_key,
        cfg->openrouter.api_key, cfg->groq.api_key,
        cfg->zhipu.api_key, cfg->vllm.api_key,
        cfg->gemini.api_key, cfg->deepseek.api_key,
        cfg->ollama.api_key, cfg->xai.api_key,
        cfg->telegram.token, cfg->discord.token,
        cfg->irc.password, cfg->slack.bot_token,
        cfg->slack.app_token, cfg->web.bearer_token,
        cfg->web_tools.brave_api_key,
        cfg->gitea.token,
        cfg->x.consumer_key, cfg->x.consumer_secret,
        cfg->x.access_token, cfg->x.access_token_secret,
    };
    for (int i = 0; i < (int)(sizeof(fields) / sizeof(fields[0])); i++) {
        if (fields[i] && strncmp(fields[i], "vault://", 8) == 0)
            return 1;
    }
    /* Check delegation target bearer tokens */
    for (int i = 0; i < cfg->delegation.target_count; i++) {
        const char *v = cfg->delegation.targets[i].bearer_token;
        if (v && strncmp(v, "vault://", 8) == 0)
            return 1;
    }
    /* Check MCP server env values */
    for (int s = 0; s < cfg->mcp.server_count; s++) {
        for (int e = 0; e < cfg->mcp.servers[s].env_count; e++) {
            const char *v = cfg->mcp.servers[s].env_values[e];
            if (v && strncmp(v, "vault://", 8) == 0)
                return 1;
        }
    }
    return 0;
}

/* Resolve a single vault:// field */
static void resolve_vault_field(char **field, const sc_vault_t *vault)
{
    if (!field || !*field || !vault) return;
    if (strncmp(*field, "vault://", 8) != 0) return;

    const char *key = *field + 8;
    const char *value = sc_vault_get(vault, key);
    if (value) {
        free(*field);
        *field = sc_strdup(value);
    } else {
        SC_LOG_WARN(LOG_TAG, "vault key '%s' not found", key);
    }
}

/* Resolve vault:// references in all secret fields */
static void resolve_vault_refs(sc_config_t *cfg)
{
    if (!has_vault_refs(cfg)) return;

    /* Get vault password from env or prompt */
    char *vault_path = sc_vault_get_path();
    if (!sc_vault_exists(vault_path)) {
        SC_LOG_WARN(LOG_TAG, "config has vault:// references but vault "
                    "does not exist at %s", vault_path);
        free(vault_path);
        return;
    }

    sc_vault_t *vault = sc_vault_new(vault_path);
    free(vault_path);
    if (!vault) return;

    /* Try env var first, then interactive prompt */
    const char *env_pw = getenv("SMOLCLAW_VAULT_PASSWORD");
    char *prompted_pw = NULL;
    const char *password = env_pw;

    if (!password || password[0] == '\0') {
        prompted_pw = sc_vault_prompt_password("Vault password: ");
        password = prompted_pw;
    }

    if (!password || password[0] == '\0') {
        SC_LOG_WARN(LOG_TAG, "no vault password provided");
        sc_vault_free(vault);
        sc_vault_free_password(prompted_pw);
        return;
    }

    if (sc_vault_unlock(vault, password) != 0) {
        SC_LOG_ERROR(LOG_TAG, "vault unlock failed (wrong password?)");
        sc_vault_free(vault);
        sc_vault_free_password(prompted_pw);
        return;
    }

    sc_vault_free_password(prompted_pw);

    SC_LOG_INFO(LOG_TAG, "vault unlocked successfully");
    sc_audit_log_ext("vault", "unlocked", 0, 0, NULL, NULL, "vault_unlock");

    /* Resolve all vault:// fields */
    resolve_vault_field(&cfg->anthropic.api_key, vault);
    resolve_vault_field(&cfg->openai.api_key, vault);
    resolve_vault_field(&cfg->openrouter.api_key, vault);
    resolve_vault_field(&cfg->groq.api_key, vault);
    resolve_vault_field(&cfg->zhipu.api_key, vault);
    resolve_vault_field(&cfg->vllm.api_key, vault);
    resolve_vault_field(&cfg->gemini.api_key, vault);
    resolve_vault_field(&cfg->deepseek.api_key, vault);
    resolve_vault_field(&cfg->ollama.api_key, vault);
    resolve_vault_field(&cfg->xai.api_key, vault);
    resolve_vault_field(&cfg->telegram.token, vault);
    resolve_vault_field(&cfg->discord.token, vault);
    resolve_vault_field(&cfg->irc.password, vault);
    resolve_vault_field(&cfg->slack.bot_token, vault);
    resolve_vault_field(&cfg->slack.app_token, vault);
    resolve_vault_field(&cfg->web.bearer_token, vault);
    resolve_vault_field(&cfg->x.consumer_key, vault);
    resolve_vault_field(&cfg->x.consumer_secret, vault);
    resolve_vault_field(&cfg->x.access_token, vault);
    resolve_vault_field(&cfg->x.access_token_secret, vault);
    resolve_vault_field(&cfg->web_tools.brave_api_key, vault);
    resolve_vault_field(&cfg->gitea.token, vault);

    /* Resolve vault:// references in delegation targets */
    for (int i = 0; i < cfg->delegation.target_count; i++)
        resolve_vault_field(&cfg->delegation.targets[i].bearer_token, vault);

    /* Resolve vault:// references in MCP server env values */
    for (int s = 0; s < cfg->mcp.server_count; s++) {
        for (int e = 0; e < cfg->mcp.servers[s].env_count; e++)
            resolve_vault_field(&cfg->mcp.servers[s].env_values[e], vault);
    }

    sc_vault_free(vault);
}

int sc_config_collect_vault_keys(const sc_config_t *cfg, char ***keys)
{
    if (!cfg || !cfg->raw || !keys) return 0;

    *keys = NULL;
    int count = 0, cap = 0;

    /* Walk JSON tree iteratively, collect vault:// string values */
    const cJSON *stack[64];
    int sp = 0;
    stack[sp++] = cfg->raw->child;

    while (sp > 0) {
        const cJSON *item = stack[--sp];
        while (item) {
            if (cJSON_IsString(item) && item->valuestring &&
                strncmp(item->valuestring, "vault://", 8) == 0) {
                const char *key_name = item->valuestring + 8;
                int dup = 0;
                for (int i = 0; i < count; i++) {
                    if (strcmp((*keys)[i], key_name) == 0) { dup = 1; break; }
                }
                if (!dup) {
                    if (count >= cap) {
                        cap = cap ? cap * 2 : 8;
                        char **tmp = realloc(*keys, (size_t)cap * sizeof(char *));
                        if (!tmp) return count;
                        *keys = tmp;
                    }
                    (*keys)[count++] = sc_strdup(key_name);
                }
            }
            if (item->child && sp < 64)
                stack[sp++] = item->child;
            item = item->next;
        }
    }

    return count;
}
#endif /* SC_ENABLE_VAULT */

/*
 * Parse a comma-separated env var into a string list.
 * Frees any existing list, allocates new one. Returns new count.
 */
static int env_parse_csv(const char *env_name, char ***list, int *count)
{
    const char *val = getenv(env_name);
    if (!val || val[0] == '\0') return 0;

    /* Free existing */
    for (int i = 0; i < *count; i++)
        free((*list)[i]);
    free(*list);
    *list = NULL;
    *count = 0;

    /* Count separators to size array */
    int n = 1;
    for (const char *p = val; *p; p++)
        if (*p == ',') n++;

    *list = calloc((size_t)n, sizeof(char *));
    if (!*list) return 0;

    char *tmp = sc_strdup(val);
    char *saveptr = NULL;
    char *tok = strtok_r(tmp, ",", &saveptr);
    while (tok) {
        while (*tok == ' ') tok++;
        char *end = tok + strlen(tok) - 1;
        while (end > tok && *end == ' ') *end-- = '\0';
        if (*tok)
            (*list)[(*count)++] = sc_strdup(tok);
        tok = strtok_r(NULL, ",", &saveptr);
    }
    free(tmp);
    return *count;
}

/* Apply env overrides for agent defaults */
static void env_override_agent_defaults(sc_config_t *cfg)
{
    env_override_str(&cfg->workspace,  "SMOLCLAW_AGENTS_DEFAULTS_WORKSPACE");
    env_override_str(&cfg->provider,   "SMOLCLAW_AGENTS_DEFAULTS_PROVIDER");
    env_override_str(&cfg->model,      "SMOLCLAW_AGENTS_DEFAULTS_MODEL");
    env_override_int(&cfg->max_tokens, "SMOLCLAW_AGENTS_DEFAULTS_MAX_TOKENS");
    env_override_int(&cfg->context_window, "SMOLCLAW_AGENTS_DEFAULTS_CONTEXT_WINDOW");
    env_override_double(&cfg->temperature, "SMOLCLAW_AGENTS_DEFAULTS_TEMPERATURE");
    env_override_int(&cfg->max_tool_iterations, "SMOLCLAW_AGENTS_DEFAULTS_MAX_TOOL_ITERATIONS");
    env_override_bool(&cfg->restrict_to_workspace, "SMOLCLAW_AGENTS_DEFAULTS_RESTRICT_TO_WORKSPACE");
    env_override_int(&cfg->session_summary_threshold, "SMOLCLAW_AGENTS_DEFAULTS_SESSION_SUMMARY_THRESHOLD");
    env_override_int(&cfg->session_keep_last, "SMOLCLAW_AGENTS_DEFAULTS_SESSION_KEEP_LAST");
    env_override_bool(&cfg->compress_tool_results, "SMOLCLAW_AGENTS_DEFAULTS_COMPRESS_TOOL_RESULTS");
    env_override_int(&cfg->compress_keep_recent, "SMOLCLAW_AGENTS_DEFAULTS_COMPRESS_KEEP_RECENT");
    env_override_int(&cfg->compress_min_bytes, "SMOLCLAW_AGENTS_DEFAULTS_COMPRESS_MIN_BYTES");
    env_override_int(&cfg->context_warn_pct, "SMOLCLAW_AGENTS_DEFAULTS_CONTEXT_WARN_PCT");
    env_override_int(&cfg->compact_cooldown_secs, "SMOLCLAW_AGENTS_DEFAULTS_COMPACT_COOLDOWN_SECS");
    env_override_int(&cfg->max_output_chars, "SMOLCLAW_AGENTS_DEFAULTS_MAX_OUTPUT_CHARS");
    env_override_int(&cfg->max_tool_result_chars, "SMOLCLAW_AGENTS_DEFAULTS_MAX_TOOL_RESULT_CHARS");
    env_override_int(&cfg->tool_result_preview_chars, "SMOLCLAW_AGENTS_DEFAULTS_TOOL_RESULT_PREVIEW_CHARS");
    const char *tool_sel_env = getenv("SMOLCLAW_AGENTS_DEFAULTS_TOOL_SELECTION");
    if (tool_sel_env)
        cfg->tool_selection = (strcmp(tool_sel_env, "auto") == 0) ? 1 : 0;
    env_override_bool(&cfg->warmup, "SMOLCLAW_AGENTS_DEFAULTS_WARMUP");
    env_override_int(&cfg->max_fetch_chars, "SMOLCLAW_AGENTS_DEFAULTS_MAX_FETCH_CHARS");
    env_override_int(&cfg->max_background_procs, "SMOLCLAW_AGENTS_DEFAULTS_MAX_BACKGROUND_PROCS");
    env_override_int(&cfg->summary_max_transcript, "SMOLCLAW_AGENTS_DEFAULTS_SUMMARY_MAX_TRANSCRIPT");
    env_override_int(&cfg->exec_timeout_secs, "SMOLCLAW_AGENTS_DEFAULTS_EXEC_TIMEOUT_SECS");
    env_override_int(&cfg->max_tool_calls_per_turn, "SMOLCLAW_AGENTS_DEFAULTS_MAX_TOOL_CALLS_PER_TURN");
    env_override_int(&cfg->max_turn_secs, "SMOLCLAW_AGENTS_DEFAULTS_MAX_TURN_SECS");
    env_override_int(&cfg->max_output_total, "SMOLCLAW_AGENTS_DEFAULTS_MAX_OUTPUT_TOTAL");
    env_override_int(&cfg->max_tool_calls_per_hour, "SMOLCLAW_AGENTS_DEFAULTS_MAX_TOOL_CALLS_PER_HOUR");
    env_override_int(&cfg->max_tokens_per_hour, "SMOLCLAW_AGENTS_DEFAULTS_MAX_TOKENS_PER_HOUR");
    env_override_int(&cfg->rate_limit_per_minute, "SMOLCLAW_AGENTS_DEFAULTS_RATE_LIMIT_PER_MINUTE");
    env_override_bool(&cfg->restrict_message_tool, "SMOLCLAW_AGENTS_DEFAULTS_RESTRICT_MESSAGE_TOOL");
    env_override_bool(&cfg->sandbox_enabled, "SMOLCLAW_AGENTS_DEFAULTS_SANDBOX");
    env_override_bool(&cfg->memory_consolidation, "SMOLCLAW_AGENTS_DEFAULTS_MEMORY_CONSOLIDATION");
    env_override_bool(&cfg->memory_background_review, "SMOLCLAW_AGENTS_DEFAULTS_MEMORY_BACKGROUND_REVIEW");
    env_override_str(&cfg->memory_review_model, "SMOLCLAW_AGENTS_DEFAULTS_MEMORY_REVIEW_MODEL");
    env_override_bool(&cfg->memory_write_approval, "SMOLCLAW_AGENTS_DEFAULTS_MEMORY_WRITE_APPROVAL");
    env_override_bool(&cfg->announce_on_join, "SMOLCLAW_ANNOUNCE_ON_JOIN");
    env_override_bool(&cfg->verbose, "SMOLCLAW_AGENTS_DEFAULTS_VERBOSE");
    env_override_bool(&cfg->auto_confirm, "SMOLCLAW_AGENTS_DEFAULTS_AUTO_CONFIRM");
    env_override_bool(&cfg->tee_enabled, "SMOLCLAW_AGENTS_DEFAULTS_TEE_ENABLED");
    env_override_int(&cfg->tee_max_files, "SMOLCLAW_AGENTS_DEFAULTS_TEE_MAX_FILES");
    env_override_int(&cfg->tee_max_file_size, "SMOLCLAW_AGENTS_DEFAULTS_TEE_MAX_FILE_SIZE");
    env_override_str(&cfg->log_path, "SMOLCLAW_LOG_PATH");

    const char *exec_mode_env = getenv("SMOLCLAW_AGENTS_DEFAULTS_EXEC_MODE");
    if (exec_mode_env)
        cfg->exec_use_allowlist = (strcmp(exec_mode_env, "allowlist") == 0);

    const char *scope_env = getenv("SMOLCLAW_AGENTS_DEFAULTS_NETWORK_SCOPE");
    if (scope_env) {
        if (strcmp(scope_env, "none") == 0)        cfg->network_scope = 0;
        else if (strcmp(scope_env, "local") == 0)   cfg->network_scope = 1;
        else if (strcmp(scope_env, "public") == 0)  cfg->network_scope = 2;
        else if (strcmp(scope_env, "any") == 0)     cfg->network_scope = 3;
    }

    env_parse_csv("SMOLCLAW_AGENTS_DEFAULTS_EXEC_ALLOWED_COMMANDS",
                  &cfg->exec_allowed_commands, &cfg->exec_allowed_command_count);
    env_parse_csv("SMOLCLAW_AGENTS_DEFAULTS_ALLOWED_TOOLS",
                  &cfg->allowed_tools, &cfg->allowed_tool_count);
    env_parse_csv("SMOLCLAW_AGENTS_DEFAULTS_FALLBACK_MODELS",
                  &cfg->fallback_models, &cfg->fallback_model_count);

    /* Model aliases (semicolon-separated key=value pairs) */
    const char *alias_env = getenv("SMOLCLAW_AGENTS_DEFAULTS_MODEL_ALIASES");
    if (alias_env && alias_env[0] != '\0') {
        for (int i = 0; i < cfg->model_alias_count; i++) {
            free(cfg->model_alias_names[i]);
            free(cfg->model_alias_models[i]);
        }
        free(cfg->model_alias_names);
        free(cfg->model_alias_models);
        cfg->model_alias_names = NULL;
        cfg->model_alias_models = NULL;
        cfg->model_alias_count = 0;

        int count = 1;
        for (const char *p = alias_env; *p; p++)
            if (*p == ';') count++;

        cfg->model_alias_names  = calloc((size_t)count, sizeof(char *));
        cfg->model_alias_models = calloc((size_t)count, sizeof(char *));
        if (cfg->model_alias_names && cfg->model_alias_models) {
            char *tmp = sc_strdup(alias_env);
            char *saveptr = NULL;
            char *tok = strtok_r(tmp, ";", &saveptr);
            while (tok) {
                while (*tok == ' ') tok++;
                char *eq = strchr(tok, '=');
                if (eq && eq != tok) {
                    *eq = '\0';
                    char *val = eq + 1;
                    char *kend = eq - 1;
                    while (kend > tok && *kend == ' ') *kend-- = '\0';
                    while (*val == ' ') val++;
                    char *vend = val + strlen(val) - 1;
                    while (vend > val && *vend == ' ') *vend-- = '\0';
                    if (*tok && *val) {
                        cfg->model_alias_names[cfg->model_alias_count] = sc_strdup(tok);
                        cfg->model_alias_models[cfg->model_alias_count] = sc_strdup(val);
                        cfg->model_alias_count++;
                    }
                }
                tok = strtok_r(NULL, ";", &saveptr);
            }
            free(tmp);
        }
    }
}

/* Apply env overrides for channels */
static void env_override_channels(sc_config_t *cfg)
{
    env_override_bool(&cfg->telegram.enabled,    "SMOLCLAW_CHANNELS_TELEGRAM_ENABLED");
    env_override_str(&cfg->telegram.token,       "SMOLCLAW_CHANNELS_TELEGRAM_TOKEN");
    env_override_str(&cfg->telegram.api_base,    "SMOLCLAW_CHANNELS_TELEGRAM_API_BASE");
    env_override_str(&cfg->telegram.proxy,       "SMOLCLAW_CHANNELS_TELEGRAM_PROXY");
    env_override_str(&cfg->telegram.dm_policy,   "SMOLCLAW_CHANNELS_TELEGRAM_DM_POLICY");

    env_override_bool(&cfg->discord.enabled,     "SMOLCLAW_CHANNELS_DISCORD_ENABLED");
    env_override_str(&cfg->discord.token,        "SMOLCLAW_CHANNELS_DISCORD_TOKEN");
    env_override_str(&cfg->discord.api_base,     "SMOLCLAW_CHANNELS_DISCORD_API_BASE");
    env_override_str(&cfg->discord.dm_policy,    "SMOLCLAW_CHANNELS_DISCORD_DM_POLICY");

    env_override_bool(&cfg->irc.enabled,         "SMOLCLAW_CHANNELS_IRC_ENABLED");
    env_override_str(&cfg->irc.hostname,         "SMOLCLAW_CHANNELS_IRC_HOSTNAME");
    env_override_int(&cfg->irc.port,             "SMOLCLAW_CHANNELS_IRC_PORT");
    env_override_str(&cfg->irc.nick,             "SMOLCLAW_CHANNELS_IRC_NICK");
    env_override_str(&cfg->irc.password,         "SMOLCLAW_CHANNELS_IRC_PASSWORD");
    env_override_bool(&cfg->irc.use_tls,         "SMOLCLAW_CHANNELS_IRC_TLS");
    env_override_str(&cfg->irc.group_trigger,    "SMOLCLAW_CHANNELS_IRC_GROUP_TRIGGER");
    env_override_str(&cfg->irc.dm_policy,        "SMOLCLAW_CHANNELS_IRC_DM_POLICY");

    env_override_bool(&cfg->slack.enabled,       "SMOLCLAW_CHANNELS_SLACK_ENABLED");
    env_override_str(&cfg->slack.bot_token,      "SMOLCLAW_CHANNELS_SLACK_BOT_TOKEN");
    env_override_str(&cfg->slack.app_token,      "SMOLCLAW_CHANNELS_SLACK_APP_TOKEN");
    env_override_str(&cfg->slack.dm_policy,      "SMOLCLAW_CHANNELS_SLACK_DM_POLICY");

    env_override_bool(&cfg->web.enabled,         "SMOLCLAW_CHANNELS_WEB_ENABLED");
    env_override_str(&cfg->web.bind_addr,        "SMOLCLAW_CHANNELS_WEB_BIND_ADDR");
    env_override_int(&cfg->web.port,             "SMOLCLAW_CHANNELS_WEB_PORT");
    env_override_bool(&cfg->web.auto_port,       "SMOLCLAW_CHANNELS_WEB_AUTO_PORT");
    env_override_str(&cfg->web.bearer_token,     "SMOLCLAW_CHANNELS_WEB_BEARER_TOKEN");
    env_override_str(&cfg->web.tls_cert,         "SMOLCLAW_WEB_TLS_CERT");
    env_override_str(&cfg->web.tls_key,          "SMOLCLAW_WEB_TLS_KEY");
    env_override_str(&cfg->web.dm_policy,        "SMOLCLAW_CHANNELS_WEB_DM_POLICY");
    env_override_str(&cfg->web.isolation_pattern, "SMOLCLAW_CHANNELS_WEB_ISOLATION_PATTERN");

    env_override_bool(&cfg->x.enabled,            "SMOLCLAW_CHANNELS_X_ENABLED");
    env_override_str(&cfg->x.consumer_key,        "SMOLCLAW_CHANNELS_X_CONSUMER_KEY");
    env_override_str(&cfg->x.consumer_secret,     "SMOLCLAW_CHANNELS_X_CONSUMER_SECRET");
    env_override_str(&cfg->x.access_token,        "SMOLCLAW_CHANNELS_X_ACCESS_TOKEN");
    env_override_str(&cfg->x.access_token_secret, "SMOLCLAW_CHANNELS_X_ACCESS_TOKEN_SECRET");
    env_override_int(&cfg->x.poll_interval_sec,   "SMOLCLAW_CHANNELS_X_POLL_INTERVAL");
    env_override_bool(&cfg->x.enable_dms,         "SMOLCLAW_CHANNELS_X_ENABLE_DMS");
    env_override_bool(&cfg->x.read_only,         "SMOLCLAW_CHANNELS_X_READ_ONLY");
    env_override_str(&cfg->x.dm_policy,           "SMOLCLAW_CHANNELS_X_DM_POLICY");
    env_override_bool(&cfg->signal_.enabled,      "SMOLCLAW_CHANNELS_SIGNAL_ENABLED");
    env_override_str(&cfg->signal_.account,       "SMOLCLAW_CHANNELS_SIGNAL_ACCOUNT");
    env_override_str(&cfg->signal_.http_host,     "SMOLCLAW_CHANNELS_SIGNAL_HTTP_HOST");
    env_override_int(&cfg->signal_.http_port,     "SMOLCLAW_CHANNELS_SIGNAL_HTTP_PORT");
    env_override_str(&cfg->signal_.http_url,      "SMOLCLAW_CHANNELS_SIGNAL_HTTP_URL");
    env_override_str(&cfg->signal_.proxy,         "SMOLCLAW_CHANNELS_SIGNAL_PROXY");
    env_override_str(&cfg->signal_.group_trigger, "SMOLCLAW_CHANNELS_SIGNAL_GROUP_TRIGGER");
    env_override_str(&cfg->signal_.dm_policy,     "SMOLCLAW_CHANNELS_SIGNAL_DM_POLICY");
}

/* Apply env overrides for providers */
static void env_override_providers(sc_config_t *cfg)
{
    env_override_str(&cfg->anthropic.api_key,   "SMOLCLAW_PROVIDERS_ANTHROPIC_API_KEY");
    env_override_str(&cfg->anthropic.api_base,  "SMOLCLAW_PROVIDERS_ANTHROPIC_API_BASE");
    env_override_str(&cfg->openai.api_key,      "SMOLCLAW_PROVIDERS_OPENAI_API_KEY");
    env_override_str(&cfg->openai.api_base,     "SMOLCLAW_PROVIDERS_OPENAI_API_BASE");
    env_override_str(&cfg->openrouter.api_key,  "SMOLCLAW_PROVIDERS_OPENROUTER_API_KEY");
    env_override_str(&cfg->openrouter.api_base, "SMOLCLAW_PROVIDERS_OPENROUTER_API_BASE");
    env_override_str(&cfg->groq.api_key,        "SMOLCLAW_PROVIDERS_GROQ_API_KEY");
    env_override_str(&cfg->groq.api_base,       "SMOLCLAW_PROVIDERS_GROQ_API_BASE");
    env_override_str(&cfg->zhipu.api_key,       "SMOLCLAW_PROVIDERS_ZHIPU_API_KEY");
    env_override_str(&cfg->zhipu.api_base,      "SMOLCLAW_PROVIDERS_ZHIPU_API_BASE");
    env_override_str(&cfg->vllm.api_key,        "SMOLCLAW_PROVIDERS_VLLM_API_KEY");
    env_override_str(&cfg->vllm.api_base,       "SMOLCLAW_PROVIDERS_VLLM_API_BASE");
    env_override_str(&cfg->gemini.api_key,      "SMOLCLAW_PROVIDERS_GEMINI_API_KEY");
    env_override_str(&cfg->gemini.api_base,     "SMOLCLAW_PROVIDERS_GEMINI_API_BASE");
    env_override_str(&cfg->deepseek.api_key,    "SMOLCLAW_PROVIDERS_DEEPSEEK_API_KEY");
    env_override_str(&cfg->deepseek.api_base,   "SMOLCLAW_PROVIDERS_DEEPSEEK_API_BASE");
    env_override_str(&cfg->ollama.api_key,      "SMOLCLAW_PROVIDERS_OLLAMA_API_KEY");
    env_override_str(&cfg->ollama.api_base,     "SMOLCLAW_PROVIDERS_OLLAMA_API_BASE");
    env_override_str(&cfg->xai.api_key,         "SMOLCLAW_PROVIDERS_XAI_API_KEY");
    env_override_str(&cfg->xai.api_base,        "SMOLCLAW_PROVIDERS_XAI_API_BASE");
}

/* Apply env overrides for gitea */
static void env_override_gitea(sc_config_t *cfg)
{
    env_override_str(&cfg->gitea.url,         "SMOLCLAW_GITEA_URL");
    env_override_str(&cfg->gitea.token,       "SMOLCLAW_GITEA_TOKEN");
    env_override_str(&cfg->gitea.default_org, "SMOLCLAW_GITEA_DEFAULT_ORG");
}

/* Apply env overrides for web tools */
static void env_override_web_tools(sc_config_t *cfg)
{
    env_override_bool(&cfg->web_tools.brave_enabled,   "SMOLCLAW_TOOLS_WEB_BRAVE_ENABLED");
    env_override_str(&cfg->web_tools.brave_api_key,    "SMOLCLAW_TOOLS_WEB_BRAVE_API_KEY");
    env_override_str(&cfg->web_tools.brave_base_url,   "SMOLCLAW_TOOLS_WEB_BRAVE_BASE_URL");
    env_override_int(&cfg->web_tools.brave_max_results, "SMOLCLAW_TOOLS_WEB_BRAVE_MAX_RESULTS");
    env_override_bool(&cfg->web_tools.searxng_enabled,      "SMOLCLAW_TOOLS_WEB_SEARXNG_ENABLED");
    env_override_str(&cfg->web_tools.searxng_base_url,     "SMOLCLAW_TOOLS_WEB_SEARXNG_BASE_URL");
    env_override_int(&cfg->web_tools.searxng_max_results,  "SMOLCLAW_TOOLS_WEB_SEARXNG_MAX_RESULTS");
    env_override_bool(&cfg->web_tools.duckduckgo_enabled, "SMOLCLAW_TOOLS_WEB_DUCKDUCKGO_ENABLED");
    env_override_int(&cfg->web_tools.duckduckgo_max_results, "SMOLCLAW_TOOLS_WEB_DUCKDUCKGO_MAX_RESULTS");
}

/* Apply all env var overrides */
static void apply_env_overrides(sc_config_t *cfg)
{
    env_override_agent_defaults(cfg);
    env_override_providers(cfg);
    env_override_channels(cfg);
    env_override_web_tools(cfg);
    env_override_gitea(cfg);

    /* Heartbeat */
    env_override_bool(&cfg->heartbeat.enabled,   "SMOLCLAW_HEARTBEAT_ENABLED");
    env_override_int(&cfg->heartbeat.interval,   "SMOLCLAW_HEARTBEAT_INTERVAL");

    /* MCP */
    env_override_bool(&cfg->mcp.enabled,         "SMOLCLAW_MCP_ENABLED");

    /* Updater */
    env_override_bool(&cfg->updater.enabled,             "SMOLCLAW_UPDATER_ENABLED");
    env_override_str(&cfg->updater.manifest_url,         "SMOLCLAW_UPDATER_MANIFEST_URL");
    env_override_int(&cfg->updater.check_interval_hours, "SMOLCLAW_UPDATER_CHECK_INTERVAL");
    env_override_bool(&cfg->updater.auto_apply,          "SMOLCLAW_UPDATER_AUTO_APPLY");

    /* Notifications */
    env_override_str(&cfg->notify_urls,                  "SMOLCLAW_NOTIFY_URLS");
}

sc_config_t *sc_config_default(void)
{
    sc_config_t *cfg = calloc(1, sizeof(*cfg));
    if (!cfg) return NULL;

    /* Agent defaults — use SMOLCLAW_HOME/workspace if set, else default */
    const char *home_override = getenv("SMOLCLAW_HOME");
    if (home_override && home_override[0]) {
        char ws[PATH_MAX];
        snprintf(ws, sizeof(ws), "%s/workspace", home_override);
        cfg->workspace = sc_strdup(ws);
    } else {
        cfg->workspace = sc_strdup(SC_DEFAULT_WORKSPACE);
    }
    cfg->restrict_to_workspace = 1;
    cfg->provider             = sc_strdup("");
    cfg->model                = sc_strdup(SC_DEFAULT_MODEL);
    cfg->max_tokens           = SC_DEFAULT_MAX_TOKENS;
    cfg->context_window       = SC_DEFAULT_CONTEXT_WINDOW;
    cfg->temperature          = SC_DEFAULT_TEMPERATURE;
    cfg->max_tool_iterations  = SC_DEFAULT_MAX_ITERATIONS;
    cfg->session_summary_threshold = SC_SESSION_SUMMARY_THRESHOLD;
    cfg->session_keep_last    = SC_SESSION_KEEP_LAST;
    cfg->compress_tool_results = 1;
    cfg->compress_keep_recent = SC_COMPRESS_KEEP_RECENT;
    cfg->compress_min_bytes   = SC_COMPRESS_MIN_BYTES;
    cfg->context_warn_pct     = 80;
    cfg->compact_cooldown_secs = 300;
    cfg->max_output_chars     = SC_MAX_OUTPUT_CHARS;
    cfg->max_tool_result_chars = SC_DEFAULT_MAX_TOOL_RESULT_CHARS;
    cfg->tool_result_preview_chars = SC_DEFAULT_TOOL_RESULT_PREVIEW_CHARS;
    cfg->tool_selection = 0;  /* fixed (send all tools) */
    cfg->warmup = 0;
    cfg->warmup_providers = calloc(2, sizeof(char *));
    if (cfg->warmup_providers) {
        cfg->warmup_providers[0] = sc_strdup("ollama");
        cfg->warmup_providers[1] = sc_strdup("vllm");
        cfg->warmup_provider_count = 2;
    }
    cfg->max_fetch_chars      = SC_MAX_FETCH_CHARS;
    cfg->max_background_procs = SC_BG_MAX_PROCS;
    cfg->summary_max_transcript = SC_SUMMARY_MAX_TRANSCRIPT;
    cfg->exec_timeout_secs    = SC_DEFAULT_EXEC_TIMEOUT;
    cfg->max_tool_calls_per_turn = SC_DEFAULT_MAX_TOOL_CALLS_PER_TURN;
    cfg->max_turn_secs        = SC_DEFAULT_MAX_TURN_SECS;
    cfg->max_output_total     = SC_DEFAULT_MAX_OUTPUT_TOTAL;
    cfg->max_tool_calls_per_hour = SC_DEFAULT_MAX_TOOL_CALLS_PER_HOUR;
    cfg->max_tokens_per_hour = SC_DEFAULT_MAX_TOKENS_PER_HOUR;
    cfg->rate_limit_per_minute = SC_DEFAULT_RATE_LIMIT_PER_MINUTE;
    cfg->network_scope        = 2; /* SC_NET_SCOPE_PUBLIC */
    cfg->silent_tokens_enabled = 1; /* task 3.9: suppress [SILENT]/NO_REPLY */
    cfg->sandbox_enabled      = 1;
    cfg->memory_consolidation = 1;
    cfg->memory_background_review = 0;
    cfg->memory_notifications = 0;
    cfg->memory_write_approval = 0;
    cfg->tee_enabled          = 1;
    cfg->tee_max_files        = 50;
    cfg->tee_max_file_size    = 10 * 1024 * 1024;

    /* Providers: anthropic default base */
    cfg->anthropic.api_base = sc_strdup("https://api.anthropic.com/v1");
    cfg->openai.api_base    = sc_strdup("https://api.openai.com/v1");
    cfg->openrouter.api_base = sc_strdup("https://openrouter.ai/api/v1");
    cfg->ollama.api_base    = sc_strdup("http://localhost:11434/v1");
    cfg->xai.api_base       = sc_strdup("https://api.x.ai/v1");

    /* Channel DM policy: strict mode defaults to allowlist (deny unknown),
     * non-strict defaults to open (backward compatible). */
#if SC_STRICT_SECURITY
    const char *default_dm = "allowlist";
    cfg->exec_use_allowlist = 1;
#else
    const char *default_dm = "open";
#endif

    /* Telegram: disabled by default */
    cfg->telegram.enabled = 0;
    cfg->telegram.dm_policy = sc_strdup(default_dm);

    /* Discord: disabled by default */
    cfg->discord.enabled = 0;
    cfg->discord.dm_policy = sc_strdup(default_dm);

    /* IRC: disabled by default */
    cfg->irc.enabled = 0;
    cfg->irc.port = 6667;
    cfg->irc.dm_policy = sc_strdup(default_dm);

    /* Slack: disabled by default */
    cfg->slack.enabled = 0;
    cfg->slack.dm_policy = sc_strdup(default_dm);

    /* X: disabled by default, read-only by default */
    cfg->x.enabled = 0;
    cfg->x.poll_interval_sec = 60;
    cfg->x.read_only = 1;
    cfg->x.dm_policy = sc_strdup(default_dm);

    /* Signal: disabled by default; native signal-cli daemon defaults */
    cfg->signal_.enabled = 0;
    cfg->signal_.http_host = sc_strdup("127.0.0.1");
    cfg->signal_.http_port = 7583;
    cfg->signal_.dm_policy = sc_strdup(default_dm);

    /* Web: disabled by default */
    cfg->web.enabled = 0;
    cfg->web.bind_addr = sc_strdup("127.0.0.1");
    cfg->web.port = SC_DEFAULT_WEB_PORT;
    cfg->web.dm_policy = sc_strdup(default_dm);
    /* Session isolation: opt-in to the common delegate convention by default.
     * Set to "" or NULL in config to disable. */
    cfg->web.isolation_pattern = sc_strdup("wf-*");

    /* Web tools */
    cfg->web_tools.brave_enabled      = 0;
    cfg->web_tools.brave_max_results  = SC_MAX_SEARCH_RESULTS;
    cfg->web_tools.searxng_enabled    = 0;
    cfg->web_tools.searxng_max_results = SC_MAX_SEARCH_RESULTS;
    cfg->web_tools.duckduckgo_enabled = 1;
    cfg->web_tools.duckduckgo_max_results = SC_MAX_SEARCH_RESULTS;

    /* Heartbeat */
    cfg->heartbeat.enabled  = 1;
    cfg->heartbeat.interval = SC_DEFAULT_HEARTBEAT_INTERVAL;

    /* MCP */
    cfg->mcp.enabled = 1;

    /* Updater */
    cfg->updater.enabled = 0;  /* off by default — no manifest URL */
    cfg->updater.check_interval_hours = SC_DEFAULT_UPDATE_CHECK_HOURS;
    cfg->updater.auto_apply = 0;

    return cfg;
}

/* Load agents.defaults section from JSON */
static void load_agent_defaults(sc_config_t *cfg, const cJSON *root)
{
    const cJSON *agents   = sc_json_get_object(root, "agents");
    const cJSON *defaults = agents ? sc_json_get_object(agents, "defaults") : NULL;
    if (!defaults) return;

    override_str_field(&cfg->workspace, defaults, "workspace");
    override_str_field(&cfg->provider, defaults, "provider");
    override_str_field(&cfg->model, defaults, "model");
    override_str_field(&cfg->summary_model, defaults, "summary_model");

    cfg->fallback_models = sc_json_parse_string_list(
        sc_json_get_array(defaults, "fallback_models"),
        &cfg->fallback_model_count);

    const cJSON *aliases = sc_json_get_object(defaults, "model_aliases");
    if (aliases) {
        int n = cJSON_GetArraySize(aliases);
        if (n > 0) {
            cfg->model_alias_names  = calloc((size_t)n, sizeof(char *));
            cfg->model_alias_models = calloc((size_t)n, sizeof(char *));
            if (cfg->model_alias_names && cfg->model_alias_models) {
                const cJSON *item;
                cJSON_ArrayForEach(item, aliases) {
                    if (cJSON_IsString(item) && item->string && item->valuestring) {
                        cfg->model_alias_names[cfg->model_alias_count] =
                            sc_strdup(item->string);
                        cfg->model_alias_models[cfg->model_alias_count] =
                            sc_strdup(item->valuestring);
                        cfg->model_alias_count++;
                    }
                }
            }
        }
    }

    cfg->restrict_to_workspace = sc_json_get_bool(defaults, "restrict_to_workspace",
                                                   cfg->restrict_to_workspace);
    cfg->workspace_per_session = sc_json_get_bool(defaults, "workspace_per_session", 0);
    cfg->max_tokens          = sc_json_get_int(defaults, "max_tokens", cfg->max_tokens);
    cfg->context_window      = sc_json_get_int(defaults, "context_window", cfg->context_window);
    cfg->temperature         = sc_json_get_double(defaults, "temperature", cfg->temperature);
    {
        cJSON *rf = cJSON_GetObjectItem(defaults, "response_format");
        if (rf && cJSON_IsObject(rf)) {
            cJSON_Delete(cfg->response_format);
            cfg->response_format = cJSON_Duplicate(rf, 1);
        }
    }
    cfg->max_tool_iterations = sc_json_get_int(defaults, "max_tool_iterations",
                                                cfg->max_tool_iterations);
    cfg->session_summary_threshold = sc_json_get_int(defaults,
        "session_summary_threshold", cfg->session_summary_threshold);
    cfg->session_keep_last = sc_json_get_int(defaults,
        "session_keep_last", cfg->session_keep_last);
    cfg->compress_tool_results = sc_json_get_bool(defaults,
        "compress_tool_results", cfg->compress_tool_results);
    cfg->compress_keep_recent = sc_json_get_int(defaults,
        "compress_keep_recent", cfg->compress_keep_recent);
    cfg->compress_min_bytes = sc_json_get_int(defaults,
        "compress_min_bytes", cfg->compress_min_bytes);
    cfg->context_warn_pct = sc_json_get_int(defaults,
        "context_warn_pct", cfg->context_warn_pct);
    cfg->compact_cooldown_secs = sc_json_get_int(defaults,
        "compact_cooldown_secs", cfg->compact_cooldown_secs);
    cfg->max_output_chars = sc_json_get_int(defaults,
        "max_output_chars", cfg->max_output_chars);
    cfg->max_tool_result_chars = sc_json_get_int(defaults,
        "max_tool_result_chars", cfg->max_tool_result_chars);
    cfg->tool_result_preview_chars = sc_json_get_int(defaults,
        "tool_result_preview_chars", cfg->tool_result_preview_chars);
    const char *tool_sel = sc_json_get_string(defaults, "tool_selection", NULL);
    if (tool_sel)
        cfg->tool_selection = (strcmp(tool_sel, "auto") == 0) ? 1 : 0;
    const cJSON *local_opt = sc_json_get_object(defaults, "local_optimizations");
    if (local_opt) {
        cfg->warmup = sc_json_get_bool(local_opt, "warmup", cfg->warmup);
        cJSON *wp = sc_json_get_array(local_opt, "warmup_providers");
        if (wp) {
            for (int i = 0; i < cfg->warmup_provider_count; i++)
                free(cfg->warmup_providers[i]);
            free(cfg->warmup_providers);
            cfg->warmup_providers = sc_json_parse_string_list(wp, &cfg->warmup_provider_count);
        }
    }
    cfg->max_fetch_chars = sc_json_get_int(defaults,
        "max_fetch_chars", cfg->max_fetch_chars);
    cfg->max_background_procs = sc_json_get_int(defaults,
        "max_background_procs", cfg->max_background_procs);
    cfg->summary_max_transcript = sc_json_get_int(defaults,
        "summary_max_transcript", cfg->summary_max_transcript);
    cfg->exec_timeout_secs = sc_json_get_int(defaults,
        "exec_timeout_secs", cfg->exec_timeout_secs);
    cfg->max_tool_calls_per_turn = sc_json_get_int(defaults,
        "max_tool_calls_per_turn", cfg->max_tool_calls_per_turn);
    cfg->max_turn_secs = sc_json_get_int(defaults,
        "max_turn_secs", cfg->max_turn_secs);
    cfg->max_output_total = sc_json_get_int(defaults,
        "max_output_total", cfg->max_output_total);
    cfg->max_tool_calls_per_hour = sc_json_get_int(defaults,
        "max_tool_calls_per_hour", cfg->max_tool_calls_per_hour);
    cfg->max_tokens_per_hour = sc_json_get_int(defaults,
        "max_tokens_per_hour", cfg->max_tokens_per_hour);
    cfg->rate_limit_per_minute = sc_json_get_int(defaults,
        "rate_limit_per_minute", cfg->rate_limit_per_minute);

    cfg->allowed_tools = sc_json_parse_string_list(
        sc_json_get_array(defaults, "allowed_tools"), &cfg->allowed_tool_count);
    cfg->restrict_message_tool = sc_json_get_bool(defaults,
        "restrict_message_tool", cfg->restrict_message_tool);

    const char *exec_mode = sc_json_get_string(defaults, "exec_mode", NULL);
    if (exec_mode && strcmp(exec_mode, "allowlist") == 0)
        cfg->exec_use_allowlist = 1;
    cfg->exec_allowed_commands = sc_json_parse_string_list(
        sc_json_get_array(defaults, "exec_allowed_commands"),
        &cfg->exec_allowed_command_count);

    const char *net_scope = sc_json_get_string(defaults, "network_scope", NULL);
    if (net_scope) {
        if (strcmp(net_scope, "none") == 0)        cfg->network_scope = 0;
        else if (strcmp(net_scope, "local") == 0)   cfg->network_scope = 1;
        else if (strcmp(net_scope, "public") == 0)  cfg->network_scope = 2;
        else if (strcmp(net_scope, "any") == 0)     cfg->network_scope = 3;
    }

    cfg->sandbox_enabled = sc_json_get_bool(defaults, "sandbox",
                                             cfg->sandbox_enabled);
    cfg->memory_consolidation = sc_json_get_bool(defaults, "memory_consolidation",
                                                  cfg->memory_consolidation);
    cfg->memory_background_review = sc_json_get_bool(defaults,
        "memory_background_review", cfg->memory_background_review);
    override_str_field(&cfg->memory_review_model, defaults, "memory_review_model");
    cfg->memory_write_approval = sc_json_get_bool(defaults, "memory_write_approval", cfg->memory_write_approval);
    {
        const char *mn = sc_json_get_string(defaults, "memory_notifications", "off");
        if (strcmp(mn, "verbose") == 0)   cfg->memory_notifications = 2;
        else if (strcmp(mn, "on") == 0)   cfg->memory_notifications = 1;
        else                              cfg->memory_notifications = 0;
    }
    cfg->announce_on_join = sc_json_get_bool(defaults, "announce_on_join",
                                              cfg->announce_on_join);
    cfg->verbose = sc_json_get_bool(defaults, "verbose", cfg->verbose);
    cfg->auto_confirm = sc_json_get_bool(defaults, "auto_confirm",
                                          cfg->auto_confirm);

    /* Operator mode preset (3.2) then explicit approval_policy override (3.3).
     * Default policy is dangerous-only (matches prior per-tool confirm). */
    cfg->approval_policy = 0;
    sc_config_apply_operator_mode(cfg,
        sc_json_get_string(defaults, "operator_mode", NULL));
    cfg->approval_policy = parse_approval_policy(
        sc_json_get_string(defaults, "approval_policy", NULL),
        cfg->approval_policy);

    /* Pricing overrides (borrowed pointer — lives as long as parsed config JSON) */
    {
        cJSON *pricing = cJSON_GetObjectItem((cJSON *)defaults, "pricing");
        if (pricing && cJSON_IsObject(pricing))
            cfg->pricing_overrides = pricing;
    }

    /* Tee config from agents.defaults.tee.{enabled,max_files,max_file_size} */
    const cJSON *tee = sc_json_get_object(defaults, "tee");
    if (tee) {
        cfg->tee_enabled = sc_json_get_bool(tee, "enabled", cfg->tee_enabled);
        cfg->tee_max_files = sc_json_get_int(tee, "max_files", cfg->tee_max_files);
        cfg->tee_max_file_size = sc_json_get_int(tee, "max_file_size",
                                                   cfg->tee_max_file_size);
    }

    override_str_field(&cfg->log_path, defaults, "log_path");
}

/* Load channels section from JSON */
static void load_channels(sc_config_t *cfg, const cJSON *root)
{
    const cJSON *channels = sc_json_get_object(root, "channels");
    if (!channels) return;

    const cJSON *tg = sc_json_get_object(channels, "telegram");
    if (tg) {
        cfg->telegram.enabled = sc_json_get_bool(tg, "enabled", 0);
        free(cfg->telegram.token);
        cfg->telegram.token = sc_strdup(sc_json_get_string(tg, "token", NULL));
        override_str_field(&cfg->telegram.api_base, tg, "api_base");
        free(cfg->telegram.proxy);
        cfg->telegram.proxy = sc_strdup(sc_json_get_string(tg, "proxy", NULL));
        override_str_field(&cfg->telegram.dm_policy, tg, "dm_policy");
        cfg->telegram.allow_from = sc_json_parse_string_list(
            sc_json_get_array(tg, "allow_from"), &cfg->telegram.allow_from_count);
        cfg->telegram.tools = sc_json_parse_string_list(
            sc_json_get_array(tg, "tools"), &cfg->telegram.tool_count);
    }

    const cJSON *dc = sc_json_get_object(channels, "discord");
    if (dc) {
        cfg->discord.enabled = sc_json_get_bool(dc, "enabled", 0);
        free(cfg->discord.token);
        cfg->discord.token = sc_strdup(sc_json_get_string(dc, "token", NULL));
        override_str_field(&cfg->discord.api_base, dc, "api_base");
        override_str_field(&cfg->discord.dm_policy, dc, "dm_policy");
        cfg->discord.allow_from = sc_json_parse_string_list(
            sc_json_get_array(dc, "allow_from"), &cfg->discord.allow_from_count);
        cfg->discord.tools = sc_json_parse_string_list(
            sc_json_get_array(dc, "tools"), &cfg->discord.tool_count);
    }

    const cJSON *irc = sc_json_get_object(channels, "irc");
    if (irc) {
        cfg->irc.enabled = sc_json_get_bool(irc, "enabled", 0);
        override_str_field(&cfg->irc.hostname, irc, "hostname");
        cfg->irc.port = sc_json_get_int(irc, "port", cfg->irc.port);
        override_str_field(&cfg->irc.nick, irc, "nick");
        override_str_field(&cfg->irc.username, irc, "username");
        override_str_field(&cfg->irc.password, irc, "password");
        cfg->irc.use_tls = sc_json_get_bool(irc, "tls", 0);
        override_str_field(&cfg->irc.group_trigger, irc, "group_trigger");
        override_str_field(&cfg->irc.dm_policy, irc, "dm_policy");
        cfg->irc.join_channels = sc_json_parse_string_list(
            sc_json_get_array(irc, "join_channels"), &cfg->irc.join_channel_count);
        cfg->irc.allow_from = sc_json_parse_string_list(
            sc_json_get_array(irc, "allow_from"), &cfg->irc.allow_from_count);
        cfg->irc.tools = sc_json_parse_string_list(
            sc_json_get_array(irc, "tools"), &cfg->irc.tool_count);
    }

    const cJSON *slack = sc_json_get_object(channels, "slack");
    if (slack) {
        cfg->slack.enabled = sc_json_get_bool(slack, "enabled", 0);
        override_str_field(&cfg->slack.bot_token, slack, "bot_token");
        override_str_field(&cfg->slack.app_token, slack, "app_token");
        override_str_field(&cfg->slack.dm_policy, slack, "dm_policy");
        cfg->slack.allow_from = sc_json_parse_string_list(
            sc_json_get_array(slack, "allow_from"), &cfg->slack.allow_from_count);
        cfg->slack.tools = sc_json_parse_string_list(
            sc_json_get_array(slack, "tools"), &cfg->slack.tool_count);
    }

    const cJSON *webcfg = sc_json_get_object(channels, "web");
    if (webcfg) {
        cfg->web.enabled = sc_json_get_bool(webcfg, "enabled", 0);
        override_str_field(&cfg->web.bind_addr, webcfg, "bind_addr");
        cfg->web.port = sc_json_get_int(webcfg, "port", cfg->web.port);
        cfg->web.auto_port = sc_json_get_bool(webcfg, "auto_port", 0);
        override_str_field(&cfg->web.bearer_token, webcfg, "bearer_token");
        override_str_field(&cfg->web.tls_cert, webcfg, "tls_cert");
        override_str_field(&cfg->web.tls_key, webcfg, "tls_key");
        override_str_field(&cfg->web.dm_policy, webcfg, "dm_policy");
        cfg->web.allow_from = sc_json_parse_string_list(
            sc_json_get_array(webcfg, "allow_from"), &cfg->web.allow_from_count);
        cfg->web.tools = sc_json_parse_string_list(
            sc_json_get_array(webcfg, "tools"), &cfg->web.tool_count);
        cfg->web.request_timeout_secs = sc_json_get_int(webcfg,
            "request_timeout_secs", cfg->web.request_timeout_secs);
        override_str_field(&cfg->web.isolation_pattern, webcfg,
                           "isolation_pattern");
        override_str_field(&cfg->web.embed_stream_url, webcfg,
                           "embed_stream_url");
    }

    const cJSON *xcfg = sc_json_get_object(channels, "x");
    if (xcfg) {
        cfg->x.enabled = sc_json_get_bool(xcfg, "enabled", 0);
        override_str_field(&cfg->x.consumer_key, xcfg, "consumer_key");
        override_str_field(&cfg->x.consumer_secret, xcfg, "consumer_secret");
        override_str_field(&cfg->x.access_token, xcfg, "access_token");
        override_str_field(&cfg->x.access_token_secret, xcfg, "access_token_secret");
        cfg->x.poll_interval_sec = sc_json_get_int(xcfg, "poll_interval_sec",
                                                     cfg->x.poll_interval_sec);
        cfg->x.enable_dms = sc_json_get_bool(xcfg, "enable_dms", 0);
        cfg->x.read_only = sc_json_get_bool(xcfg, "read_only", cfg->x.read_only);
        override_str_field(&cfg->x.dm_policy, xcfg, "dm_policy");
        cfg->x.allow_from = sc_json_parse_string_list(
            sc_json_get_array(xcfg, "allow_from"), &cfg->x.allow_from_count);
        cfg->x.tools = sc_json_parse_string_list(
            sc_json_get_array(xcfg, "tools"), &cfg->x.tool_count);
    }

    const cJSON *sig = sc_json_get_object(channels, "signal");
    if (sig) {
        cfg->signal_.enabled = sc_json_get_bool(sig, "enabled", 0);
        override_str_field(&cfg->signal_.account, sig, "account");
        override_str_field(&cfg->signal_.http_host, sig, "http_host");
        cfg->signal_.http_port = sc_json_get_int(sig, "http_port",
                                                  cfg->signal_.http_port);
        override_str_field(&cfg->signal_.http_url, sig, "http_url");
        override_str_field(&cfg->signal_.proxy, sig, "proxy");
        override_str_field(&cfg->signal_.group_trigger, sig, "group_trigger");
        override_str_field(&cfg->signal_.dm_policy, sig, "dm_policy");
        cfg->signal_.allow_from = sc_json_parse_string_list(
            sc_json_get_array(sig, "allow_from"), &cfg->signal_.allow_from_count);
        cfg->signal_.tools = sc_json_parse_string_list(
            sc_json_get_array(sig, "tools"), &cfg->signal_.tool_count);
    }
}

/* Load MCP section from JSON */
static void load_mcp_config(sc_config_t *cfg, const cJSON *root)
{
    const cJSON *mcp = sc_json_get_object(root, "mcp");
    if (!mcp) return;

    cfg->mcp.enabled = sc_json_get_bool(mcp, "enabled", 1);
    const cJSON *servers = sc_json_get_object(mcp, "servers");
    if (!servers) return;

    int n = cJSON_GetArraySize(servers);
    if (n <= 0) return;

    cfg->mcp.servers = calloc((size_t)n, sizeof(sc_mcp_server_config_t));
    if (!cfg->mcp.servers) return;

    const cJSON *srv;
    cJSON_ArrayForEach(srv, servers) {
        if (!srv->string || !cJSON_IsObject(srv)) continue;
        sc_mcp_server_config_t *s = &cfg->mcp.servers[cfg->mcp.server_count];
        s->name = sc_strdup(srv->string);

        /* command array */
        const cJSON *cmd = sc_json_get_array(srv, "command");
        if (cmd) {
            int cn = cJSON_GetArraySize(cmd);
            if (cn > 0) {
                s->command = calloc((size_t)cn, sizeof(char *));
                if (s->command) {
                    const cJSON *ci;
                    cJSON_ArrayForEach(ci, cmd) {
                        if (cJSON_IsString(ci) && ci->valuestring)
                            s->command[s->command_count++] = sc_strdup(ci->valuestring);
                    }
                }
            }
        }

        /* env object */
        const cJSON *env = sc_json_get_object(srv, "env");
        if (env) {
            int en = cJSON_GetArraySize(env);
            if (en > 0) {
                s->env_keys   = calloc((size_t)en, sizeof(char *));
                s->env_values = calloc((size_t)en, sizeof(char *));
                if (s->env_keys && s->env_values) {
                    const cJSON *ei;
                    cJSON_ArrayForEach(ei, env) {
                        if (ei->string && cJSON_IsString(ei) && ei->valuestring) {
                            s->env_keys[s->env_count]   = sc_strdup(ei->string);
                            s->env_values[s->env_count] = sc_strdup(ei->valuestring);
                            s->env_count++;
                        }
                    }
                }
            }
        }

        /* capabilities object (optional per-server sandbox overrides) */
        const cJSON *caps = sc_json_get_object(srv, "capabilities");
        if (caps) {
            const cJSON *fs_r = cJSON_GetObjectItem(caps, "fs_read");
            s->caps.fs_read = sc_json_parse_string_list(
                fs_r, &s->caps.fs_read_count);
            const cJSON *fs_w = cJSON_GetObjectItem(caps, "fs_write");
            s->caps.fs_write = sc_json_parse_string_list(
                fs_w, &s->caps.fs_write_count);
            const cJSON *proc = cJSON_GetObjectItem(caps, "process");
            if (proc && cJSON_IsArray(proc) && cJSON_GetArraySize(proc) == 0)
                s->caps.no_process = 1;  /* empty array = deny */
            /* network: [] (empty array) or false = deny outbound sockets. */
            const cJSON *net = cJSON_GetObjectItem(caps, "network");
            if ((cJSON_IsArray(net) && cJSON_GetArraySize(net) == 0) ||
                (cJSON_IsBool(net) && !cJSON_IsTrue(net)))
                s->caps.no_network = 1;
            /* sandbox: false = run this (trusted) server with no OS sandbox. */
            const cJSON *sb = cJSON_GetObjectItem(caps, "sandbox");
            if (cJSON_IsBool(sb) && !cJSON_IsTrue(sb))
                s->caps.no_sandbox = 1;
        }

        cfg->mcp.server_count++;
    }
}

/* Load delegation section from JSON */
static void load_delegation_config(sc_config_t *cfg, const cJSON *root)
{
    const cJSON *deleg = sc_json_get_object(root, "delegation");
    if (!deleg) return;

    const cJSON *targets = sc_json_get_object(deleg, "targets");
    if (!targets) return;

    int n = cJSON_GetArraySize(targets);
    if (n <= 0) return;

    cfg->delegation.targets = calloc((size_t)n, sizeof(sc_delegate_target_t));
    if (!cfg->delegation.targets) return;

    const cJSON *tgt;
    cJSON_ArrayForEach(tgt, targets) {
        if (!tgt->string || !cJSON_IsObject(tgt)) continue;
        sc_delegate_target_t *t = &cfg->delegation.targets[cfg->delegation.target_count];
        t->name = sc_strdup(tgt->string);
        const char *url = sc_json_get_string(tgt, "url", NULL);
        if (url) t->url = sc_strdup(url);
        const char *token = sc_json_get_string(tgt, "bearer_token", NULL);
        if (token) t->bearer_token = sc_strdup(token);
        t->timeout_secs = sc_json_get_int(tgt, "timeout_secs", 120);
        cfg->delegation.target_count++;
    }
}

sc_config_t *sc_config_load(const char *path)
{
    sc_config_t *cfg = sc_config_default();
    if (!cfg) return NULL;

    /* Warn if config file permissions are too open */
    struct stat st;
    if (stat(path, &st) == 0 && (st.st_mode & 077) != 0) {
        SC_LOG_WARN(LOG_TAG, "Config file %s has permissive permissions (%04o). "
                    "Recommend: chmod 600 %s", path, st.st_mode & 0777, path);
    }

    cJSON *root = sc_json_load_file(path);
    if (!root) {
        SC_LOG_WARN(LOG_TAG, "Failed to parse config %s — using defaults with env overrides",
                    path);
        apply_env_overrides(cfg);
        return cfg;
    }

    cfg->raw = root;

    /* Check config version — newer config may have security fields we don't know about */
    int file_version = sc_json_get_int(root, "config_version", 0);
    if (file_version > SC_CONFIG_VERSION) {
#if SC_STRICT_SECURITY
        SC_LOG_ERROR(LOG_TAG, "Config version %d is newer than binary (supports up to %d). "
                     "Refusing to load in strict security mode — upgrade the binary.",
                     file_version, SC_CONFIG_VERSION);
        cJSON_Delete(root);
        cfg->raw = NULL;
        sc_config_free(cfg);
        return NULL;
#else
        SC_LOG_WARN(LOG_TAG, "Config version %d is newer than binary (supports up to %d). "
                    "Unknown security fields may be ignored.",
                    file_version, SC_CONFIG_VERSION);
#endif
    }

    load_agent_defaults(cfg, root);

    /* providers */
#if SC_ENABLE_MOA
    parse_moa(cfg, root);
#endif

    const cJSON *providers = sc_json_get_object(root, "providers");
    if (providers) {
        parse_provider(providers, "anthropic",  &cfg->anthropic);
        parse_provider(providers, "openai",     &cfg->openai);
        parse_provider(providers, "openrouter", &cfg->openrouter);
        parse_provider(providers, "groq",       &cfg->groq);
        parse_provider(providers, "zhipu",      &cfg->zhipu);
        parse_provider(providers, "vllm",       &cfg->vllm);
        parse_provider(providers, "gemini",     &cfg->gemini);
        parse_provider(providers, "deepseek",   &cfg->deepseek);
        parse_provider(providers, "ollama",     &cfg->ollama);
        parse_provider(providers, "xai",        &cfg->xai);

        /* Parse any additional (custom) provider names not in the builtin list */
        static const char *builtins[] = {
            "anthropic","openai","openrouter","groq","zhipu",
            "vllm","gemini","deepseek","ollama","xai",NULL
        };
        cJSON *prov_item;
        cJSON_ArrayForEach(prov_item, (cJSON *)providers) {
            if (!prov_item->string) continue;
            int is_builtin = 0;
            for (int b = 0; builtins[b]; b++) {
                if (strcmp(prov_item->string, builtins[b]) == 0) {
                    is_builtin = 1;
                    break;
                }
            }
            if (!is_builtin && cfg->custom_provider_count < 8) {
                int idx = cfg->custom_provider_count;
                cfg->custom_providers[idx].name = sc_strdup(prov_item->string);
                parse_provider(providers, prov_item->string,
                               &cfg->custom_providers[idx].config);
                cfg->custom_provider_count++;
            }
        }
    }

    load_channels(cfg, root);

    /* tools.web */
    const cJSON *tools = sc_json_get_object(root, "tools");
    const cJSON *web   = tools ? sc_json_get_object(tools, "web") : NULL;
    if (web) {
        const cJSON *brave = sc_json_get_object(web, "brave");
        if (brave) {
            cfg->web_tools.brave_enabled    = sc_json_get_bool(brave, "enabled", 0);
            free(cfg->web_tools.brave_api_key);
            cfg->web_tools.brave_api_key    = sc_strdup(sc_json_get_string(brave, "api_key", NULL));
            override_str_field(&cfg->web_tools.brave_base_url, brave, "base_url");
            cfg->web_tools.brave_max_results = sc_json_get_int(brave, "max_results",
                                                                SC_MAX_SEARCH_RESULTS);
        }
        const cJSON *sxng = sc_json_get_object(web, "searxng");
        if (sxng) {
            cfg->web_tools.searxng_enabled     = sc_json_get_bool(sxng, "enabled", 0);
            free(cfg->web_tools.searxng_base_url);
            cfg->web_tools.searxng_base_url    = sc_strdup(sc_json_get_string(sxng, "base_url", NULL));
            cfg->web_tools.searxng_max_results = sc_json_get_int(sxng, "max_results",
                                                                   SC_MAX_SEARCH_RESULTS);
        }
        const cJSON *ddg = sc_json_get_object(web, "duckduckgo");
        if (ddg) {
            cfg->web_tools.duckduckgo_enabled     = sc_json_get_bool(ddg, "enabled", 1);
            cfg->web_tools.duckduckgo_max_results = sc_json_get_int(ddg, "max_results",
                                                                     SC_MAX_SEARCH_RESULTS);
        }
    }

    /* git tool settings */
    const cJSON *git_sec = sc_json_get_object(root, "git");
    if (git_sec) {
        const cJSON *par = cJSON_GetObjectItem(git_sec, "push_allowed_remotes");
        if (par && cJSON_IsArray(par)) {
            int n = cJSON_GetArraySize(par);
            if (n > 0) {
                /* Free old list */
                for (int i = 0; i < cfg->git.push_allowed_remote_count; i++)
                    free(cfg->git.push_allowed_remotes[i]);
                free(cfg->git.push_allowed_remotes);
                cfg->git.push_allowed_remotes = calloc((size_t)n, sizeof(char *));
                cfg->git.push_allowed_remote_count = 0;
                if (cfg->git.push_allowed_remotes) {
                    const cJSON *item;
                    cJSON_ArrayForEach(item, par) {
                        if (cJSON_IsString(item) && item->valuestring)
                            cfg->git.push_allowed_remotes[cfg->git.push_allowed_remote_count++] =
                                sc_strdup(item->valuestring);
                    }
                }
            }
        }
    }

    /* gitea */
    const cJSON *gitea = sc_json_get_object(root, "gitea");
    if (gitea) {
        free(cfg->gitea.url);
        cfg->gitea.url   = sc_strdup(sc_json_get_string(gitea, "url", NULL));
        free(cfg->gitea.token);
        cfg->gitea.token = sc_strdup(sc_json_get_string(gitea, "token", NULL));
        free(cfg->gitea.default_org);
        cfg->gitea.default_org = sc_strdup(
            sc_json_get_string(gitea, "default_org", NULL));
    }

    /* camera */
    const cJSON *camera = sc_json_get_object(root, "camera");
    if (camera) {
        free(cfg->camera.snap_command);
        cfg->camera.snap_command = sc_strdup(
            sc_json_get_string(camera, "snap_command", NULL));
        free(cfg->camera.events_dir);
        cfg->camera.events_dir = sc_strdup(
            sc_json_get_string(camera, "events_dir", "camera/motion"));
        free(cfg->camera.vision_url);
        cfg->camera.vision_url = sc_strdup(
            sc_json_get_string(camera, "vision_url", NULL));
        free(cfg->camera.vision_model);
        cfg->camera.vision_model = sc_strdup(
            sc_json_get_string(camera, "vision_model", NULL));
        cfg->camera.vision_timeout_secs = sc_json_get_int(
            camera, "vision_timeout_secs", 120);
    }

    /* heartbeat */
    const cJSON *hb = sc_json_get_object(root, "heartbeat");
    if (hb) {
        cfg->heartbeat.enabled  = sc_json_get_bool(hb, "enabled", 1);
        cfg->heartbeat.interval = sc_json_get_int(hb, "interval", SC_DEFAULT_HEARTBEAT_INTERVAL);
    }

    /* updater */
    const cJSON *upd = sc_json_get_object(root, "updater");
    if (upd) {
        cfg->updater.enabled = sc_json_get_bool(upd, "enabled", 0);
        override_str_field(&cfg->updater.manifest_url, upd, "manifest_url");
        cfg->updater.check_interval_hours = sc_json_get_int(upd, "check_interval_hours",
                                                             SC_DEFAULT_UPDATE_CHECK_HOURS);
        cfg->updater.auto_apply = sc_json_get_bool(upd, "auto_apply", 0);
    }

    load_mcp_config(cfg, root);
    load_delegation_config(cfg, root);

    /* notifications */
    const char *nu = sc_json_get_string(root, "notify_urls", NULL);
    if (nu) {
        free(cfg->notify_urls);
        cfg->notify_urls = sc_strdup(nu);
    }

    /* Automatic session reset (task 3.7) */
    cfg->session_reset.daily_reset_hour = 4;
    cfg->session_reset.idle_minutes = 1440;
    const cJSON *sreset = sc_json_get_object(root, "session_reset");
    if (sreset) {
        const char *m = sc_json_get_string(sreset, "mode", "none");
        if (strcmp(m, "daily") == 0)      cfg->session_reset.mode = 1;
        else if (strcmp(m, "idle") == 0)  cfg->session_reset.mode = 2;
        else if (strcmp(m, "both") == 0)  cfg->session_reset.mode = 3;
        else                              cfg->session_reset.mode = 0;
        cfg->session_reset.daily_reset_hour =
            sc_json_get_int(sreset, "daily_reset_hour", 4);
        cfg->session_reset.idle_minutes =
            sc_json_get_int(sreset, "idle_minutes", 1440);
    }

    /* Busy-input mode (task 3.8) */
    const char *bim = sc_json_get_string(root, "busy_input_mode", "interrupt");
    cfg->busy_input_mode = (strcmp(bim, "queue") == 0) ? 1 : 0;

    /* Silent delivery tokens (task 3.9): default true. */
    cfg->silent_tokens_enabled =
        sc_json_get_bool(root, "silent_tokens_enabled", cfg->silent_tokens_enabled);

    /* Apply environment variable overrides last */
    apply_env_overrides(cfg);

    /* Resolve file references (file:///path, @/path) in secret fields */
    resolve_secret_refs(cfg);

    /* Resolve vault:// references in secret fields */
#if SC_ENABLE_VAULT
    resolve_vault_refs(cfg);
#endif

    /* Validate and clamp config values */
    if (cfg->max_tokens < 1) cfg->max_tokens = SC_DEFAULT_MAX_TOKENS;
    if (cfg->max_tool_iterations < 1) cfg->max_tool_iterations = SC_DEFAULT_MAX_ITERATIONS;
    if (cfg->max_output_chars < 1) cfg->max_output_chars = SC_MAX_OUTPUT_CHARS;
    if (cfg->max_tool_result_chars < 1) cfg->max_tool_result_chars = SC_DEFAULT_MAX_TOOL_RESULT_CHARS;
    if (cfg->tool_result_preview_chars < 1) cfg->tool_result_preview_chars = SC_DEFAULT_TOOL_RESULT_PREVIEW_CHARS;
    /* Preview must be smaller than the spill threshold, else nothing spills usefully. */
    if (cfg->tool_result_preview_chars >= cfg->max_tool_result_chars)
        cfg->tool_result_preview_chars = cfg->max_tool_result_chars / 2;
    if (cfg->max_fetch_chars < 1) cfg->max_fetch_chars = SC_MAX_FETCH_CHARS;
    if (cfg->exec_timeout_secs < 0) cfg->exec_timeout_secs = SC_DEFAULT_EXEC_TIMEOUT;
    if (cfg->max_tool_calls_per_turn < 1) cfg->max_tool_calls_per_turn = SC_DEFAULT_MAX_TOOL_CALLS_PER_TURN;
    if (cfg->max_turn_secs < 1) cfg->max_turn_secs = SC_DEFAULT_MAX_TURN_SECS;
    if (cfg->max_output_total < 1) cfg->max_output_total = SC_DEFAULT_MAX_OUTPUT_TOTAL;
    if (cfg->max_tool_calls_per_hour < 1) cfg->max_tool_calls_per_hour = SC_DEFAULT_MAX_TOOL_CALLS_PER_HOUR;
    if (cfg->rate_limit_per_minute < 0) cfg->rate_limit_per_minute = SC_DEFAULT_RATE_LIMIT_PER_MINUTE;
    if (cfg->temperature < 0.0) cfg->temperature = 0.0;
    if (cfg->temperature > 2.0) cfg->temperature = 2.0;

    SC_LOG_INFO(LOG_TAG, "loaded config from %s", path);
    sc_audit_log_ext("config", path, 0, 0, NULL, NULL, "config_load");

    /* Verify config integrity against deploy-time hash if available */
    {
        char hash_path[1024];
        snprintf(hash_path, sizeof(hash_path), "%s.sha256", path);
        FILE *hf = fopen(hash_path, "r");
        char expected[128] = {0};
        if (hf) {
            if (!fgets(expected, sizeof(expected), hf))
                expected[0] = '\0';
            fclose(hf);
        }
        if (expected[0]) {
            /* Trim whitespace */
            size_t elen = strlen(expected);
            while (elen > 0 && (expected[elen-1] == '\n' || expected[elen-1] == '\r'
                   || expected[elen-1] == ' '))
                expected[--elen] = '\0';
            (void)elen;

            /* Compute actual hash via sha256sum */
            char cmd[1024];
            snprintf(cmd, sizeof(cmd), "sha256sum '%s' 2>/dev/null", path);
            FILE *fp = popen(cmd, "r");
            if (fp) {
                char actual[128] = {0};
                if (fgets(actual, sizeof(actual), fp)) {
                    char *sp = strchr(actual, ' ');
                    if (sp) *sp = '\0';
                    if (elen > 0 && strlen(actual) > 0 &&
                        strcmp(actual, expected) != 0) {
                        SC_LOG_WARN(LOG_TAG,
                            "CONFIG INTEGRITY MISMATCH: %s may have been "
                            "tampered with (expected %.12s..., got %.12s...)",
                            path, expected, actual);
                    }
                }
                pclose(fp);
            }
        }
    }

    return cfg;
}

/* Rotate config backups: .bak.4 deleted, .bak.N → .bak.N+1, current → .bak */
static void backup_config(const char *path)
{
    char old_path[PATH_MAX], new_path[PATH_MAX];

    /* Delete oldest */
    snprintf(old_path, sizeof(old_path), "%s.bak.4", path);
    remove(old_path);

    /* Rotate .bak.3→4, .bak.2→3, .bak.1→2 */
    for (int i = 3; i >= 1; i--) {
        snprintf(old_path, sizeof(old_path), "%s.bak.%d", path, i);
        snprintf(new_path, sizeof(new_path), "%s.bak.%d", path, i + 1);
        rename(old_path, new_path);
    }

    /* .bak → .bak.1 */
    snprintf(old_path, sizeof(old_path), "%s.bak", path);
    snprintf(new_path, sizeof(new_path), "%s.bak.1", path);
    rename(old_path, new_path);

    /* Copy current → .bak */
    snprintf(new_path, sizeof(new_path), "%s.bak", path);
    FILE *src = fopen(path, "rb");
    if (src) {
        FILE *dst = fopen(new_path, "wb");
        if (dst) {
            char buf[4096];
            size_t n;
            while ((n = fread(buf, 1, sizeof(buf), src)) > 0)
                fwrite(buf, 1, n, dst);
            fclose(dst);
            chmod(new_path, 0600);
        }
        fclose(src);
    }
}

/* Serialize agents.defaults section to JSON */
static void save_agent_defaults(cJSON *root, const sc_config_t *cfg)
{
    cJSON *agents   = cJSON_AddObjectToObject(root, "agents");
    cJSON *defaults = cJSON_AddObjectToObject(agents, "defaults");
    if (cfg->workspace)
        cJSON_AddStringToObject(defaults, "workspace", cfg->workspace);
    cJSON_AddBoolToObject(defaults, "restrict_to_workspace", cfg->restrict_to_workspace);
    if (cfg->provider)
        cJSON_AddStringToObject(defaults, "provider", cfg->provider);
    if (cfg->model)
        cJSON_AddStringToObject(defaults, "model", cfg->model);
    if (cfg->fallback_model_count > 0) {
        cJSON *fb_arr = cJSON_AddArrayToObject(defaults, "fallback_models");
        for (int i = 0; i < cfg->fallback_model_count; i++) {
            if (cfg->fallback_models[i])
                cJSON_AddItemToArray(fb_arr, cJSON_CreateString(cfg->fallback_models[i]));
        }
    }
    if (cfg->model_alias_count > 0) {
        cJSON *aliases_obj = cJSON_AddObjectToObject(defaults, "model_aliases");
        for (int i = 0; i < cfg->model_alias_count; i++) {
            if (cfg->model_alias_names[i] && cfg->model_alias_models[i])
                cJSON_AddStringToObject(aliases_obj, cfg->model_alias_names[i],
                                        cfg->model_alias_models[i]);
        }
    }
    cJSON_AddNumberToObject(defaults, "max_tokens", cfg->max_tokens);
    if (cfg->context_window > 0)
        cJSON_AddNumberToObject(defaults, "context_window", cfg->context_window);
    cJSON_AddNumberToObject(defaults, "temperature", cfg->temperature);
    if (cfg->response_format)
        cJSON_AddItemToObject(defaults, "response_format",
                              cJSON_Duplicate(cfg->response_format, 1));
    cJSON_AddNumberToObject(defaults, "max_tool_iterations", cfg->max_tool_iterations);
    cJSON_AddNumberToObject(defaults, "session_summary_threshold", cfg->session_summary_threshold);
    cJSON_AddNumberToObject(defaults, "session_keep_last", cfg->session_keep_last);
    cJSON_AddBoolToObject(defaults, "compress_tool_results", cfg->compress_tool_results);
    cJSON_AddNumberToObject(defaults, "compress_keep_recent", cfg->compress_keep_recent);
    cJSON_AddNumberToObject(defaults, "compress_min_bytes", cfg->compress_min_bytes);
    cJSON_AddNumberToObject(defaults, "context_warn_pct", cfg->context_warn_pct);
    cJSON_AddNumberToObject(defaults, "compact_cooldown_secs", cfg->compact_cooldown_secs);
    cJSON_AddNumberToObject(defaults, "max_output_chars", cfg->max_output_chars);
    cJSON_AddNumberToObject(defaults, "max_tool_result_chars", cfg->max_tool_result_chars);
    cJSON_AddNumberToObject(defaults, "tool_result_preview_chars", cfg->tool_result_preview_chars);
    cJSON_AddStringToObject(defaults, "tool_selection", cfg->tool_selection == 1 ? "auto" : "fixed");
    cJSON *local_opt_obj = cJSON_AddObjectToObject(defaults, "local_optimizations");
    if (local_opt_obj) {
        cJSON_AddBoolToObject(local_opt_obj, "warmup", cfg->warmup);
        cJSON *wp_arr = cJSON_AddArrayToObject(local_opt_obj, "warmup_providers");
        for (int i = 0; wp_arr && i < cfg->warmup_provider_count; i++)
            if (cfg->warmup_providers[i])
                cJSON_AddItemToArray(wp_arr, cJSON_CreateString(cfg->warmup_providers[i]));
    }
    cJSON_AddNumberToObject(defaults, "max_fetch_chars", cfg->max_fetch_chars);
    cJSON_AddNumberToObject(defaults, "max_background_procs", cfg->max_background_procs);
    cJSON_AddNumberToObject(defaults, "summary_max_transcript", cfg->summary_max_transcript);
    cJSON_AddNumberToObject(defaults, "exec_timeout_secs", cfg->exec_timeout_secs);
    cJSON_AddNumberToObject(defaults, "max_tool_calls_per_turn", cfg->max_tool_calls_per_turn);
    cJSON_AddNumberToObject(defaults, "max_turn_secs", cfg->max_turn_secs);
    cJSON_AddNumberToObject(defaults, "max_output_total", cfg->max_output_total);
    cJSON_AddNumberToObject(defaults, "max_tool_calls_per_hour", cfg->max_tool_calls_per_hour);
    if (cfg->max_tokens_per_hour > 0)
        cJSON_AddNumberToObject(defaults, "max_tokens_per_hour", cfg->max_tokens_per_hour);
    cJSON_AddNumberToObject(defaults, "rate_limit_per_minute", cfg->rate_limit_per_minute);
    if (cfg->allowed_tool_count > 0) {
        cJSON *at_arr = cJSON_AddArrayToObject(defaults, "allowed_tools");
        for (int i = 0; i < cfg->allowed_tool_count; i++) {
            if (cfg->allowed_tools[i])
                cJSON_AddItemToArray(at_arr, cJSON_CreateString(cfg->allowed_tools[i]));
        }
    }
    if (cfg->restrict_message_tool)
        cJSON_AddBoolToObject(defaults, "restrict_message_tool", cfg->restrict_message_tool);
    {
        const char *scope_names[] = {"none", "local", "public", "any"};
        int si = cfg->network_scope;
        if (si >= 0 && si <= 3)
            cJSON_AddStringToObject(defaults, "network_scope", scope_names[si]);
    }
    cJSON_AddBoolToObject(defaults, "sandbox", cfg->sandbox_enabled);
    cJSON_AddBoolToObject(defaults, "memory_consolidation", cfg->memory_consolidation);
    cJSON_AddBoolToObject(defaults, "memory_background_review", cfg->memory_background_review);
    cJSON_AddBoolToObject(defaults, "memory_write_approval", cfg->memory_write_approval);
    if (cfg->memory_review_model)
        cJSON_AddStringToObject(defaults, "memory_review_model", cfg->memory_review_model);
    cJSON_AddStringToObject(defaults, "memory_notifications",
        cfg->memory_notifications == 2 ? "verbose" :
        cfg->memory_notifications == 1 ? "on" : "off");

    /* Tee config */
    {
        cJSON *tee = cJSON_CreateObject();
        cJSON_AddBoolToObject(tee, "enabled", cfg->tee_enabled);
        cJSON_AddNumberToObject(tee, "max_files", cfg->tee_max_files);
        cJSON_AddNumberToObject(tee, "max_file_size", cfg->tee_max_file_size);
        cJSON_AddItemToObject(defaults, "tee", tee);
    }

    if (cfg->log_path)
        cJSON_AddStringToObject(defaults, "log_path", cfg->log_path);
}

/* Helper: serialize an allow_from list into a channel JSON object */
static void save_allow_from(cJSON *obj, const char *const *list, int count)
{
    cJSON *arr = cJSON_AddArrayToObject(obj, "allow_from");
    for (int i = 0; i < count; i++) {
        if (list[i])
            cJSON_AddItemToArray(arr, cJSON_CreateString(list[i]));
    }
}

/* Serialize channels section to JSON */
static void save_channels(cJSON *root, const sc_config_t *cfg)
{
    cJSON *channels = cJSON_AddObjectToObject(root, "channels");

    /* telegram */
    cJSON *tg = cJSON_AddObjectToObject(channels, "telegram");
    cJSON_AddBoolToObject(tg, "enabled", cfg->telegram.enabled);
    if (cfg->telegram.token)
        cJSON_AddStringToObject(tg, "token", cfg->telegram.token);
    if (cfg->telegram.api_base)
        cJSON_AddStringToObject(tg, "api_base", cfg->telegram.api_base);
    if (cfg->telegram.proxy)
        cJSON_AddStringToObject(tg, "proxy", cfg->telegram.proxy);
    if (cfg->telegram.dm_policy)
        cJSON_AddStringToObject(tg, "dm_policy", cfg->telegram.dm_policy);
    save_allow_from(tg, (const char *const *)cfg->telegram.allow_from,
                    cfg->telegram.allow_from_count);

    /* discord */
    cJSON *dc_obj = cJSON_AddObjectToObject(channels, "discord");
    cJSON_AddBoolToObject(dc_obj, "enabled", cfg->discord.enabled);
    if (cfg->discord.token)
        cJSON_AddStringToObject(dc_obj, "token", cfg->discord.token);
    if (cfg->discord.api_base)
        cJSON_AddStringToObject(dc_obj, "api_base", cfg->discord.api_base);
    if (cfg->discord.dm_policy)
        cJSON_AddStringToObject(dc_obj, "dm_policy", cfg->discord.dm_policy);
    save_allow_from(dc_obj, (const char *const *)cfg->discord.allow_from,
                    cfg->discord.allow_from_count);

    /* irc */
    cJSON *irc_obj = cJSON_AddObjectToObject(channels, "irc");
    cJSON_AddBoolToObject(irc_obj, "enabled", cfg->irc.enabled);
    if (cfg->irc.hostname)
        cJSON_AddStringToObject(irc_obj, "hostname", cfg->irc.hostname);
    cJSON_AddNumberToObject(irc_obj, "port", cfg->irc.port);
    if (cfg->irc.nick)
        cJSON_AddStringToObject(irc_obj, "nick", cfg->irc.nick);
    if (cfg->irc.username)
        cJSON_AddStringToObject(irc_obj, "username", cfg->irc.username);
    if (cfg->irc.password)
        cJSON_AddStringToObject(irc_obj, "password", cfg->irc.password);
    cJSON_AddBoolToObject(irc_obj, "tls", cfg->irc.use_tls);
    if (cfg->irc.group_trigger)
        cJSON_AddStringToObject(irc_obj, "group_trigger", cfg->irc.group_trigger);
    if (cfg->irc.join_channel_count > 0) {
        cJSON *jc_arr = cJSON_AddArrayToObject(irc_obj, "join_channels");
        for (int i = 0; i < cfg->irc.join_channel_count; i++) {
            if (cfg->irc.join_channels[i])
                cJSON_AddItemToArray(jc_arr, cJSON_CreateString(cfg->irc.join_channels[i]));
        }
    }
    if (cfg->irc.dm_policy)
        cJSON_AddStringToObject(irc_obj, "dm_policy", cfg->irc.dm_policy);
    save_allow_from(irc_obj, (const char *const *)cfg->irc.allow_from,
                    cfg->irc.allow_from_count);

    /* slack */
    cJSON *slack_obj = cJSON_AddObjectToObject(channels, "slack");
    cJSON_AddBoolToObject(slack_obj, "enabled", cfg->slack.enabled);
    if (cfg->slack.bot_token)
        cJSON_AddStringToObject(slack_obj, "bot_token", cfg->slack.bot_token);
    if (cfg->slack.app_token)
        cJSON_AddStringToObject(slack_obj, "app_token", cfg->slack.app_token);
    if (cfg->slack.dm_policy)
        cJSON_AddStringToObject(slack_obj, "dm_policy", cfg->slack.dm_policy);
    save_allow_from(slack_obj, (const char *const *)cfg->slack.allow_from,
                    cfg->slack.allow_from_count);

    /* web */
    cJSON *web_obj = cJSON_AddObjectToObject(channels, "web");
    cJSON_AddBoolToObject(web_obj, "enabled", cfg->web.enabled);
    if (cfg->web.bind_addr)
        cJSON_AddStringToObject(web_obj, "bind_addr", cfg->web.bind_addr);
    cJSON_AddNumberToObject(web_obj, "port", cfg->web.port);
    cJSON_AddBoolToObject(web_obj, "auto_port", cfg->web.auto_port);
    if (cfg->web.bearer_token)
        cJSON_AddStringToObject(web_obj, "bearer_token", cfg->web.bearer_token);
    if (cfg->web.tls_cert)
        cJSON_AddStringToObject(web_obj, "tls_cert", cfg->web.tls_cert);
    if (cfg->web.tls_key)
        cJSON_AddStringToObject(web_obj, "tls_key", cfg->web.tls_key);
    if (cfg->web.dm_policy)
        cJSON_AddStringToObject(web_obj, "dm_policy", cfg->web.dm_policy);
    save_allow_from(web_obj, (const char *const *)cfg->web.allow_from,
                    cfg->web.allow_from_count);
    if (cfg->web.request_timeout_secs > 0)
        cJSON_AddNumberToObject(web_obj, "request_timeout_secs",
                                cfg->web.request_timeout_secs);
    if (cfg->web.isolation_pattern)
        cJSON_AddStringToObject(web_obj, "isolation_pattern",
                                cfg->web.isolation_pattern);

    /* x */
    cJSON *x_obj = cJSON_AddObjectToObject(channels, "x");
    cJSON_AddBoolToObject(x_obj, "enabled", cfg->x.enabled);
    if (cfg->x.consumer_key)
        cJSON_AddStringToObject(x_obj, "consumer_key", cfg->x.consumer_key);
    if (cfg->x.consumer_secret)
        cJSON_AddStringToObject(x_obj, "consumer_secret", cfg->x.consumer_secret);
    if (cfg->x.access_token)
        cJSON_AddStringToObject(x_obj, "access_token", cfg->x.access_token);
    if (cfg->x.access_token_secret)
        cJSON_AddStringToObject(x_obj, "access_token_secret", cfg->x.access_token_secret);
    cJSON_AddNumberToObject(x_obj, "poll_interval_sec", cfg->x.poll_interval_sec);
    cJSON_AddBoolToObject(x_obj, "enable_dms", cfg->x.enable_dms);
    cJSON_AddBoolToObject(x_obj, "read_only", cfg->x.read_only);
    if (cfg->x.dm_policy)
        cJSON_AddStringToObject(x_obj, "dm_policy", cfg->x.dm_policy);
    save_allow_from(x_obj, (const char *const *)cfg->x.allow_from,
                    cfg->x.allow_from_count);

    /* signal */
    cJSON *sig_obj = cJSON_AddObjectToObject(channels, "signal");
    cJSON_AddBoolToObject(sig_obj, "enabled", cfg->signal_.enabled);
    if (cfg->signal_.account)
        cJSON_AddStringToObject(sig_obj, "account", cfg->signal_.account);
    if (cfg->signal_.http_host)
        cJSON_AddStringToObject(sig_obj, "http_host", cfg->signal_.http_host);
    cJSON_AddNumberToObject(sig_obj, "http_port", cfg->signal_.http_port);
    if (cfg->signal_.http_url)
        cJSON_AddStringToObject(sig_obj, "http_url", cfg->signal_.http_url);
    if (cfg->signal_.proxy)
        cJSON_AddStringToObject(sig_obj, "proxy", cfg->signal_.proxy);
    if (cfg->signal_.group_trigger)
        cJSON_AddStringToObject(sig_obj, "group_trigger", cfg->signal_.group_trigger);
    if (cfg->signal_.dm_policy)
        cJSON_AddStringToObject(sig_obj, "dm_policy", cfg->signal_.dm_policy);
    save_allow_from(sig_obj, (const char *const *)cfg->signal_.allow_from,
                    cfg->signal_.allow_from_count);
}

/* Serialize MCP section to JSON */
static void save_mcp_config(cJSON *root, const sc_config_t *cfg)
{
    cJSON *mcp_obj = cJSON_AddObjectToObject(root, "mcp");
    cJSON_AddBoolToObject(mcp_obj, "enabled", cfg->mcp.enabled);
    if (cfg->mcp.server_count <= 0) return;

    cJSON *servers_obj = cJSON_AddObjectToObject(mcp_obj, "servers");
    for (int i = 0; i < cfg->mcp.server_count; i++) {
        const sc_mcp_server_config_t *s = &cfg->mcp.servers[i];
        if (!s->name) continue;
        cJSON *srv = cJSON_AddObjectToObject(servers_obj, s->name);
        if (s->command_count > 0) {
            cJSON *cmd_arr = cJSON_AddArrayToObject(srv, "command");
            for (int j = 0; j < s->command_count; j++) {
                if (s->command[j])
                    cJSON_AddItemToArray(cmd_arr, cJSON_CreateString(s->command[j]));
            }
        }
        if (s->env_count > 0) {
            cJSON *env_obj = cJSON_AddObjectToObject(srv, "env");
            for (int j = 0; j < s->env_count; j++) {
                if (s->env_keys[j] && s->env_values[j])
                    cJSON_AddStringToObject(env_obj, s->env_keys[j], s->env_values[j]);
            }
        }
    }
}

/* Serialize delegation section to JSON */
static void save_delegation_config(cJSON *root, const sc_config_t *cfg)
{
    if (cfg->delegation.target_count <= 0) return;

    cJSON *deleg_obj = cJSON_AddObjectToObject(root, "delegation");
    cJSON *targets_obj = cJSON_AddObjectToObject(deleg_obj, "targets");
    for (int i = 0; i < cfg->delegation.target_count; i++) {
        const sc_delegate_target_t *t = &cfg->delegation.targets[i];
        if (!t->name) continue;
        cJSON *tgt = cJSON_AddObjectToObject(targets_obj, t->name);
        if (t->url)
            cJSON_AddStringToObject(tgt, "url", t->url);
        if (t->bearer_token)
            cJSON_AddStringToObject(tgt, "bearer_token", t->bearer_token);
        if (t->timeout_secs != 120)
            cJSON_AddNumberToObject(tgt, "timeout_secs", t->timeout_secs);
    }
}

int sc_config_save(const char *path, const sc_config_t *cfg)
{
    backup_config(path);

    cJSON *root = cJSON_CreateObject();
    if (!root) return -1;

    cJSON_AddNumberToObject(root, "config_version", SC_CONFIG_VERSION);

    save_agent_defaults(root, cfg);

    /* providers */
    cJSON *providers = cJSON_AddObjectToObject(root, "providers");
    provider_to_json(providers, "anthropic",  &cfg->anthropic);
    provider_to_json(providers, "openai",     &cfg->openai);
    provider_to_json(providers, "openrouter", &cfg->openrouter);
    provider_to_json(providers, "groq",       &cfg->groq);
    provider_to_json(providers, "zhipu",      &cfg->zhipu);
    provider_to_json(providers, "vllm",       &cfg->vllm);
    provider_to_json(providers, "gemini",     &cfg->gemini);
    provider_to_json(providers, "deepseek",   &cfg->deepseek);
    provider_to_json(providers, "ollama",    &cfg->ollama);
    provider_to_json(providers, "xai",       &cfg->xai);

    save_channels(root, cfg);

    /* tools.web */
    cJSON *tools = cJSON_AddObjectToObject(root, "tools");
    cJSON *web   = cJSON_AddObjectToObject(tools, "web");
    cJSON *brave = cJSON_AddObjectToObject(web, "brave");
    cJSON_AddBoolToObject(brave, "enabled", cfg->web_tools.brave_enabled);
    if (cfg->web_tools.brave_api_key)
        cJSON_AddStringToObject(brave, "api_key", cfg->web_tools.brave_api_key);
    if (cfg->web_tools.brave_base_url)
        cJSON_AddStringToObject(brave, "base_url", cfg->web_tools.brave_base_url);
    cJSON_AddNumberToObject(brave, "max_results", cfg->web_tools.brave_max_results);
    cJSON *sxng = cJSON_AddObjectToObject(web, "searxng");
    cJSON_AddBoolToObject(sxng, "enabled", cfg->web_tools.searxng_enabled);
    if (cfg->web_tools.searxng_base_url)
        cJSON_AddStringToObject(sxng, "base_url", cfg->web_tools.searxng_base_url);
    cJSON_AddNumberToObject(sxng, "max_results", cfg->web_tools.searxng_max_results);
    cJSON *ddg = cJSON_AddObjectToObject(web, "duckduckgo");
    cJSON_AddBoolToObject(ddg, "enabled", cfg->web_tools.duckduckgo_enabled);
    cJSON_AddNumberToObject(ddg, "max_results", cfg->web_tools.duckduckgo_max_results);

    /* heartbeat */
    cJSON *hb = cJSON_AddObjectToObject(root, "heartbeat");
    cJSON_AddBoolToObject(hb, "enabled", cfg->heartbeat.enabled);
    cJSON_AddNumberToObject(hb, "interval", cfg->heartbeat.interval);

    /* updater */
    cJSON *upd_obj = cJSON_AddObjectToObject(root, "updater");
    cJSON_AddBoolToObject(upd_obj, "enabled", cfg->updater.enabled);
    if (cfg->updater.manifest_url)
        cJSON_AddStringToObject(upd_obj, "manifest_url", cfg->updater.manifest_url);
    cJSON_AddNumberToObject(upd_obj, "check_interval_hours", cfg->updater.check_interval_hours);
    cJSON_AddBoolToObject(upd_obj, "auto_apply", cfg->updater.auto_apply);

    save_mcp_config(root, cfg);
    save_delegation_config(root, cfg);

    int ret = sc_json_save_file(path, root);
    cJSON_Delete(root);
    return ret;
}

char *sc_config_workspace_path(const sc_config_t *cfg)
{
    if (!cfg || !cfg->workspace) return NULL;
    return sc_expand_home(cfg->workspace);
}

char *sc_config_get_path(void)
{
    char *home = sc_get_home_dir();
    if (!home) return NULL;
    size_t len = strlen(home);
    char *path = malloc(len + sizeof("/config.json"));
    if (!path) { free(home); return NULL; }
    snprintf(path, len + sizeof("/config.json"), "%s/config.json", home);
    free(home);
    return path;
}

void sc_config_free(sc_config_t *cfg)
{
    if (!cfg) return;

    free(cfg->workspace);
    free(cfg->provider);
    free(cfg->model);
    free(cfg->memory_review_model);
    free(cfg->log_path);
    for (int i = 0; i < cfg->fallback_model_count; i++)
        free(cfg->fallback_models[i]);
    free(cfg->fallback_models);
    for (int i = 0; i < cfg->warmup_provider_count; i++)
        free(cfg->warmup_providers[i]);
    free(cfg->warmup_providers);
    for (int i = 0; i < cfg->allowed_tool_count; i++)
        free(cfg->allowed_tools[i]);
    free(cfg->allowed_tools);
    for (int i = 0; i < cfg->model_alias_count; i++) {
        free(cfg->model_alias_names[i]);
        free(cfg->model_alias_models[i]);
    }
    free(cfg->model_alias_names);
    free(cfg->model_alias_models);
    for (int i = 0; i < cfg->exec_allowed_command_count; i++)
        free(cfg->exec_allowed_commands[i]);
    free(cfg->exec_allowed_commands);

    free_provider(&cfg->anthropic);
    free_provider(&cfg->openai);
    free_provider(&cfg->openrouter);
    free_provider(&cfg->groq);
    free_provider(&cfg->zhipu);
    free_provider(&cfg->vllm);
    free_provider(&cfg->gemini);
    free_provider(&cfg->deepseek);
    free_provider(&cfg->ollama);
    free_provider(&cfg->xai);

    free(cfg->telegram.token);
    free(cfg->telegram.api_base);
    free(cfg->telegram.proxy);
    free(cfg->telegram.dm_policy);
    for (int i = 0; i < cfg->telegram.allow_from_count; i++)
        free(cfg->telegram.allow_from[i]);
    free(cfg->telegram.allow_from);

    free(cfg->discord.token);
    free(cfg->discord.api_base);
    free(cfg->discord.dm_policy);
    for (int i = 0; i < cfg->discord.allow_from_count; i++)
        free(cfg->discord.allow_from[i]);
    free(cfg->discord.allow_from);

    free(cfg->irc.hostname);
    free(cfg->irc.nick);
    free(cfg->irc.username);
    free(cfg->irc.password);
    free(cfg->irc.group_trigger);
    free(cfg->irc.dm_policy);
    for (int i = 0; i < cfg->irc.join_channel_count; i++)
        free(cfg->irc.join_channels[i]);
    free(cfg->irc.join_channels);
    for (int i = 0; i < cfg->irc.allow_from_count; i++)
        free(cfg->irc.allow_from[i]);
    free(cfg->irc.allow_from);

    free(cfg->slack.bot_token);
    free(cfg->slack.app_token);
    free(cfg->slack.dm_policy);
    for (int i = 0; i < cfg->slack.allow_from_count; i++)
        free(cfg->slack.allow_from[i]);
    free(cfg->slack.allow_from);

    free(cfg->web.bind_addr);
    free(cfg->web.bearer_token);
    free(cfg->web.tls_cert);
    free(cfg->web.tls_key);
    free(cfg->web.dm_policy);
    free(cfg->web.isolation_pattern);
    free(cfg->web.embed_stream_url);
    for (int i = 0; i < cfg->web.allow_from_count; i++)
        free(cfg->web.allow_from[i]);
    free(cfg->web.allow_from);

    free(cfg->x.consumer_key);
    free(cfg->x.consumer_secret);
    free(cfg->x.access_token);
    free(cfg->x.access_token_secret);
    free(cfg->x.api_base);
    free(cfg->x.dm_policy);
    for (int i = 0; i < cfg->x.allow_from_count; i++)
        free(cfg->x.allow_from[i]);
    free(cfg->x.allow_from);

    free(cfg->signal_.account);
    free(cfg->signal_.http_host);
    free(cfg->signal_.http_url);
    free(cfg->signal_.proxy);
    free(cfg->signal_.group_trigger);
    free(cfg->signal_.dm_policy);
    for (int i = 0; i < cfg->signal_.allow_from_count; i++)
        free(cfg->signal_.allow_from[i]);
    free(cfg->signal_.allow_from);

    free(cfg->web_tools.brave_api_key);
    free(cfg->web_tools.brave_base_url);
    free(cfg->web_tools.searxng_base_url);

    for (int i = 0; i < cfg->git.push_allowed_remote_count; i++)
        free(cfg->git.push_allowed_remotes[i]);
    free(cfg->git.push_allowed_remotes);

    free(cfg->gitea.url);
    free(cfg->gitea.token);
    free(cfg->gitea.default_org);

    free(cfg->camera.snap_command);
    free(cfg->camera.events_dir);
    free(cfg->camera.vision_url);
    free(cfg->camera.vision_model);

    /* MCP */
    for (int i = 0; i < cfg->mcp.server_count; i++) {
        sc_mcp_server_config_t *s = &cfg->mcp.servers[i];
        free(s->name);
        for (int j = 0; j < s->command_count; j++)
            free(s->command[j]);
        free(s->command);
        for (int j = 0; j < s->env_count; j++) {
            free(s->env_keys[j]);
            free(s->env_values[j]);
        }
        free(s->env_keys);
        free(s->env_values);
    }
    free(cfg->mcp.servers);

    /* Delegation */
    for (int i = 0; i < cfg->delegation.target_count; i++) {
        sc_delegate_target_t *t = &cfg->delegation.targets[i];
        free(t->name);
        free(t->url);
        free(t->bearer_token);
    }
    free(cfg->delegation.targets);

    /* Updater */
    free(cfg->updater.manifest_url);

    /* Notifications */
    free(cfg->notify_urls);

#if SC_ENABLE_MOA
    free(cfg->moa.default_preset);
    for (int i = 0; i < cfg->moa.preset_count; i++) {
        sc_moa_preset_cfg_t *pr = &cfg->moa.presets[i];
        free(pr->name);
        free(pr->aggregator.provider);
        free(pr->aggregator.model);
        for (int j = 0; j < pr->reference_count; j++) {
            free(pr->reference_models[j].provider);
            free(pr->reference_models[j].model);
        }
    }
#endif

    cJSON_Delete(cfg->response_format);
    if (cfg->raw) cJSON_Delete(cfg->raw);

    free(cfg);
}
