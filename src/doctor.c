/*
 * doctor.c - Configuration and dependency validation (smolclaw doctor)
 *
 * Extracted from main.c (audit 4298ba13 / PR-9).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <curl/curl.h>

#include "sc_features.h"
#include "constants.h"
#include "config.h"
#include "doctor.h"
#include "util/str.h"
#include "util/curl_common.h"
#if SC_ENABLE_VAULT
#include "util/vault.h"
#endif

/* Check workspace directory and subdirs */
static void doctor_check_workspace(const sc_config_t *cfg, int *pass, int *fail)
{
    char *workspace = sc_config_workspace_path(cfg);
    if (!workspace) {
        DOC_FAIL(fail, "Workspace — not configured");
        return;
    }

    struct stat st;
    if (stat(workspace, &st) != 0 || !S_ISDIR(st.st_mode)) {
        DOC_FAIL(fail, "Workspace (%s) — directory not found", workspace);
        free(workspace);
        return;
    }

    DOC_PASS(pass, "Workspace (%s)", workspace);

    const char *subdirs[] = { "memory", "sessions", "state" };
    for (int i = 0; i < 3; i++) {
        sc_strbuf_t sb;
        sc_strbuf_init(&sb);
        sc_strbuf_appendf(&sb, "%s/%s", workspace, subdirs[i]);
        char *subdir = sc_strbuf_finish(&sb);
        if (stat(subdir, &st) == 0 && S_ISDIR(st.st_mode))
            DOC_PASS(pass, "  %s/", subdirs[i]);
        else
            DOC_FAIL(fail, "  %s/ — missing", subdirs[i]);
        free(subdir);
    }
    free(workspace);
}

/* Try to load vault password from env var or $SMOLCLAW_HOME/env file.
 * Returns malloc'd string or NULL. Caller must free. */
#if SC_ENABLE_VAULT
static char *doctor_load_vault_password(void)
{
    const char *env_pw = getenv("SMOLCLAW_VAULT_PASSWORD");
    if (env_pw && env_pw[0])
        return sc_strdup(env_pw);

    const char *home = getenv("SMOLCLAW_HOME");
    if (!home || !home[0]) return NULL;

    char env_path[512];
    snprintf(env_path, sizeof(env_path), "%s/env", home);
    FILE *ef = fopen(env_path, "r");
    if (!ef) return NULL;

    char *pw = NULL;
    char line[512];
    while (fgets(line, sizeof(line), ef)) {
        if (strncmp(line, "SMOLCLAW_VAULT_PASSWORD=", 24) == 0) {
            char *val = line + 24;
            size_t vlen = strlen(val);
            if (vlen > 0 && val[vlen - 1] == '\n')
                val[vlen - 1] = '\0';
            pw = sc_strdup(val);
            break;
        }
    }
    fclose(ef);
    return pw;
}

/* Try to resolve a vault:// key. Returns 1 if key exists, 0 otherwise. */
static int doctor_vault_key_exists(const char *key_name)
{
    char *vault_path = sc_vault_get_path();
    if (!vault_path || !sc_vault_exists(vault_path)) {
        free(vault_path);
        return 0;
    }
    sc_vault_t *vault = sc_vault_new(vault_path);
    free(vault_path);
    if (!vault) return 0;

    char *pw = doctor_load_vault_password();
    if (!pw) { sc_vault_free(vault); return 0; }

    int found = 0;
    if (sc_vault_unlock(vault, pw) == 0) {
        const char *val = sc_vault_get(vault, key_name);
        found = (val && val[0]);
    }
    sc_vault_free(vault);
    free(pw);
    return found;
}
#endif

/* Check API key for the configured provider */
static void doctor_check_provider(const sc_config_t *cfg, int *pass, int *fail)
{
    const char *provider = cfg->provider;
    if (!provider || !provider[0]) provider = "anthropic";

    const char *api_key = NULL;
    if (strcmp(provider, "anthropic") == 0) api_key = cfg->anthropic.api_key;
    else if (strcmp(provider, "openai") == 0) api_key = cfg->openai.api_key;
    else if (strcmp(provider, "openrouter") == 0) api_key = cfg->openrouter.api_key;
    else if (strcmp(provider, "groq") == 0) api_key = cfg->groq.api_key;
    else if (strcmp(provider, "gemini") == 0) api_key = cfg->gemini.api_key;
    else if (strcmp(provider, "deepseek") == 0) api_key = cfg->deepseek.api_key;
    else if (strcmp(provider, "xai") == 0) api_key = cfg->xai.api_key;
    else if (strcmp(provider, "zhipu") == 0) api_key = cfg->zhipu.api_key;
    else if (strcmp(provider, "ollama") == 0) api_key = "not_required";
    else if (strcmp(provider, "vllm") == 0) api_key = cfg->vllm.api_key;
    else {
        for (int i = 0; i < cfg->custom_provider_count; i++) {
            if (cfg->custom_providers[i].name &&
                strcmp(cfg->custom_providers[i].name, provider) == 0) {
                api_key = cfg->custom_providers[i].config.api_key;
                break;
            }
        }
    }

    if (api_key && api_key[0]) {
        if (strncmp(api_key, "vault://", 8) == 0) {
#if SC_ENABLE_VAULT
            const char *key_name = api_key + 8;
            if (doctor_vault_key_exists(key_name))
                DOC_PASS(pass, "API key: %s (vault, verified)", provider);
            else
                DOC_FAIL(fail, "API key: %s — vault ref '%s' unresolved "
                         "(check vault password and vault key)", provider, key_name);
#else
            DOC_FAIL(fail, "API key: %s — vault:// ref but vault feature disabled "
                     "(rebuild with SC_ENABLE_VAULT=ON or use literal key)", provider);
#endif
        } else {
            DOC_PASS(pass, "API key: %s (set)", provider);
        }
    } else {
        DOC_FAIL(fail, "API key: %s (not set)", provider);
    }
}

/* Check SMOLCLAW_HOME / ~/.smolclaw directory */
static void doctor_check_home(int *pass, int *fail)
{
    char *home = sc_get_home_dir();
    if (!home) {
        DOC_FAIL(fail, "Home directory — could not determine path");
        return;
    }

    struct stat st;
    if (stat(home, &st) != 0) {
        DOC_FAIL(fail, "Home directory (%s) — does not exist", home);
        free(home);
        return;
    }
    if (!S_ISDIR(st.st_mode)) {
        DOC_FAIL(fail, "Home directory (%s) — not a directory", home);
        free(home);
        return;
    }

    int perms = st.st_mode & 0777;
    if ((perms & 0077) != 0)
        DOC_FAIL(fail, "Home directory (%s) — permissions %04o (should be 0700)",
                 home, perms);
    else
        DOC_PASS(pass, "Home directory (%s, %04o)", home, perms);

    const char *env = getenv("SMOLCLAW_HOME");
    if (env && env[0])
        DOC_PASS(pass, "  SMOLCLAW_HOME=%s", env);

    free(home);
}

/* Check provider API connectivity (TCP connect only, no HTTP request) */
static void doctor_check_connectivity(const sc_config_t *cfg, int *pass, int *fail)
{
    const char *provider = cfg->provider;
    if (!provider || !provider[0]) provider = "anthropic";

    /* Get base URL from config or provider defaults */
    const char *base_url = NULL;
    sc_provider_config_t *pcfg = NULL;

    if (strcmp(provider, "anthropic") == 0) pcfg = (sc_provider_config_t *)&cfg->anthropic;
    else if (strcmp(provider, "openai") == 0) pcfg = (sc_provider_config_t *)&cfg->openai;
    else if (strcmp(provider, "openrouter") == 0) pcfg = (sc_provider_config_t *)&cfg->openrouter;
    else if (strcmp(provider, "groq") == 0) pcfg = (sc_provider_config_t *)&cfg->groq;
    else if (strcmp(provider, "gemini") == 0) pcfg = (sc_provider_config_t *)&cfg->gemini;
    else if (strcmp(provider, "deepseek") == 0) pcfg = (sc_provider_config_t *)&cfg->deepseek;
    else if (strcmp(provider, "xai") == 0) pcfg = (sc_provider_config_t *)&cfg->xai;
    else if (strcmp(provider, "zhipu") == 0) pcfg = (sc_provider_config_t *)&cfg->zhipu;
    else if (strcmp(provider, "ollama") == 0) pcfg = (sc_provider_config_t *)&cfg->ollama;
    else if (strcmp(provider, "vllm") == 0) pcfg = (sc_provider_config_t *)&cfg->vllm;

    if (pcfg && pcfg->api_base && pcfg->api_base[0])
        base_url = pcfg->api_base;

    /* Fall back to known defaults */
    if (!base_url) {
        if (strcmp(provider, "anthropic") == 0) base_url = "https://api.anthropic.com";
        else if (strcmp(provider, "openai") == 0) base_url = "https://api.openai.com";
        else if (strcmp(provider, "openrouter") == 0) base_url = "https://openrouter.ai";
        else if (strcmp(provider, "groq") == 0) base_url = "https://api.groq.com";
        else if (strcmp(provider, "gemini") == 0) base_url = "https://generativelanguage.googleapis.com";
        else if (strcmp(provider, "deepseek") == 0) base_url = "https://api.deepseek.com";
        else if (strcmp(provider, "xai") == 0) base_url = "https://api.x.ai";
        else if (strcmp(provider, "zhipu") == 0) base_url = "https://open.bigmodel.cn";
        else if (strcmp(provider, "ollama") == 0) base_url = "http://localhost:11434";
    }

    /* Check custom providers */
    if (!base_url) {
        for (int i = 0; i < cfg->custom_provider_count; i++) {
            if (cfg->custom_providers[i].name &&
                strcmp(cfg->custom_providers[i].name, provider) == 0 &&
                cfg->custom_providers[i].config.api_base) {
                base_url = cfg->custom_providers[i].config.api_base;
                break;
            }
        }
    }

    if (!base_url) {
        DOC_FAIL(fail, "Connectivity: %s — no base URL known", provider);
        return;
    }

    CURL *curl = sc_curl_init();
    if (!curl) {
        DOC_FAIL(fail, "Connectivity: %s — curl init failed", provider);
        return;
    }

    curl_easy_setopt(curl, CURLOPT_URL, base_url);
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res == CURLE_OK)
        DOC_PASS(pass, "Connectivity: %s (%s) — reachable", provider, base_url);
    else
        DOC_FAIL(fail, "Connectivity: %s (%s) — %s",
                 provider, base_url, curl_easy_strerror(res));
}

/* Check fallback model configuration */
static void doctor_check_fallbacks(const sc_config_t *cfg, int *pass, int *fail)
{
    if (cfg->fallback_model_count > 0) {
        sc_strbuf_t sb;
        sc_strbuf_init(&sb);
        sc_strbuf_appendf(&sb, "Fallback models: %d configured (", cfg->fallback_model_count);
        for (int i = 0; i < cfg->fallback_model_count; i++) {
            if (i > 0) sc_strbuf_append(&sb, ", ");
            sc_strbuf_append(&sb, cfg->fallback_models[i]);
        }
        sc_strbuf_append(&sb, ")");
        char *msg = sc_strbuf_finish(&sb);
        DOC_PASS(pass, "%s", msg);
        free(msg);
    } else {
        DOC_FAIL(fail, "Fallback models: none configured — single point of failure");
    }
}

/* Check channel configs */
static void doctor_check_channels(const sc_config_t *cfg, int *pass, int *fail)
{
    if (cfg->telegram.enabled) {
        if (cfg->telegram.token && cfg->telegram.token[0])
            DOC_PASS(pass, "Telegram: enabled, token set");
        else
            DOC_FAIL(fail, "Telegram: enabled but token is empty");
    }
    if (cfg->discord.enabled) {
        if (cfg->discord.token && cfg->discord.token[0])
            DOC_PASS(pass, "Discord: enabled, token set");
        else
            DOC_FAIL(fail, "Discord: enabled but token is empty");
    }
    if (cfg->irc.enabled) {
        if (cfg->irc.hostname && cfg->irc.hostname[0])
            DOC_PASS(pass, "IRC: enabled, host=%s:%d", cfg->irc.hostname, cfg->irc.port);
        else
            DOC_FAIL(fail, "IRC: enabled but hostname is empty");
    }
    if (cfg->slack.enabled) {
        if (cfg->slack.bot_token && cfg->slack.bot_token[0] &&
            cfg->slack.app_token && cfg->slack.app_token[0])
            DOC_PASS(pass, "Slack: enabled, tokens set");
        else
            DOC_FAIL(fail, "Slack: enabled but tokens missing");
    }
    if (cfg->web.enabled) {
        DOC_PASS(pass, "Web: enabled on %s:%d", cfg->web.bind_addr, cfg->web.port);
    }
}

#if SC_ENABLE_VAULT
static void doctor_check_vault(const sc_config_t *cfg, int *pass, int *fail)
{
    char *vault_path = sc_vault_get_path();

    char **ref_keys = NULL;
    int ref_count = sc_config_collect_vault_keys(cfg, &ref_keys);

    if (ref_count == 0) {
        if (sc_vault_exists(vault_path)) {
            struct stat vst;
            if (stat(vault_path, &vst) == 0 && (vst.st_mode & 0077) == 0)
                DOC_PASS(pass, "Vault: %s (0600, no refs in config)", vault_path);
            else
                DOC_FAIL(fail, "Vault: %s (permissions too open)", vault_path);
        } else {
            DOC_PASS(pass, "Vault: not initialized (no refs in config)");
        }
        free(vault_path);
        return;
    }

    /* Config has vault:// references — vault is required */
    if (!sc_vault_exists(vault_path)) {
        DOC_FAIL(fail, "Vault: %s — not found (config has %d vault:// ref%s)",
                 vault_path, ref_count, ref_count > 1 ? "s" : "");
        for (int i = 0; i < ref_count; i++) {
            DOC_FAIL(fail, "  vault key '%s' — vault missing", ref_keys[i]);
            free(ref_keys[i]);
        }
        free(ref_keys);
        free(vault_path);
        return;
    }

    struct stat vst;
    if (stat(vault_path, &vst) == 0 && (vst.st_mode & 0077) != 0)
        DOC_FAIL(fail, "Vault: %s (permissions too open: %04o)",
                 vault_path, vst.st_mode & 0777);
    else
        DOC_PASS(pass, "Vault: %s (0600)", vault_path);

    /* Try to unlock and verify referenced keys */
    sc_vault_t *vault = sc_vault_new(vault_path);
    free(vault_path);
    if (!vault) {
        DOC_FAIL(fail, "Vault: failed to open");
        for (int i = 0; i < ref_count; i++) free(ref_keys[i]);
        free(ref_keys);
        return;
    }

    char *loaded_pw = doctor_load_vault_password();
    if (!loaded_pw) {
        DOC_FAIL(fail, "Vault: SMOLCLAW_VAULT_PASSWORD not set — cannot verify %d key%s",
                 ref_count, ref_count > 1 ? "s" : "");
        sc_vault_free(vault);
        for (int i = 0; i < ref_count; i++) free(ref_keys[i]);
        free(ref_keys);
        free(loaded_pw);
        return;
    }

    if (sc_vault_unlock(vault, loaded_pw) != 0) {
        DOC_FAIL(fail, "Vault: unlock failed (wrong password or corrupted)");
        sc_vault_free(vault);
        for (int i = 0; i < ref_count; i++) free(ref_keys[i]);
        free(ref_keys);
        free(loaded_pw);
        return;
    }

    DOC_PASS(pass, "Vault: unlocked (%d ref%s to check)",
             ref_count, ref_count > 1 ? "s" : "");

    for (int i = 0; i < ref_count; i++) {
        const char *val = sc_vault_get(vault, ref_keys[i]);
        if (val && val[0])
            DOC_PASS(pass, "  vault key '%s' — present", ref_keys[i]);
        else
            DOC_FAIL(fail, "  vault key '%s' — MISSING from vault", ref_keys[i]);
        free(ref_keys[i]);
    }
    free(ref_keys);
    sc_vault_free(vault);
    free(loaded_pw);
}
#endif

/* Run all doctor checks. Returns loaded config (caller must free) or NULL.
 * Populates *out_pass and *out_fail with check counts. */
sc_config_t *sc_run_doctor_checks(int argc, char **argv,
                                       int *out_pass, int *out_fail)
{
    int pass = 0, fail = 0;

    /* Parse --config <path> flag */
    char *config_path = NULL;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_path = sc_strdup(argv[++i]);
            break;
        }
    }
    if (!config_path)
        config_path = sc_config_get_path();

    /* 1. Config file */
    if (!config_path) {
        DOC_FAIL(&fail, "Could not determine config path");
        *out_pass = pass; *out_fail = fail;
        return NULL;
    }

    sc_config_t *cfg = sc_config_load(config_path);
    if (cfg) {
        DOC_PASS(&pass, "Config file (%s)", config_path);
    } else {
        DOC_FAIL(&fail, "Config file (%s) — not found or invalid", config_path);
        free(config_path);
        *out_pass = pass; *out_fail = fail;
        return NULL;
    }
    free(config_path);

    /* 2. Home directory */
    doctor_check_home(&pass, &fail);

    /* 3. Workspace */
    doctor_check_workspace(cfg, &pass, &fail);

    /* 4. Model */
    if (cfg->model && cfg->model[0])
        DOC_PASS(&pass, "Model: %s", cfg->model);
    else
        DOC_FAIL(&fail, "Model — not configured");

    /* 5. Provider API key */
    doctor_check_provider(cfg, &pass, &fail);

    /* 6. Fallback models */
    doctor_check_fallbacks(cfg, &pass, &fail);

    /* 7. Provider connectivity */
    doctor_check_connectivity(cfg, &pass, &fail);

    /* 8. Channel configs */
    doctor_check_channels(cfg, &pass, &fail);

    /* 9. Vault */
#if SC_ENABLE_VAULT
    doctor_check_vault(cfg, &pass, &fail);
#endif

    /* 10. Updater */
#if SC_ENABLE_UPDATER
    if (cfg->updater.enabled) {
        if (cfg->updater.manifest_url && cfg->updater.manifest_url[0])
            DOC_PASS(&pass, "Updater: manifest_url configured");
        else
            DOC_FAIL(&fail, "Updater: enabled but manifest_url not set");

        /* Check binary path writable */
        if (access("/proc/self/exe", F_OK) == 0) {
            char bin[4096];
            ssize_t len = readlink("/proc/self/exe", bin, sizeof(bin) - 1);
            if (len > 0) {
                bin[len] = '\0';
                if (access(bin, W_OK) == 0)
                    DOC_PASS(&pass, "Updater: binary writable (%s)", bin);
                else
                    DOC_FAIL(&fail, "Updater: binary not writable (%s)", bin);
            }
        }
    }
#endif

    /* 11. System info */
    DOC_PASS(&pass, "libcurl %s", curl_version());
#if SC_ENABLE_VAULT || SC_ENABLE_DISCORD || SC_ENABLE_IRC || SC_ENABLE_UPDATER
    DOC_PASS(&pass, "OpenSSL linked");
#endif

    *out_pass = pass;
    *out_fail = fail;
    return cfg;
}

int sc_cmd_doctor(int argc, char **argv)
{
    int pass = 0, fail = 0;
    printf("%s doctor\n", SC_NAME);

    sc_config_t *cfg = sc_run_doctor_checks(argc, argv, &pass, &fail);
    printf("\n  %d passed, %d failed\n", pass, fail);
    sc_config_free(cfg);
    return fail > 0 ? 1 : 0;
}
