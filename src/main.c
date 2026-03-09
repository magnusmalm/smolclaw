/*
 * smolclaw - main entry point
 * CLI interface: version, onboard, agent, gateway commands.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include <event2/event.h>

#include "sc_features.h"
#include "constants.h"
#include "config.h"
#include "logger.h"
#include "agent.h"
#include "bus.h"
#include "pairing.h"
#include "workspace.h"
#include "channels/manager.h"
#include "channels/cli.h"
#include "tools/message.h"
#include "audit.h"
#include "providers/factory.h"
#include "util/str.h"

#if SC_ENABLE_CRON
#include "cron/service.h"
#include "tools/cron.h"
#endif
#if SC_ENABLE_HEARTBEAT
#include "heartbeat/service.h"
#endif
#if SC_ENABLE_VAULT
#include "util/vault.h"
#endif
#if SC_ENABLE_UPDATER
#include "updater/updater.h"
#include "updater/transport_http.h"
#endif
#include "cost.h"
#include "backup.h"
#if SC_ENABLE_ANALYTICS
#include "analytics.h"
#endif
#include <curl/curl.h>

/* Global for signal handling */
static volatile sig_atomic_t g_shutdown = 0;
static volatile sig_atomic_t g_reload_config = 0;
static int g_wakeup_fd = -1; /* inbound pipe write end, for signal handler */

int sc_shutdown_requested(void) { return g_shutdown; }

static void signal_handler(int sig)
{
    (void)sig;
    g_shutdown = 1;
    /* Wake up blocking read() in sc_bus_consume_inbound().
     * SIGTERM may be delivered to any thread; writing to the pipe
     * ensures the main thread unblocks regardless. write() is
     * async-signal-safe. */
    if (g_wakeup_fd >= 0) {
        char c = 0;
        (void)write(g_wakeup_fd, &c, 1);
    }
}

static void sighup_handler(int sig)
{
    (void)sig;
    g_reload_config = 1;
    /* Wake the main loop so it processes the reload promptly */
    if (g_wakeup_fd >= 0) {
        char c = 0;
        (void)write(g_wakeup_fd, &c, 1);
    }
}

static void install_signal(int signo, void (*handler)(int))
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sa.sa_flags = SA_RESTART;
    sigemptyset(&sa.sa_mask);
    sigaction(signo, &sa, NULL);
}

/* Load config, exit if NULL (strict security mode rejects version mismatch) */
static sc_config_t *load_config_or_exit(void)
{
    char *path = sc_config_get_path();
    sc_config_t *cfg = sc_config_load(path);
    free(path);
    if (!cfg) {
        fprintf(stderr, "Fatal: could not load config\n");
        exit(1);
    }
    return cfg;
}

static void print_version(void)
{
    printf("%s %s %s (%s, %s)\n", SC_LOGO, SC_NAME, SC_VERSION,
           SC_GIT_HASH, SC_BUILD_DATE);
}

static int cmd_backup(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s backup <create|verify|list|restore> [options]\n", SC_NAME);
        return 1;
    }
    const char *sub = argv[2];

    if (strcmp(sub, "create") == 0) {
        int config_only = 0, include_sessions = 0;
        const char *name = NULL;
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--config-only") == 0) config_only = 1;
            else if (strcmp(argv[i], "--include-sessions") == 0) include_sessions = 1;
            else if (strcmp(argv[i], "--name") == 0 && i + 1 < argc) name = argv[++i];
        }
        char *result = sc_backup_create(name, config_only, include_sessions);
        if (!result) return 1;
        printf("%s\n", result);
        free(result);
        return 0;
    } else if (strcmp(sub, "verify") == 0) {
        const char *name = (argc > 3) ? argv[3] : NULL;
        return sc_backup_verify(name) == 0 ? 0 : 1;
    } else if (strcmp(sub, "list") == 0) {
        return sc_backup_list() >= 0 ? 0 : 1;
    } else if (strcmp(sub, "restore") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s backup restore <name> [--dry-run]\n", SC_NAME);
            return 1;
        }
        int dry_run = 0;
        for (int i = 4; i < argc; i++)
            if (strcmp(argv[i], "--dry-run") == 0) dry_run = 1;
        return sc_backup_restore(argv[3], dry_run);
    }
    fprintf(stderr, "Unknown backup subcommand: %s\n", sub);
    return 1;
}

#if SC_ENABLE_STREAMING
/* Streaming callback: print text deltas to stdout as they arrive */
static void stream_print_cb(const char *delta, void *ctx)
{
    (void)ctx;
    if (delta) {
        fputs(delta, stdout);
        fflush(stdout);
    }
}
#endif

static void print_help(void)
{
    printf("%s %s - Personal AI Assistant v%s\n\n", SC_LOGO, SC_NAME, SC_VERSION);
    printf("Usage: %s <command>\n\n", SC_NAME);
    printf("Commands:\n");
    printf("  onboard     Initialize configuration and workspace\n");
    printf("  agent       Interact with the agent directly\n");
    printf("  gateway     Start gateway (channels + agent + services)\n");
    printf("  pairing     Manage channel pairing requests\n");
    printf("  cost        View token usage and costs\n");
    printf("  doctor      Validate configuration and dependencies\n");
    printf("              --config <path>  Validate a specific config file\n");
#if SC_ENABLE_VAULT
    printf("  vault       Manage encrypted secret vault\n");
#endif
#if SC_ENABLE_UPDATER
    printf("  update      Check for and apply updates\n");
#endif
    printf("  backup      Backup and restore state\n");
    printf("              create [--config-only] [--include-sessions] [--name TAG]\n");
    printf("              verify [NAME]    list    restore NAME [--dry-run]\n");
    printf("  version     Show version information\n");
}

#if SC_ENABLE_HEARTBEAT
/* Heartbeat handler callback */
static char *heartbeat_handler(const char *prompt, const char *channel,
                                const char *chat_id, void *ctx)
{
    sc_agent_t *agent = ctx;
    if (!agent) return NULL;

    const char *ch = (channel && channel[0]) ? channel : SC_CHANNEL_CLI;
    const char *cid = (chat_id && chat_id[0]) ? chat_id : "direct";

    return sc_agent_process_heartbeat(agent, prompt, ch, cid);
}
#endif

/* Resolve a channel name to its allow_from list and count in the config.
 * Returns 1 if found, 0 if unknown channel. */
static int get_allow_from_for_channel(sc_config_t *cfg, const char *channel,
                                       char ****allow_from, int **count)
{
    if (strcmp(channel, "telegram") == 0) {
        *allow_from = &cfg->telegram.allow_from;
        *count = &cfg->telegram.allow_from_count;
    } else if (strcmp(channel, "discord") == 0) {
        *allow_from = &cfg->discord.allow_from;
        *count = &cfg->discord.allow_from_count;
    } else if (strcmp(channel, "irc") == 0) {
        *allow_from = &cfg->irc.allow_from;
        *count = &cfg->irc.allow_from_count;
    } else if (strcmp(channel, "slack") == 0) {
        *allow_from = &cfg->slack.allow_from;
        *count = &cfg->slack.allow_from_count;
    } else {
        return 0;
    }
    return 1;
}

static void cmd_pairing_list(sc_pairing_store_t *ps, const char *channel)
{
    sc_pairing_request_t *reqs;
    int count = sc_pairing_store_list(ps, &reqs);
    if (count == 0) {
        printf("No pending pairing requests for %s\n", channel);
    } else {
        printf("Pending pairing requests for %s:\n", channel);
        for (int i = 0; i < count; i++) {
            printf("  %s  sender=%s\n", reqs[i].code, reqs[i].sender_id);
        }
    }
}

static void cmd_pairing_approve(sc_pairing_store_t *ps, const char *channel,
                                  const char *code)
{
    char *sender_id = sc_pairing_store_approve(ps, code);
    if (!sender_id) {
        fprintf(stderr, "Error: no pending request with code %s\n", code);
        return;
    }

    printf("Approved: %s\n", sender_id);

    char *config_path = sc_config_get_path();
    sc_config_t *cfg = sc_config_load(config_path);
    if (cfg) {
        char ***allow_from = NULL;
        int *count = NULL;

        if (get_allow_from_for_channel(cfg, channel, &allow_from, &count) &&
            allow_from && count) {
            char **new_list = realloc(*allow_from,
                (size_t)(*count + 1) * sizeof(char *));
            if (new_list) {
                new_list[*count] = sender_id;
                sender_id = NULL; /* ownership transferred */
                *allow_from = new_list;
                (*count)++;
            }

            if (sc_config_save(config_path, cfg) == 0) {
                printf("Config updated: %s added to %s allow_from\n",
                       new_list[*count - 1], channel);
            } else {
                fprintf(stderr, "Warning: could not save config\n");
            }
        }

        sc_config_free(cfg);
    }
    free(config_path);
    free(sender_id);
}

static void cmd_pairing_revoke(const char *channel, const char *user_id)
{
    char *config_path = sc_config_get_path();
    sc_config_t *cfg = sc_config_load(config_path);

    char ***allow_from = NULL;
    int *count = NULL;

    if (!get_allow_from_for_channel(cfg, channel, &allow_from, &count) ||
        !count || *count == 0) {
        fprintf(stderr, "No allow_from list for channel %s\n", channel);
        sc_config_free(cfg);
        free(config_path);
        return;
    }

    int found = 0;
    for (int i = 0; i < *count; i++) {
        if ((*allow_from)[i] && strcmp((*allow_from)[i], user_id) == 0) {
            free((*allow_from)[i]);
            for (int j = i; j < *count - 1; j++)
                (*allow_from)[j] = (*allow_from)[j + 1];
            (*count)--;
            found = 1;
            break;
        }
    }

    if (!found) {
        fprintf(stderr, "User '%s' not found in %s allow_from\n", user_id, channel);
    } else if (sc_config_save(config_path, cfg) == 0) {
        printf("Revoked: %s removed from %s allow_from\n", user_id, channel);
    } else {
        fprintf(stderr, "Warning: could not save config\n");
    }

    sc_config_free(cfg);
    free(config_path);
}

static void cmd_pairing(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "Usage: %s pairing <list|approve|revoke> <channel> [code|user_id]\n", SC_NAME);
        return;
    }

    const char *action = argv[2];
    const char *channel = argv[3];

    char *store_dir = sc_expand_home("~/.smolclaw/pairing");
    sc_pairing_store_t *ps = sc_pairing_store_new(channel, store_dir);
    free(store_dir);

    if (!ps) {
        fprintf(stderr, "Error: could not open pairing store for %s\n", channel);
        return;
    }

    if (strcmp(action, "list") == 0)
        cmd_pairing_list(ps, channel);
    else if (strcmp(action, "approve") == 0 && argc >= 5)
        cmd_pairing_approve(ps, channel, argv[4]);
    else if (strcmp(action, "revoke") == 0 && argc >= 5)
        cmd_pairing_revoke(channel, argv[4]);
    else
        fprintf(stderr, "Unknown pairing action: %s (use list, approve, or revoke)\n", action);

    sc_pairing_store_free(ps);
}

static void cmd_onboard(void)
{
    char *config_path = sc_config_get_path();
    if (!config_path) {
        fprintf(stderr, "Error: could not determine config path\n");
        return;
    }

    /* Check if config exists */
    struct stat st;
    if (stat(config_path, &st) == 0) {
        printf("Config already exists at %s\n", config_path);
        printf("Overwrite? (y/n): ");
        char resp[16];
        if (!fgets(resp, sizeof(resp), stdin) || resp[0] != 'y') {
            printf("Aborted.\n");
            free(config_path);
            return;
        }
    }

    /* Create default config */
    sc_config_t *cfg = sc_config_default();
    if (!cfg) {
        fprintf(stderr, "Error: could not create default config\n");
        free(config_path);
        return;
    }

    if (sc_config_save(config_path, cfg) != 0) {
        fprintf(stderr, "Error: could not save config to %s\n", config_path);
        sc_config_free(cfg);
        free(config_path);
        return;
    }

    /* Extract workspace templates */
    char *workspace = sc_config_workspace_path(cfg);
    if (workspace) {
        mkdir(workspace, 0755);
        sc_workspace_extract(workspace);
        free(workspace);
    }

    printf("%s %s is ready!\n\n", SC_LOGO, SC_NAME);
    printf("Next steps:\n");
    printf("  1. Add your API key to %s\n", config_path);
    printf("  2. Chat: %s agent -m \"Hello!\"\n", SC_NAME);

    sc_config_free(cfg);
    free(config_path);
}

/* Run interactive CLI loop: prompt, read, process, print.
 * Returns on exit/quit, EOF, or g_shutdown. */
static void agent_interactive_loop(sc_agent_t *agent, sc_bus_t *bus,
                                    const char *session_key, int no_stream)
{
    sc_channel_t *cli = sc_channel_cli_new(bus);
    if (!cli) return;

    cli->start(cli);
    sc_bus_set_outbound_handler(bus, NULL, NULL);

    printf("%s Interactive mode (Ctrl+C to exit)\n\n", SC_LOGO);

    while (!g_shutdown) {
        char buf[4096];
        printf("You: ");
        fflush(stdout);
        if (!fgets(buf, sizeof(buf), stdin)) break;

        char *trimmed = sc_trim(buf);
        if (!trimmed || trimmed[0] == '\0') { free(trimmed); continue; }
        if (strcmp(trimmed, "exit") == 0 || strcmp(trimmed, "quit") == 0) {
            free(trimmed);
            printf("Goodbye!\n");
            break;
        }

        if (!no_stream) printf("\n%s ", SC_LOGO);
        char *response = sc_agent_process_direct(agent, trimmed, session_key);
        free(trimmed);

        if (response) {
            if (no_stream)
                printf("\n%s %s\n\n", SC_LOGO, response);
            else
                printf("\n\n");
            free(response);
        }
    }

    cli->destroy(cli);
}

static void cmd_agent(int argc, char **argv)
{
    const char *message = NULL;
    const char *session_key = "cli:default";
    int no_stream = 0;

    /* Parse flags */
    for (int i = 2; i < argc; i++) {
        if ((strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--message") == 0) && i + 1 < argc) {
            message = argv[++i];
        } else if ((strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--session") == 0) && i + 1 < argc) {
            session_key = argv[++i];
        } else if (strcmp(argv[i], "--debug") == 0 || strcmp(argv[i], "-d") == 0) {
            sc_logger_set_level(SC_LOG_DEBUG);
        } else if (strcmp(argv[i], "--no-stream") == 0) {
            no_stream = 1;
        }
    }

    /* Load config */
    sc_config_t *cfg = load_config_or_exit();

    /* Open persistent log file if configured */
    if (cfg->log_path)
        sc_logger_set_file(cfg->log_path);

    /* Create provider */
    sc_provider_t *provider = sc_provider_create(cfg);
    if (!provider) {
        fprintf(stderr, "Error: could not create provider\n");
        sc_config_free(cfg);
        return;
    }

    /* Create event base and bus */
    struct event_base *base = event_base_new();
    sc_bus_t *bus = sc_bus_create(base);

    /* Create agent */
    sc_agent_t *agent = sc_agent_new(cfg, bus, provider);
    if (!agent) {
        fprintf(stderr, "Error: could not create agent\n");
        sc_bus_destroy(bus);
        event_base_free(base);
        sc_config_free(cfg);
        return;
    }

    /* Wire SIGINT so Ctrl+C sets g_shutdown for mid-turn abort */
    install_signal(SIGINT, signal_handler);

    /* Set CLI confirmation callback for dangerous tools */
    sc_tool_registry_set_confirm(agent->tools, sc_cli_confirm_tool, NULL);

    /* Wire allowlist from config */
    if (cfg->allowed_tools && cfg->allowed_tool_count > 0) {
        sc_tool_registry_set_allowed(agent->tools, cfg->allowed_tools,
                                      cfg->allowed_tool_count);
    }

    /* Enable streaming for CLI mode */
#if SC_ENABLE_STREAMING
    if (!no_stream)
        sc_agent_set_stream_cb(agent, stream_print_cb, NULL);
#else
    no_stream = 1;
#endif

    if (message) {
        /* Single message mode */
        if (!no_stream) printf("\n%s ", SC_LOGO);
        char *response = sc_agent_process_direct(agent, message, session_key);
        if (response) {
            if (no_stream)
                printf("\n%s %s\n", SC_LOGO, response);
            else
                printf("\n"); /* Streaming already printed content */
            free(response);
        }
    } else {
        agent_interactive_loop(agent, bus, session_key, no_stream);
    }

    sc_agent_free(agent);
    sc_bus_destroy(bus);
    event_base_free(base);
    sc_config_free(cfg);
}

/* Typing indicator thread context */
typedef struct {
    sc_channel_manager_t *mgr;
    const char *channel;
    const char *chat_id;
    int running;
} typing_ctx_t;

static void *typing_thread_fn(void *arg)
{
    typing_ctx_t *ctx = arg;
    while (ctx->running) {
        sc_channel_manager_send_typing(ctx->mgr, ctx->channel, ctx->chat_id);
        /* Sleep 4 seconds in 100ms increments, checking running flag */
        for (int i = 0; i < 40 && ctx->running; i++)
            usleep(100000);
    }
    return NULL;
}

#if SC_ENABLE_VAULT

/* Create a new vault with password confirmation */
static void vault_cmd_init(const char *vault_path, int argc, char **argv)
{
    if (sc_vault_exists(vault_path)) {
        fprintf(stderr, "Vault already exists at %s\n", vault_path);
        return;
    }

    /* Check for --password-stdin flag */
    int password_stdin = 0;
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--password-stdin") == 0) {
            password_stdin = 1;
            break;
        }
    }

    char *pw1 = NULL;
    char *pw2 = NULL;

    if (password_stdin) {
        char buf[256];
        if (!fgets(buf, sizeof(buf), stdin) || buf[0] == '\n') {
            fprintf(stderr, "Password cannot be empty\n");
            return;
        }
        /* Strip trailing newline */
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n')
            buf[len - 1] = '\0';
        pw1 = sc_strdup(buf);
        memset(buf, 0, sizeof(buf));
    } else {
        pw1 = sc_vault_prompt_password("New vault password: ");
        if (!pw1 || pw1[0] == '\0') {
            fprintf(stderr, "Password cannot be empty\n");
            sc_vault_free_password(pw1);
            return;
        }

        pw2 = sc_vault_prompt_password("Confirm password: ");
        if (!pw2 || strcmp(pw1, pw2) != 0) {
            fprintf(stderr, "Passwords do not match\n");
            sc_vault_free_password(pw1);
            sc_vault_free_password(pw2);
            return;
        }
    }

    sc_vault_t *v = sc_vault_new(vault_path);
    if (sc_vault_init(v, pw1) == 0) {
        printf("Vault created at %s\n", vault_path);
        printf("\nUse vault:// references in config.json:\n");
        printf("  \"api_key\": \"vault://anthropic_api_key\"\n");
    } else {
        fprintf(stderr, "Failed to create vault\n");
    }

    sc_vault_free(v);
    sc_vault_free_password(pw1);
    sc_vault_free_password(pw2);
}

/* Load vault, prompt for password, unlock.
 * Returns unlocked vault or NULL on failure (prints errors). Caller frees. */
static sc_vault_t *vault_load_and_unlock(const char *vault_path)
{
    if (!sc_vault_exists(vault_path)) {
        fprintf(stderr, "No vault found. Run: %s vault init\n", SC_NAME);
        return NULL;
    }

    sc_vault_t *v = sc_vault_new(vault_path);

    const char *env_pw = getenv("SMOLCLAW_VAULT_PASSWORD");
    char *prompted_pw = NULL;
    const char *password = env_pw;

    if (!password || password[0] == '\0') {
        prompted_pw = sc_vault_prompt_password("Vault password: ");
        password = prompted_pw;
    }

    if (!password || sc_vault_unlock(v, password) != 0) {
        fprintf(stderr, "Failed to unlock vault (wrong password?)\n");
        sc_vault_free(v);
        sc_vault_free_password(prompted_pw);
        return NULL;
    }

    sc_vault_free_password(prompted_pw);

    return v;
}

static void vault_cmd_set(sc_vault_t *v, int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "Usage: %s vault set <key> [--value-stdin]\n", SC_NAME);
        return;
    }

    /* Check for --value-stdin flag */
    int value_stdin = 0;
    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "--value-stdin") == 0) {
            value_stdin = 1;
            break;
        }
    }

    char *value = NULL;
    if (value_stdin) {
        char buf[4096];
        if (fgets(buf, sizeof(buf), stdin) && buf[0] != '\0' && buf[0] != '\n') {
            size_t len = strlen(buf);
            if (len > 0 && buf[len - 1] == '\n')
                buf[len - 1] = '\0';
            value = sc_strdup(buf);
            memset(buf, 0, sizeof(buf));
        }
    } else {
        value = sc_vault_prompt_password("Secret value: ");
    }

    if (value && value[0] != '\0') {
        sc_vault_set(v, argv[3], value);
        if (sc_vault_save(v) == 0)
            printf("Stored '%s'\n", argv[3]);
        else
            fprintf(stderr, "Failed to save vault\n");
    } else {
        fprintf(stderr, "Value cannot be empty\n");
    }
    sc_vault_free_password(value);
}

static void vault_cmd_get(sc_vault_t *v, int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "Usage: %s vault get <key>\n", SC_NAME);
        return;
    }
    const char *val = sc_vault_get(v, argv[3]);
    if (val)
        printf("%s\n", val);
    else
        fprintf(stderr, "Key '%s' not found\n", argv[3]);
}

static void vault_cmd_list(sc_vault_t *v)
{
    char **keys = NULL;
    int count = sc_vault_list(v, &keys);
    if (count == 0) {
        printf("Vault is empty\n");
    } else {
        for (int i = 0; i < count; i++) {
            printf("  %s\n", keys[i]);
            free(keys[i]);
        }
        free(keys);
    }
}

static void vault_cmd_remove(sc_vault_t *v, int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "Usage: %s vault remove <key>\n", SC_NAME);
        return;
    }
    if (sc_vault_remove(v, argv[3]) == 0) {
        if (sc_vault_save(v) == 0)
            printf("Removed '%s'\n", argv[3]);
        else
            fprintf(stderr, "Failed to save vault\n");
    } else {
        fprintf(stderr, "Key '%s' not found\n", argv[3]);
    }
}

static void vault_cmd_export(sc_vault_t *v)
{
    char **keys = NULL;
    int count = sc_vault_list(v, &keys);
    for (int i = 0; i < count; i++) {
        const char *val = sc_vault_get(v, keys[i]);
        printf("%s=%s\n", keys[i], val ? val : "");
        free(keys[i]);
    }
    free(keys);
}

static void vault_cmd_change_password(sc_vault_t *v)
{
    char *new_pw1 = sc_vault_prompt_password("New password: ");
    if (!new_pw1 || new_pw1[0] == '\0') {
        fprintf(stderr, "Password cannot be empty\n");
        sc_vault_free_password(new_pw1);
        return;
    }
    char *new_pw2 = sc_vault_prompt_password("Confirm new password: ");
    if (new_pw2 && strcmp(new_pw1, new_pw2) == 0) {
        if (sc_vault_change_password(v, new_pw1) == 0)
            printf("Password changed successfully\n");
        else
            fprintf(stderr, "Failed to change password\n");
    } else {
        fprintf(stderr, "Passwords do not match\n");
    }
    sc_vault_free_password(new_pw1);
    sc_vault_free_password(new_pw2);
}

static void cmd_vault(int argc, char **argv)
{
    if (argc < 3) {
        printf("Usage: %s vault <subcommand>\n\n", SC_NAME);
        printf("Subcommands:\n");
        printf("  init                       Create a new encrypted vault\n");
        printf("    --password-stdin         Read password from stdin (non-interactive)\n");
        printf("  set <key>                  Store a secret (prompts for value)\n");
        printf("    --value-stdin            Read value from stdin (non-interactive)\n");
        printf("  get <key>                  Print a decrypted secret\n");
        printf("  list                       List stored key names\n");
        printf("  remove <key>               Remove a secret\n");
        printf("  export                     Print all key=value pairs\n");
        printf("  change-password            Re-encrypt with a new password\n");
        return;
    }

    const char *subcmd = argv[2];
    char *vault_path = sc_vault_get_path();

    if (strcmp(subcmd, "init") == 0) {
        vault_cmd_init(vault_path, argc, argv);
        free(vault_path);
        return;
    }

    sc_vault_t *v = vault_load_and_unlock(vault_path);
    free(vault_path);
    if (!v) return;

    if      (strcmp(subcmd, "set") == 0)             vault_cmd_set(v, argc, argv);
    else if (strcmp(subcmd, "get") == 0)             vault_cmd_get(v, argc, argv);
    else if (strcmp(subcmd, "list") == 0)            vault_cmd_list(v);
    else if (strcmp(subcmd, "remove") == 0)          vault_cmd_remove(v, argc, argv);
    else if (strcmp(subcmd, "export") == 0)          vault_cmd_export(v);
    else if (strcmp(subcmd, "change-password") == 0) vault_cmd_change_password(v);
    else fprintf(stderr, "Unknown vault subcommand: %s\n", subcmd);

    sc_vault_free(v);
}
#endif /* SC_ENABLE_VAULT */

static void cmd_cost(int argc, char **argv)
{
    sc_config_t *cfg = load_config_or_exit();

    char *workspace = sc_config_workspace_path(cfg);
    sc_cost_tracker_t *ct = sc_cost_tracker_new(workspace);
    free(workspace);
    sc_config_free(cfg);

    if (!ct) {
        fprintf(stderr, "Error: could not initialize cost tracker\n");
        return;
    }

    int do_reset = 0;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--reset") == 0 || strcmp(argv[i], "-r") == 0)
            do_reset = 1;
    }

    if (do_reset)
        sc_cost_tracker_reset(ct);
    else
        sc_cost_tracker_print_summary(ct);

    sc_cost_tracker_free(ct);
}

#if SC_ENABLE_ANALYTICS
static void cmd_analytics(int argc, char **argv)
{
    sc_config_t *cfg = load_config_or_exit();

    char *workspace = sc_config_workspace_path(cfg);
    sc_analytics_t *a = sc_analytics_new(workspace);
    free(workspace);
    sc_config_free(cfg);

    if (!a) {
        fprintf(stderr, "Error: could not initialize analytics\n");
        return;
    }

    const char *subcmd = (argc >= 3) ? argv[2] : "summary";
    char *output = NULL;

    if (strcmp(subcmd, "summary") == 0)       output = sc_analytics_summary(a);
    else if (strcmp(subcmd, "today") == 0)     output = sc_analytics_today(a);
    else if (strcmp(subcmd, "week") == 0)      output = sc_analytics_period(a, 7);
    else if (strcmp(subcmd, "month") == 0)     output = sc_analytics_period(a, 30);
    else if (strcmp(subcmd, "model") == 0)     output = sc_analytics_by_model(a, 30);
    else if (strcmp(subcmd, "channel") == 0)   output = sc_analytics_by_channel(a, 30);
    else if (strcmp(subcmd, "reset") == 0) {
        sc_analytics_reset(a);
        printf("Analytics data reset.\n");
    } else {
        fprintf(stderr, "Unknown analytics subcommand: %s\n"
                "Usage: %s analytics [summary|today|week|month|model|channel|reset]\n",
                subcmd, SC_NAME);
    }

    if (output) {
        printf("%s", output);
        free(output);
    }

    sc_analytics_free(a);
}
#endif /* SC_ENABLE_ANALYTICS */

#if SC_ENABLE_UPDATER
static void cmd_update(int argc, char **argv)
{
    const char *subcmd = (argc >= 3) ? argv[2] : "check";

    if (strcmp(subcmd, "rollback") == 0) {
        if (sc_updater_rollback() == 0)
            printf("Rolled back to previous binary\n");
        else
            fprintf(stderr, "Rollback failed\n");
        return;
    }

    /* Load config for manifest URL */
    sc_config_t *cfg = load_config_or_exit();

    if (!cfg->updater.manifest_url || !cfg->updater.manifest_url[0]) {
        fprintf(stderr, "Error: updater.manifest_url not configured\n");
        sc_config_free(cfg);
        return;
    }

    sc_update_transport_t *transport =
        sc_update_transport_http_new(cfg->updater.manifest_url);
    sc_updater_t *updater = sc_updater_new(transport);
    if (!updater) {
        fprintf(stderr, "Error: could not create updater\n");
        sc_config_free(cfg);
        return;
    }

    if (strcmp(subcmd, "check") == 0) {
        printf("Checking for updates...\n");
        sc_update_manifest_t *m = sc_updater_check(updater);
        if (m) {
            printf("Update available: %s -> %s\n", SC_VERSION, m->latest);
            if (m->changelog)
                printf("Changelog: %s\n", m->changelog);
            printf("\nRun '%s update apply' to install\n", SC_NAME);
            sc_update_manifest_free(m);
        } else {
            printf("Already up to date (%s)\n", SC_VERSION_FULL);
        }
    } else if (strcmp(subcmd, "apply") == 0) {
        printf("Checking for updates...\n");
        sc_update_manifest_t *m = sc_updater_check(updater);
        if (!m) {
            printf("Already up to date (%s)\n", SC_VERSION_FULL);
        } else {
            printf("Downloading %s...\n", m->latest);
            sc_fetch_result_t *r = sc_updater_download(updater, m);
            if (r && r->success) {
                printf("Applying update...\n");
                if (sc_updater_apply(r->path) == 0) {
                    printf("Updated to %s. Restart to use the new version.\n",
                           m->latest);
                } else {
                    fprintf(stderr, "Apply failed\n");
                }
            } else {
                fprintf(stderr, "Download failed: %s\n",
                        (r && r->error) ? r->error : "unknown error");
            }
            sc_fetch_result_free(r);
            sc_update_manifest_free(m);
        }
    } else {
        fprintf(stderr, "Usage: %s update [check|apply|rollback]\n", SC_NAME);
    }

    sc_updater_free(updater);
    sc_config_free(cfg);
}
#endif /* SC_ENABLE_UPDATER */

/* Doctor helper macros — used by check functions */
#define DOC_PASS(pass, ...) do { \
    printf("  \033[32m[PASS]\033[0m "); printf(__VA_ARGS__); printf("\n"); (*(pass))++; \
} while(0)
#define DOC_FAIL(fail, ...) do { \
    printf("  \033[31m[FAIL]\033[0m "); printf(__VA_ARGS__); printf("\n"); (*(fail))++; \
} while(0)

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

    if (api_key && api_key[0])
        DOC_PASS(pass, "API key: %s (set)", provider);
    else
        DOC_FAIL(fail, "API key: %s (not set)", provider);
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

    const char *env_pw = getenv("SMOLCLAW_VAULT_PASSWORD");
    if (!env_pw || env_pw[0] == '\0') {
        DOC_FAIL(fail, "Vault: SMOLCLAW_VAULT_PASSWORD not set — cannot verify %d key%s",
                 ref_count, ref_count > 1 ? "s" : "");
        sc_vault_free(vault);
        for (int i = 0; i < ref_count; i++) free(ref_keys[i]);
        free(ref_keys);
        return;
    }

    if (sc_vault_unlock(vault, env_pw) != 0) {
        DOC_FAIL(fail, "Vault: unlock failed (wrong password or corrupted)");
        sc_vault_free(vault);
        for (int i = 0; i < ref_count; i++) free(ref_keys[i]);
        free(ref_keys);
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
}
#endif

static int cmd_doctor(int argc, char **argv)
{
    int pass = 0, fail = 0;

    printf("%s doctor\n", SC_NAME);

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
        printf("\n  %d passed, %d failed\n", pass, fail);
        return 1;
    }

    sc_config_t *cfg = sc_config_load(config_path);
    if (cfg) {
        DOC_PASS(&pass, "Config file (%s)", config_path);
    } else {
        DOC_FAIL(&fail, "Config file (%s) — not found or invalid", config_path);
        free(config_path);
        printf("\n  %d passed, %d failed\n", pass, fail);
        return 1;
    }

    /* 2. Workspace */
    doctor_check_workspace(cfg, &pass, &fail);

    /* 3. Model */
    if (cfg->model && cfg->model[0])
        DOC_PASS(&pass, "Model: %s", cfg->model);
    else
        DOC_FAIL(&fail, "Model — not configured");

    /* 4. Provider API key */
    doctor_check_provider(cfg, &pass, &fail);

    /* 5. Channel configs */
    doctor_check_channels(cfg, &pass, &fail);

    /* 6. Vault */
#if SC_ENABLE_VAULT
    doctor_check_vault(cfg, &pass, &fail);
#endif

    /* 7. Updater */
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

    /* 8. System info */
    DOC_PASS(&pass, "libcurl %s", curl_version());
#if SC_ENABLE_VAULT || SC_ENABLE_DISCORD || SC_ENABLE_IRC || SC_ENABLE_UPDATER
    DOC_PASS(&pass, "OpenSSL linked");
#endif

    printf("\n  %d passed, %d failed\n", pass, fail);

    sc_config_free(cfg);
    free(config_path);
    return fail > 0 ? 1 : 0;
}

#undef DOC_PASS
#undef DOC_FAIL

/* Process a single inbound message: typing indicator, agent response, send */
static void gateway_process_message(sc_agent_t *agent,
                                     sc_channel_manager_t *ch_mgr,
                                     sc_inbound_msg_t *msg)
{
    /* Start typing indicator thread */
    typing_ctx_t typing = { ch_mgr, msg->channel, msg->chat_id, 1 };
    pthread_t typing_tid;
    int typing_started = 0;
    if (!sc_is_internal_channel(msg->channel)) {
        typing_started = (pthread_create(&typing_tid, NULL,
                                         typing_thread_fn, &typing) == 0);
    }

    /* Build response */
    char *response = NULL;
    if (msg->channel && strcmp(msg->channel, SC_CHANNEL_SYSTEM) == 0) {
        SC_LOG_INFO("gateway", "System message received");
    } else {
        response = sc_agent_process_direct(agent, msg->content, msg->session_key);
    }

    /* Stop typing thread */
    if (typing_started) {
        typing.running = 0;
        pthread_join(typing_tid, NULL);
    }

    if (response && response[0]) {
        /* Check if message tool already sent */
        sc_tool_t *mt = sc_tool_registry_get(agent->tools, "message");
        int already_sent = mt ? sc_tool_message_has_sent(mt) : 0;

        if (!already_sent) {
            sc_channel_manager_send(ch_mgr, msg->channel, msg->chat_id, response);
        }
    }

    free(response);
}

/* Gateway auto-approves — deny patterns and allowlist are the guards */
static int gateway_auto_confirm(const char *tool, const char *args, void *ctx)
{
    (void)tool; (void)args; (void)ctx;
    return 1;
}

typedef struct {
#if SC_ENABLE_CRON
    sc_cron_service_t *cron;
#endif
#if SC_ENABLE_HEARTBEAT
    sc_heartbeat_service_t *hb;
#endif
#if SC_ENABLE_UPDATER
    sc_updater_t *updater;
    struct event *update_timer;
#endif
    int _unused; /* avoid empty struct */
} gateway_services_t;

#if SC_ENABLE_UPDATER
/* Periodic update check timer callback */
static void update_timer_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd; (void)what;
    gateway_services_t *svc = arg;
    if (!svc->updater) return;

    SC_LOG_INFO("updater", "Periodic update check");
    sc_update_manifest_t *m = sc_updater_check(svc->updater);
    if (!m) return;

    SC_LOG_INFO("updater", "Update available: %s -> %s", SC_VERSION, m->latest);
    sc_audit_log_ext("updater", m->latest, 0, 0, NULL, NULL, "update_available");

    sc_update_manifest_free(m);
}
#endif

/* Create and start optional services (cron, heartbeat). */
static void gateway_start_services(gateway_services_t *svc,
                                    sc_agent_t *agent,
                                    sc_bus_t *bus,
                                    struct event_base *base,
                                    const sc_config_t *cfg,
                                    const char *workspace)
{
    (void)svc; (void)agent; (void)bus; (void)base; (void)cfg; (void)workspace;

#if SC_ENABLE_CRON
    sc_strbuf_t cron_path;
    sc_strbuf_init(&cron_path);
    sc_strbuf_appendf(&cron_path, "%s/cron/jobs.json", workspace);
    char *cron_store = sc_strbuf_finish(&cron_path);

    svc->cron = sc_cron_service_new(cron_store, base);
    free(cron_store);
    sc_agent_register_tool(agent, sc_tool_cron_new(svc->cron));
    sc_cron_service_start(svc->cron);
    printf("  Cron service started\n");
#endif

#if SC_ENABLE_HEARTBEAT
    svc->hb = sc_heartbeat_service_new(
        workspace, cfg->heartbeat.interval, cfg->heartbeat.enabled, base);
    sc_heartbeat_service_set_bus(svc->hb, bus);
    sc_heartbeat_service_set_state(svc->hb, agent->state);
    sc_heartbeat_service_set_handler(svc->hb, heartbeat_handler, agent);
    sc_heartbeat_service_start(svc->hb);
    printf("  Heartbeat service started\n");
#endif

#if SC_ENABLE_UPDATER
    if (cfg->updater.enabled && cfg->updater.manifest_url &&
        cfg->updater.manifest_url[0] && cfg->updater.check_interval_hours > 0) {
        sc_update_transport_t *transport =
            sc_update_transport_http_new(cfg->updater.manifest_url);
        svc->updater = sc_updater_new(transport);
        if (svc->updater) {
            long secs = (long)cfg->updater.check_interval_hours * 3600;
            struct timeval tv = { secs, 0 };
            svc->update_timer = event_new(base, -1, EV_PERSIST, update_timer_cb, svc);
            event_add(svc->update_timer, &tv);
            printf("  Update check every %dh\n", cfg->updater.check_interval_hours);
        }
    }
#endif
}

/* Stop and free optional services. */
static void gateway_stop_services(gateway_services_t *svc)
{
    (void)svc;
#if SC_ENABLE_UPDATER
    if (svc->update_timer) {
        event_del(svc->update_timer);
        event_free(svc->update_timer);
    }
    sc_updater_free(svc->updater);
#endif
#if SC_ENABLE_HEARTBEAT
    sc_heartbeat_service_stop(svc->hb);
    sc_heartbeat_service_free(svc->hb);
#endif
#if SC_ENABLE_CRON
    sc_cron_service_stop(svc->cron);
    sc_cron_service_free(svc->cron);
#endif
}

/* Main event loop: dispatch libevent, consume bus messages, handle SIGHUP. */
static void gateway_event_loop(struct event_base *base,
                                sc_bus_t *bus,
                                sc_agent_t *agent,
                                sc_channel_manager_t *ch_mgr,
                                sc_config_t **cfg_ptr,
                                const char *config_path)
{
    while (!g_shutdown) {
        if (g_reload_config) {
            g_reload_config = 0;
            sc_config_t *new_cfg = sc_config_load(config_path);
            if (new_cfg) {
                sc_agent_reload_config(agent, new_cfg);
                sc_channel_manager_reload_config(ch_mgr, new_cfg);
                sc_config_free(*cfg_ptr);
                *cfg_ptr = new_cfg;
                SC_LOG_INFO("gateway", "Config reloaded via SIGHUP");
                sc_audit_log_ext("config", "SIGHUP reload", 0, 0,
                                 NULL, NULL, "config_reload");
            } else {
                SC_LOG_ERROR("gateway", "Config reload failed, keeping current config");
            }
        }

        event_base_loop(base, EVLOOP_NONBLOCK);

        sc_inbound_msg_t *msg = sc_bus_consume_inbound(bus);
        if (msg) {
            gateway_process_message(agent, ch_mgr, msg);
            sc_inbound_msg_free(msg);
        }

        usleep(10000);
    }
}

/* Stop channels and services, free all resources. */
static void gateway_shutdown(sc_channel_manager_t *ch_mgr,
                              gateway_services_t *svc,
                              sc_agent_t *agent,
                              sc_bus_t *bus,
                              struct event_base *base,
                              sc_config_t *cfg,
                              char *config_path,
                              char *workspace)
{
    printf("\nShutting down...\n");

    sc_channel_manager_stop_all(ch_mgr);
    gateway_stop_services(svc);
    sc_agent_stop(agent);

    sc_channel_manager_free(ch_mgr);
    sc_agent_free(agent);
    /* Benign race: if a signal arrives between here and sc_bus_destroy(),
     * write(-1, ...) simply returns EBADF (ignored via (void) cast). */
    g_wakeup_fd = -1;
    sc_bus_destroy(bus);
    event_base_free(base);
    sc_config_free(cfg);
    free(config_path);
    free(workspace);

    printf("  Gateway stopped\n");
}

static void cmd_gateway(int argc, char **argv)
{
    /* Parse flags */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--debug") == 0 || strcmp(argv[i], "-d") == 0) {
            sc_logger_set_level(SC_LOG_DEBUG);
        }
    }

    /* Load config */
    char *config_path = sc_config_get_path();
    sc_config_t *cfg = sc_config_load(config_path);
    if (!cfg) {
        fprintf(stderr, "Fatal: could not load config\n");
        free(config_path);
        return;
    }

    /* Open persistent log file if configured */
    if (cfg->log_path)
        sc_logger_set_file(cfg->log_path);

    /* Create provider (retry with exponential backoff) */
    sc_provider_t *provider = NULL;
    for (int attempt = 0; attempt < 5 && !provider; attempt++) {
        if (attempt > 0) {
            int delay = 5 << (attempt - 1);
            SC_LOG_WARN("gateway", "Provider creation failed, retry %d/5 in %ds",
                        attempt, delay);
            sleep((unsigned)delay);
        }
        provider = sc_provider_create(cfg);
    }
    if (!provider) {
        fprintf(stderr, "Error: could not create provider after 5 attempts\n");
        sc_config_free(cfg);
        return;
    }

    /* Event loop */
    struct event_base *base = event_base_new();
    /* Signal handling */
    install_signal(SIGINT, signal_handler);
    install_signal(SIGTERM, signal_handler);
    install_signal(SIGHUP, sighup_handler);

    /* Bus */
    sc_bus_t *bus = sc_bus_create(base);
    g_wakeup_fd = bus->inbound_pipe[1];

    /* Agent */
    sc_agent_t *agent = sc_agent_new(cfg, bus, provider);
    if (!agent) {
        fprintf(stderr, "Error: could not create agent\n");
        sc_bus_destroy(bus);
        event_base_free(base);
        sc_config_free(cfg);
        return;
    }

    sc_audit_log_ext("provider", provider->name, 0, 0, NULL, NULL, "provider_init");
    sc_audit_log_ext("agent", cfg->model, 0, 0, NULL, NULL, "agent_init");

    /* Gateway auto-approves tools — deny patterns and allowlist are the guards */
    sc_tool_registry_set_confirm(agent->tools, gateway_auto_confirm, NULL);

    /* Wire allowlist from config */
    if (cfg->allowed_tools && cfg->allowed_tool_count > 0) {
        sc_tool_registry_set_allowed(agent->tools, cfg->allowed_tools,
                                      cfg->allowed_tool_count);
    }

    char *workspace = sc_config_workspace_path(cfg);

    /* Start optional services */
    gateway_services_t svc = {0};
    gateway_start_services(&svc, agent, bus, base, cfg, workspace);

    /* Channel manager */
    sc_channel_manager_t *ch_mgr = sc_channel_manager_new(cfg, bus);

    printf("\n%s %s Gateway v%s\n", SC_LOGO, SC_NAME, SC_VERSION);
    sc_channel_manager_start_all(ch_mgr);
    printf("  Channels started\n");
    printf("\nPress Ctrl+C to stop\n\n");

    gateway_event_loop(base, bus, agent, ch_mgr, &cfg, config_path);
    gateway_shutdown(ch_mgr, &svc, agent, bus, base, cfg, config_path, workspace);
}

int main(int argc, char **argv)
{
    sc_logger_init(NULL);

    if (argc < 2) {
        print_help();
        return 1;
    }

    const char *command = argv[1];

    if (strcmp(command, "help") == 0 ||
        strcmp(command, "--help") == 0 ||
        strcmp(command, "-h") == 0) {
        print_help();
    } else if (strcmp(command, "version") == 0 ||
               strcmp(command, "--version") == 0 ||
               strcmp(command, "-v") == 0) {
        print_version();
    } else if (strcmp(command, "onboard") == 0) {
        cmd_onboard();
    } else if (strcmp(command, "agent") == 0) {
        cmd_agent(argc, argv);
    } else if (strcmp(command, "gateway") == 0) {
        cmd_gateway(argc, argv);
    } else if (strcmp(command, "pairing") == 0) {
        cmd_pairing(argc, argv);
    } else if (strcmp(command, "cost") == 0) {
        cmd_cost(argc, argv);
#if SC_ENABLE_ANALYTICS
    } else if (strcmp(command, "analytics") == 0) {
        cmd_analytics(argc, argv);
#endif
    } else if (strcmp(command, "backup") == 0) {
        return cmd_backup(argc, argv);
    } else if (strcmp(command, "doctor") == 0) {
        return cmd_doctor(argc, argv);
#if SC_ENABLE_VAULT
    } else if (strcmp(command, "vault") == 0) {
        cmd_vault(argc, argv);
#endif
#if SC_ENABLE_UPDATER
    } else if (strcmp(command, "update") == 0) {
        cmd_update(argc, argv);
#endif
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        print_help();
        return 1;
    }

    sc_logger_shutdown();
    return 0;
}
