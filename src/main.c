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
#include <time.h>
#include <unistd.h>
#include <dirent.h>

#include <event2/event.h>

#include "sc_features.h"
#include "constants.h"
#include "config.h"
#include "logger.h"
#include "agent.h"
#include "memory.h"
#include "bus.h"
#include "gateway_route.h"
#include "pairing.h"
#include "workspace.h"
#include "channels/manager.h"
#include "channels/cli.h"
#include "tools/host.h"
#include "tools/message.h"
#include "audit.h"
#include "session.h"
#include "session_maint.h"
#include "slash.h"
#include "providers/factory.h"
#include "util/sandbox.h"
#include "util/str.h"
#if SC_ENABLE_MEMORY_SEARCH
#include "memory_index.h"
#endif

#if SC_ENABLE_CRON
#include "cron/service.h"
#include "tools/cron.h"
#include "memory_compact.h"
#endif
#if SC_ENABLE_HEARTBEAT
#include "heartbeat/service.h"
#endif
#if SC_ENABLE_COMPANION
#include "companion/setup.h"
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
#include "doctor.h"
#if SC_ENABLE_XAI_OAUTH
#include "util/xai_oauth.h"
#endif
#if SC_ENABLE_ANALYTICS
#include "analytics.h"
#endif
#if SC_ENABLE_MCP_SERVER
#include "mcp/server.h"
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

/* Auto-approve callback for headless/autonomous operation (defined later) */
static int gateway_auto_confirm(const char *tool, const char *args, void *ctx);

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
/* Streaming callback: handle fine-grained events during LLM response */
static void stream_print_cb(const sc_stream_event_t *event, void *ctx)
{
    (void)ctx;
    if (!event) return;
    switch (event->type) {
    case SC_STREAM_TEXT:
        if (event->data) {
            fputs(event->data, stdout);
            fflush(stdout);
        }
        break;
    case SC_STREAM_TOOL_START:
        if (event->tool_name) {
            fprintf(stderr, "\n[calling %s...]\n", event->tool_name);
            fflush(stderr);
        }
        break;
    case SC_STREAM_THINKING_START:
        fprintf(stderr, "\n[thinking...]\n");
        fflush(stderr);
        break;
    default:
        break; /* Other events ignored in CLI mode */
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
#if SC_ENABLE_MCP_SERVER
    printf("  mcp-server  Run as MCP server (JSON-RPC over stdio)\n");
#endif
    printf("  pairing     Manage channel pairing requests\n");
    printf("  cost        View token usage and costs\n");
    printf("  context     Show prompt budget breakdown for a session\n");
    printf("  memory      Review staged memory writes (pending|approve <id>|reject <id>)\n");
    printf("  doctor      Validate configuration and dependencies\n");
    printf("              --local [--model M]  Probe live provider capabilities\n");
    printf("  selftest    Run doctor checks + LLM round-trip, exit 0/1\n");
    printf("              --config <path>  Use a specific config file\n");
    printf("  host-refresh Refresh host inventory and retained metrics\n");
#if SC_ENABLE_VAULT
    printf("  vault       Manage encrypted secret vault\n");
#endif
#if SC_ENABLE_UPDATER
    printf("  update      Check for and apply updates\n");
#endif
#if SC_ENABLE_XAI_OAUTH
    printf("  auth        xAI Grok OAuth: login|status|logout|refresh xai\n");
    printf("              login xai [--no-browser] [--timeout N]\n");
#endif
    printf("  backup      Backup and restore state\n");
    printf("              create [--config-only] [--include-sessions] [--name TAG]\n");
    printf("              verify [NAME]    list    restore NAME [--dry-run]\n");
    printf("  session     Maintain stored sessions\n");
    printf("              compact [--force] [--max-bytes N] [key...]\n");
    printf("              prune [--keep N] [--yes]\n");
    printf("  version     Show version information\n");
#if SC_ENABLE_COMPANION
    printf("  companion   Android companion setup\n");
    printf("              qr [--url ORIGIN] [--force]\n");
#endif
}

#if SC_ENABLE_MCP_SERVER
static void cmd_mcp_server(int argc, char **argv)
{
    int all_tools = 0;
    for (int i = 2; i < argc; i++)
        if (strcmp(argv[i], "--all-tools") == 0) all_tools = 1;

    sc_config_t *cfg = load_config_or_exit();
    char *workspace = sc_config_workspace_path(cfg);

    /* Create tool registry with standalone tools */
    sc_tool_registry_t *reg = sc_tool_registry_new();
    if (!reg) {
        fprintf(stderr, "Error: could not create tool registry\n");
        free(workspace);
        sc_config_free(cfg);
        return;
    }

    sc_register_tools_standalone(reg, cfg, workspace);
    sc_tool_registry_set_approval_policy(reg, cfg->approval_policy);

    /* Tool exposure precedence: explicit config allowlist > read-only default
     * (3.6: an external MCP client gets read-only tools unless the operator
     * passes --all-tools or sets allowed_tools). */
    if (cfg->allowed_tools && cfg->allowed_tool_count > 0) {
        sc_tool_registry_set_allowed(reg, cfg->allowed_tools,
                                      cfg->allowed_tool_count);
    } else if (!all_tools) {
        int n = 0;
        const char **ro = sc_tools_readonly_names(&n);
        sc_tool_registry_set_allowed(reg, (char **)ro, n);
        SC_LOG_INFO("main", "MCP server: read-only tools only "
                    "(pass --all-tools to expose write/exec)");
    }

    SC_LOG_INFO("main", "Starting MCP server with %d tools",
                sc_tool_registry_count(reg));

    /* Run stdio server — blocks until EOF or shutdown */
    sc_mcp_server_run(reg);

    sc_tool_registry_free(reg);
    free(workspace);
    sc_config_free(cfg);
}
#endif

static int cmd_host_refresh(void)
{
    sc_config_t *cfg = load_config_or_exit();
    char *workspace = sc_config_workspace_path(cfg);
    int sample_ok = 0;
    int inventory_ok = 0;
    int sandbox_avail = 0;
    int landlock_ok = 0;
    int seccomp_ok = 0;
    const char *sandbox_status = "disabled";
    int rc = 1;
#if SC_ENABLE_MEMORY_SEARCH
    sc_memory_index_t *midx = NULL;
#endif

    if (!workspace || !workspace[0]) {
        fprintf(stderr, "Error: could not resolve workspace path\n");
        goto done;
    }

#if SC_ENABLE_MEMORY_SEARCH
    {
        sc_strbuf_t db_sb;
        sc_strbuf_init(&db_sb);
        sc_strbuf_appendf(&db_sb, "%s/memory/search.db", workspace);
        char *db_path = sc_strbuf_finish(&db_sb);
        if (db_path) {
            midx = sc_memory_index_new(db_path);
            free(db_path);
            if (midx) {
                sc_strbuf_t mem_sb;
                sc_strbuf_init(&mem_sb);
                sc_strbuf_appendf(&mem_sb, "%s/memory", workspace);
                char *mem_dir = sc_strbuf_finish(&mem_sb);
                sc_memory_index_defer_rebuild(midx, mem_dir);
                free(mem_dir);

                sc_strbuf_t ctx_sb;
                sc_strbuf_init(&ctx_sb);
                sc_strbuf_appendf(&ctx_sb, "%s/context", workspace);
                char *ctx_dir = sc_strbuf_finish(&ctx_sb);
                struct stat ctx_st;
                if (stat(ctx_dir, &ctx_st) == 0 && S_ISDIR(ctx_st.st_mode))
                    sc_memory_index_defer_ctx_rebuild(midx, ctx_dir);
                free(ctx_dir);
            }
        }
    }
#endif

    sample_ok = (sc_host_record_sample(workspace, 1) == 0);
    sandbox_avail = sc_sandbox_available();
    landlock_ok = (sandbox_avail & SC_SANDBOX_LANDLOCK) != 0;
    seccomp_ok = (sandbox_avail & SC_SANDBOX_SECCOMP) != 0;
    if (cfg->sandbox_enabled)
        sandbox_status = (landlock_ok && seccomp_ok) ? "ok" : "degraded";
    inventory_ok =
        (sc_host_refresh_inventory_artifacts(
             workspace,
#if SC_ENABLE_MEMORY_SEARCH
             midx
#else
             NULL
#endif
             ,
             cfg->sandbox_enabled
         ) == 0);

    printf("workspace: %s\n", workspace);
    printf("sample: %s\n", sample_ok ? "ok" : "error");
    printf("inventory: %s\n", inventory_ok ? "ok" : "error");
    printf("sandbox_status: %s\n", sandbox_status);
    printf("sandbox_landlock: %s\n", landlock_ok ? "available" : "unavailable");
    printf("sandbox_seccomp: %s\n", seccomp_ok ? "available" : "unavailable");
    rc = (sample_ok && inventory_ok) ? 0 : 1;

done:
#if SC_ENABLE_MEMORY_SEARCH
    sc_memory_index_free(midx);
#endif
    free(workspace);
    sc_config_free(cfg);
    return rc;
}

#if SC_ENABLE_CRON
/* Cron handler callback — dispatches via the bus to avoid blocking the
 * event loop. The LLM call in sc_agent_process_heartbeat can take 10-60s,
 * which would freeze the entire gateway if called synchronously here. */
static char *cron_handler(sc_cron_job_t *job, void *ctx)
{
    sc_agent_t *agent = ctx;
    if (!agent || !job) return NULL;

    const char *msg = job->payload.message;
    if (!msg) return NULL;

    /* #compact-memory — AI-driven MEMORY.md compaction.
     * Runs synchronously (blocks event loop 2-10s for LLM call).
     * Acceptable because cron jobs run between user turns, not during. */
    if (strncmp(msg, "#compact-memory", 15) == 0) {
        SC_LOG_INFO("cron", "Running memory compaction job '%s'",
                    job->name ? job->name : job->id);
        int rc = sc_memory_compact(agent->workspace, agent->provider,
                                    agent->model, 0);
        return sc_strdup(rc == 0 ? "ok" : "error");
    }

    /* Dispatch via bus — the gateway_process_message handler will pick this
     * up on the next event loop iteration and process it asynchronously. */
    SC_LOG_INFO("cron", "Dispatching cron job '%s' via bus",
                job->name ? job->name : job->id);
    sc_inbound_msg_t *imsg = sc_inbound_msg_new(
        SC_CHANNEL_CLI, "cron", "cron", msg, "cron:patrol", NULL,
        /* isolated */ 0, /* namespace_id */ NULL,
        /* run_repo_dir */ NULL);
    if (imsg)
        sc_bus_publish_inbound(agent->bus, imsg);
    return sc_strdup("dispatched");
}
#endif

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
    if (!cfg) {
        fprintf(stderr, "Could not load config\n");
        free(config_path);
        return;
    }

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

    char *home = sc_get_home_dir();
    if (!home) {
        fprintf(stderr, "Error: could not determine smolclaw home directory\n");
        return;
    }
    char *store_dir = malloc(strlen(home) + sizeof("/pairing"));
    if (!store_dir) { free(home); return; }
    snprintf(store_dir, strlen(home) + sizeof("/pairing"), "%s/pairing", home);
    free(home);
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

    /* Ensure home directory exists with secure permissions */
    char *home = sc_get_home_dir();
    if (home) {
        mkdir(home, 0700);
        chmod(home, 0700);
        free(home);
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
        mkdir(workspace, 0700);
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

        /* Slash commands: handled locally, no LLM turn. */
        char *slash_reply = NULL;
        if (sc_slash_dispatch(agent, session_key, trimmed, &slash_reply)) {
            if (slash_reply) printf("\n%s %s\n\n", SC_LOGO, slash_reply);
            free(slash_reply);
            free(trimmed);
            continue;
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

    /* Set tool confirmation callback — auto-approve for headless operation,
     * interactive CLI prompt otherwise */
    if (cfg->auto_confirm)
        sc_tool_registry_set_confirm(agent->tools, gateway_auto_confirm, NULL);
    else
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
    volatile int running;
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

    if (!ct) {
        fprintf(stderr, "Error: could not initialize cost tracker\n");
        sc_config_free(cfg);
        return;
    }

    /* Wire pricing overrides so print_summary shows dollar amounts */
    if (cfg->pricing_overrides)
        sc_cost_tracker_set_pricing(ct, cfg->pricing_overrides);

    int do_reset = 0;
    int do_sessions = 0;
    int do_recompute = 0;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--reset") == 0 || strcmp(argv[i], "-r") == 0)
            do_reset = 1;
        else if (strcmp(argv[i], "--sessions") == 0 || strcmp(argv[i], "-s") == 0)
            do_sessions = 1;
        else if (strcmp(argv[i], "--recompute") == 0)
            do_recompute = 1;
    }

    if (do_reset) {
        sc_cost_tracker_reset(ct);
    } else if (do_recompute) {
        int n = sc_cost_tracker_recompute(ct);
        if (n < 0)
            fprintf(stderr, "Error: recompute failed\n");
        else
            printf("Recomputed estimated_cost_usd for %d model entr%s.\n",
                   n, n == 1 ? "y" : "ies");
        sc_cost_tracker_print_summary(ct);
    } else if (do_sessions) {
        sc_cost_tracker_print_sessions(ct);
    } else {
        sc_cost_tracker_print_summary(ct);
    }

    sc_cost_tracker_free(ct);
    sc_config_free(cfg);
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

/* ---------- session maintenance ---------- */

static void session_init_audit(const char *workspace)
{
    sc_strbuf_t ab;
    sc_strbuf_init(&ab);
    sc_strbuf_appendf(&ab, "%s/audit.log", workspace);
    char *audit_path = sc_strbuf_finish(&ab);
    sc_audit_init(audit_path);
    free(audit_path);
}

static int session_compact(int argc, char **argv, const char *sessions_dir)
{
    int force = 0;
    size_t max_bytes = SC_COMPACT_DEFAULT_MAX;
    const char *keys[64];
    int key_count = 0;

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--force") == 0) {
            force = 1;
        } else if (strcmp(argv[i], "--max-bytes") == 0 && i + 1 < argc) {
            long v = strtol(argv[++i], NULL, 10);
            if (v >= 64) max_bytes = (size_t)v;
        } else if (key_count < 64) {
            keys[key_count++] = argv[i];
        }
    }

    /* Build the list of files to compact. */
    char *paths[64];
    int n = 0;
    if (key_count > 0) {
        for (int i = 0; i < key_count; i++) {
            char *safe = sc_sanitize_filename(keys[i]);
            sc_strbuf_t sb;
            sc_strbuf_init(&sb);
            sc_strbuf_appendf(&sb, "%s/%s.jsonl", sessions_dir, safe);
            paths[n++] = sc_strbuf_finish(&sb);
            free(safe);
        }
    } else {
        DIR *dir = opendir(sessions_dir);
        if (dir) {
            struct dirent *ent;
            while ((ent = readdir(dir)) != NULL && n < 64) {
                size_t len = strlen(ent->d_name);
                if (len <= 6 || strcmp(ent->d_name + len - 6, ".jsonl") != 0)
                    continue;
                sc_strbuf_t sb;
                sc_strbuf_init(&sb);
                sc_strbuf_appendf(&sb, "%s/%s", sessions_dir, ent->d_name);
                paths[n++] = sc_strbuf_finish(&sb);
            }
            closedir(dir);
        }
    }

    if (n == 0) {
        printf("No sessions to compact in %s\n", sessions_dir);
        return 0;
    }

    int total_files = 0;
    long total_saved = 0;
    for (int i = 0; i < n; i++) {
        int fields = 0;
        long saved = 0;
        int rc = sc_session_compact_file(paths[i], max_bytes, &fields, &saved);
        if (rc == 0) {
            printf("compacted %s: %d field(s), %ld bytes saved (.bak written)\n",
                   paths[i], fields, saved);
            sc_audit_log_ext("session", paths[i], 0, 0, NULL, NULL,
                             "session_compact");
            total_files++;
            total_saved += saved;
        } else if (rc == 1) {
            printf("skipped %s: nothing oversized\n", paths[i]);
        } else {
            fprintf(stderr, "error compacting %s (original intact)\n", paths[i]);
        }
        free(paths[i]);
    }

    (void)force;
    printf("\nCompacted %d file(s), %ld bytes saved. "
           "Full tool output remains in the audit log.\n",
           total_files, total_saved);
    return 0;
}

static int session_prune(int argc, char **argv, const char *sessions_dir)
{
    int keep = 20;
    int yes = 0;

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--keep") == 0 && i + 1 < argc) {
            long v = strtol(argv[++i], NULL, 10);
            if (v >= 0) keep = (int)v;
        } else if (strcmp(argv[i], "--yes") == 0 || strcmp(argv[i], "-y") == 0) {
            yes = 1;
        }
    }

    int count = 0;
    char **cands = sc_session_prune_candidates(sessions_dir, keep, &count);
    if (count == 0) {
        printf("Nothing to prune (keeping newest %d).\n", keep);
        free(cands);
        return 0;
    }

    printf("The following %d session(s) older than the newest %d will be deleted:\n",
           count, keep);
    for (int i = 0; i < count; i++)
        printf("  %s\n", cands[i]);

    if (!yes) {
        printf("Proceed? [y/N] ");
        fflush(stdout);
        int c = getchar();
        if (c != 'y' && c != 'Y') {
            printf("Aborted.\n");
            for (int i = 0; i < count; i++) free(cands[i]);
            free(cands);
            return 0;
        }
    }

    int removed = 0;
    for (int i = 0; i < count; i++) {
        if (unlink(cands[i]) == 0) {
            sc_audit_log_ext("session", cands[i], 0, 0, NULL, NULL,
                             "session_prune");
            removed++;
        } else {
            fprintf(stderr, "failed to delete %s\n", cands[i]);
        }
        free(cands[i]);
    }
    free(cands);

    printf("Pruned %d session(s).\n", removed);
    return 0;
}

/* Task 4.7: prompt-budget overview. Estimates how the prompt for a session
 * breaks down — system prompt, tool schemas, conversation history, and tool
 * results — in bytes and (rough) tokens, and warns when the total approaches
 * the model context window. Read-only; does not call any provider. */
static int cmd_context(int argc, char **argv)
{
    const char *session_key = "cli:default";
    int warn_pct_override = -1;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--warn-pct") == 0 && i + 1 < argc)
            warn_pct_override = atoi(argv[++i]);
        else if (argv[i][0] != '-')
            session_key = argv[i];
    }

    sc_config_t *cfg = load_config_or_exit();
    char *workspace = sc_config_workspace_path(cfg);

    /* Tools: register the standalone set and size each schema. */
    size_t tools_bytes = 0;
    int tool_count = 0;
    sc_tool_registry_t *reg = sc_tool_registry_new();
    if (reg) {
        sc_register_tools_standalone(reg, cfg, workspace);
        sc_tool_definition_t *defs = sc_tool_registry_to_defs(reg, &tool_count);
        for (int i = 0; i < tool_count; i++) {
            tools_bytes += strlen(defs[i].name ? defs[i].name : "");
            tools_bytes += strlen(defs[i].description ? defs[i].description : "");
            if (defs[i].parameters) {
                char *p = cJSON_PrintUnformatted(defs[i].parameters);
                if (p) { tools_bytes += strlen(p); free(p); }
            }
        }
        sc_tool_definitions_free(defs, tool_count);
    }

    /* System prompt. */
    sc_context_builder_t *cb = sc_context_builder_new(workspace);
    if (cb && reg) sc_context_builder_set_tools(cb, reg);
    char *sys = cb ? sc_context_build_system_prompt(cb) : NULL;
    size_t sys_bytes = sys ? strlen(sys) : 0;

    /* Conversation history vs tool results from the stored session. */
    sc_strbuf_t sb; sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/sessions", workspace);
    char *sessions_dir = sc_strbuf_finish(&sb);
    sc_session_manager_t *sm = sc_session_manager_new(sessions_dir);
    size_t hist_bytes = 0, toolres_bytes = 0;
    int msg_count = 0, toolres_count = 0;
    if (sm) {
        int count = 0;
        sc_llm_message_t *h = sc_session_get_history(sm, session_key, &count);
        msg_count = count;
        for (int i = 0; i < count; i++) {
            size_t c = h[i].content ? strlen(h[i].content) : 0;
            if (h[i].tool_call_id) { toolres_bytes += c; toolres_count++; }
            else hist_bytes += c;
        }
    }

    int sys_tok     = sc_context_estimate_tokens(sys_bytes);
    int tools_tok   = sc_context_estimate_tokens(tools_bytes);
    int hist_tok    = sc_context_estimate_tokens(hist_bytes);
    int toolres_tok = sc_context_estimate_tokens(toolres_bytes);
    int total_tok   = sys_tok + tools_tok + hist_tok + toolres_tok;
    size_t total_bytes = sys_bytes + tools_bytes + hist_bytes + toolres_bytes;
    int window = cfg->context_window > 0 ? cfg->context_window : cfg->max_tokens;
    int warn_pct = warn_pct_override >= 0 ? warn_pct_override : cfg->context_warn_pct;

    printf("Prompt budget for session '%s'  (model: %s)\n\n",
           session_key, cfg->model ? cfg->model : "(unset)");
    printf("  %-16s %12s %10s\n", "component", "bytes", "~tokens");
    printf("  %-16s %12s %10s\n", "----------------", "------------", "----------");
    printf("  %-16s %12zu %10d\n", "system prompt", sys_bytes, sys_tok);
    printf("  %-16s %12zu %10d   (%d tools)\n", "tool schemas", tools_bytes, tools_tok, tool_count);
    printf("  %-16s %12zu %10d   (%d msgs)\n", "history", hist_bytes, hist_tok, msg_count - toolres_count);
    printf("  %-16s %12zu %10d   (%d results)\n", "tool results", toolres_bytes, toolres_tok, toolres_count);
    printf("  %-16s %12s %10s\n", "", "------------", "----------");
    printf("  %-16s %12zu %10d\n", "total", total_bytes, total_tok);

    if (window > 0) {
        int pct = (int)((long)total_tok * 100 / window);
        printf("\n  context window: %d tokens  (%d%% used)\n", window, pct);
        if (sc_context_budget_warn(total_tok, window, warn_pct))
            printf("  WARNING: estimated usage >= %d%% of the context window\n", warn_pct);
    }

    free(sys);
    sc_context_builder_free(cb);
    if (sm) sc_session_manager_free(sm);
    if (reg) sc_tool_registry_free(reg);
    free(sessions_dir);
    free(workspace);
    sc_config_free(cfg);
    return 0;
}

/* Read a whole file into a malloc'd string (NUL-terminated), or NULL. */
static char *slurp_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    char chunk[4097];
    size_t r;
    while ((r = fread(chunk, 1, sizeof(chunk) - 1, f)) > 0) {
        chunk[r] = '\0';
        sc_strbuf_append(&sb, chunk);
    }
    fclose(f);
    return sc_strbuf_finish(&sb);
}

/* Task 4.14: review staged memory writes. */
static int cmd_memory(int argc, char **argv)
{
    const char *sub = (argc >= 3) ? argv[2] : "";
    const char *id  = (argc >= 4) ? argv[3] : NULL;

    sc_config_t *cfg = load_config_or_exit();
    char *workspace = sc_config_workspace_path(cfg);
    sc_memory_t *mem = sc_memory_new(workspace);
    char *pdir = mem ? sc_memory_pending_dir_dup(mem) : NULL;
    int rc = 0;

    if (!pdir) {
        fprintf(stderr, "Error: could not resolve pending memory dir\n");
        rc = 1;
    } else if (strcmp(sub, "pending") == 0) {
        DIR *d = opendir(pdir);
        int n = 0;
        if (d) {
            struct dirent *e;
            while ((e = readdir(d)) != NULL) {
                size_t l = strlen(e->d_name);
                if (l < 4 || strcmp(e->d_name + l - 3, ".md") != 0) continue;
                char path[1024];
                snprintf(path, sizeof(path), "%s/%s", pdir, e->d_name);
                char *content = slurp_file(path);
                char *prev = content ? sc_truncate(content, 100) : NULL;
                printf("  %s\n      %s\n", e->d_name, prev ? prev : "");
                free(prev); free(content);
                n++;
            }
            closedir(d);
        }
        printf("%d pending memory entr%s.\n", n, n == 1 ? "y" : "ies");
    } else if (strcmp(sub, "approve") == 0 && id) {
        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", pdir, id);
        char *content = slurp_file(path);
        if (!content) { fprintf(stderr, "No such pending entry: %s\n", id); rc = 1; }
        else {
            char *existing = sc_memory_read_long_term(mem);
            sc_strbuf_t sb; sc_strbuf_init(&sb);
            if (existing && existing[0]) {
                sc_strbuf_append(&sb, existing);
                if (existing[strlen(existing) - 1] != '\n') sc_strbuf_append(&sb, "\n");
            }
            sc_strbuf_append(&sb, content);
            char *full = sc_strbuf_finish(&sb);
            if (full && sc_memory_write_long_term(mem, full) == 0) {
                remove(path);
                printf("Approved %s.\n", id);
            } else { fprintf(stderr, "Failed to commit %s\n", id); rc = 1; }
            free(full); free(existing); free(content);
        }
    } else if (strcmp(sub, "reject") == 0 && id) {
        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", pdir, id);
        if (remove(path) == 0) printf("Rejected %s.\n", id);
        else { fprintf(stderr, "No such pending entry: %s\n", id); rc = 1; }
    } else {
        fprintf(stderr,
            "Usage: %s memory pending\n"
            "       %s memory approve <id>\n"
            "       %s memory reject <id>\n",
            SC_NAME, SC_NAME, SC_NAME);
        rc = 1;
    }

    free(pdir);
    if (mem) sc_memory_free(mem);
    free(workspace);
    sc_config_free(cfg);
    return rc;
}

static int cmd_session(int argc, char **argv)
{
    const char *subcmd = (argc >= 3) ? argv[2] : "";

    sc_config_t *cfg = load_config_or_exit();
    char *workspace = sc_config_workspace_path(cfg);
    session_init_audit(workspace);

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/sessions", workspace);
    char *sessions_dir = sc_strbuf_finish(&sb);

    int rc = 0;
    if (strcmp(subcmd, "compact") == 0) {
        /* Refuse while a gateway is live unless --force: it may be appending
         * to a session we'd rewrite from under it. */
        int force = 0;
        for (int i = 3; i < argc; i++)
            if (strcmp(argv[i], "--force") == 0) force = 1;
        if (sc_gateway_is_running(workspace) && !force) {
            fprintf(stderr, "Refusing: gateway appears to be running. "
                    "Stop it or pass --force.\n");
            rc = 1;
        } else {
            rc = session_compact(argc, argv, sessions_dir);
        }
    } else if (strcmp(subcmd, "prune") == 0) {
        rc = session_prune(argc, argv, sessions_dir);
    } else {
        fprintf(stderr,
                "Usage: %s session compact [--force] [--max-bytes N] [key...]\n"
                "       %s session prune [--keep N] [--yes]\n"
                "\n"
                "compact truncates oversized tool-result bodies (head + tail +\n"
                "marker), rewriting atomically with a .bak. The full output is\n"
                "retained in the workspace audit log.\n",
                SC_NAME, SC_NAME);
        rc = 1;
    }

    free(sessions_dir);
    free(workspace);
    sc_config_free(cfg);
    sc_audit_shutdown();
    return rc;
}

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


static int cmd_selftest(int argc, char **argv)
{
    int pass = 0, fail = 0;
    printf("%s selftest\n\n", SC_NAME);

    printf("--- Doctor checks ---\n");
    sc_config_t *cfg = sc_run_doctor_checks(argc, argv, &pass, &fail);
    if (!cfg) {
        printf("\n  %d passed, %d failed\n", pass, fail);
        printf("\nSelftest FAILED (config not loadable)\n");
        return 1;
    }

    /* LLM round-trip test */
    printf("\n--- LLM round-trip ---\n");
    sc_provider_t *provider = sc_provider_create(cfg);
    if (!provider) {
        DOC_FAIL(&fail, "LLM: could not create provider");
        printf("\n  %d passed, %d failed\n", pass, fail);
        printf("\nSelftest FAILED\n");
        sc_config_free(cfg);
        return 1;
    }

    const char *model = cfg->model;
    if (!model || !model[0]) model = provider->get_default_model(provider);

    /* Build a minimal single-message conversation */
    sc_llm_message_t msgs[1];
    msgs[0].role = "user";
    msgs[0].content = "Reply with exactly: OK";
    msgs[0].tool_calls = NULL;
    msgs[0].tool_call_count = 0;
    msgs[0].tool_call_id = NULL;

    cJSON *options = cJSON_CreateObject();
    cJSON_AddNumberToObject(options, "max_tokens", 64);
    cJSON_AddNumberToObject(options, "temperature", 0.0);

    sc_llm_response_t *resp = provider->chat(
        provider, msgs, 1, NULL, 0, model, options);
    cJSON_Delete(options);

    if (!resp) {
        DOC_FAIL(&fail, "LLM: provider returned NULL (no response)");
    } else if (resp->http_status != 200) {
        DOC_FAIL(&fail, "LLM: HTTP %d from %s", resp->http_status, model);
    } else if (!resp->content || !resp->content[0]) {
        DOC_FAIL(&fail, "LLM: empty response from %s", model);
    } else {
        DOC_PASS(&pass, "LLM: %s responded (HTTP 200, %d tokens)",
                 model, resp->usage.completion_tokens);
    }

    if (resp) sc_llm_response_free(resp);
    if (provider->destroy) provider->destroy(provider);
    sc_config_free(cfg);

    printf("\n  %d passed, %d failed\n", pass, fail);
    printf("\nSelftest %s\n", fail > 0 ? "FAILED" : "PASSED");
    return fail > 0 ? 1 : 0;
}

/* Process a single inbound message: typing indicator, agent response, send */
static void gateway_process_message(sc_agent_t *agent,
                                     sc_channel_manager_t *ch_mgr,
                                     sc_inbound_msg_t *msg)
{
    /* Automatic session reset (task 3.7): if the policy says this chat's
     * session is stale (idle/daily), clear it before processing — no LLM call.
     * System/internal channels are exempt. */
    if (agent->session_reset_mode != SC_SESSION_RESET_NONE && msg->session_key &&
        !(msg->channel && strcmp(msg->channel, SC_CHANNEL_SYSTEM) == 0)) {
        long last = sc_session_get_updated(agent->sessions, msg->session_key);
        if (last > 0 &&
            sc_session_reset_due(agent->session_reset_mode,
                                 agent->session_reset_daily_hour,
                                 agent->session_reset_idle_min,
                                 last, time(NULL))) {
            sc_session_reset(agent->sessions, msg->session_key);
            SC_LOG_INFO("gateway", "Session '%s' reset by policy (mode=%d)",
                        msg->session_key, agent->session_reset_mode);
            sc_audit_log_ext("session", msg->session_key, 0, 0, msg->channel,
                             msg->chat_id, "session_reset_policy");
        }
    }

    /* Slash commands (e.g. /reset, /model, /help): handle locally without an
     * LLM turn and reply on the same channel. System/internal channels are
     * never user chat input, so they bypass this. */
    if (!(msg->channel && strcmp(msg->channel, SC_CHANNEL_SYSTEM) == 0)) {
        char *slash_reply = NULL;
        if (sc_slash_dispatch(agent, msg->session_key, msg->content,
                              &slash_reply)) {
            if (slash_reply && slash_reply[0])
                sc_channel_manager_send(ch_mgr, msg->channel, msg->chat_id,
                                        slash_reply);
            sc_audit_log_ext("slash", msg->content, 0, 0, msg->channel,
                             msg->chat_id, "slash_command");
            free(slash_reply);
            return;
        }
    }

    /* Start typing indicator thread */
    typing_ctx_t typing = { ch_mgr, msg->channel, msg->chat_id, 1 };
    pthread_t typing_tid;
    int typing_started = 0;
    if (!sc_is_internal_channel(msg->channel)) {
        typing_started = (pthread_create(&typing_tid, NULL,
                                         typing_thread_fn, &typing) == 0);
    }

    /* Phase 5 per-turn tool-workspace override: narrow the tool registry's
     * workspace to <agent->workspace>/<run_repo_dir> for this turn so
     * delegate tools (read_file, list_dir, exec, git) can't browse stale
     * workspace state from other runs. Restored after the response is
     * built so subsequent turns / non-delegate channels see the full ws.
     * Validation in gateway_route.h; stat() catches a missing dir at
     * runtime. agent->workspace itself is unchanged — memory consolidation
     * and scratchpad still write to the agent-wide path. */
    char *narrowed_ws = NULL;
    if (sc_gateway_run_repo_dir_safe(msg->run_repo_dir)
        && agent->workspace && agent->workspace[0]
        && agent->tools) {
        size_t narrowed_len = strlen(agent->workspace) + 1
                            + strlen(msg->run_repo_dir) + 1;
        narrowed_ws = malloc(narrowed_len);
        if (!narrowed_ws) {
            /* leave NULL */
        } else {
            int narrowed_n = snprintf(narrowed_ws, narrowed_len, "%s/%s",
                                      agent->workspace, msg->run_repo_dir);
            if (narrowed_n < 0 || (size_t)narrowed_n >= narrowed_len) {
                free(narrowed_ws);
                narrowed_ws = NULL;
            }
        }
        if (narrowed_ws) {
            struct stat st;
            if (stat(narrowed_ws, &st) == 0 && S_ISDIR(st.st_mode)) {
                sc_tool_registry_set_workspace(agent->tools, narrowed_ws);
                SC_LOG_DEBUG("gateway",
                             "tool workspace narrowed to %s for this turn",
                             narrowed_ws);
            } else {
                SC_LOG_WARN("gateway",
                            "run_repo_dir '%s' does not resolve to a dir under %s, ignoring",
                            msg->run_repo_dir, agent->workspace);
                free(narrowed_ws);
                narrowed_ws = NULL;
            }
        }
    }

    /* Build response */
    char *response = NULL;
    if (msg->channel && strcmp(msg->channel, SC_CHANNEL_SYSTEM) == 0) {
        SC_LOG_INFO("gateway", "System message received");
    } else if (sc_gateway_should_isolate(msg)) {
        /* Phase 4 isolation: route through the isolated entry so per-session
         * memory and post-compact scratchpad land in the namespaced bucket.
         * Decision helper in gateway_route.h, exercised by
         * tests/test_gateway_routing.c. */
        response = sc_agent_process_isolated(agent, msg->content, msg->session_key,
                                              msg->channel, msg->chat_id,
                                              msg->namespace_id);
    } else {
        response = sc_agent_process_channel(agent, msg->content, msg->session_key,
                                                  msg->channel, msg->chat_id);
    }

    /* Restore tool workspace (Phase 5). Always runs if we narrowed,
     * regardless of which agent_process_* path we took. */
    if (narrowed_ws) {
        sc_tool_registry_set_workspace(agent->tools, agent->workspace);
        free(narrowed_ws);
    }

    /* Stop typing thread */
    if (typing_started) {
        typing.running = 0;
        pthread_join(typing_tid, NULL);
    }

    /* Task 3.9: intentional silence. If the final response is exactly a
     * silence token ([SILENT]/SILENT/NO_REPLY/NO REPLY), suppress outbound
     * delivery. The turn is already in the transcript (run_agent_loop stored
     * the assistant message before returning), so alternation is preserved.
     * Error strings begin with "Error: ..." and never match a token, so
     * failed turns still surface. */
    if (response && response[0] && agent->silent_tokens_enabled &&
        sc_gateway_is_silent_token(response)) {
        SC_LOG_INFO("gateway", "Silent token '%s' — suppressing delivery",
                    response);
        free(response);
        return;
    }

    if (response && response[0]) {
        /* Check if message tool already sent */
        sc_tool_t *mt = sc_tool_registry_get(agent->tools, "message");
        int already_sent = mt ? sc_tool_message_has_sent(mt) : 0;

        if (!already_sent || msg->response_format) {
            if (msg->response_format && agent->bus) {
                sc_outbound_msg_t *out = sc_outbound_msg_new(msg->channel,
                                                             msg->chat_id,
                                                             response);
                if (out) {
                    out->is_final_response = 1;
                    sc_bus_publish_outbound(agent->bus, out);
                } else if (!already_sent) {
                    sc_channel_manager_send(ch_mgr, msg->channel,
                                            msg->chat_id, response);
                }
            } else {
                sc_channel_manager_send(ch_mgr, msg->channel, msg->chat_id,
                                        response);
            }
        }
    }

    free(response);
}

/* Outbound handler: forward bus messages to channel manager (for verbose progress) */
static void gateway_outbound_handler(sc_outbound_msg_t *msg, void *ctx)
{
    sc_channel_manager_t *ch_mgr = ctx;
    sc_channel_manager_dispatch(ch_mgr, msg);
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
    const char *host_sample_workspace;
    time_t host_sample_next;
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

    svc->host_sample_workspace = workspace;
    if (workspace && workspace[0]) {
        sc_host_record_sample(workspace, 1);
        svc->host_sample_next = time(NULL) + sc_host_sample_interval_sec();
    }

#if SC_ENABLE_CRON
    sc_strbuf_t cron_path;
    sc_strbuf_init(&cron_path);
    sc_strbuf_appendf(&cron_path, "%s/cron/jobs.json", workspace);
    char *cron_store = sc_strbuf_finish(&cron_path);

    svc->cron = sc_cron_service_new(cron_store, base);
    free(cron_store);
    sc_agent_register_tool(agent, sc_tool_cron_new(svc->cron));
    sc_cron_service_set_handler(svc->cron, cron_handler, agent);
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
                                gateway_services_t *svc,
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

#if SC_ENABLE_CRON
        /* Manual cron tick — EVLOOP_NONBLOCK doesn't dispatch timers */
        if (svc->cron)
            sc_cron_service_tick(svc->cron);
#endif

        if (svc->host_sample_workspace && svc->host_sample_next > 0) {
            time_t now = time(NULL);
            if (now >= svc->host_sample_next) {
                sc_host_record_sample(svc->host_sample_workspace, 0);
                svc->host_sample_next = now + sc_host_sample_interval_sec();
            }
        }

        sc_inbound_msg_t *msg = sc_bus_try_consume_inbound(bus);
        if (msg) {
            /* Queue mode (3.8): coalesce any other messages from the same chat
             * that piled up during the previous turn into one follow-up. */
            if (agent->busy_input_mode == 1 && msg->channel && msg->chat_id) {
                int extra = 0;
                sc_inbound_msg_t **more = sc_bus_drain_inbound_matching(
                    bus, msg->channel, msg->chat_id, &extra);
                if (extra > 0) {
                    sc_strbuf_t sb;
                    sc_strbuf_init(&sb);
                    sc_strbuf_append(&sb, msg->content ? msg->content : "");
                    for (int i = 0; i < extra; i++) {
                        if (more[i]->content && more[i]->content[0]) {
                            sc_strbuf_append(&sb, "\n");
                            sc_strbuf_append(&sb, more[i]->content);
                        }
                        sc_inbound_msg_free(more[i]);
                    }
                    free(msg->content);
                    msg->content = sc_strbuf_finish(&sb);
                    SC_LOG_INFO("gateway",
                                "queue mode: coalesced %d message(s) for %s/%s",
                                extra, msg->channel, msg->chat_id);
                }
                free(more);
            }
            gateway_process_message(agent, ch_mgr, msg);
            sc_inbound_msg_free(msg);
        }

        usleep(100000);  /* 100ms — saves ~90% idle CPU vs 10ms */
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

    /* Tighten home directory permissions if too open */
    {
        char *home = sc_get_home_dir();
        if (home) {
            struct stat hst;
            if (stat(home, &hst) == 0 && (hst.st_mode & 0077) != 0) {
                if (chmod(home, 0700) == 0)
                    SC_LOG_INFO("gateway", "Tightened %s permissions to 0700", home);
            }
            free(home);
        }
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

    /* Acquire the gateway run-lock so `session compact` can detect a live
     * gateway and refuse to rewrite sessions under it without --force. */
    int gw_lock_fd = sc_gateway_lock_acquire(workspace);
    if (gw_lock_fd < 0)
        SC_LOG_WARN("gateway", "Could not acquire run-lock; "
                    "`session compact` will not detect this gateway");

    /* Start optional services */
    gateway_services_t svc = {0};
    gateway_start_services(&svc, agent, bus, base, cfg, workspace);

    /* Channel manager */
    sc_channel_manager_t *ch_mgr = sc_channel_manager_new(cfg, bus);
    sc_bus_set_outbound_handler(bus, gateway_outbound_handler, ch_mgr);

    printf("\n%s %s Gateway v%s\n", SC_LOGO, SC_NAME, SC_VERSION);
    sc_channel_manager_start_all(ch_mgr);
    printf("  Channels started\n");
    printf("\nPress Ctrl+C to stop\n\n");

    gateway_event_loop(base, bus, agent, ch_mgr, &svc, &cfg, config_path);
    if (gw_lock_fd >= 0) close(gw_lock_fd);
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
#if SC_ENABLE_MCP_SERVER
    } else if (strcmp(command, "mcp-server") == 0) {
        cmd_mcp_server(argc, argv);
#endif
    } else if (strcmp(command, "pairing") == 0) {
        cmd_pairing(argc, argv);
    } else if (strcmp(command, "cost") == 0) {
        cmd_cost(argc, argv);
#if SC_ENABLE_ANALYTICS
    } else if (strcmp(command, "analytics") == 0) {
        cmd_analytics(argc, argv);
#endif
    } else if (strcmp(command, "session") == 0) {
        int rc = cmd_session(argc, argv);
        sc_logger_shutdown();
        return rc;
    } else if (strcmp(command, "context") == 0) {
        int rc = cmd_context(argc, argv);
        sc_logger_shutdown();
        return rc;
    } else if (strcmp(command, "memory") == 0) {
        int rc = cmd_memory(argc, argv);
        sc_logger_shutdown();
        return rc;
    } else if (strcmp(command, "backup") == 0) {
        return cmd_backup(argc, argv);
    } else if (strcmp(command, "doctor") == 0) {
        return sc_cmd_doctor(argc, argv);
    } else if (strcmp(command, "selftest") == 0) {
        return cmd_selftest(argc, argv);
    } else if (strcmp(command, "host-refresh") == 0) {
        int rc = cmd_host_refresh();
        sc_logger_shutdown();
        return rc;
#if SC_ENABLE_VAULT
    } else if (strcmp(command, "vault") == 0) {
        cmd_vault(argc, argv);
#endif
#if SC_ENABLE_UPDATER
    } else if (strcmp(command, "update") == 0) {
        cmd_update(argc, argv);
#endif
#if SC_ENABLE_XAI_OAUTH
    } else if (strcmp(command, "auth") == 0) {
        return sc_cmd_auth(argc, argv);
#endif
#if SC_ENABLE_COMPANION
    } else if (strcmp(command, "companion") == 0) {
        if (argc < 3 || strcmp(argv[2], "qr") != 0) {
            fprintf(stderr, "Usage: smolclaw companion qr [--url ORIGIN] [--force]\n");
            return 1;
        }
        int rc = sc_companion_cmd_qr(argc - 2, argv + 2);
        sc_logger_shutdown();
        return rc;
#endif
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        print_help();
        return 1;
    }

    sc_logger_shutdown();
    return 0;
}
