/*
 * smolclaw - agent loop
 * Public API, initialization, tool registration, message routing.
 * LLM iteration logic in agent_turn.c, session management in agent_session.c.
 */

#include "agent.h"
#include "agent_internal.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include "cJSON.h"
#include "sc_features.h"
#include "constants.h"
#include "audit.h"
#include "logger.h"
#include "tools/filesystem.h"
#include "tools/shell.h"
#include "tools/message.h"
#include "tools/memory_tools.h"
#include "providers/factory.h"
#include "memory.h"
#include "util/str.h"
#include "util/secrets.h"
#include "util/prompt_guard.h"

#if SC_ENABLE_WEB_TOOLS
#include "tools/web.h"
#endif
#if SC_ENABLE_SPAWN
#include "tools/spawn.h"
#endif
#if SC_ENABLE_BACKGROUND
#include "tools/background.h"
#endif
#if SC_ENABLE_MCP
#include "mcp/bridge.h"
#endif
#if SC_ENABLE_GIT
#include "tools/git.h"
#endif
#if SC_ENABLE_CODE_GRAPH
#include "tools/code_graph.h"
#endif
#if SC_ENABLE_X_TOOLS
#include "tools/x_tools.h"
#endif
#include "cost.h"
#if SC_ENABLE_TEE
#include "tee.h"
#endif
#include "util/sandbox.h"
#if SC_ENABLE_ANALYTICS
#include "analytics.h"
#endif
#if SC_ENABLE_MEMORY_SEARCH
#include "memory_index.h"
#include "tools/memory_search.h"
#include "tools/context_tools.h"

static void memory_index_cb(const char *source, const char *content, void *ctx)
{
    sc_memory_index_put_chunked((sc_memory_index_t *)ctx, source, content);
}
#endif

/* Built-in model aliases (overridable by config) */
static const struct { const char *name; const char *model; } builtin_aliases[] = {
    { "opus",   "claude-opus-4-6" },
    { "sonnet", "claude-sonnet-4-5-20250929" },
    { "haiku",  "claude-haiku-4-5-20251001" },
    { "gpt4o",  "gpt-4o" },
    { "o3",     "o3" },
};
#define BUILTIN_ALIAS_COUNT (int)(sizeof(builtin_aliases) / sizeof(builtin_aliases[0]))

/* Forward declarations */
static char *process_message(sc_agent_t *agent, sc_inbound_msg_t *msg);
static char *run_agent_loop(sc_agent_t *agent, const char *session_key,
                            const char *channel, const char *chat_id,
                            const char *user_message, int no_history);
static void update_tool_contexts(sc_agent_t *agent, const char *channel, const char *chat_id);

/* Message send callback for the message tool */
static int message_send_cb(const char *channel, const char *chat_id,
                           const char *content, void *ctx)
{
    sc_agent_t *agent = ctx;
    if (!agent || !agent->bus) return -1;

    sc_outbound_msg_t *out = sc_outbound_msg_new(channel, chat_id, content);
    if (!out) return -1;

    sc_bus_publish_outbound(agent->bus, out);
    return 0;
}

/* Register standalone tools (no agent dependency).
 * Used by both the full agent and the MCP server mode. */
void sc_register_tools_standalone(sc_tool_registry_t *reg, sc_config_t *cfg,
                                   const char *workspace)
{
    int restrict_ws = cfg->restrict_to_workspace;

    /* Filesystem tools */
    sc_tool_registry_register(reg, sc_tool_read_file_new(workspace, restrict_ws));
    sc_tool_registry_register(reg, sc_tool_write_file_new(workspace, restrict_ws));
    sc_tool_registry_register(reg, sc_tool_list_dir_new(workspace, restrict_ws));
    sc_tool_registry_register(reg, sc_tool_edit_file_new(workspace, restrict_ws));
    sc_tool_registry_register(reg, sc_tool_append_file_new(workspace, restrict_ws));

    /* Shell */
    sc_tool_t *exec_tool = sc_tool_exec_new(workspace, restrict_ws,
                                             cfg->max_output_chars,
                                             cfg->exec_timeout_secs);
    if (cfg->exec_use_allowlist && cfg->exec_allowed_commands) {
        sc_tool_exec_set_allowlist(exec_tool, 1,
                                    cfg->exec_allowed_commands,
                                    cfg->exec_allowed_command_count);
    }
    sc_tool_exec_set_sandbox(exec_tool, cfg->sandbox_enabled);
    if (cfg->sandbox_enabled) {
        int avail = sc_sandbox_available();
        if (!(avail & SC_SANDBOX_LANDLOCK))
            SC_LOG_WARN("agent", "Landlock not available — exec children will run without filesystem sandbox");
        if (!(avail & SC_SANDBOX_SECCOMP))
            SC_LOG_WARN("agent", "seccomp-bpf not available — exec children will run without syscall filter");
    }
    sc_tool_registry_register(reg, exec_tool);

    /* Web tools */
#if SC_ENABLE_WEB_TOOLS
    sc_web_search_opts_t web_opts = {
        .brave_enabled = cfg->web_tools.brave_enabled,
        .brave_api_key = cfg->web_tools.brave_api_key,
        .brave_base_url = cfg->web_tools.brave_base_url,
        .brave_max_results = cfg->web_tools.brave_max_results,
        .searxng_enabled = cfg->web_tools.searxng_enabled,
        .searxng_base_url = cfg->web_tools.searxng_base_url,
        .searxng_max_results = cfg->web_tools.searxng_max_results,
        .duckduckgo_enabled = cfg->web_tools.duckduckgo_enabled,
        .duckduckgo_max_results = cfg->web_tools.duckduckgo_max_results,
    };
    sc_tool_t *search = sc_tool_web_search_new(web_opts);
    if (search) sc_tool_registry_register(reg, search);
    sc_tool_registry_register(reg, sc_tool_web_fetch_new(cfg->max_fetch_chars));
#endif

    /* X tools */
#if SC_ENABLE_X_TOOLS
    if (cfg->x.consumer_key && cfg->x.consumer_key[0] &&
        cfg->x.access_token && cfg->x.access_token[0]) {
        sc_tool_t *xt;
        xt = sc_tool_x_get_tweet_new(&cfg->x);
        if (xt) sc_tool_registry_register(reg, xt);
        xt = sc_tool_x_get_thread_new(&cfg->x);
        if (xt) sc_tool_registry_register(reg, xt);
        xt = sc_tool_x_search_new(&cfg->x);
        if (xt) sc_tool_registry_register(reg, xt);
        xt = sc_tool_x_get_user_new(&cfg->x);
        if (xt) sc_tool_registry_register(reg, xt);
    }
#endif

    /* Memory tools */
    sc_tool_registry_register(reg, sc_tool_memory_read_new(workspace));
    sc_tool_registry_register(reg, sc_tool_memory_write_new(workspace));
    sc_tool_registry_register(reg, sc_tool_memory_log_new(workspace));

    /* Memory search (FTS5 index) — standalone mode */
#if SC_ENABLE_MEMORY_SEARCH
    {
        sc_strbuf_t db_sb;
        sc_strbuf_init(&db_sb);
        sc_strbuf_appendf(&db_sb, "%s/memory/search.db", workspace);
        char *db_path = sc_strbuf_finish(&db_sb);

        sc_memory_index_t *midx = sc_memory_index_new(db_path);
        free(db_path);

        if (midx) {
            sc_strbuf_t mem_sb;
            sc_strbuf_init(&mem_sb);
            sc_strbuf_appendf(&mem_sb, "%s/memory", workspace);
            char *mem_dir = sc_strbuf_finish(&mem_sb);
            sc_memory_index_rebuild(midx, mem_dir);
            free(mem_dir);

            sc_tool_registry_register(reg,
                                       sc_tool_memory_search_new(midx));

            /* Index context artifacts directory if it exists */
            {
                sc_strbuf_t ctx_sb;
                sc_strbuf_init(&ctx_sb);
                sc_strbuf_appendf(&ctx_sb, "%s/context", workspace);
                char *ctx_dir = sc_strbuf_finish(&ctx_sb);
                struct stat ctx_st;
                if (stat(ctx_dir, &ctx_st) == 0 && S_ISDIR(ctx_st.st_mode)) {
                    static const char *ctx_exts[] = {
                        ".md", ".txt", ".yaml", ".yml",
                        ".json", ".sql", ".toml"
                    };
                    sc_memory_index_rebuild_dir(midx, ctx_dir, "ctx:",
                        ctx_exts, 7);
                    sc_tool_registry_register(reg,
                        sc_tool_context_search_new(midx));
                }
                free(ctx_dir);
            }
            /* Note: midx ownership leaks in standalone mode —
             * acceptable since the process exits after MCP server stops */
        }
    }
#endif

    /* Git tool */
#if SC_ENABLE_GIT
    sc_tool_registry_register(reg,
                               sc_tool_git_new(workspace, restrict_ws));
#endif

    /* Code graph tool */
#if SC_ENABLE_CODE_GRAPH
    sc_tool_registry_register(reg,
                               sc_tool_code_graph_new(workspace));
#endif
}

/* Register all default tools into the agent's registry.
 * This includes agent-specific tools (message, spawn, tee) that
 * sc_register_tools_standalone() omits. */
static void register_default_tools(sc_agent_t *agent, sc_config_t *cfg)
{
    const char *workspace = agent->workspace;
    int restrict_ws = cfg->restrict_to_workspace;

    /* Filesystem tools */
    sc_tool_registry_register(agent->tools, sc_tool_read_file_new(workspace, restrict_ws));
    sc_tool_registry_register(agent->tools, sc_tool_write_file_new(workspace, restrict_ws));
    sc_tool_registry_register(agent->tools, sc_tool_list_dir_new(workspace, restrict_ws));
    sc_tool_registry_register(agent->tools, sc_tool_edit_file_new(workspace, restrict_ws));
    sc_tool_registry_register(agent->tools, sc_tool_append_file_new(workspace, restrict_ws));

    /* Shell */
    sc_tool_t *exec_tool = sc_tool_exec_new(workspace, restrict_ws,
                                             cfg->max_output_chars,
                                             cfg->exec_timeout_secs);
    if (cfg->exec_use_allowlist && cfg->exec_allowed_commands) {
        sc_tool_exec_set_allowlist(exec_tool, 1,
                                    cfg->exec_allowed_commands,
                                    cfg->exec_allowed_command_count);
    }
    sc_tool_exec_set_sandbox(exec_tool, cfg->sandbox_enabled);
    if (cfg->sandbox_enabled) {
        int avail = sc_sandbox_available();
        if (!(avail & SC_SANDBOX_LANDLOCK))
            SC_LOG_WARN("agent", "Landlock not available — exec children will run without filesystem sandbox");
        if (!(avail & SC_SANDBOX_SECCOMP))
            SC_LOG_WARN("agent", "seccomp-bpf not available — exec children will run without syscall filter");
    }
#if SC_ENABLE_TEE
    if (cfg->tee_enabled) {
        sc_tee_config_t *tee = calloc(1, sizeof(*tee));
        if (tee) {
            tee->max_files = cfg->tee_max_files;
            tee->max_file_size = (size_t)cfg->tee_max_file_size;
            sc_tee_init(tee, workspace);
            agent->tee_cfg = tee;
            sc_tool_exec_set_tee(exec_tool, tee);
        }
    }
#endif
    sc_tool_registry_register(agent->tools, exec_tool);

    /* Web tools */
#if SC_ENABLE_WEB_TOOLS
    sc_web_search_opts_t web_opts = {
        .brave_enabled = cfg->web_tools.brave_enabled,
        .brave_api_key = cfg->web_tools.brave_api_key,
        .brave_base_url = cfg->web_tools.brave_base_url,
        .brave_max_results = cfg->web_tools.brave_max_results,
        .searxng_enabled = cfg->web_tools.searxng_enabled,
        .searxng_base_url = cfg->web_tools.searxng_base_url,
        .searxng_max_results = cfg->web_tools.searxng_max_results,
        .duckduckgo_enabled = cfg->web_tools.duckduckgo_enabled,
        .duckduckgo_max_results = cfg->web_tools.duckduckgo_max_results,
    };
    sc_tool_t *search = sc_tool_web_search_new(web_opts);
    if (search) sc_tool_registry_register(agent->tools, search);
    sc_tool_registry_register(agent->tools, sc_tool_web_fetch_new(cfg->max_fetch_chars));
#endif

    /* X tools */
#if SC_ENABLE_X_TOOLS
    if (cfg->x.consumer_key && cfg->x.consumer_key[0] &&
        cfg->x.access_token && cfg->x.access_token[0]) {
        sc_tool_t *xt;
        xt = sc_tool_x_get_tweet_new(&cfg->x);
        if (xt) sc_tool_registry_register(agent->tools, xt);
        xt = sc_tool_x_get_thread_new(&cfg->x);
        if (xt) sc_tool_registry_register(agent->tools, xt);
        xt = sc_tool_x_search_new(&cfg->x);
        if (xt) sc_tool_registry_register(agent->tools, xt);
        xt = sc_tool_x_get_user_new(&cfg->x);
        if (xt) sc_tool_registry_register(agent->tools, xt);
    }
#endif

    /* Message tool (agent-specific: needs bus callback) */
    sc_tool_t *msg_tool = sc_tool_message_new();
    sc_tool_message_set_callback(msg_tool, message_send_cb, agent);
    if (cfg->restrict_message_tool)
        sc_tool_message_set_restrict(msg_tool, 1);
    sc_tool_registry_register(agent->tools, msg_tool);

    /* Memory tools */
    sc_tool_t *mem_write_tool = sc_tool_memory_write_new(workspace);
    sc_tool_t *mem_log_tool = sc_tool_memory_log_new(workspace);
    sc_tool_registry_register(agent->tools, sc_tool_memory_read_new(workspace));
    sc_tool_registry_register(agent->tools, mem_write_tool);
    sc_tool_registry_register(agent->tools, mem_log_tool);

    /* Memory search (FTS5 index) */
#if SC_ENABLE_MEMORY_SEARCH
    {
        sc_strbuf_t db_sb;
        sc_strbuf_init(&db_sb);
        sc_strbuf_appendf(&db_sb, "%s/memory/search.db", workspace);
        char *db_path = sc_strbuf_finish(&db_sb);

        sc_memory_index_t *midx = sc_memory_index_new(db_path);
        free(db_path);

        if (midx) {
            sc_strbuf_t mem_sb;
            sc_strbuf_init(&mem_sb);
            sc_strbuf_appendf(&mem_sb, "%s/memory", workspace);
            char *mem_dir = sc_strbuf_finish(&mem_sb);
            sc_memory_index_rebuild(midx, mem_dir);
            free(mem_dir);

            agent->memory_index = midx;
            sc_tool_registry_register(agent->tools,
                                       sc_tool_memory_search_new(midx));

            /* Wire index callback into write/log tools */
            sc_tool_memory_set_index_cb(mem_write_tool,
                                         memory_index_cb, midx);
            sc_tool_memory_set_index_cb(mem_log_tool,
                                         memory_index_cb, midx);

            /* Index context artifacts directory if it exists */
            {
                sc_strbuf_t ctx_sb;
                sc_strbuf_init(&ctx_sb);
                sc_strbuf_appendf(&ctx_sb, "%s/context", workspace);
                char *ctx_dir = sc_strbuf_finish(&ctx_sb);
                struct stat ctx_st;
                if (stat(ctx_dir, &ctx_st) == 0 && S_ISDIR(ctx_st.st_mode)) {
                    static const char *ctx_exts[] = {
                        ".md", ".txt", ".yaml", ".yml",
                        ".json", ".sql", ".toml"
                    };
                    sc_memory_index_rebuild_dir(midx, ctx_dir, "ctx:",
                        ctx_exts, 7);
                    sc_tool_registry_register(agent->tools,
                        sc_tool_context_search_new(midx));
                }
                free(ctx_dir);
            }
        }
    }
#endif

    /* Git tool */
#if SC_ENABLE_GIT
    sc_tool_registry_register(agent->tools,
                               sc_tool_git_new(workspace, restrict_ws));
#endif

    /* Code graph tool */
#if SC_ENABLE_CODE_GRAPH
    sc_tool_registry_register(agent->tools,
                               sc_tool_code_graph_new(workspace));
#endif

    /* Spawn tool (agent-specific: needs agent pointer) */
#if SC_ENABLE_SPAWN
    sc_tool_registry_register(agent->tools, sc_tool_spawn_new(agent));
#endif

    /* Background process tools */
#if SC_ENABLE_BACKGROUND
    sc_tool_t *bg_tool = sc_tool_exec_bg_new(workspace, restrict_ws,
                                              cfg->max_background_procs);
    if (cfg->exec_use_allowlist && cfg->exec_allowed_commands) {
        sc_tool_exec_bg_set_allowlist(bg_tool, 1,
                                       cfg->exec_allowed_commands,
                                       cfg->exec_allowed_command_count);
    }
    sc_tool_exec_bg_set_sandbox(bg_tool, cfg->sandbox_enabled);
#if SC_ENABLE_TEE
    if (agent->tee_cfg)
        sc_tool_bg_poll_set_tee(agent->tee_cfg);
#endif
    sc_tool_registry_register(agent->tools, bg_tool);
    sc_tool_registry_register(agent->tools, sc_tool_bg_poll_new());
    sc_tool_registry_register(agent->tools, sc_tool_bg_kill_new());
#endif

    /* MCP external tool servers */
#if SC_ENABLE_MCP
    if (cfg->mcp.enabled && cfg->mcp.server_count > 0)
        agent->mcp_bridge = sc_mcp_bridge_start(&cfg->mcp, agent->tools,
                                                 agent->workspace);
#endif
}

/* Initialize fallback providers from config */
static void init_fallback_providers(sc_agent_t *agent, sc_config_t *cfg)
{
    if (cfg->fallback_model_count <= 0) return;

    agent->fallback_providers = calloc((size_t)cfg->fallback_model_count,
                                       sizeof(sc_provider_t *));
    agent->fallback_models = calloc((size_t)cfg->fallback_model_count,
                                    sizeof(char *));
    if (!agent->fallback_providers || !agent->fallback_models) {
        free(agent->fallback_providers);
        free(agent->fallback_models);
        agent->fallback_providers = NULL;
        agent->fallback_models = NULL;
        return;
    }

    for (int i = 0; i < cfg->fallback_model_count; i++) {
        sc_provider_t *fp = sc_provider_create_for_model(cfg,
            cfg->fallback_models[i]);
        if (fp) {
            agent->fallback_models[agent->fallback_count] =
                sc_strdup(sc_model_strip_prefix(cfg->fallback_models[i]));
            agent->fallback_providers[agent->fallback_count] = fp;
            agent->fallback_count++;
        } else {
            SC_LOG_WARN("agent", "Failed to create fallback provider for '%s'",
                        cfg->fallback_models[i]);
        }
    }
}

/* Initialize model aliases: merge built-ins with config overrides (config wins) */
static void init_model_aliases(sc_agent_t *agent, sc_config_t *cfg)
{
    int max_aliases = BUILTIN_ALIAS_COUNT + cfg->model_alias_count;
    agent->alias_names     = calloc((size_t)max_aliases, sizeof(char *));
    agent->alias_models    = calloc((size_t)max_aliases, sizeof(char *));
    agent->alias_providers = calloc((size_t)max_aliases, sizeof(sc_provider_t *));
    if (!agent->alias_names || !agent->alias_models || !agent->alias_providers) {
        free(agent->alias_names);
        free(agent->alias_models);
        free(agent->alias_providers);
        agent->alias_names = NULL;
        agent->alias_models = NULL;
        agent->alias_providers = NULL;
        return;
    }

    /* Start with built-in aliases */
    for (int i = 0; i < BUILTIN_ALIAS_COUNT; i++) {
        int overridden = 0;
        for (int j = 0; j < cfg->model_alias_count; j++) {
            if (strcasecmp(builtin_aliases[i].name,
                           cfg->model_alias_names[j]) == 0) {
                overridden = 1;
                break;
            }
        }
        if (overridden) continue;

        sc_provider_t *ap = sc_provider_create_for_model(cfg,
            builtin_aliases[i].model);
        if (ap) {
            agent->alias_names[agent->alias_count] =
                sc_strdup(builtin_aliases[i].name);
            agent->alias_models[agent->alias_count] =
                sc_strdup(sc_model_strip_prefix(builtin_aliases[i].model));
            agent->alias_providers[agent->alias_count] = ap;
            agent->alias_count++;
        } else {
            SC_LOG_WARN("agent", "Failed to create alias provider for '%s' (%s)",
                        builtin_aliases[i].name, builtin_aliases[i].model);
        }
    }

    /* Add config aliases */
    for (int i = 0; i < cfg->model_alias_count; i++) {
        sc_provider_t *ap = sc_provider_create_for_model(cfg,
            cfg->model_alias_models[i]);
        if (ap) {
            agent->alias_names[agent->alias_count] =
                sc_strdup(cfg->model_alias_names[i]);
            agent->alias_models[agent->alias_count] =
                sc_strdup(sc_model_strip_prefix(cfg->model_alias_models[i]));
            agent->alias_providers[agent->alias_count] = ap;
            agent->alias_count++;
        } else {
            SC_LOG_WARN("agent", "Failed to create alias provider for '%s' (%s)",
                        cfg->model_alias_names[i], cfg->model_alias_models[i]);
        }
    }

    if (agent->alias_count > 0) {
        SC_LOG_INFO("agent", "Registered %d model aliases", agent->alias_count);
    }
}

/* ======================================================================
 * Per-channel tool allowlists
 * ====================================================================== */

static void free_channel_tools(sc_agent_t *agent)
{
    for (int i = 0; i < agent->channel_tools_count; i++) {
        free(agent->channel_tools[i].channel);
        for (int j = 0; j < agent->channel_tools[i].tool_count; j++)
            free(agent->channel_tools[i].tools[j]);
        free(agent->channel_tools[i].tools);
    }
    agent->channel_tools_count = 0;
}

static void add_channel_tools(sc_agent_t *agent, const char *channel,
                               char **tools, int count)
{
    if (!tools || count <= 0) return;
    if (agent->channel_tools_count >= SC_MAX_CHANNEL_TOOL_ENTRIES) return;

    int idx = agent->channel_tools_count++;
    agent->channel_tools[idx].channel = sc_strdup(channel);
    agent->channel_tools[idx].tools = calloc((size_t)count, sizeof(char *));
    if (!agent->channel_tools[idx].tools) {
        agent->channel_tools_count--;
        return;
    }
    for (int i = 0; i < count; i++)
        agent->channel_tools[idx].tools[i] = sc_strdup(tools[i]);
    agent->channel_tools[idx].tool_count = count;
    SC_LOG_INFO("agent", "Channel '%s': %d tools in allowlist", channel, count);
}

static void load_channel_tools(sc_agent_t *agent, const sc_config_t *cfg)
{
    free_channel_tools(agent);
    add_channel_tools(agent, "telegram", cfg->telegram.tools, cfg->telegram.tool_count);
    add_channel_tools(agent, "discord", cfg->discord.tools, cfg->discord.tool_count);
    add_channel_tools(agent, "irc", cfg->irc.tools, cfg->irc.tool_count);
    add_channel_tools(agent, "slack", cfg->slack.tools, cfg->slack.tool_count);
    add_channel_tools(agent, "web", cfg->web.tools, cfg->web.tool_count);
    add_channel_tools(agent, "x", cfg->x.tools, cfg->x.tool_count);
}

/* ======================================================================
 * Public API
 * ====================================================================== */

sc_agent_t *sc_agent_new(sc_config_t *cfg, sc_bus_t *bus, sc_provider_t *provider)
{
    sc_agent_t *agent = calloc(1, sizeof(*agent));
    if (!agent) return NULL;

    char *workspace = sc_config_workspace_path(cfg);
    agent->bus = bus;
    agent->provider = provider;
    agent->workspace = workspace;
    agent->model = sc_strdup(sc_model_strip_prefix(cfg->model));
    agent->context_window = cfg->max_tokens;
    agent->temperature = cfg->temperature;
    agent->max_iterations = cfg->max_tool_iterations;
    agent->session_summary_threshold = cfg->session_summary_threshold;
    agent->session_keep_last = cfg->session_keep_last;
    agent->max_output_chars = cfg->max_output_chars;
    agent->max_fetch_chars = cfg->max_fetch_chars;
    agent->max_background_procs = cfg->max_background_procs;
    agent->summary_max_transcript = cfg->summary_max_transcript;
    agent->exec_timeout_secs = cfg->exec_timeout_secs;
    agent->max_tool_calls_per_turn = cfg->max_tool_calls_per_turn;
    agent->max_turn_secs = cfg->max_turn_secs;
    agent->max_output_total = cfg->max_output_total;
    agent->max_tool_calls_per_hour = cfg->max_tool_calls_per_hour;
    agent->memory_consolidation = cfg->memory_consolidation;
    agent->verbose = cfg->verbose;
    agent->running = 0;
    agent->hourly_slots = calloc(SC_HOURLY_SLOTS, sizeof(sc_hourly_slot_t));

    /* Session manager */
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/sessions", workspace);
    char *sessions_dir = sc_strbuf_finish(&sb);
    agent->sessions = sc_session_manager_new(sessions_dir);
    free(sessions_dir);

    /* State manager */
    agent->state = sc_state_new(workspace);

    /* Tool registry */
    agent->tools = sc_tool_registry_new();
    register_default_tools(agent, cfg);

    /* Context builder */
    agent->context_builder = sc_context_builder_new(workspace);
    sc_context_builder_set_tools(agent->context_builder, agent->tools);

    /* Audit log */
    {
        sc_strbuf_t ab;
        sc_strbuf_init(&ab);
        sc_strbuf_appendf(&ab, "%s/audit.log", workspace);
        char *audit_path = sc_strbuf_finish(&ab);
        sc_audit_init(audit_path);
        free(audit_path);
    }

    /* Cost tracker */
    agent->cost_tracker = sc_cost_tracker_new(workspace);

#if SC_ENABLE_ANALYTICS
    agent->analytics = sc_analytics_new(workspace);
#endif

    /* Fallback providers + model aliases */
    init_fallback_providers(agent, cfg);
    init_model_aliases(agent, cfg);

    /* Per-channel tool allowlists */
    load_channel_tools(agent, cfg);

    return agent;
}

void sc_agent_free(sc_agent_t *agent)
{
    if (!agent) return;
    /* Drain outstanding summarization thread before freeing resources */
    sc_drain_summarize(agent);
    sc_cost_tracker_free(agent->cost_tracker);
#if SC_ENABLE_ANALYTICS
    if (agent->analytics)
        sc_analytics_free(agent->analytics);
#endif
#if SC_ENABLE_TEE
    if (agent->tee_cfg) {
        sc_tee_config_free(agent->tee_cfg);
        free(agent->tee_cfg);
    }
#endif
#if SC_ENABLE_MEMORY_SEARCH
    if (agent->memory_index)
        sc_memory_index_free(agent->memory_index);
#endif
#if SC_ENABLE_MCP
    sc_mcp_bridge_free(agent->mcp_bridge);
#endif
#if SC_ENABLE_BACKGROUND
    sc_bg_cleanup_all();
#endif
    sc_audit_shutdown();
    free_channel_tools(agent);
    free(agent->workspace);
    free(agent->model);
    sc_session_manager_free(agent->sessions);
    sc_state_free(agent->state);
    sc_context_builder_free(agent->context_builder);
    sc_tool_registry_free(agent->tools);
    /* Fallback providers (owned) */
    for (int i = 0; i < agent->fallback_count; i++) {
        if (agent->fallback_providers[i] && agent->fallback_providers[i]->destroy)
            agent->fallback_providers[i]->destroy(agent->fallback_providers[i]);
        free(agent->fallback_models[i]);
    }
    free(agent->fallback_providers);
    free(agent->fallback_models);
    /* Alias providers (owned) */
    for (int i = 0; i < agent->alias_count; i++) {
        if (agent->alias_providers[i] && agent->alias_providers[i]->destroy)
            agent->alias_providers[i]->destroy(agent->alias_providers[i]);
        free(agent->alias_names[i]);
        free(agent->alias_models[i]);
    }
    free(agent->alias_providers);
    free(agent->alias_names);
    free(agent->alias_models);
    free(agent->hourly_slots);
    /* provider and bus are borrowed */
    free(agent);
}

int sc_agent_run(sc_agent_t *agent)
{
    agent->running = 1;

    while (agent->running) {
        sc_inbound_msg_t *msg = sc_bus_consume_inbound(agent->bus);
        if (!msg) continue;

        char *response = process_message(agent, msg);

        if (response && response[0]) {
            sc_tool_t *mt = sc_tool_registry_get(agent->tools, "message");
            int already_sent = mt ? sc_tool_message_has_sent(mt) : 0;

            if (!already_sent) {
                sc_outbound_msg_t *out = sc_outbound_msg_new(
                    msg->channel, msg->chat_id, response);
                if (out) sc_bus_publish_outbound(agent->bus, out);
            }
        }

        free(response);
        sc_inbound_msg_free(msg);
    }

    return 0;
}

void sc_agent_stop(sc_agent_t *agent)
{
    if (agent) agent->running = 0;
}

void sc_agent_register_tool(sc_agent_t *agent, sc_tool_t *tool)
{
    if (agent && agent->tools && tool) {
        sc_tool_registry_register(agent->tools, tool);
    }
}

void sc_agent_set_stream_cb(sc_agent_t *agent, sc_stream_cb cb, void *ctx)
{
    if (!agent) return;
    agent->stream_cb = cb;
    agent->stream_ctx = ctx;
}

void sc_agent_wait_summarize(sc_agent_t *agent)
{
    if (!agent) return;
    sc_drain_summarize(agent);
}

void sc_agent_reload_config(sc_agent_t *agent, const sc_config_t *cfg)
{
    if (!agent || !cfg) return;

    agent->max_iterations = cfg->max_tool_iterations;
    agent->max_tool_calls_per_turn = cfg->max_tool_calls_per_turn;
    agent->max_turn_secs = cfg->max_turn_secs;
    agent->max_output_total = cfg->max_output_total;
    agent->max_tool_calls_per_hour = cfg->max_tool_calls_per_hour;
    agent->verbose = cfg->verbose;
    agent->exec_timeout_secs = cfg->exec_timeout_secs;
    agent->max_output_chars = cfg->max_output_chars;
    agent->max_fetch_chars = cfg->max_fetch_chars;
    agent->temperature = cfg->temperature;
    agent->context_window = cfg->max_tokens;

    if (cfg->allowed_tools && cfg->allowed_tool_count > 0) {
        sc_tool_registry_set_allowed(agent->tools, cfg->allowed_tools,
                                      cfg->allowed_tool_count);
    } else {
        sc_tool_registry_set_allowed(agent->tools, NULL, 0);
    }

    /* Per-channel tool allowlists */
    load_channel_tools(agent, cfg);

    /* Note: exec_timeout_secs, max_output_chars, max_fetch_chars are captured
     * by tools at construction time and cannot be updated by reload. */
    SC_LOG_INFO("agent", "Config reloaded (max_iterations=%d, max_tool_calls=%d, "
                "max_turn_secs=%d, temperature=%.2f)",
                agent->max_iterations, agent->max_tool_calls_per_turn,
                agent->max_turn_secs, agent->temperature);
}

char *sc_agent_process_direct(sc_agent_t *agent, const char *content,
                               const char *session_key)
{
    const char *sk = session_key ? session_key : "cli:default";
    return run_agent_loop(agent, sk, SC_CHANNEL_CLI, "direct", content, 0);
}

char *sc_agent_process_channel(sc_agent_t *agent, const char *content,
                                const char *session_key,
                                const char *channel, const char *chat_id)
{
    const char *sk = session_key ? session_key : "cli:default";
    const char *ch = channel ? channel : SC_CHANNEL_CLI;
    const char *cid = chat_id ? chat_id : "direct";
    return run_agent_loop(agent, sk, ch, cid, content, 0);
}

char *sc_agent_process_heartbeat(sc_agent_t *agent, const char *content,
                                  const char *channel, const char *chat_id)
{
    return run_agent_loop(agent, "heartbeat", channel, chat_id, content, 1);
}

/* ======================================================================
 * Internal message processing
 * ====================================================================== */

static char *process_message(sc_agent_t *agent, sc_inbound_msg_t *msg)
{
    char *preview = sc_truncate(msg->content, 80);
    SC_LOG_INFO("agent", "Processing message from %s:%s: %s",
                msg->channel, msg->sender_id, preview ? preview : "");
    free(preview);

    return run_agent_loop(agent, msg->session_key, msg->channel, msg->chat_id,
                          msg->content, 0);
}

static char *run_agent_loop(sc_agent_t *agent, const char *session_key,
                            const char *channel, const char *chat_id,
                            const char *user_message, int no_history)
{
    /* Record last channel for heartbeat routing (skip internal channels) */
    if (channel && chat_id && !sc_is_internal_channel(channel)) {
        sc_strbuf_t ck;
        sc_strbuf_init(&ck);
        sc_strbuf_appendf(&ck, "%s:%s", channel, chat_id);
        char *channel_key = sc_strbuf_finish(&ck);
        sc_state_set_last_channel(agent->state, channel_key);
        free(channel_key);
    }

    update_tool_contexts(agent, channel, chat_id);

    sc_llm_message_t *history = NULL;
    int history_count = 0;
    const char *summary = NULL;

    if (!no_history) {
        history = sc_session_get_history(agent->sessions, session_key, &history_count);
        summary = sc_session_get_summary(agent->sessions, session_key);
    }

    /* Check for in-prompt model override ("Use X:" or "@X") */
    const char *actual_message = user_message;
    sc_provider_t *use_provider = agent->provider;
    const char *use_model = agent->model;

    const char *override_rest = NULL;
    char *alias = sc_parse_model_override(user_message, &override_rest);
    if (alias) {
        for (int i = 0; i < agent->alias_count; i++) {
            if (strcasecmp(alias, agent->alias_names[i]) == 0) {
                use_provider = agent->alias_providers[i];
                use_model = agent->alias_models[i];
                actual_message = override_rest;
                SC_LOG_INFO("agent", "Model override: alias '%s' → model '%s'",
                            alias, use_model);
                break;
            }
        }
        free(alias);
    }

    /* Build messages */
    int msg_count = 0;
    sc_llm_message_t *messages = sc_context_build_messages(
        agent->context_builder,
        history, history_count,
        summary, actual_message,
        channel, chat_id,
        &msg_count);

    if (!messages)
        return sc_strdup("Error: failed to build context messages.");

    /* Save user message to session (stripped of alias prefix) */
    sc_session_add_message(agent->sessions, session_key, "user", actual_message);

    /* Run LLM iteration loop */
    int iterations = 0;
    char *failure_reason = NULL;
    char *final_content = sc_run_llm_iteration(agent, use_provider, use_model,
                                                messages, msg_count,
                                                session_key, channel, chat_id,
                                                &iterations, &failure_reason);

    sc_llm_message_array_free(messages, msg_count);

    /* Handle empty response — use failure reason if available */
    if (!final_content || final_content[0] == '\0') {
        free(final_content);
        if (failure_reason) {
            final_content = failure_reason;
            failure_reason = NULL;
        } else {
            final_content = sc_strdup(
                "I've completed processing but have no response to give.");
        }
    }
    free(failure_reason);

    /* Outbound secret scanning */
    char *redacted_final = sc_redact_secrets(final_content);
    if (redacted_final) {
        free(final_content);
        final_content = redacted_final;
    }

    /* Save final assistant message */
    sc_session_add_message(agent->sessions, session_key, "assistant", final_content);
    sc_session_save(agent->sessions, session_key);

    if (!no_history)
        sc_maybe_summarize(agent, session_key);

    char *preview = sc_truncate(final_content, 120);
    SC_LOG_INFO("agent", "Response (%d iterations): %s", iterations, preview ? preview : "");
    free(preview);

    return final_content;
}

static void update_tool_contexts(sc_agent_t *agent, const char *channel, const char *chat_id)
{
    sc_tool_t *msg = sc_tool_registry_get(agent->tools, "message");
    if (msg && msg->set_context) {
        msg->set_context(msg, channel, chat_id);
    }
}

/*
 * Parse "Use <alias>: <message>" or "@<alias> <message>" from user input.
 * Returns alias name (caller owns) or NULL if no match.
 * Sets *rest to point to the actual message content after the prefix.
 */
char *sc_parse_model_override(const char *content, const char **rest)
{
    if (!content || !rest) return NULL;

    /* Skip leading whitespace */
    while (*content == ' ') content++;

    /* "Use <alias>: <message>" (case-insensitive) */
    if (strncasecmp(content, "use ", 4) == 0) {
        const char *alias_start = content + 4;
        while (*alias_start == ' ') alias_start++;
        const char *colon = strchr(alias_start, ':');
        if (colon && colon != alias_start) {
            const char *p = alias_start;
            while (p < colon && !isspace((unsigned char)*p)) p++;
            if (p == colon) {
                size_t len = (size_t)(colon - alias_start);
                if (len >= 64) return NULL;
                char *alias = malloc(len + 1);
                if (!alias) return NULL;
                memcpy(alias, alias_start, len);
                alias[len] = '\0';
                const char *msg = colon + 1;
                while (*msg == ' ') msg++;
                *rest = msg;
                return alias;
            }
        }
    }

    /* "@<alias> <message>" */
    if (content[0] == '@') {
        const char *alias_start = content + 1;
        if (*alias_start == '\0' || isspace((unsigned char)*alias_start)) return NULL;
        const char *end = alias_start;
        while (*end && !isspace((unsigned char)*end)) end++;
        if (end == alias_start) return NULL;

        size_t len = (size_t)(end - alias_start);
        if (len >= 64) return NULL;
        char *alias = malloc(len + 1);
        if (!alias) return NULL;
        memcpy(alias, alias_start, len);
        alias[len] = '\0';
        while (*end == ' ') end++;
        *rest = end;
        return alias;
    }

    return NULL;
}
