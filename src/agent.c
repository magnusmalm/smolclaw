/*
 * smolclaw - agent loop
 * Public API, initialization, tool registration, message routing.
 * LLM iteration logic in agent_turn.c, session management in agent_session.c.
 */

#include "agent.h"
#include "agent_internal.h"

#include <ctype.h>
#include <dirent.h>
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
#include "tools/host.h"
#include "tools/shell.h"
#include "tools/message.h"
#include "tools/memory_tools.h"
#include "tools/scratchpad.h"
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
#if SC_ENABLE_DELEGATE
#include "tools/delegate.h"
#include "tools/converse.h"
#endif
#if SC_ENABLE_BACKGROUND
#include "tools/background.h"
#endif
#if SC_ENABLE_MCP
#include "mcp/bridge.h"
#include "tools/tool_search.h"
#endif
#include "tools/skill_tool.h"
#if SC_ENABLE_GIT
#include "tools/git.h"
#include "tools/worktree.h"
#endif
#if SC_ENABLE_GITEA
#include "tools/gitea.h"
#endif
#if SC_ENABLE_CAMERA
#include "tools/camera.h"
#endif
#if SC_ENABLE_CODE_GRAPH
#include "tools/code_graph.h"
#include "tools/symbol_lookup.h"
#endif
#if SC_ENABLE_X_TOOLS
#include "tools/x_tools.h"
#endif
#include "tools/notify.h"
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
                            const char *user_message, int no_history,
                            const cJSON *response_format_override,
                            int isolated, const char *namespace_id);
static void update_tool_contexts(sc_agent_t *agent, const char *channel, const char *chat_id);

/* Message send callback for the message tool */
static int message_send_cb(const char *channel, const char *chat_id,
                           const char *content, void *ctx)
{
    sc_agent_t *agent = ctx;
    if (!agent || !agent->bus) return -1;
    if (agent->response_format) {
        SC_LOG_WARN("agent", "Blocking message tool during structured-output turn");
        return -1;
    }

    sc_outbound_msg_t *out = sc_outbound_msg_new(channel, chat_id, content);
    if (!out) return -1;

    sc_bus_publish_outbound(agent->bus, out);
    return 0;
}

static void free_tool_name_list(char **names, int count)
{
    if (!names) return;
    for (int i = 0; i < count; i++)
        free(names[i]);
    free(names);
}

static char **dup_allowed_tool_names(sc_tool_registry_t *reg, int *out_count)
{
    char **names = NULL;

    if (out_count) *out_count = 0;
    if (!reg || !reg->allowed_tools || reg->allowed_count <= 0)
        return NULL;

    names = calloc((size_t)reg->allowed_count, sizeof(char *));
    if (!names) return NULL;
    for (int i = 0; i < reg->allowed_count; i++) {
        names[i] = sc_strdup(reg->allowed_tools[i]);
        if (!names[i]) {
            free_tool_name_list(names, reg->allowed_count);
            return NULL;
        }
    }
    if (out_count) *out_count = reg->allowed_count;
    return names;
}

static char **build_structured_output_allowlist(sc_tool_registry_t *reg, int *out_count)
{
    char **names = NULL;
    int count = 0;
    int capacity = 0;

    if (out_count) *out_count = 0;
    if (!reg) return NULL;

    if (reg->allowed_tools && reg->allowed_count > 0) {
        capacity = reg->allowed_count;
        names = calloc((size_t)capacity, sizeof(char *));
        if (!names) return NULL;
        for (int i = 0; i < reg->allowed_count; i++) {
            const char *name = reg->allowed_tools[i];
            if (!name || strcmp(name, "message") == 0)
                continue;
            names[count] = sc_strdup(name);
            if (!names[count]) {
                free_tool_name_list(names, capacity);
                return NULL;
            }
            count++;
        }
    } else {
        capacity = reg->count;
        names = calloc((size_t)capacity, sizeof(char *));
        if (!names) return NULL;
        for (int i = 0; i < reg->count; i++) {
            const char *name = reg->tools[i] ? reg->tools[i]->name : NULL;
            if (!name || strcmp(name, "message") == 0)
                continue;
            names[count] = sc_strdup(name);
            if (!names[count]) {
                free_tool_name_list(names, capacity);
                return NULL;
            }
            count++;
        }
    }

    if (count == 0) {
        free(names);
        return NULL;
    }
    if (out_count) *out_count = count;
    return names;
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
    /* Block commands that have dedicated tools */
    {
        const char *covered[4];
        int nc = 0;
#if SC_ENABLE_GIT
        covered[nc++] = "git";
#endif
#if SC_ENABLE_GITEA
        if (cfg->gitea.url && cfg->gitea.token)
            covered[nc++] = "curl";
#endif
        if (nc > 0)
            sc_tool_exec_set_tool_covered(exec_tool, covered, nc);
    }
    sc_tool_registry_register(reg, exec_tool);

    /* Web tools */
#if SC_ENABLE_WEB_TOOLS
    sc_web_set_network_scope(cfg->network_scope);
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

    /* Scratchpad: persistent working notes that survive compaction */
    sc_tool_registry_register(reg, sc_tool_scratchpad_new(workspace));
    sc_tool_registry_register(reg,
                              sc_tool_host_status_new(workspace,
                                                      cfg->sandbox_enabled));

    sc_memory_index_t *midx = NULL;

    /* Memory search (FTS5 index) — standalone mode */
#if SC_ENABLE_MEMORY_SEARCH
    {
        sc_strbuf_t db_sb;
        sc_strbuf_init(&db_sb);
        sc_strbuf_appendf(&db_sb, "%s/memory/search.db", workspace);
        char *db_path = sc_strbuf_finish(&db_sb);

        midx = sc_memory_index_new(db_path);
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
                }
                sc_tool_registry_register(reg,
                    sc_tool_context_search_new(midx));
                free(ctx_dir);
            }
            /* Note: midx ownership leaks in standalone mode —
             * acceptable since the process exits after MCP server stops */
        }
    }
#endif

    sc_host_record_sample(workspace, 1);
    sc_host_refresh_inventory_artifacts(workspace, midx,
                                        cfg->sandbox_enabled);
    sc_tool_registry_register(reg,
                              sc_tool_host_inventory_new(workspace, midx,
                                                         cfg->sandbox_enabled));
    sc_tool_registry_register(reg, sc_tool_host_trend_new(workspace));

    /* Git tool */
#if SC_ENABLE_GIT
    sc_tool_registry_register(reg,
                               sc_tool_git_new(workspace, restrict_ws,
                                   (const char **)cfg->git.push_allowed_remotes,
                                   cfg->git.push_allowed_remote_count));
#endif

    /* Code graph tool + thin symbol_lookup wrapper (Drill-down convenience) */
#if SC_ENABLE_CODE_GRAPH
    sc_tool_registry_register(reg,
                               sc_tool_code_graph_new(workspace));
    sc_tool_registry_register(reg,
                               sc_tool_symbol_lookup_new(workspace));
#endif

    /* Gitea tool */
#if SC_ENABLE_GITEA
    if (cfg->gitea.url && cfg->gitea.token)
        sc_tool_registry_register(reg,
                                   sc_tool_gitea_new(cfg->gitea.url,
                                                      cfg->gitea.token,
                                                      cfg->gitea.default_org));
#endif

    /* Camera tool */
#if SC_ENABLE_CAMERA
    if (cfg->camera.snap_command || cfg->camera.vision_url)
        sc_tool_registry_register(reg,
            sc_tool_camera_new(workspace,
                               cfg->camera.snap_command,
                               cfg->camera.events_dir,
                               cfg->camera.vision_url,
                               cfg->camera.vision_model,
                               cfg->camera.vision_timeout_secs));
#endif

    /* Notify tool */
    if (cfg->notify_urls && cfg->notify_urls[0])
        sc_tool_registry_register(reg,
                                   sc_tool_notify_new(cfg->notify_urls));
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
    /* Block commands that have dedicated tools */
    {
        const char *covered[4];
        int nc = 0;
#if SC_ENABLE_GIT
        covered[nc++] = "git";
#endif
#if SC_ENABLE_GITEA
        if (cfg->gitea.url && cfg->gitea.token)
            covered[nc++] = "curl";
#endif
        if (nc > 0)
            sc_tool_exec_set_tool_covered(exec_tool, covered, nc);
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
    sc_web_set_network_scope(cfg->network_scope);
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
    sc_tool_registry_register(agent->tools,
                              sc_tool_host_status_new(workspace,
                                                      cfg->sandbox_enabled));

    /* Memory tools */
    sc_tool_t *mem_write_tool = sc_tool_memory_write_new(workspace);
    sc_tool_t *mem_log_tool = sc_tool_memory_log_new(workspace);
    sc_tool_registry_register(agent->tools, sc_tool_memory_read_new(workspace));
    sc_tool_registry_register(agent->tools, mem_write_tool);
    sc_tool_registry_register(agent->tools, mem_log_tool);

    /* Scratchpad: persistent working notes that survive compaction */
    sc_tool_registry_register(agent->tools, sc_tool_scratchpad_new(workspace));

    sc_memory_index_t *midx = NULL;

    /* Memory search (FTS5 index) */
#if SC_ENABLE_MEMORY_SEARCH
    {
        sc_strbuf_t db_sb;
        sc_strbuf_init(&db_sb);
        sc_strbuf_appendf(&db_sb, "%s/memory/search.db", workspace);
        char *db_path = sc_strbuf_finish(&db_sb);

        midx = sc_memory_index_new(db_path);
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
                }
                sc_tool_registry_register(agent->tools,
                    sc_tool_context_search_new(midx));
                free(ctx_dir);
            }
        }
    }
#endif

    sc_host_record_sample(workspace, 1);
    sc_host_refresh_inventory_artifacts(workspace, midx,
                                        cfg->sandbox_enabled);
    sc_tool_registry_register(agent->tools,
                               sc_tool_host_inventory_new(workspace, midx,
                                                          cfg->sandbox_enabled));
    sc_tool_registry_register(agent->tools,
                               sc_tool_host_trend_new(workspace));

    /* Git tool + worktree isolation */
#if SC_ENABLE_GIT
    sc_tool_registry_register(agent->tools,
                               sc_tool_git_new(workspace, restrict_ws,
                                   (const char **)cfg->git.push_allowed_remotes,
                                   cfg->git.push_allowed_remote_count));
    sc_tool_registry_register(agent->tools, sc_tool_worktree_enter_new(agent));
    sc_tool_registry_register(agent->tools, sc_tool_worktree_exit_new(agent));
#endif

    /* Code graph tool + thin symbol_lookup wrapper (Drill-down convenience) */
#if SC_ENABLE_CODE_GRAPH
    sc_tool_registry_register(agent->tools,
                               sc_tool_code_graph_new(workspace));
    sc_tool_registry_register(agent->tools,
                               sc_tool_symbol_lookup_new(workspace));
#endif

    /* Gitea tool */
#if SC_ENABLE_GITEA
    if (cfg->gitea.url && cfg->gitea.token)
        sc_tool_registry_register(agent->tools,
                                   sc_tool_gitea_new(cfg->gitea.url,
                                                      cfg->gitea.token,
                                                      cfg->gitea.default_org));
#endif

    /* Camera tool */
#if SC_ENABLE_CAMERA
    if (cfg->camera.snap_command || cfg->camera.vision_url)
        sc_tool_registry_register(agent->tools,
            sc_tool_camera_new(workspace,
                               cfg->camera.snap_command,
                               cfg->camera.events_dir,
                               cfg->camera.vision_url,
                               cfg->camera.vision_model,
                               cfg->camera.vision_timeout_secs));
#endif

    /* Notify tool */
    if (cfg->notify_urls && cfg->notify_urls[0])
        sc_tool_registry_register(agent->tools,
                                   sc_tool_notify_new(cfg->notify_urls));

    /* Spawn tool (agent-specific: needs agent pointer) */
#if SC_ENABLE_SPAWN
    sc_tool_registry_register(agent->tools, sc_tool_spawn_new(agent));
#endif

    /* Delegate + converse tools (agent-to-agent task routing) */
#if SC_ENABLE_DELEGATE
    if (cfg->delegation.target_count > 0) {
        sc_tool_registry_register(agent->tools,
                                   sc_tool_delegate_new(&cfg->delegation, workspace));
        sc_tool_registry_register(agent->tools,
                                   sc_tool_converse_new(&cfg->delegation, workspace));
    }
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
    if (cfg->mcp.enabled && cfg->mcp.server_count > 0) {
        agent->mcp_bridge = sc_mcp_bridge_start(&cfg->mcp, agent->tools,
                                                 agent->workspace);
        /* Register tool_search if any deferred tools exist */
        int has_deferred = 0;
        for (int i = 0; i < agent->tools->count; i++) {
            if (agent->tools->tools[i]->deferred) { has_deferred = 1; break; }
        }
        if (has_deferred) {
            sc_tool_t *ts = sc_tool_search_new(agent->tools);
            if (ts) sc_tool_registry_register(agent->tools, ts);
        }
    }
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
        sc_provider_t *fp = NULL;
        /* If model has a provider/ prefix, use that provider.
         * Otherwise, if the primary is a custom provider, clone it
         * for fallbacks so they route to the same endpoint. */
        int has_prefix = (strchr(cfg->fallback_models[i], '/') != NULL);
        if (has_prefix) {
            fp = sc_provider_create_for_model(cfg, cfg->fallback_models[i]);
        } else if (cfg->custom_provider_count > 0 && cfg->provider &&
                   agent->provider && agent->provider->clone) {
            /* Custom provider active — fallbacks should use same endpoint */
            int is_custom = 0;
            for (int c = 0; c < cfg->custom_provider_count; c++) {
                if (cfg->custom_providers[c].name &&
                    strcmp(cfg->custom_providers[c].name, cfg->provider) == 0) {
                    is_custom = 1;
                    break;
                }
            }
            if (is_custom) {
                fp = agent->provider->clone(agent->provider);
                if (fp)
                    SC_LOG_INFO("agent", "Fallback '%s' using custom provider '%s'",
                                cfg->fallback_models[i], cfg->provider);
            } else {
                fp = sc_provider_create_for_model(cfg, cfg->fallback_models[i]);
            }
        } else {
            fp = sc_provider_create_for_model(cfg, cfg->fallback_models[i]);
        }
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

/* Context transform: observation masking.
 * Replace old tool results with structured placeholders that preserve the
 * action chain (what the agent did) while discarding bulky tool output
 * (what the tool returned).  Short results (<200 bytes) are kept intact
 * since they're cheap and often contain error messages or confirmations.
 * Recent results (last 6 messages) are always kept in full. */
#define MASK_KEEP_RECENT  6
#define MASK_SIZE_EXEMPT  200

/* Find the tool call metadata for a given tool_call_id by scanning backward
 * from position `from` in the message array.  Returns NULL if not found. */
static const sc_tool_call_t *
find_tool_call_for_id(sc_llm_message_t *msgs, int from, const char *id)
{
    if (!id) return NULL;
    for (int i = from - 1; i >= 0; i--) {
        for (int j = 0; j < msgs[i].tool_call_count; j++) {
            if (msgs[i].tool_calls[j].id &&
                strcmp(msgs[i].tool_calls[j].id, id) == 0)
                return &msgs[i].tool_calls[j];
        }
    }
    return NULL;
}

/* Extract a compact label from tool arguments (first string value). */
static const char *
summarize_tool_arg(const sc_tool_call_t *tc, char *buf, size_t bufsz)
{
    if (!tc || !tc->arguments) return "";
    /* Try common single-value keys: path, file, command, query, url */
    static const char *keys[] = {"path","file","command","query","url",
                                 "subcommand","repo_path","content",NULL};
    for (int k = 0; keys[k]; k++) {
        cJSON *v = cJSON_GetObjectItem(tc->arguments, keys[k]);
        if (v && cJSON_IsString(v) && v->valuestring) {
            snprintf(buf, bufsz, "\"%.*s\"",
                     (int)(bufsz - 4), v->valuestring);
            return buf;
        }
    }
    return "";
}

static int mask_old_observations(sc_context_snap_t *snap, void *userdata)
{
    (void)userdata;
    int count = *snap->msg_count;
    int cutoff = count > MASK_KEEP_RECENT ? count - MASK_KEEP_RECENT : 0;
    sc_llm_message_t *msgs = *snap->msgs;

    for (int i = 0; i < cutoff; i++) {
        sc_llm_message_t *msg = &msgs[i];
        if (!msg->tool_call_id) continue;   /* not a tool result */
        if (!msg->content) continue;
        size_t len = strlen(msg->content);
        if (len <= MASK_SIZE_EXEMPT) continue;  /* short results kept */

        /* Find the matching tool call to get name + args */
        const sc_tool_call_t *tc = find_tool_call_for_id(msgs, i, msg->tool_call_id);
        const char *tool_name = (tc && tc->name) ? tc->name : "unknown";
        char tn_safe[64];
        if (strlen(tool_name) >= sizeof(tn_safe)) {
            snprintf(tn_safe, sizeof(tn_safe), "%.60s...", tool_name);
            tool_name = tn_safe;
        }
        char arg_buf[80];
        const char *arg_summary = summarize_tool_arg(tc, arg_buf, sizeof(arg_buf));

        /* Count lines for metadata */
        int lines = 1;
        for (const char *p = msg->content; *p; p++)
            if (*p == '\n') lines++;

        int is_error = (strstr(msg->content, "ERROR") ||
                        strstr(msg->content, "error:") ||
                        strstr(msg->content, "failed"));

        /* Build replacement placeholder */
        char placeholder[256];
        snprintf(placeholder, sizeof(placeholder),
                 "[tool_result: %s(%s) -> %s, %zu bytes, %d lines]",
                 tool_name, arg_summary,
                 is_error ? "ERROR" : "ok", len, lines);

        char *replacement = NULL;
        if (snap->arena) {
            size_t plen = strlen(placeholder) + 1;
            replacement = sc_arena_alloc(snap->arena, plen);
            if (replacement) memcpy(replacement, placeholder, plen);
        } else {
            replacement = sc_strdup(placeholder);
        }
        if (!replacement) continue;
        free(msg->content);
        msg->content = replacement;
    }
    return 0;
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
    agent->isolation_cleanup_tick_secs = SC_ISOLATION_CLEANUP_TICK_SECS_DEFAULT;
    agent->isolation_ttl_secs          = SC_ISOLATION_TTL_SECS_DEFAULT;
    agent->model = sc_strdup(sc_model_strip_prefix(cfg->model));
    agent->summary_model = cfg->summary_model
        ? sc_strdup(sc_model_strip_prefix(cfg->summary_model)) : NULL;
    agent->max_tokens = cfg->max_tokens;
    agent->context_window = cfg->context_window > 0 ? cfg->context_window : cfg->max_tokens;
    agent->provider_ctx_window = cfg->context_window;
    agent->temperature = cfg->temperature;
    agent->response_format = cfg->response_format
        ? cJSON_Duplicate(cfg->response_format, 1) : NULL;
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
    agent->max_tokens_per_hour = cfg->max_tokens_per_hour;
    agent->memory_consolidation = cfg->memory_consolidation;
    agent->workspace_per_session = cfg->workspace_per_session;
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

    /* Per-turn arena allocator (64KB initial, grows as needed) */
    agent->arena = sc_arena_new(0);

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
    if (agent->cost_tracker && cfg->pricing_overrides)
        sc_cost_tracker_set_pricing(agent->cost_tracker, cfg->pricing_overrides);

#if SC_ENABLE_ANALYTICS
    agent->analytics = sc_analytics_new(workspace);
#endif

    /* Fallback providers + model aliases */
    init_fallback_providers(agent, cfg);
    init_model_aliases(agent, cfg);

    /* Per-channel tool allowlists */
    load_channel_tools(agent, cfg);

    /* Context transform: mask old tool results to save tokens */
    sc_agent_add_transform(agent, "mask_old_observations",
                           mask_old_observations, NULL);

    /* Load skills from standard directories */
    agent->skills = sc_skill_registry_new();
    if (agent->skills) {
        /* User skills: ~/.smolclaw/skills/ */
        const char *home = getenv("HOME");
        if (home) {
            char user_skills[512];
            snprintf(user_skills, sizeof(user_skills), "%s/.smolclaw/skills", home);
            sc_skill_registry_load_dir(agent->skills, user_skills);
        }
        /* Project skills: workspace/.claude/skills/ */
        if (workspace) {
            char proj_skills[512];
            snprintf(proj_skills, sizeof(proj_skills), "%s/.claude/skills", workspace);
            sc_skill_registry_load_dir(agent->skills, proj_skills);
        }
        /* Register skill tool if any skills loaded */
        if (agent->skills->count > 0) {
            sc_tool_t *st = sc_tool_skill_new(agent->skills, agent);
            if (st) sc_tool_registry_register(agent->tools, st);
            /* Make skills visible in system prompt */
            sc_context_builder_set_skills(agent->context_builder, agent->skills);
        }
    }

    return agent;
}

void sc_agent_free(sc_agent_t *agent)
{
    if (!agent) return;
    /* Drain outstanding summarization thread before freeing resources */
    sc_drain_summarize(agent);
    sc_arena_free(agent->arena);
    sc_skill_registry_free(agent->skills);
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
    cJSON_Delete(agent->response_format);
    free(agent->workspace);
    free(agent->model);
    free(agent->summary_model);
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
    free(agent->transforms);
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

            if (!already_sent || msg->response_format) {
                sc_outbound_msg_t *out = sc_outbound_msg_new(
                    msg->channel, msg->chat_id, response);
                if (out) {
                    if (msg->response_format)
                        out->is_final_response = 1;
                    sc_bus_publish_outbound(agent->bus, out);
                }
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

void sc_agent_add_transform(sc_agent_t *agent, const char *name,
                             sc_context_transform_fn fn, void *userdata)
{
    if (!agent || !fn) return;
    if (agent->transform_count >= agent->transform_cap) {
        int new_cap = agent->transform_cap ? agent->transform_cap * 2 : 4;
        sc_context_transform_t *new_arr = realloc(agent->transforms,
            (size_t)new_cap * sizeof(sc_context_transform_t));
        if (!new_arr) return;
        agent->transforms = new_arr;
        agent->transform_cap = new_cap;
    }
    sc_context_transform_t *t = &agent->transforms[agent->transform_count++];
    t->fn = fn;
    t->userdata = userdata;
    t->name = name ? name : "unnamed";
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
    agent->max_tokens_per_hour = cfg->max_tokens_per_hour;
    agent->verbose = cfg->verbose;
    agent->exec_timeout_secs = cfg->exec_timeout_secs;
    agent->max_output_chars = cfg->max_output_chars;
    agent->max_fetch_chars = cfg->max_fetch_chars;
    agent->temperature = cfg->temperature;
    cJSON_Delete(agent->response_format);
    agent->response_format = cfg->response_format
        ? cJSON_Duplicate(cfg->response_format, 1) : NULL;
    agent->max_tokens = cfg->max_tokens;
    agent->context_window = cfg->context_window > 0 ? cfg->context_window : cfg->max_tokens;
    agent->provider_ctx_window = cfg->context_window;

    if (cfg->allowed_tools && cfg->allowed_tool_count > 0) {
        sc_tool_registry_set_allowed(agent->tools, cfg->allowed_tools,
                                      cfg->allowed_tool_count);
    } else {
        sc_tool_registry_set_allowed(agent->tools, NULL, 0);
    }

    /* Per-channel tool allowlists */
    load_channel_tools(agent, cfg);

    /* Network scope can be updated at runtime (module-level static in web.c) */
#if SC_ENABLE_WEB_TOOLS
    sc_web_set_network_scope(cfg->network_scope);
#endif

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
    return run_agent_loop(agent, sk, SC_CHANNEL_CLI, "direct", content, 0, NULL,
                          /* isolated */ 0, /* namespace_id */ NULL);
}

/* Remove a directory tree recursively (rm -rf equivalent). */
static void remove_tree(const char *path)
{
    DIR *d = opendir(path);
    if (!d) { unlink(path); return; }
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        char child[1024];
        snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
        struct stat st;
        if (lstat(child, &st) == 0 && S_ISDIR(st.st_mode))
            remove_tree(child);
        else
            unlink(child);
    }
    closedir(d);
    rmdir(path);
}

/* Prune old task directories, keeping the most recent `keep` entries.
 * Directories are sorted by mtime (oldest first). */
#define TASK_WORKSPACE_KEEP 5

static void prune_task_workspaces(const char *workspace)
{
    char tasks_dir[1024];
    snprintf(tasks_dir, sizeof(tasks_dir), "%s/tasks", workspace);

    DIR *d = opendir(tasks_dir);
    if (!d) return;

    /* Collect entries with mtime */
    struct { char name[256]; time_t mtime; } entries[512];
    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && count < 512) {
        if (ent->d_name[0] == '.') continue;
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", tasks_dir, ent->d_name);
        struct stat st;
        if (stat(full, &st) == 0 && S_ISDIR(st.st_mode)) {
            snprintf(entries[count].name, sizeof(entries[count].name),
                     "%s", ent->d_name);
            entries[count].mtime = st.st_mtime;
            count++;
        }
    }
    closedir(d);

    if (count <= TASK_WORKSPACE_KEEP) return;

    /* Sort by mtime ascending (oldest first) */
    for (int i = 0; i < count - 1; i++)
        for (int j = i + 1; j < count; j++)
            if (entries[j].mtime < entries[i].mtime) {
                char tmp_name[256];
                time_t tmp_mt = entries[i].mtime;
                memcpy(tmp_name, entries[i].name, sizeof(tmp_name));
                memcpy(entries[i].name, entries[j].name, sizeof(tmp_name));
                entries[i].mtime = entries[j].mtime;
                memcpy(entries[j].name, tmp_name, sizeof(tmp_name));
                entries[j].mtime = tmp_mt;
            }

    /* Remove oldest entries */
    int to_remove = count - TASK_WORKSPACE_KEEP;
    for (int i = 0; i < to_remove; i++) {
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", tasks_dir, entries[i].name);
        remove_tree(full);
    }
}

char *sc_agent_process_channel(sc_agent_t *agent, const char *content,
                                const char *session_key,
                                const char *channel, const char *chat_id)
{
    const char *sk = session_key ? session_key : "cli:default";
    const char *ch = channel ? channel : SC_CHANNEL_CLI;
    const char *cid = chat_id ? chat_id : "direct";

    /* Per-session workspace isolation: create a subdirectory under
     * workspace/tasks/<short_session_id>/ and switch all tools to it.
     * This prevents cross-task file pollution. */
    char *task_ws = NULL;
    if (agent->workspace_per_session && agent->workspace) {
        /* Extract short ID from session key (last component after ':') */
        const char *short_id = strrchr(sk, ':');
        short_id = short_id ? short_id + 1 : sk;

        size_t len = strlen(agent->workspace) + strlen(short_id) + 16;
        task_ws = malloc(len);
        if (task_ws) {
            snprintf(task_ws, len, "%s/tasks/%s", agent->workspace, short_id);
            /* Create tasks/ parent and task subdir */
            char tasks_dir[1024];
            snprintf(tasks_dir, sizeof(tasks_dir), "%s/tasks", agent->workspace);
            mkdir(tasks_dir, 0700);
            mkdir(task_ws, 0700);
            sc_tool_registry_set_workspace(agent->tools, task_ws);
        }
    }

    char *result = run_agent_loop(agent, sk, ch, cid, content, 0, NULL,
                                   /* isolated */ 0, /* namespace_id */ NULL);

    /* Restore original workspace and prune old task dirs */
    if (task_ws) {
        sc_tool_registry_set_workspace(agent->tools, agent->workspace);
        free(task_ws);
        prune_task_workspaces(agent->workspace);
    }

    return result;
}

char *sc_agent_process_heartbeat(sc_agent_t *agent, const char *content,
                                  const char *channel, const char *chat_id)
{
    return run_agent_loop(agent, "heartbeat", channel, chat_id, content, 1, NULL,
                          /* isolated */ 0, /* namespace_id */ NULL);
}

char *sc_agent_process_isolated(sc_agent_t *agent, const char *content,
                                 const char *session_key,
                                 const char *channel, const char *chat_id,
                                 const char *namespace_id)
{
    const char *sk  = session_key ? session_key : "isolated:default";
    const char *ch  = channel     ? channel     : SC_CHANNEL_CLI;
    const char *cid = chat_id     ? chat_id     : "direct";
    return run_agent_loop(agent, sk, ch, cid, content, 0, NULL,
                          /* isolated */ 1, namespace_id);
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

    /* Slash command: /skill-name args → expand skill and send as user message */
    const char *content = msg->content;
    char *expanded = NULL;
    if (content && content[0] == '/' && agent->skills && agent->skills->count > 0) {
        /* Parse "/name args" */
        const char *p = content + 1;
        const char *space = strchr(p, ' ');
        char name[65];
        if (space) {
            size_t nlen = (size_t)(space - p);
            if (nlen > 64) nlen = 64;
            memcpy(name, p, nlen);
            name[nlen] = '\0';
        } else {
            snprintf(name, sizeof(name), "%s", p);
        }
        sc_skill_t *skill = sc_skill_registry_find(agent->skills, name);
        if (skill && skill->user_invocable) {
            const char *args = space ? space + 1 : "";
            expanded = sc_skill_expand(skill, args);
            if (expanded) {
                SC_LOG_INFO("agent", "Slash command: /%s → skill expanded (%zu bytes)",
                            name, strlen(expanded));
                content = expanded;
            }
        }
    }

    char *result = run_agent_loop(agent, msg->session_key, msg->channel,
                                   msg->chat_id, content, 0,
                                   msg->response_format,
                                   msg->isolated, msg->namespace_id);
    free(expanded);
    return result;
}

/*
 * Unwrap raw "message" tool call JSON from LLM final content.
 * Small models sometimes emit {"name":"message","arguments":{"text":"..."}}
 * or wrap it in markdown code fences instead of plain text.
 * Returns extracted text (caller frees) or NULL if not a message tool call.
 */
static char *
unwrap_message_tool_call(const char *content)
{
    if (!content)
        return NULL;

    const char *json_start = content;

    /* Strip leading whitespace */
    while (*json_start == ' ' || *json_start == '\t' ||
           *json_start == '\n' || *json_start == '\r')
        json_start++;

    /* Strip markdown code fence: ```json ... ``` */
    if (strncmp(json_start, "```", 3) == 0) {
        const char *p = json_start + 3;
        /* Skip optional language tag */
        while (*p && *p != '\n') p++;
        if (*p == '\n') p++;
        json_start = p;

        /* Find closing fence */
        const char *end = strstr(json_start, "```");
        if (!end)
            return NULL;
        /* Ensure nothing substantial after closing fence */
        const char *after = end + 3;
        while (*after == ' ' || *after == '\t' ||
               *after == '\n' || *after == '\r')
            after++;
        if (*after != '\0')
            return NULL; /* text after fence — not a pure tool call */

        /* Make a null-terminated copy of the fenced content */
        size_t len = (size_t)(end - json_start);
        char *tmp = malloc(len + 1);
        if (!tmp) return NULL;
        memcpy(tmp, json_start, len);
        tmp[len] = '\0';

        cJSON *obj = cJSON_Parse(tmp);
        free(tmp);
        if (!obj) return NULL;

        const char *name = NULL;
        cJSON *n = cJSON_GetObjectItem(obj, "name");
        if (n && cJSON_IsString(n)) name = n->valuestring;
        if (!name || strcmp(name, "message") != 0) {
            cJSON_Delete(obj);
            return NULL;
        }
        cJSON *args = cJSON_GetObjectItem(obj, "arguments");
        cJSON *text = args ? cJSON_GetObjectItem(args, "text") : NULL;
        if (!text) text = args ? cJSON_GetObjectItem(args, "content") : NULL;
        char *result = NULL;
        if (text && cJSON_IsString(text) && text->valuestring[0])
            result = sc_strdup(text->valuestring);
        cJSON_Delete(obj);
        return result;
    }

    /* Try bare JSON */
    if (*json_start != '{')
        return NULL;

    cJSON *obj = cJSON_Parse(json_start);
    if (!obj)
        return NULL;

    /* Ensure nothing after the JSON object */
    const char *after_json = json_start;
    int depth = 0;
    for (const char *c = json_start; *c; c++) {
        if (*c == '{') depth++;
        else if (*c == '}') {
            depth--;
            if (depth == 0) { after_json = c + 1; break; }
        }
    }
    while (*after_json == ' ' || *after_json == '\t' ||
           *after_json == '\n' || *after_json == '\r')
        after_json++;
    if (*after_json != '\0') {
        cJSON_Delete(obj);
        return NULL; /* text after JSON — not a pure tool call */
    }

    const char *name = NULL;
    cJSON *n = cJSON_GetObjectItem(obj, "name");
    if (n && cJSON_IsString(n)) name = n->valuestring;
    if (!name || strcmp(name, "message") != 0) {
        cJSON_Delete(obj);
        return NULL;
    }
    cJSON *args = cJSON_GetObjectItem(obj, "arguments");
    cJSON *text = args ? cJSON_GetObjectItem(args, "text") : NULL;
    if (!text) text = args ? cJSON_GetObjectItem(args, "content") : NULL;
    char *result = NULL;
    if (text && cJSON_IsString(text) && text->valuestring[0])
        result = sc_strdup(text->valuestring);
    cJSON_Delete(obj);
    return result;
}

static char *run_agent_loop(sc_agent_t *agent, const char *session_key,
                            const char *channel, const char *chat_id,
                            const char *user_message, int no_history,
                            const cJSON *response_format_override,
                            int isolated, const char *namespace_id)
{
    /* Reset per-turn arena — all previous arena allocations are invalid */
    if (agent->arena)
        sc_arena_reset(agent->arena);

    /* Periodic isolation-session cleanup tick. Cheap (one opendir + a
     * handful of stats per stale entry) and runs on the agent thread so
     * there are no extra threading concerns. At most one cleanup per
     * isolation_cleanup_tick_secs. */
    if (agent->workspace && agent->isolation_cleanup_tick_secs > 0) {
        time_t now = time(NULL);
        if (now - agent->last_isolation_cleanup >=
                agent->isolation_cleanup_tick_secs) {
            int removed = sc_memory_cleanup_sessions(agent->workspace,
                                                      agent->isolation_ttl_secs);
            if (removed > 0)
                SC_LOG_INFO("agent",
                    "Isolation cleanup: pruned %d stale session dir(s)",
                    removed);
            agent->last_isolation_cleanup = now;
        }
    }

    /* Defensive: isolated requires a namespace_id. Treat the malformed
     * combination as non-isolated so downstream code can take its normal
     * path. See docs/design/session-isolation-plan.md §6. */
    if (isolated && (!namespace_id || !namespace_id[0])) {
        SC_LOG_WARN("agent",
            "run_agent_loop: isolated=1 with no namespace_id; running shared");
        isolated = 0;
    }

    /* For isolated turns we build a fresh per-turn context_builder so the
     * system prompt omits shared workspace memory. The agent's persistent
     * context_builder (with shared memory) is left untouched. */
    sc_context_builder_t *turn_cb = isolated
        ? sc_context_builder_new_isolated(agent->workspace, namespace_id)
        : NULL;
    if (isolated && !turn_cb) {
        SC_LOG_WARN("agent",
            "run_agent_loop: failed to build isolated context (ns='%s'); "
            "falling back to shared", namespace_id);
        isolated = 0;
    }
    /* From this point on, `effective_cb` is what builds the system prompt
     * for this turn. */
    sc_context_builder_t *effective_cb = turn_cb
        ? turn_cb : agent->context_builder;
    /* Pass tools/skills to the per-turn builder so its system prompt
     * matches what the agent advertises. */
    if (turn_cb) {
        sc_context_builder_set_tools(turn_cb, agent->tools);
        sc_context_builder_set_skills(turn_cb, agent->skills);
    }

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
        effective_cb,
        history, history_count,
        summary, actual_message,
        channel, chat_id,
        &msg_count);

    if (!messages) {
        sc_context_builder_free(turn_cb);
        return sc_strdup("Error: failed to build context messages.");
    }

    /* Apply context transforms */
    if (agent->transform_count > 0) {
        int msg_cap = msg_count + 16; /* headroom for transforms that append */
        messages = realloc(messages, (size_t)msg_cap * sizeof(sc_llm_message_t));
        if (messages) {
            sc_context_snap_t snap = {
                .msgs = &messages,
                .msg_count = &msg_count,
                .msg_cap = &msg_cap,
                .channel = channel,
                .session_key = session_key,
                .arena = agent->arena,
            };
            for (int i = 0; i < agent->transform_count; i++) {
                SC_LOG_DEBUG("agent", "Running context transform: %s",
                             agent->transforms[i].name);
                int rc = agent->transforms[i].fn(&snap, agent->transforms[i].userdata);
                if (rc != 0) {
                    SC_LOG_WARN("agent", "Context transform '%s' returned %d, skipping remaining",
                                agent->transforms[i].name, rc);
                    break;
                }
            }
        }
    }

    if (!messages) {
        sc_context_builder_free(turn_cb);
        return sc_strdup("Error: failed to build context messages.");
    }

    /* Save user message to session (stripped of alias prefix) */
    sc_session_add_message(agent->sessions, session_key, "user", actual_message);

    /* Run LLM iteration loop */
    int iterations = 0;
    char *failure_reason = NULL;
    char *final_thinking = NULL;
    cJSON *saved_response_format = agent->response_format;
    char **saved_allowed_tools = NULL;
    char **structured_allowed = NULL;
    int saved_allowed_count = 0;
    int structured_allowed_count = 0;

    if (response_format_override) {
        saved_allowed_tools = dup_allowed_tool_names(agent->tools,
                                                     &saved_allowed_count);
        structured_allowed = build_structured_output_allowlist(agent->tools,
                                                               &structured_allowed_count);
        if (structured_allowed_count > 0) {
            sc_tool_registry_set_allowed(agent->tools, structured_allowed,
                                         structured_allowed_count);
        }
        agent->response_format = (cJSON *)response_format_override;
    }
    /* Isolated turns: deny tools whose handles are pinned to the shared
     * agent workspace. Phase 4/5 isolate the prompt and file tools, but
     * these would still let a delegate pull (or push) agent-wide memory
     * on demand — the secondary vector from the 2026-06-05 contamination
     * diagnosis. Cleared right after the turn, like the allowlist swap
     * above and the set_workspace swap in sc_agent_process_channel. */
    static const char *SHARED_MEMORY_TOOLS[] = {
        "memory_read", "memory_write", "memory_log", "memory_search", "note"
    };
    if (isolated) {
        sc_tool_registry_set_denied(agent->tools, SHARED_MEMORY_TOOLS,
            (int)(sizeof(SHARED_MEMORY_TOOLS) / sizeof(SHARED_MEMORY_TOOLS[0])));
    }
    char *final_content = sc_run_llm_iteration(agent, use_provider, use_model,
                                                messages, msg_count,
                                                session_key, channel, chat_id,
                                                &iterations, &failure_reason,
                                                &final_thinking,
                                                isolated, namespace_id);
    if (isolated)
        sc_tool_registry_set_denied(agent->tools, NULL, 0);
    if (response_format_override) {
        sc_tool_registry_set_allowed(agent->tools, saved_allowed_tools,
                                     saved_allowed_count);
    }
    agent->response_format = saved_response_format;
    free_tool_name_list(structured_allowed, structured_allowed_count);
    free_tool_name_list(saved_allowed_tools, saved_allowed_count);

    sc_llm_message_array_free(messages, msg_count);

    /* Unwrap raw message tool call JSON from small models */
    if (final_content) {
        char *unwrapped = unwrap_message_tool_call(final_content);
        if (unwrapped) {
            SC_LOG_DEBUG("agent", "Unwrapped message tool call from final content");
            free(final_content);
            final_content = unwrapped;
        }
    }

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

    /* Save final assistant message (with thinking if present) */
    if (final_thinking) {
        sc_llm_message_t msg = {0};
        msg.role = "assistant";
        msg.content = final_content;
        msg.thinking = final_thinking;
        sc_session_add_full_message(agent->sessions, session_key, &msg);
        /* Don't free msg fields — they're borrowed, freed below */
    } else {
        sc_session_add_message(agent->sessions, session_key, "assistant", final_content);
    }
    free(final_thinking);
    sc_session_save(agent->sessions, session_key);

    if (!no_history)
        sc_maybe_summarize(agent, session_key, isolated, namespace_id);

    /* Per-turn isolated builder (if any) owns memory + namespace allocs;
     * release before returning. */
    sc_context_builder_free(turn_cb);

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
