#include "slash.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "agent.h"
#include "agent_internal.h"
#include "session.h"
#include "util/str.h"
#include "sc_features.h"

/* Resolve a model alias name to its target model, or return the input
 * unchanged if it isn't a configured alias. */
static const char *resolve_model_alias(const sc_agent_t *agent, const char *name)
{
    for (int i = 0; i < agent->alias_count; i++) {
        if (agent->alias_names[i] && strcmp(agent->alias_names[i], name) == 0)
            return agent->alias_models[i] ? agent->alias_models[i] : name;
    }
    return name;
}

static char *cmd_help(void)
{
    return sc_strdup(
        "Available commands:\n"
        "  /help            Show this help\n"
        "  /status          Session model, message count, summary state\n"
        "  /reset, /new     Start a fresh session for this chat\n"
        "  /model [alias]    Show or change the model\n"
        "  /compress        Summarize and compact this session");
}

static char *cmd_status(sc_agent_t *agent, const char *session_key)
{
    int count = 0;
    sc_session_get_history(agent->sessions, session_key, &count);
    const char *summary = sc_session_get_summary(agent->sessions, session_key);

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "Session: %s\n", session_key ? session_key : "(none)");
    sc_strbuf_appendf(&sb, "Model: %s\n", agent->model ? agent->model : "(default)");
    sc_strbuf_appendf(&sb, "Messages: %d\n", count);
    sc_strbuf_appendf(&sb, "Summary: %s",
                      (summary && summary[0]) ? "present" : "none");
    return sc_strbuf_finish(&sb);
}

static char *cmd_reset(sc_agent_t *agent, const char *session_key)
{
    if (sc_session_reset(agent->sessions, session_key) == 0)
        return sc_strdup("Session reset. Starting fresh.");
    return sc_strdup("Could not reset session.");
}

static char *cmd_model(sc_agent_t *agent, const char *arg)
{
    if (!arg || !arg[0]) {
        sc_strbuf_t sb;
        sc_strbuf_init(&sb);
        sc_strbuf_appendf(&sb, "Current model: %s",
                          agent->model ? agent->model : "(default)");
        if (agent->alias_count > 0) {
            sc_strbuf_appendf(&sb, "\nAliases:");
            for (int i = 0; i < agent->alias_count; i++)
                sc_strbuf_appendf(&sb, " %s", agent->alias_names[i]);
        }
#if SC_ENABLE_MOA
        if (agent->provider && agent->provider->name &&
            strcmp(agent->provider->name, "moa") == 0)
            sc_strbuf_appendf(&sb, "\n(MoA active — /model <preset> switches preset)");
#endif
        return sc_strbuf_finish(&sb);
    }

    const char *resolved = resolve_model_alias(agent, arg);
    char *dup = sc_strdup(resolved);
    if (!dup) return sc_strdup("Could not change model.");
    free(agent->model);
    agent->model = dup;

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "Model set to %s for this gateway.", agent->model);
    return sc_strbuf_finish(&sb);
}

static char *cmd_compress(sc_agent_t *agent, const char *session_key)
{
    /* Shared path with the agent-initiated compact tool (task 4.12). The slash
     * command has no cooldown — a human asking to compress should not be
     * rate-limited. */
    if (sc_agent_compact_session(agent, session_key) != 0)
        return sc_strdup("Nothing to compress yet.");
    return sc_strdup("Compressing this session (summarization scheduled).");
}

int sc_slash_dispatch(sc_agent_t *agent, const char *session_key,
                      const char *content, char **out_reply)
{
    if (out_reply) *out_reply = NULL;
    if (!agent || !content) return 0;

    /* Skip leading whitespace; a slash command must start with '/'. */
    const char *p = content;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '/') return 0;
    p++;  /* past the slash */

    /* Extract the command token (up to whitespace), lowercased. */
    char cmd[32];
    size_t n = 0;
    while (p[n] && p[n] != ' ' && p[n] != '\t' && p[n] != '\n' && n < sizeof(cmd) - 1) {
        cmd[n] = (char)tolower((unsigned char)p[n]);
        n++;
    }
    cmd[n] = '\0';

    /* The argument is the remainder, trimmed. */
    const char *arg = p + n;
    while (*arg == ' ' || *arg == '\t') arg++;
    /* Trim a trailing newline / spaces into a local copy. */
    char arg_buf[256];
    size_t alen = 0;
    while (arg[alen] && arg[alen] != '\n' && alen < sizeof(arg_buf) - 1) {
        arg_buf[alen] = arg[alen];
        alen++;
    }
    while (alen > 0 && (arg_buf[alen - 1] == ' ' || arg_buf[alen - 1] == '\t'))
        alen--;
    arg_buf[alen] = '\0';

    char *reply = NULL;
    if (strcmp(cmd, "help") == 0)
        reply = cmd_help();
    else if (strcmp(cmd, "status") == 0)
        reply = cmd_status(agent, session_key);
    else if (strcmp(cmd, "reset") == 0 || strcmp(cmd, "new") == 0)
        reply = cmd_reset(agent, session_key);
    else if (strcmp(cmd, "model") == 0)
        reply = cmd_model(agent, arg_buf);
    else if (strcmp(cmd, "compress") == 0)
        reply = cmd_compress(agent, session_key);
    else
        return 0;  /* not a recognized command → let the agent handle it */

    if (out_reply) *out_reply = reply;
    else free(reply);
    return 1;
}
