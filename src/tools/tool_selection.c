/*
 * smolclaw - adaptive tool selection (Phase 1.5)
 */
#include "tools/tool_selection.h"
#include "logger.h"

#include <string.h>
#include <ctype.h>
#include <stdlib.h>

/* Tool categories (bitmask). A tool whose name is not in the built-in map is
 * UNKNOWN and always kept (don't hide skill/MCP/custom tools from the model). */
enum {
    CAT_FILE  = 1u << 0,  /* read / list / search files + code */
    CAT_EDIT  = 1u << 1,  /* write / edit / create */
    CAT_SHELL = 1u << 2,  /* exec / build / run / git / gitea / worktree */
    CAT_WEB   = 1u << 3,  /* web search / fetch / X */
    CAT_MEM   = 1u << 4,  /* long-term memory / notes */
    CAT_SYS   = 1u << 5,  /* host metrics / inventory */
};
#define CAT_UNKNOWN 0xFFFFFFFFu

sc_tool_selection_mode_t sc_tool_selection_from_str(const char *s)
{
    if (s && strcmp(s, "auto") == 0)
        return SC_TOOL_SELECTION_AUTO;
    return SC_TOOL_SELECTION_FIXED;
}

const char *sc_tool_selection_to_str(sc_tool_selection_mode_t mode)
{
    return mode == SC_TOOL_SELECTION_AUTO ? "auto" : "fixed";
}

/* Map a tool name to its category bitmask. UNKNOWN means "always keep". */
static unsigned category_of(const char *name)
{
    if (!name) return CAT_UNKNOWN;

    /* memory_* tools + scratchpad note */
    if (strncmp(name, "memory", 6) == 0) return CAT_MEM;
    if (strcmp(name, "note") == 0) return CAT_MEM;

    /* read / search files and code */
    if (strcmp(name, "read_file") == 0 || strcmp(name, "list_dir") == 0 ||
        strcmp(name, "glob") == 0 || strcmp(name, "code_graph") == 0 ||
        strcmp(name, "repo_search") == 0 || strcmp(name, "symbol_lookup") == 0 ||
        strcmp(name, "session_search") == 0 || strcmp(name, "context_search") == 0)
        return CAT_FILE;

    if (strcmp(name, "write_file") == 0 || strcmp(name, "edit_file") == 0 ||
        strcmp(name, "append_file") == 0)
        return CAT_EDIT;

    /* exec / background / VCS (git, gitea, worktree). Note the background tool
     * registers as "background", not "exec_background". */
    if (strcmp(name, "exec") == 0 || strcmp(name, "background") == 0 ||
        strcmp(name, "bg_poll") == 0 || strcmp(name, "bg_kill") == 0 ||
        strcmp(name, "git") == 0 || strcmp(name, "gitea") == 0 ||
        strcmp(name, "worktree_enter") == 0 || strcmp(name, "worktree_exit") == 0)
        return CAT_SHELL;

    /* web + X/Twitter (x_search, x_get_tweet, x_get_thread, x_get_user) */
    if (strcmp(name, "web_search") == 0 || strcmp(name, "web_fetch") == 0 ||
        strncmp(name, "x_", 2) == 0)
        return CAT_WEB;

    /* host_status / host_inventory / host_trend */
    if (strncmp(name, "host_", 5) == 0) return CAT_SYS;

    return CAT_UNKNOWN;
}

static int contains_any(const char *lc, const char *const *kw)
{
    for (int i = 0; kw[i]; i++)
        if (strstr(lc, kw[i]))
            return 1;
    return 0;
}

/* Is the (lowercased, trimmed) message a short greeting / chat with no task? */
static int is_greeting(const char *lc)
{
    static const char *const greet[] = {
        "hi", "hello", "hey", "yo", "sup", "hiya", "howdy", "greetings",
        "thanks", "thank you", "thx", "ty", "cheers", "ok", "okay", "cool",
        "nice", "great", "good morning", "good evening", "good afternoon",
        "how are you", "what's up", "whats up", "good night", NULL
    };
    size_t len = strlen(lc);
    if (len == 0) return 1;
    if (len > 48) return 0;  /* long messages are not pure greetings */
    for (int i = 0; greet[i]; i++) {
        size_t gl = strlen(greet[i]);
        if (strncmp(lc, greet[i], gl) == 0) {
            /* require a word boundary after the greeting token */
            char after = lc[gl];
            if (after == '\0' || after == ' ' || after == ',' ||
                after == '.' || after == '!' || after == '?')
                return 1;
        }
    }
    return 0;
}

/* Build the desired-category bitmask from keywords in the lowercased message. */
static unsigned classify_message(const char *lc)
{
    unsigned want = 0;

    static const char *const file_kw[] = {
        "read", "file", "open ", "show ", "cat ", "list", "directory",
        "folder", "find ", "grep", "search", "look ", "locate", "where is",
        "content", " src", "function", "class ", "definition", "ls ", NULL
    };
    static const char *const edit_kw[] = {
        "write", "edit", "create", "modify", "change", "update", "fix ",
        "replace", "patch", "append", "rename", "delete", "implement",
        "refactor", "add a", "add the", NULL
    };
    static const char *const shell_kw[] = {
        "run ", "exec", "build", "compile", "install", " test", "make ",
        "cmake", "command", "shell", "bash", "npm ", "git ", "./",
        "execute", "worktree", "branch", "commit", "merge", "checkout",
        "clone", "gitea", "issue", "pull request", "pr ", NULL
    };
    static const char *const web_kw[] = {
        "http", "url", " web", "browse", "google", "fetch", "look up",
        "online", "internet", "website", "tweet", "twitter", "x.com", NULL
    };
    static const char *const mem_kw[] = {
        "remember", "recall", "memory", "note ", "earlier", "last time",
        "we discussed", "you said", "previously", NULL
    };
    static const char *const sys_kw[] = {
        "host", "cpu", "disk", "uptime", "load average", "metric",
        "sensor", "temperature", "resource usage", "system status",
        " swap", "hostname", NULL
    };

    if (contains_any(lc, file_kw))  want |= CAT_FILE | CAT_MEM;
    if (contains_any(lc, edit_kw))  want |= CAT_EDIT | CAT_FILE;
    if (contains_any(lc, shell_kw)) want |= CAT_SHELL | CAT_FILE;
    if (contains_any(lc, web_kw))   want |= CAT_WEB;
    if (contains_any(lc, mem_kw))   want |= CAT_MEM | CAT_FILE;
    if (contains_any(lc, sys_kw))   want |= CAT_SYS;

    return want;
}

int sc_tool_selection_apply(sc_tool_selection_mode_t mode, const char *user_msg,
                            sc_tool_definition_t *defs, int count)
{
    if (mode != SC_TOOL_SELECTION_AUTO || !defs || count <= 0 || !user_msg)
        return count;

    /* Lowercase a bounded copy of the message. */
    char lc[512];
    size_t n = 0;
    for (const char *p = user_msg; *p && n < sizeof(lc) - 1; p++)
        lc[n++] = (char)tolower((unsigned char)*p);
    lc[n] = '\0';

    int greeting = is_greeting(lc);
    unsigned want = greeting ? 0u : classify_message(lc);

    /* Ambiguous (not a greeting, no keyword matched): keep everything —
     * never starve the model when the heuristic is uncertain. */
    if (!greeting && want == 0)
        return count;

    int w = 0;
    for (int r = 0; r < count; r++) {
        unsigned cat = category_of(defs[r].name);
        int keep;
        if (greeting)
            keep = (cat == CAT_UNKNOWN);  /* greeting: drop known task tools */
        else
            keep = (cat == CAT_UNKNOWN) || (cat & want);

        if (keep) {
            if (w != r) defs[w] = defs[r];  /* shallow move of owned pointers */
            w++;
        } else {
            sc_tool_definition_free(&defs[r]);  /* frees fields, NULLs them */
        }
    }

    SC_LOG_DEBUG("agent", "Adaptive tool selection: %d/%d tools (greeting=%d, want=0x%x)",
                 w, count, greeting, want);
    return w;
}
