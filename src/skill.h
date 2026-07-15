/*
 * skill.h - User-defined prompt templates (skills)
 *
 * Skills are markdown files with YAML frontmatter, stored in
 * <dir>/<name>/SKILL.md or <dir>/<name>.md where <dir> is
 * $SMOLCLAW_HOME/skills (per-agent, wins on name collision),
 * ~/.smolclaw/skills (shared), or {workspace}/.claude/skills (project).
 * Invoked as /skill-name args or via the skill tool.
 */

#ifndef SC_SKILL_H
#define SC_SKILL_H

typedef struct {
    char *name;
    char *description;
    char *when_to_use;       /* guides LLM on when to invoke */
    char *argument_hint;     /* parameter name(s) for $ARGUMENTS */
    char **allowed_tools;    /* tool restriction (NULL = all) */
    int   allowed_tool_count;
    char *model;             /* model override (NULL = inherit) */
    char *context;           /* "inline" (default) or "fork" */
    int   user_invocable;    /* 1 = show in slash commands (default) */
    int   disable_model;     /* 1 = LLM can't call, user-only */
    /* Lazy-loaded content */
    char *skill_dir;         /* directory containing the skill file */
    char *file_path;         /* full path to SKILL.md */
    char *content;           /* loaded on first use (NULL until then) */
} sc_skill_t;

typedef struct {
    sc_skill_t *skills;
    int         count;
    int         cap;
} sc_skill_registry_t;

/* Create/destroy */
sc_skill_registry_t *sc_skill_registry_new(void);
void sc_skill_registry_free(sc_skill_registry_t *reg);

/* Load skills from a directory (scans for SKILL.md files).
 * Merges into existing registry (deduplicates by name). */
int sc_skill_registry_load_dir(sc_skill_registry_t *reg, const char *dir);

/* Find skill by name. Returns NULL if not found. */
sc_skill_t *sc_skill_registry_find(sc_skill_registry_t *reg, const char *name);

/* Get lazy-loaded content with $ARGUMENTS expansion.
 * Caller owns result. */
char *sc_skill_expand(sc_skill_t *skill, const char *arguments);

/* Generate system prompt listing of available skills.
 * Caller owns result. Returns NULL if no skills. */
char *sc_skill_registry_listing(sc_skill_registry_t *reg);

#endif /* SC_SKILL_H */
