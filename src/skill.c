/*
 * skill.c - User-defined prompt templates (skills)
 *
 * Scans directories for SKILL.md files, parses YAML frontmatter,
 * lazy-loads content on invocation, expands $ARGUMENTS.
 */

#include "skill.h"
#include "util/str.h"
#include "logger.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define LOG_TAG "skill"

/* --- YAML frontmatter parser (minimal subset) --- */

/* Extract value after "key: " from a line. Returns malloc'd string or NULL. */
static char *parse_yaml_value(const char *line, const char *key)
{
    size_t klen = strlen(key);
    if (strncmp(line, key, klen) != 0) return NULL;
    if (line[klen] != ':') return NULL;
    const char *val = line + klen + 1;
    while (*val == ' ') val++;
    /* Strip trailing whitespace/newline */
    size_t vlen = strlen(val);
    while (vlen > 0 && (val[vlen - 1] == '\n' || val[vlen - 1] == '\r'
                        || val[vlen - 1] == ' '))
        vlen--;
    if (vlen == 0) return NULL;
    char *result = malloc(vlen + 1);
    if (!result) return NULL;
    memcpy(result, val, vlen);
    result[vlen] = '\0';
    return result;
}

/* Parse comma-separated list from a YAML value. Returns array + count. */
static char **parse_csv_list(const char *val, int *out_count)
{
    *out_count = 0;
    if (!val || !val[0]) return NULL;

    /* Count commas */
    int n = 1;
    for (const char *p = val; *p; p++)
        if (*p == ',') n++;

    char **list = calloc((size_t)n, sizeof(char *));
    if (!list) return NULL;

    char *copy = sc_strdup(val);
    char *saveptr = NULL;
    char *tok = strtok_r(copy, ",", &saveptr);
    while (tok && *out_count < n) {
        while (*tok == ' ') tok++;
        char *end = tok + strlen(tok) - 1;
        while (end > tok && *end == ' ') *end-- = '\0';
        if (*tok)
            list[(*out_count)++] = sc_strdup(tok);
        tok = strtok_r(NULL, ",", &saveptr);
    }
    free(copy);
    return list;
}

/* Parse a SKILL.md file. Returns 0 on success. */
static int parse_skill_file(const char *path, const char *dir, sc_skill_t *skill)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    memset(skill, 0, sizeof(*skill));
    skill->user_invocable = 1;  /* default */
    skill->file_path = sc_strdup(path);
    skill->skill_dir = sc_strdup(dir);

    /* Read file to find frontmatter */
    char line[1024];
    int in_frontmatter = 0;
    int found_start = 0;

    while (fgets(line, sizeof(line), f)) {
        if (!found_start && strncmp(line, "---", 3) == 0) {
            found_start = 1;
            in_frontmatter = 1;
            continue;
        }
        if (in_frontmatter && strncmp(line, "---", 3) == 0) {
            break;  /* end of frontmatter */
        }
        if (!in_frontmatter) continue;

        /* Parse frontmatter fields */
        char *v;
        if ((v = parse_yaml_value(line, "name")))
            skill->name = v;
        else if ((v = parse_yaml_value(line, "description")))
            skill->description = v;
        else if ((v = parse_yaml_value(line, "when-to-use")))
            skill->when_to_use = v;
        else if ((v = parse_yaml_value(line, "arguments")))
            skill->argument_hint = v;
        else if ((v = parse_yaml_value(line, "allowed-tools"))) {
            skill->allowed_tools = parse_csv_list(v, &skill->allowed_tool_count);
            free(v);
        }
        else if ((v = parse_yaml_value(line, "model")))
            skill->model = v;
        else if ((v = parse_yaml_value(line, "context")))
            skill->context = v;
        else if ((v = parse_yaml_value(line, "user-invocable"))) {
            skill->user_invocable = (strcmp(v, "false") != 0 && strcmp(v, "0") != 0);
            free(v);
        }
        else if ((v = parse_yaml_value(line, "disable-model-invocation"))) {
            skill->disable_model = (strcmp(v, "true") == 0 || strcmp(v, "1") == 0);
            free(v);
        }
    }
    fclose(f);

    /* Derive name from directory if not in frontmatter */
    if (!skill->name) {
        const char *last_slash = strrchr(dir, '/');
        skill->name = sc_strdup(last_slash ? last_slash + 1 : dir);
    }

    return skill->name ? 0 : -1;
}

/* Lazy-load skill content (everything after the second ---) */
static char *load_content(sc_skill_t *skill)
{
    if (skill->content) return skill->content;
    if (!skill->file_path) return NULL;

    FILE *f = fopen(skill->file_path, "r");
    if (!f) return NULL;

    char line[1024];
    int dashes = 0;

    /* Skip to after second --- */
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "---", 3) == 0) {
            dashes++;
            if (dashes >= 2) break;
        }
    }

    /* Read remaining content */
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    while (fgets(line, sizeof(line), f))
        sc_strbuf_append(&sb, line);
    fclose(f);

    skill->content = sc_strbuf_finish(&sb);
    return skill->content;
}

static void skill_free_fields(sc_skill_t *s)
{
    free(s->name);
    free(s->description);
    free(s->when_to_use);
    free(s->argument_hint);
    for (int i = 0; i < s->allowed_tool_count; i++)
        free(s->allowed_tools[i]);
    free(s->allowed_tools);
    free(s->model);
    free(s->context);
    free(s->skill_dir);
    free(s->file_path);
    free(s->content);
}

/* --- Public API --- */

sc_skill_registry_t *sc_skill_registry_new(void)
{
    return calloc(1, sizeof(sc_skill_registry_t));
}

void sc_skill_registry_free(sc_skill_registry_t *reg)
{
    if (!reg) return;
    for (int i = 0; i < reg->count; i++)
        skill_free_fields(&reg->skills[i]);
    free(reg->skills);
    free(reg);
}

int sc_skill_registry_load_dir(sc_skill_registry_t *reg, const char *dir)
{
    if (!reg || !dir) return -1;

    DIR *d = opendir(dir);
    if (!d) return 0;  /* directory doesn't exist = no skills, not an error */

    int loaded = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;

        char path[1024];

        /* Check for dir/name/SKILL.md */
        snprintf(path, sizeof(path), "%s/%s/SKILL.md", dir, ent->d_name);
        struct stat st;
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
            char skill_dir[1024];
            snprintf(skill_dir, sizeof(skill_dir), "%s/%s", dir, ent->d_name);

            sc_skill_t skill;
            if (parse_skill_file(path, skill_dir, &skill) == 0) {
                /* Dedup by name */
                if (sc_skill_registry_find(reg, skill.name)) {
                    skill_free_fields(&skill);
                    continue;
                }
                /* Add to registry */
                if (reg->count >= reg->cap) {
                    int new_cap = reg->cap ? reg->cap * 2 : 8;
                    sc_skill_t *new_arr = realloc(reg->skills,
                        (size_t)new_cap * sizeof(sc_skill_t));
                    if (!new_arr) { skill_free_fields(&skill); continue; }
                    reg->skills = new_arr;
                    reg->cap = new_cap;
                }
                reg->skills[reg->count++] = skill;
                loaded++;
                SC_LOG_INFO(LOG_TAG, "Loaded skill: %s (%s)", skill.name, path);
            }
            continue;
        }

        /* Check for dir/name.md (flat file) */
        snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        size_t nlen = strlen(ent->d_name);
        if (nlen > 3 && strcmp(ent->d_name + nlen - 3, ".md") == 0 &&
            stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
            sc_skill_t skill;
            if (parse_skill_file(path, dir, &skill) == 0) {
                if (sc_skill_registry_find(reg, skill.name)) {
                    skill_free_fields(&skill);
                    continue;
                }
                if (reg->count >= reg->cap) {
                    int new_cap = reg->cap ? reg->cap * 2 : 8;
                    sc_skill_t *new_arr = realloc(reg->skills,
                        (size_t)new_cap * sizeof(sc_skill_t));
                    if (!new_arr) { skill_free_fields(&skill); continue; }
                    reg->skills = new_arr;
                    reg->cap = new_cap;
                }
                reg->skills[reg->count++] = skill;
                loaded++;
                SC_LOG_INFO(LOG_TAG, "Loaded skill: %s (%s)", skill.name, path);
            }
        }
    }
    closedir(d);

    if (loaded > 0)
        SC_LOG_INFO(LOG_TAG, "Loaded %d skills from %s", loaded, dir);
    return loaded;
}

sc_skill_t *sc_skill_registry_find(sc_skill_registry_t *reg, const char *name)
{
    if (!reg || !name) return NULL;
    for (int i = 0; i < reg->count; i++) {
        if (strcmp(reg->skills[i].name, name) == 0)
            return &reg->skills[i];
    }
    return NULL;
}

char *sc_skill_expand(sc_skill_t *skill, const char *arguments)
{
    char *content = load_content(skill);
    if (!content) return NULL;

    /* Replace $ARGUMENTS with actual arguments */
    if (arguments && strstr(content, "$ARGUMENTS")) {
        sc_strbuf_t sb;
        sc_strbuf_init(&sb);
        const char *p = content;
        while (*p) {
            const char *found = strstr(p, "$ARGUMENTS");
            if (!found) {
                sc_strbuf_append(&sb, p);
                break;
            }
            /* Append text before match */
            if (found > p) {
                size_t prefix_len = (size_t)(found - p);
                char *prefix = malloc(prefix_len + 1);
                if (prefix) {
                    memcpy(prefix, p, prefix_len);
                    prefix[prefix_len] = '\0';
                    sc_strbuf_append(&sb, prefix);
                    free(prefix);
                }
            }
            sc_strbuf_append(&sb, arguments);
            p = found + 10;  /* strlen("$ARGUMENTS") */
        }
        return sc_strbuf_finish(&sb);
    }

    /* No substitution needed — return copy */
    return sc_strdup(content);
}

char *sc_skill_registry_listing(sc_skill_registry_t *reg)
{
    if (!reg || reg->count == 0) return NULL;

    int visible = 0;
    for (int i = 0; i < reg->count; i++) {
        if (!reg->skills[i].disable_model)
            visible++;
    }
    if (visible == 0) return NULL;

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_append(&sb,
        "\n## Available Skills\n"
        "Use the skill tool to invoke these, or the user can type /skill-name.\n\n");

    for (int i = 0; i < reg->count; i++) {
        sc_skill_t *s = &reg->skills[i];
        if (s->disable_model) continue;

        sc_strbuf_appendf(&sb, "- **%s**", s->name);
        if (s->description)
            sc_strbuf_appendf(&sb, " — %.100s", s->description);
        if (s->when_to_use)
            sc_strbuf_appendf(&sb, " (use when: %.80s)", s->when_to_use);
        if (s->argument_hint)
            sc_strbuf_appendf(&sb, " [args: %s]", s->argument_hint);
        sc_strbuf_append(&sb, "\n");
    }

    return sc_strbuf_finish(&sb);
}
