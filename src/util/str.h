#ifndef SC_STR_H
#define SC_STR_H

#include <stddef.h>

/* strdup that handles NULL (returns NULL for NULL input) */
char *sc_strdup(const char *s);

/* Truncate string to max_len runes, appending "..." if truncated.
 * Returns newly allocated string. Caller owns result. */
char *sc_truncate(const char *s, int max_len);

/* Trim leading/trailing whitespace. Returns newly allocated string. */
char *sc_trim(const char *s);

/* Expand ~ to home directory. Returns newly allocated string. */
char *sc_expand_home(const char *path);

/* Get smolclaw home directory. Checks SMOLCLAW_HOME env var first,
 * falls back to ~/.smolclaw. Returns newly allocated string. */
char *sc_get_home_dir(void);

/* Validate that path is within workspace if restrict is true.
 * Resolves relative paths against workspace.
 * Returns newly allocated absolute path, or NULL on error. */
char *sc_validate_path(const char *path, const char *workspace, int restrict_to_workspace);

/* Realloc that preserves old pointer on failure. Returns NULL on OOM
 * (old pointer still valid). Caller must check return value. */
void *sc_safe_realloc(void *ptr, size_t size);

/* Dynamic string buffer */
typedef struct {
    char *data;
    size_t len;
    size_t cap;
    int oom;
} sc_strbuf_t;

void sc_strbuf_init(sc_strbuf_t *sb);
void sc_strbuf_append(sc_strbuf_t *sb, const char *s);
void sc_strbuf_appendf(sc_strbuf_t *sb, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void sc_strbuf_append_char(sc_strbuf_t *sb, char c);
char *sc_strbuf_finish(sc_strbuf_t *sb); /* Returns owned string, resets buf */
void sc_strbuf_free(sc_strbuf_t *sb);

/* Sanitize session key for filename (replace : with _) */
char *sc_sanitize_filename(const char *key);

/* Wrap content in XML CDATA inside a tag: <tag attrs><![CDATA[content]]></tag>
 * Handles ]]> in content by splitting CDATA sections.
 * Returns newly allocated string. Caller owns result. */
char *sc_xml_cdata_wrap(const char *tag, const char *attrs, const char *content);

/* Constant-time string comparison (prevents timing attacks).
 * Returns 0 if equal, non-zero otherwise. Both strings must be non-NULL. */
int sc_timing_safe_cmp(const char *a, const char *b);

/* Escape a string for use in XML attributes.
 * Replaces & < > " ' with XML entities.
 * Returns newly allocated string. Caller owns result. */
char *sc_xml_escape_attr(const char *s);

#endif /* SC_STR_H */
