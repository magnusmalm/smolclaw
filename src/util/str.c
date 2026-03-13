#include "str.h"

#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char *sc_strdup(const char *s)
{
    if (!s)
        return NULL;
    size_t len = strlen(s);
    char *out = malloc(len + 1);
    if (!out)
        return NULL;
    memcpy(out, s, len + 1);
    return out;
}

/* Count bytes of a single UTF-8 character starting at *p.
 * Returns 1-4 on valid lead byte, 1 on invalid (treat as single byte). */
static int utf8_char_len(const unsigned char *p)
{
    if (p[0] < 0x80) return 1;
    if ((p[0] & 0xE0) == 0xC0) return 2;
    if ((p[0] & 0xF0) == 0xE0) return 3;
    if ((p[0] & 0xF8) == 0xF0) return 4;
    return 1; /* invalid lead byte */
}

char *sc_truncate(const char *s, int max_len)
{
    if (!s)
        return NULL;

    /* Count runes and find byte offset of max_len runes */
    const unsigned char *p = (const unsigned char *)s;
    int runes = 0;
    while (*p) {
        runes++;
        p += utf8_char_len(p);
    }

    if (runes <= max_len)
        return sc_strdup(s);

    /* Take max_len runes, then append "..." */
    p = (const unsigned char *)s;
    for (int i = 0; i < max_len && *p; i++)
        p += utf8_char_len(p);

    size_t bytes = (size_t)(p - (const unsigned char *)s);
    char *out = malloc(bytes + 4); /* +3 for "..." +1 for NUL */
    if (!out) return NULL;
    memcpy(out, s, bytes);
    memcpy(out + bytes, "...", 4);
    return out;
}

char *sc_trim(const char *s)
{
    if (!s)
        return NULL;

    /* Skip leading whitespace */
    while (*s && isspace((unsigned char)*s))
        s++;

    /* Find end of trailing non-whitespace */
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1]))
        len--;

    char *out = malloc(len + 1);
    if (!out) return NULL;
    memcpy(out, s, len);
    out[len] = '\0';
    return out;
}

char *sc_expand_home(const char *path)
{
    if (!path)
        return NULL;

    if (path[0] != '~')
        return sc_strdup(path);

    /* ~ must be followed by / or be the entire string */
    if (path[1] != '\0' && path[1] != '/')
        return sc_strdup(path);

    const char *home = getenv("HOME");
    if (!home)
        return sc_strdup(path);

    size_t home_len = strlen(home);
    size_t rest_len = strlen(path + 1); /* skip the ~ */
    char *out = malloc(home_len + rest_len + 1);
    if (!out) return NULL;
    memcpy(out, home, home_len);
    memcpy(out + home_len, path + 1, rest_len + 1);
    return out;
}

char *sc_get_home_dir(void)
{
    const char *override = getenv("SMOLCLAW_HOME");
    if (override && override[0])
        return sc_strdup(override);
    return sc_expand_home("~/.smolclaw");
}

char *sc_validate_path(const char *path, const char *workspace, int restrict_to_workspace)
{
    if (!path || !workspace)
        return NULL;

    char resolved[PATH_MAX];
    char resolved_ws[PATH_MAX];

    /* Expand ~ in path */
    char *expanded = sc_expand_home(path);
    if (!expanded)
        return NULL;

    /* If path is relative, resolve against workspace */
    char *to_resolve;
    if (expanded[0] == '/') {
        to_resolve = expanded;
    } else {
        size_t ws_len = strlen(workspace);
        size_t exp_len = strlen(expanded);
        to_resolve = malloc(ws_len + 1 + exp_len + 1);
        if (!to_resolve) {
            free(expanded);
            return NULL;
        }
        memcpy(to_resolve, workspace, ws_len);
        to_resolve[ws_len] = '/';
        memcpy(to_resolve + ws_len + 1, expanded, exp_len + 1);
        free(expanded);
        expanded = to_resolve;
    }

    if (!realpath(expanded, resolved)) {
        /* File doesn't exist — walk up until we find an existing ancestor,
         * then append the non-existent tail. This handles paths like
         * "a/b/c/file.txt" where "a/b/" doesn't exist yet. */
        char *tmp = sc_strdup(expanded);
        if (!tmp) {
            free(expanded);
            return NULL;
        }

        /* Find the deepest existing ancestor */
        const char *tail = NULL;
        char *slash = tmp + strlen(tmp);
        while (slash > tmp) {
            /* Walk back to previous slash */
            while (slash > tmp && *(slash - 1) != '/') slash--;
            if (slash <= tmp) break;

            /* Remember the tail (portion after the slash) */
            tail = expanded + (size_t)(slash - tmp);
            *(slash - 1) = '\0';  /* truncate at the slash */

            if (realpath(tmp, resolved))
                break;  /* found an existing ancestor */

            /* Keep walking up */
            slash--;
            tail = NULL;
        }

        if (!tail) {
            /* No existing ancestor found */
            free(tmp);
            free(expanded);
            return NULL;
        }

        /* Reject ".." components in the non-existent tail to prevent
         * escaping the resolved ancestor via path traversal */
        const char *p = tail;
        while (*p) {
            if (p[0] == '.' && p[1] == '.' && (p[2] == '/' || p[2] == '\0')) {
                free(tmp);
                free(expanded);
                return NULL;
            }
            /* Advance to next component */
            while (*p && *p != '/') p++;
            while (*p == '/') p++;
        }

        /* Append the non-existent tail to the resolved ancestor */
        size_t rlen = strlen(resolved);
        size_t tlen = strlen(tail);
        if (rlen + 1 + tlen >= PATH_MAX) {
            free(tmp);
            free(expanded);
            return NULL;
        }
        resolved[rlen] = '/';
        memcpy(resolved + rlen + 1, tail, tlen + 1);

        free(tmp);
    }

    free(expanded);

    if (restrict_to_workspace) {
        if (!realpath(workspace, resolved_ws)) {
            return NULL;
        }
        size_t ws_len = strlen(resolved_ws);
        if (strncmp(resolved, resolved_ws, ws_len) != 0) {
            return NULL;
        }
        /* Must be exactly the workspace or followed by '/' */
        if (resolved[ws_len] != '\0' && resolved[ws_len] != '/') {
            return NULL;
        }
    }

    return sc_strdup(resolved);
}

void *sc_safe_realloc(void *ptr, size_t size)
{
    void *new_ptr = realloc(ptr, size);
    /* On failure, old ptr is still valid — caller must check return */
    return new_ptr;
}

int sc_timing_safe_cmp(const char *a, const char *b)
{
    size_t alen = strlen(a);
    size_t blen = strlen(b);
    /* Always compare max(alen,blen) bytes to avoid length leak */
    size_t len = alen > blen ? alen : blen;
    volatile unsigned char result = (alen != blen) ? 1 : 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char ca = i < alen ? (unsigned char)a[i] : 0;
        unsigned char cb = i < blen ? (unsigned char)b[i] : 0;
        result |= ca ^ cb;
    }
    return result != 0;
}

/* String buffer initial capacity */
#define STRBUF_INIT_CAP 64

void sc_strbuf_init(sc_strbuf_t *sb)
{
    sb->data = NULL;
    sb->len = 0;
    sb->cap = 0;
    sb->oom = 0;
}

static void strbuf_grow(sc_strbuf_t *sb, size_t need)
{
    if (sb->oom) return;
    if (sb->len + need + 1 <= sb->cap)
        return;
    size_t new_cap = sb->cap ? sb->cap : STRBUF_INIT_CAP;
    while (new_cap < sb->len + need + 1) {
        if (new_cap > SIZE_MAX / 2) { sb->oom = 1; return; }
        new_cap *= 2;
    }
    char *new_data = realloc(sb->data, new_cap);
    if (!new_data) {
        sb->oom = 1;
        return;
    }
    sb->data = new_data;
    sb->cap = new_cap;
}

void sc_strbuf_append(sc_strbuf_t *sb, const char *s)
{
    if (!s || sb->oom) return;
    size_t slen = strlen(s);
    strbuf_grow(sb, slen);
    if (sb->oom) return;
    memcpy(sb->data + sb->len, s, slen);
    sb->len += slen;
    sb->data[sb->len] = '\0';
}

void sc_strbuf_appendf(sc_strbuf_t *sb, const char *fmt, ...)
{
    if (sb->oom) return;

    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);

    int needed = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);

    if (needed < 0) {
        va_end(ap2);
        return;
    }

    strbuf_grow(sb, (size_t)needed);
    if (sb->oom) {
        va_end(ap2);
        return;
    }
    vsnprintf(sb->data + sb->len, (size_t)needed + 1, fmt, ap2);
    va_end(ap2);
    sb->len += (size_t)needed;
}

void sc_strbuf_append_char(sc_strbuf_t *sb, char c)
{
    if (sb->oom) return;
    strbuf_grow(sb, 1);
    if (sb->oom) return;
    sb->data[sb->len++] = c;
    sb->data[sb->len] = '\0';
}

char *sc_strbuf_finish(sc_strbuf_t *sb)
{
    if (sb->oom) {
        /* OOM occurred — free partial data and return NULL */
        free(sb->data);
        sb->data = NULL;
        sb->len = 0;
        sb->cap = 0;
        sb->oom = 0;
        return NULL;
    }
    if (!sb->data) {
        /* Return empty string */
        char *empty = malloc(1);
        if (empty) empty[0] = '\0';
        return empty;
    }
    char *result = sb->data;
    sb->data = NULL;
    sb->len = 0;
    sb->cap = 0;
    return result;
}

void sc_strbuf_free(sc_strbuf_t *sb)
{
    free(sb->data);
    sb->data = NULL;
    sb->len = 0;
    sb->cap = 0;
    sb->oom = 0;
}

char *sc_xml_cdata_wrap(const char *tag, const char *attrs, const char *content)
{
    if (!tag) return NULL;
    if (!content) content = "";

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);

    /* Opening tag with attributes */
    sc_strbuf_append_char(&sb, '<');
    sc_strbuf_append(&sb, tag);
    if (attrs && attrs[0]) {
        sc_strbuf_append_char(&sb, ' ');
        sc_strbuf_append(&sb, attrs);
    }
    sc_strbuf_append(&sb, "><![CDATA[");

    /* Append content, splitting ]]> sequences to prevent CDATA escape */
    const char *pos = content;
    while (*pos) {
        const char *danger = strstr(pos, "]]>");
        if (!danger) {
            sc_strbuf_append(&sb, pos);
            break;
        }
        /* Append up to and including ]] */
        size_t chunk = (size_t)(danger - pos) + 2;
        for (size_t i = 0; i < chunk; i++)
            sc_strbuf_append_char(&sb, pos[i]);
        /* Close and reopen CDATA section */
        sc_strbuf_append(&sb, "]]><![CDATA[>");
        pos = danger + 3;
    }

    /* Close CDATA and tag */
    sc_strbuf_append(&sb, "]]></");
    sc_strbuf_append(&sb, tag);
    sc_strbuf_append_char(&sb, '>');

    return sc_strbuf_finish(&sb);
}

char *sc_xml_escape_attr(const char *s)
{
    if (!s) return sc_strdup("");

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    for (const char *p = s; *p; p++) {
        switch (*p) {
        case '&':  sc_strbuf_append(&sb, "&amp;");  break;
        case '<':  sc_strbuf_append(&sb, "&lt;");   break;
        case '>':  sc_strbuf_append(&sb, "&gt;");   break;
        case '"':  sc_strbuf_append(&sb, "&quot;"); break;
        case '\'': sc_strbuf_append(&sb, "&apos;"); break;
        default:   sc_strbuf_append_char(&sb, *p);  break;
        }
    }
    return sc_strbuf_finish(&sb);
}

char *sc_sanitize_filename(const char *key)
{
    if (!key)
        return NULL;

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    for (const char *p = key; *p; p++) {
        if (*p == ':') {
            sc_strbuf_append(&sb, "__");  /* double underscore for colon (channel:id separator) */
        } else if (*p == '/' || *p == '\\') {
            sc_strbuf_append_char(&sb, '_');
        } else if (*p == '.' && sb.len == 0) {
            continue;  /* strip leading dots */
        } else {
            sc_strbuf_append_char(&sb, *p);
        }
    }
    char *out = sc_strbuf_finish(&sb);
    if (!out || !out[0]) {
        free(out);
        return sc_strdup("_");
    }
    return out;
}
