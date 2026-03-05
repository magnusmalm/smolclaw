/*
 * tools/output_filter.c - Compress verbose CLI tool output
 *
 * Detects common CLI tools (cargo, git, pytest, npm) and extracts
 * the essential information before it enters the LLM context.
 * Conservative: when in doubt, include more rather than drop errors.
 */

#include "tools/output_filter.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/str.h"

/* Helper: case-insensitive prefix check */
static int starts_with(const char *s, const char *prefix)
{
    return strncasecmp(s, prefix, strlen(prefix)) == 0;
}

/* Helper: skip leading whitespace */
static const char *skip_ws(const char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    return s;
}

/* Helper: check if command contains --help or -h */
static int has_help_flag(const char *cmd)
{
    if (strstr(cmd, "--help")) return 1;
    /* Check for standalone -h (not part of another flag) */
    const char *p = cmd;
    while ((p = strstr(p, "-h")) != NULL) {
        /* Check it's a standalone flag */
        if (p > cmd && p[-1] != ' ' && p[-1] != '\t') { p += 2; continue; }
        if (p[2] != '\0' && p[2] != ' ' && p[2] != '\t') { p += 2; continue; }
        return 1;
    }
    return 0;
}

sc_filter_type_t sc_filter_detect(const char *command)
{
    if (!command) return SC_FILTER_NONE;

    /* Skip leading whitespace */
    command = skip_ws(command);

    /* Don't filter help output */
    if (has_help_flag(command)) return SC_FILTER_NONE;

    if (starts_with(command, "cargo test"))   return SC_FILTER_CARGO_TEST;
    if (starts_with(command, "cargo build"))  return SC_FILTER_CARGO_BUILD;
    if (starts_with(command, "cargo check"))  return SC_FILTER_CARGO_BUILD;
    if (starts_with(command, "git status"))   return SC_FILTER_GIT_STATUS;
    if (starts_with(command, "git diff"))     return SC_FILTER_GIT_DIFF;
    if (starts_with(command, "pytest"))       return SC_FILTER_PYTEST;
    if (starts_with(command, "python -m pytest")) return SC_FILTER_PYTEST;
    if (starts_with(command, "npm test"))     return SC_FILTER_NPM_TEST;
    if (starts_with(command, "npx jest"))     return SC_FILTER_NPM_TEST;

    return SC_FILTER_NONE;
}

/* ---- cargo test filter ----
 * Extract: summary line (X passed, Y failed) + failed test names + error output */
static char *filter_cargo_test(const char *raw, size_t len)
{
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);

    int in_failure = 0;
    const char *p = raw;
    const char *end = raw + len;
    const char *summary_line = NULL;

    while (p < end) {
        /* Find line boundaries */
        const char *line_start = p;
        const char *line_end = memchr(p, '\n', (size_t)(end - p));
        if (!line_end) line_end = end;

        size_t line_len = (size_t)(line_end - line_start);
        /* Temp null-terminated copy for strstr */
        char *line = malloc(line_len + 1);
        if (!line) break;
        memcpy(line, line_start, line_len);
        line[line_len] = '\0';

        /* Detect summary line: "test result: ..." */
        if (strstr(line, "test result:")) {
            summary_line = line_start;
            sc_strbuf_append(&sb, line);
            sc_strbuf_append(&sb, "\n");
        }
        /* Include failed test lines */
        else if (strstr(line, "FAILED") || strstr(line, "---- ") ||
                 strstr(line, "failures:")) {
            sc_strbuf_append(&sb, line);
            sc_strbuf_append(&sb, "\n");
            in_failure = 1;
        }
        /* Include error lines following failures */
        else if (in_failure && (strstr(line, "thread '") || strstr(line, "panicked at") ||
                                strstr(line, "assertion") || strstr(line, "left:") ||
                                strstr(line, "right:"))) {
            sc_strbuf_append(&sb, line);
            sc_strbuf_append(&sb, "\n");
        }
        /* Include warning summary */
        else if (strstr(line, "warning:") && strstr(line, "generated")) {
            sc_strbuf_append(&sb, line);
            sc_strbuf_append(&sb, "\n");
        }
        /* Include compile errors */
        else if (strstr(line, "error[E") || strstr(line, "error:")) {
            sc_strbuf_append(&sb, line);
            sc_strbuf_append(&sb, "\n");
            in_failure = 1;
        }
        else {
            in_failure = 0;
        }

        free(line);
        p = line_end < end ? line_end + 1 : end;
    }

    /* If no summary found, include everything */
    if (!summary_line && sb.len == 0) {
        sc_strbuf_free(&sb);
        return NULL;
    }

    return sc_strbuf_finish(&sb);
}

/* ---- cargo build filter ----
 * Extract: error/warning count + error messages */
static char *filter_cargo_build(const char *raw, size_t len)
{
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);

    const char *p = raw;
    const char *end = raw + len;
    int prev_was_error = 0;

    while (p < end) {
        const char *line_start = p;
        const char *line_end = memchr(p, '\n', (size_t)(end - p));
        if (!line_end) line_end = end;

        size_t line_len = (size_t)(line_end - line_start);
        char *line = malloc(line_len + 1);
        if (!line) break;
        memcpy(line, line_start, line_len);
        line[line_len] = '\0';

        /* Include error lines, warning summaries, and context around errors */
        if (strstr(line, "error[E") || strstr(line, "error:") ||
            strstr(line, "error isa") ||
            (strstr(line, "warning:") && strstr(line, "generated")) ||
            strstr(line, "could not compile") ||
            strstr(line, "aborting due to") ||
            strstr(line, "Compiling") || strstr(line, "Finished")) {
            sc_strbuf_append(&sb, line);
            sc_strbuf_append(&sb, "\n");
            prev_was_error = (strstr(line, "error") != NULL);
        }
        /* Include context lines after error (indented lines) */
        else if (prev_was_error && line_len > 0 &&
                 (line[0] == ' ' || line[0] == '-' || line[0] == '|')) {
            sc_strbuf_append(&sb, line);
            sc_strbuf_append(&sb, "\n");
        }
        else {
            prev_was_error = 0;
        }

        free(line);
        p = line_end < end ? line_end + 1 : end;
    }

    if (sb.len == 0) {
        sc_strbuf_free(&sb);
        return NULL;
    }

    return sc_strbuf_finish(&sb);
}

/* ---- git status filter ----
 * Compact: staged N files, unstaged N, untracked N + file lists */
static char *filter_git_status(const char *raw, size_t len)
{
    int staged = 0, unstaged = 0, untracked = 0;
    sc_strbuf_t staged_files, unstaged_files, untracked_files;
    sc_strbuf_init(&staged_files);
    sc_strbuf_init(&unstaged_files);
    sc_strbuf_init(&untracked_files);

    const char *p = raw;
    const char *end = raw + len;
    int section = 0; /* 0=none, 1=staged, 2=unstaged, 3=untracked */

    while (p < end) {
        const char *line_start = p;
        const char *line_end = memchr(p, '\n', (size_t)(end - p));
        if (!line_end) line_end = end;

        size_t line_len = (size_t)(line_end - line_start);
        char *line = malloc(line_len + 1);
        if (!line) break;
        memcpy(line, line_start, line_len);
        line[line_len] = '\0';

        if (strstr(line, "Changes to be committed"))
            section = 1;
        else if (strstr(line, "Changes not staged"))
            section = 2;
        else if (strstr(line, "Untracked files"))
            section = 3;
        else if (line_len > 0 && line[0] == '\t') {
            const char *fname = skip_ws(line);
            switch (section) {
                case 1:
                    staged++;
                    sc_strbuf_appendf(&staged_files, "  %s\n", fname);
                    break;
                case 2:
                    unstaged++;
                    sc_strbuf_appendf(&unstaged_files, "  %s\n", fname);
                    break;
                case 3:
                    untracked++;
                    sc_strbuf_appendf(&untracked_files, "  %s\n", fname);
                    break;
            }
        }
        /* Branch line */
        else if (starts_with(line, "On branch") || starts_with(line, "HEAD detached")) {
            /* Pass through */
        }

        free(line);
        p = line_end < end ? line_end + 1 : end;
    }

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);

    /* Include branch info from first line */
    const char *first_nl = memchr(raw, '\n', len);
    if (first_nl) {
        size_t flen = (size_t)(first_nl - raw);
        char *first = malloc(flen + 1);
        if (first) {
            memcpy(first, raw, flen);
            first[flen] = '\0';
            sc_strbuf_appendf(&sb, "%s\n", first);
            free(first);
        }
    }

    if (staged > 0) {
        char *files = sc_strbuf_finish(&staged_files);
        sc_strbuf_appendf(&sb, "Staged (%d):\n%s", staged, files);
        free(files);
    } else {
        sc_strbuf_free(&staged_files);
    }

    if (unstaged > 0) {
        char *files = sc_strbuf_finish(&unstaged_files);
        sc_strbuf_appendf(&sb, "Unstaged (%d):\n%s", unstaged, files);
        free(files);
    } else {
        sc_strbuf_free(&unstaged_files);
    }

    if (untracked > 0) {
        char *files = sc_strbuf_finish(&untracked_files);
        sc_strbuf_appendf(&sb, "Untracked (%d):\n%s", untracked, files);
        free(files);
    } else {
        sc_strbuf_free(&untracked_files);
    }

    if (staged == 0 && unstaged == 0 && untracked == 0) {
        sc_strbuf_append(&sb, "Working tree clean\n");
    }

    return sc_strbuf_finish(&sb);
}

/* ---- git diff filter ----
 * Per-file stat summary, include full hunks only for small diffs */
static char *filter_git_diff(const char *raw, size_t len)
{
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);

    const char *p = raw;
    const char *end = raw + len;

    int file_count = 0;
    int total_adds = 0, total_dels = 0;
    int cur_adds = 0, cur_dels = 0;
    char *cur_file = NULL;
    int hunk_lines = 0;
    sc_strbuf_t hunk_buf;
    sc_strbuf_init(&hunk_buf);

    while (p < end) {
        const char *line_start = p;
        const char *line_end = memchr(p, '\n', (size_t)(end - p));
        if (!line_end) line_end = end;

        size_t line_len = (size_t)(line_end - line_start);

        /* New file header */
        if (line_len > 6 && strncmp(line_start, "diff --", 7) == 0) {
            /* Flush previous file */
            if (cur_file) {
                sc_strbuf_appendf(&sb, "%s  +%d -%d\n", cur_file, cur_adds, cur_dels);
                if (hunk_lines <= 50) {
                    char *h = sc_strbuf_finish(&hunk_buf);
                    sc_strbuf_append(&sb, h);
                    free(h);
                } else {
                    sc_strbuf_free(&hunk_buf);
                    sc_strbuf_appendf(&sb, "  (%d lines, omitted)\n", hunk_lines);
                }
                free(cur_file);
                total_adds += cur_adds;
                total_dels += cur_dels;
            }

            /* Extract filename from "diff --git a/file b/file" */
            const char *b = strstr(line_start, " b/");
            if (b) {
                size_t fname_len = (size_t)(line_end - (b + 3));
                cur_file = malloc(fname_len + 1);
                if (cur_file) {
                    memcpy(cur_file, b + 3, fname_len);
                    cur_file[fname_len] = '\0';
                }
            } else {
                cur_file = sc_strdup("(unknown)");
            }
            cur_adds = 0;
            cur_dels = 0;
            hunk_lines = 0;
            sc_strbuf_init(&hunk_buf);
            file_count++;
        }
        /* Count additions/deletions */
        else if (line_len > 0 && line_start[0] == '+' &&
                 !(line_len > 3 && strncmp(line_start, "+++", 3) == 0)) {
            cur_adds++;
            hunk_lines++;
            /* Buffer hunk content */
            char *line = malloc(line_len + 2);
            if (line) {
                memcpy(line, line_start, line_len);
                line[line_len] = '\n';
                line[line_len + 1] = '\0';
                sc_strbuf_append(&hunk_buf, line);
                free(line);
            }
        }
        else if (line_len > 0 && line_start[0] == '-' &&
                 !(line_len > 3 && strncmp(line_start, "---", 3) == 0)) {
            cur_dels++;
            hunk_lines++;
            char *line = malloc(line_len + 2);
            if (line) {
                memcpy(line, line_start, line_len);
                line[line_len] = '\n';
                line[line_len + 1] = '\0';
                sc_strbuf_append(&hunk_buf, line);
                free(line);
            }
        }
        else if (line_len > 0 && line_start[0] == '@') {
            hunk_lines++;
            char *line = malloc(line_len + 2);
            if (line) {
                memcpy(line, line_start, line_len);
                line[line_len] = '\n';
                line[line_len + 1] = '\0';
                sc_strbuf_append(&hunk_buf, line);
                free(line);
            }
        }

        p = line_end < end ? line_end + 1 : end;
    }

    /* Flush last file */
    if (cur_file) {
        sc_strbuf_appendf(&sb, "%s  +%d -%d\n", cur_file, cur_adds, cur_dels);
        if (hunk_lines <= 50) {
            char *h = sc_strbuf_finish(&hunk_buf);
            sc_strbuf_append(&sb, h);
            free(h);
        } else {
            sc_strbuf_free(&hunk_buf);
            sc_strbuf_appendf(&sb, "  (%d lines, omitted)\n", hunk_lines);
        }
        total_adds += cur_adds;
        total_dels += cur_dels;
        free(cur_file);
    }

    if (file_count > 0) {
        sc_strbuf_appendf(&sb, "\n%d files, +%d -%d\n", file_count, total_adds, total_dels);
    }

    if (sb.len == 0) {
        sc_strbuf_free(&sb);
        return NULL;
    }

    return sc_strbuf_finish(&sb);
}

/* ---- pytest filter ----
 * Extract: summary line + failed test names + first assertion per failure */
static char *filter_pytest(const char *raw, size_t len)
{
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);

    const char *p = raw;
    const char *end = raw + len;
    int in_failure = 0;
    int assertion_seen = 0;

    while (p < end) {
        const char *line_start = p;
        const char *line_end = memchr(p, '\n', (size_t)(end - p));
        if (!line_end) line_end = end;

        size_t line_len = (size_t)(line_end - line_start);
        char *line = malloc(line_len + 1);
        if (!line) break;
        memcpy(line, line_start, line_len);
        line[line_len] = '\0';

        /* Summary lines */
        if (strstr(line, " passed") || strstr(line, " failed") ||
            strstr(line, " error") || strstr(line, " warning") ||
            strstr(line, "===")) {
            if (strstr(line, "===") && (strstr(line, "FAILURES") ||
                strstr(line, "short test summary") || strstr(line, "passed") ||
                strstr(line, "failed") || strstr(line, "error"))) {
                sc_strbuf_append(&sb, line);
                sc_strbuf_append(&sb, "\n");
            } else if (!strstr(line, "===")) {
                sc_strbuf_append(&sb, line);
                sc_strbuf_append(&sb, "\n");
            }
        }
        /* Failed test headers */
        else if (strstr(line, "FAILED ") || strstr(line, "_ ") ||
                 (starts_with(line, "____") && strstr(line, " _"))) {
            sc_strbuf_append(&sb, line);
            sc_strbuf_append(&sb, "\n");
            in_failure = 1;
            assertion_seen = 0;
        }
        /* First assertion in failure */
        else if (in_failure && !assertion_seen &&
                 (strstr(line, "AssertionError") || strstr(line, "assert ") ||
                  strstr(line, "Error:") || strstr(line, "Exception"))) {
            sc_strbuf_append(&sb, line);
            sc_strbuf_append(&sb, "\n");
            assertion_seen = 1;
        }
        /* Collection errors */
        else if (strstr(line, "ERROR collecting") || strstr(line, "ModuleNotFoundError") ||
                 strstr(line, "ImportError")) {
            sc_strbuf_append(&sb, line);
            sc_strbuf_append(&sb, "\n");
        }

        free(line);
        p = line_end < end ? line_end + 1 : end;
    }

    if (sb.len == 0) {
        sc_strbuf_free(&sb);
        return NULL;
    }

    return sc_strbuf_finish(&sb);
}

/* ---- npm test filter ----
 * Extract: suite summary + failed test names */
static char *filter_npm_test(const char *raw, size_t len)
{
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);

    const char *p = raw;
    const char *end = raw + len;

    while (p < end) {
        const char *line_start = p;
        const char *line_end = memchr(p, '\n', (size_t)(end - p));
        if (!line_end) line_end = end;

        size_t line_len = (size_t)(line_end - line_start);
        char *line = malloc(line_len + 1);
        if (!line) break;
        memcpy(line, line_start, line_len);
        line[line_len] = '\0';

        /* Include summary and failure lines */
        if (strstr(line, "Tests:") || strstr(line, "Test Suites:") ||
            strstr(line, "FAIL ") || strstr(line, "PASS ") ||
            strstr(line, "● ") || strstr(line, "✕ ") ||
            strstr(line, "✓ ") || strstr(line, "✗ ") ||
            strstr(line, "Expected") || strstr(line, "Received") ||
            strstr(line, "expect(") || strstr(line, "Error:") ||
            strstr(line, "npm ERR!") ||
            strstr(line, "Time:") || strstr(line, "Ran all")) {
            sc_strbuf_append(&sb, line);
            sc_strbuf_append(&sb, "\n");
        }

        free(line);
        p = line_end < end ? line_end + 1 : end;
    }

    if (sb.len == 0) {
        sc_strbuf_free(&sb);
        return NULL;
    }

    return sc_strbuf_finish(&sb);
}

char *sc_filter_apply(sc_filter_type_t type, const char *raw, size_t len)
{
    if (!raw || len == 0 || type == SC_FILTER_NONE) return NULL;

    char *filtered = NULL;

    switch (type) {
        case SC_FILTER_CARGO_TEST:  filtered = filter_cargo_test(raw, len); break;
        case SC_FILTER_CARGO_BUILD: filtered = filter_cargo_build(raw, len); break;
        case SC_FILTER_GIT_STATUS:  filtered = filter_git_status(raw, len); break;
        case SC_FILTER_GIT_DIFF:    filtered = filter_git_diff(raw, len); break;
        case SC_FILTER_PYTEST:      filtered = filter_pytest(raw, len); break;
        case SC_FILTER_NPM_TEST:    filtered = filter_npm_test(raw, len); break;
        default: return NULL;
    }

    if (!filtered) return NULL;

    /* Only use filter if it achieves significant reduction (>50%) */
    size_t filtered_len = strlen(filtered);
    if (filtered_len >= len / 2) {
        free(filtered);
        return NULL;
    }

    return filtered;
}
