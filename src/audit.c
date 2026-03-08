/*
 * smolclaw - audit.c
 * JSON-lines audit log for tool executions.
 */

#include "audit.h"
#include "logger.h"
#include "util/str.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

#define LOG_TAG "audit"

static pthread_mutex_t audit_lock = PTHREAD_MUTEX_INITIALIZER;
static FILE *audit_file;
static char *audit_model;  /* current LLM model, set per-turn (owned) */

/* Ensure parent directory exists (single level) */
static void ensure_parent_dir(const char *path)
{
    char *copy = sc_strdup(path);
    if (!copy) return;

    char *slash = strrchr(copy, '/');
    if (slash && slash != copy) {
        *slash = '\0';
        mkdir(copy, 0755);
    }
    free(copy);
}

/* Escape a string for JSON output (minimal: backslash, quote, control chars) */
static void write_json_string(FILE *f, const char *s)
{
    fputc('"', f);
    if (s) {
        for (const char *p = s; *p; p++) {
            switch (*p) {
            case '"':  fputs("\\\"", f); break;
            case '\\': fputs("\\\\", f); break;
            case '\n': fputs("\\n", f); break;
            case '\r': fputs("\\r", f); break;
            case '\t': fputs("\\t", f); break;
            default:
                if ((unsigned char)*p < 0x20)
                    fprintf(f, "\\u%04x", (unsigned char)*p);
                else
                    fputc(*p, f);
            }
        }
    }
    fputc('"', f);
}

void sc_audit_init(const char *log_path)
{
    if (!log_path) return;

    ensure_parent_dir(log_path);

    /* Open with O_APPEND and restrictive permissions (0600) */
    int fd = open(log_path, O_WRONLY | O_APPEND | O_CREAT, 0600);
    if (fd < 0) {
        SC_LOG_WARN(LOG_TAG, "Failed to open audit log: %s", log_path);
        return;
    }
    audit_file = fdopen(fd, "a");
    if (!audit_file) {
        close(fd);
        SC_LOG_WARN(LOG_TAG, "Failed to fdopen audit log: %s", log_path);
    } else {
        SC_LOG_INFO(LOG_TAG, "Audit log opened: %s", log_path);
    }
}

void sc_audit_shutdown(void)
{
    if (audit_file) {
        fclose(audit_file);
        audit_file = NULL;
    }
    free(audit_model);
    audit_model = NULL;
}

void sc_audit_log_ext(const char *tool, const char *args_summary,
                      int is_error, long ms,
                      const char *channel, const char *user_id,
                      const char *event)
{
    pthread_mutex_lock(&audit_lock);
    if (!audit_file) {
        pthread_mutex_unlock(&audit_lock);
        return;
    }

    /* ISO 8601 timestamp */
    time_t now = time(NULL);
    struct tm tm_buf;
    gmtime_r(&now, &tm_buf);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);

    /* Truncate args summary to 200 chars */
    char trunc_buf[201];
    if (args_summary && strlen(args_summary) > 200) {
        memcpy(trunc_buf, args_summary, 200);
        trunc_buf[200] = '\0';
        args_summary = trunc_buf;
    }

    fputs("{\"ts\":", audit_file);
    write_json_string(audit_file, ts);
    fputs(",\"tool\":", audit_file);
    write_json_string(audit_file, tool);
    fputs(",\"args\":", audit_file);
    write_json_string(audit_file, args_summary ? args_summary : "");
    fprintf(audit_file, ",\"status\":\"%s\",\"ms\":%ld",
            is_error ? "error" : "ok", ms);
    if (event) {
        fputs(",\"event\":", audit_file);
        write_json_string(audit_file, event);
    }
    if (channel) {
        fputs(",\"channel\":", audit_file);
        write_json_string(audit_file, channel);
    }
    if (user_id) {
        fputs(",\"user\":", audit_file);
        write_json_string(audit_file, user_id);
    }
    if (audit_model) {
        fputs(",\"model\":", audit_file);
        write_json_string(audit_file, audit_model);
    }
    fputs("}\n", audit_file);
    fflush(audit_file);
    pthread_mutex_unlock(&audit_lock);
}

void sc_audit_log(const char *tool, const char *args_summary,
                  int is_error, long ms)
{
    sc_audit_log_ext(tool, args_summary, is_error, ms, NULL, NULL, NULL);
}

void sc_audit_set_model(const char *model)
{
    pthread_mutex_lock(&audit_lock);
    free(audit_model);
    audit_model = model ? sc_strdup(model) : NULL;
    pthread_mutex_unlock(&audit_lock);
}
