#include "logger.h"
#include "constants.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static FILE *log_file;
static sc_log_level_t min_level = SC_LOG_INFO;

/* Weak fallback — overridden by strong definition in main.c */
__attribute__((weak)) int sc_shutdown_requested(void) { return 0; }

static const char *level_names[] = {
    [SC_LOG_DEBUG] = "DEBUG",
    [SC_LOG_INFO]  = "INFO",
    [SC_LOG_WARN]  = "WARN",
    [SC_LOG_ERROR] = "ERROR",
};

void sc_logger_init(const char *log_path)
{
    min_level = SC_LOG_INFO;

    if (log_path) {
        log_file = fopen(log_path, "a");
        if (!log_file)
            fprintf(stderr, "[WARN] logger: failed to open log file: %s\n", log_path);
    }
}

void sc_logger_shutdown(void)
{
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}

void sc_logger_set_level(sc_log_level_t level)
{
    min_level = level;
}

void sc_logger_set_file(const char *log_path)
{
    if (!log_path) return;
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
    log_file = fopen(log_path, "a");
    if (!log_file)
        fprintf(stderr, "[WARN] logger: failed to open log file: %s\n", log_path);
}

void sc_log(sc_log_level_t level, const char *component, const char *fmt, ...)
{
    if (level < min_level)
        return;

    /* Generate ISO 8601 timestamp */
    time_t now = time(NULL);
    struct tm tm_buf;
    gmtime_r(&now, &tm_buf);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);

    /* Format the user message */
    va_list ap;
    va_start(ap, fmt);
    char msg[4096];
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    const char *lname = (level >= 0 && level <= SC_LOG_ERROR) ? level_names[level] : "???";

    /* Build log line: [timestamp] [LEVEL] component: message */
    char line[4352];
    if (component && component[0]) {
        snprintf(line, sizeof(line), "[%s] [%s] %s: %s", ts, lname, component, msg);
    } else {
        snprintf(line, sizeof(line), "[%s] [%s] %s", ts, lname, msg);
    }

    fprintf(stderr, "%s\n", line);

    if (log_file) {
        fprintf(log_file, "%s\n", line);
        fflush(log_file);
    }
}
