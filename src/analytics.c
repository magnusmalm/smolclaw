/*
 * analytics.c - SQLite-backed token/cost analytics
 *
 * Time-series tracking of LLM usage: tokens, tool calls, latency.
 * DB at {workspace}/state/analytics.db. WAL mode for performance.
 */

#include "analytics.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <sqlite3.h>

#include "util/str.h"
#include "logger.h"

#define LOG_TAG "analytics"
#define RETENTION_DAYS 90

struct sc_analytics {
    sqlite3 *db;
    sqlite3_stmt *insert_stmt;
};

static const char *CREATE_SQL =
    "CREATE TABLE IF NOT EXISTS turns ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  ts INTEGER NOT NULL,"
    "  model TEXT NOT NULL,"
    "  session_key TEXT,"
    "  channel TEXT,"
    "  prompt_tokens INTEGER NOT NULL,"
    "  completion_tokens INTEGER NOT NULL,"
    "  tool_calls INTEGER DEFAULT 0,"
    "  latency_ms INTEGER DEFAULT 0"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_turns_ts ON turns(ts);"
    "CREATE INDEX IF NOT EXISTS idx_turns_model ON turns(model);"
    "CREATE INDEX IF NOT EXISTS idx_turns_channel ON turns(channel);";

static const char *INSERT_SQL =
    "INSERT INTO turns (ts, model, session_key, channel, "
    "prompt_tokens, completion_tokens, tool_calls, latency_ms) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

sc_analytics_t *sc_analytics_new(const char *workspace)
{
    if (!workspace) return NULL;

    sc_analytics_t *a = calloc(1, sizeof(*a));
    if (!a) return NULL;

    /* Ensure state directory exists */
    sc_strbuf_t dir;
    sc_strbuf_init(&dir);
    sc_strbuf_appendf(&dir, "%s/state", workspace);
    char *state_dir = sc_strbuf_finish(&dir);
    mkdir(state_dir, 0755);

    sc_strbuf_t path;
    sc_strbuf_init(&path);
    sc_strbuf_appendf(&path, "%s/analytics.db", state_dir);
    char *db_path = sc_strbuf_finish(&path);
    free(state_dir);

    int rc = sqlite3_open(db_path, &a->db);
    if (rc != SQLITE_OK) {
        SC_LOG_ERROR(LOG_TAG, "Failed to open analytics DB: %s", db_path);
        free(db_path);
        free(a);
        return NULL;
    }
    free(db_path);

    /* WAL mode for better concurrent performance */
    sqlite3_exec(a->db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);
    sqlite3_exec(a->db, "PRAGMA synchronous=NORMAL", NULL, NULL, NULL);

    /* Create schema */
    char *err = NULL;
    rc = sqlite3_exec(a->db, CREATE_SQL, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        SC_LOG_ERROR(LOG_TAG, "Failed to create schema: %s", err ? err : "unknown");
        sqlite3_free(err);
        sqlite3_close(a->db);
        free(a);
        return NULL;
    }

    /* Prepare insert statement */
    rc = sqlite3_prepare_v2(a->db, INSERT_SQL, -1, &a->insert_stmt, NULL);
    if (rc != SQLITE_OK) {
        SC_LOG_ERROR(LOG_TAG, "Failed to prepare insert: %s", sqlite3_errmsg(a->db));
        sqlite3_close(a->db);
        free(a);
        return NULL;
    }

    /* Startup cleanup */
    sc_analytics_cleanup(a, RETENTION_DAYS);

    SC_LOG_INFO(LOG_TAG, "Analytics initialized");
    return a;
}

void sc_analytics_record(sc_analytics_t *a, const char *model,
                         const char *session_key, const char *channel,
                         int prompt_tokens, int completion_tokens,
                         int tool_calls, long latency_ms)
{
    if (!a || !a->insert_stmt) return;

    sqlite3_reset(a->insert_stmt);
    sqlite3_bind_int64(a->insert_stmt, 1, (sqlite3_int64)time(NULL));
    sqlite3_bind_text(a->insert_stmt, 2, model ? model : "unknown", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(a->insert_stmt, 3, session_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(a->insert_stmt, 4, channel, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(a->insert_stmt, 5, prompt_tokens);
    sqlite3_bind_int(a->insert_stmt, 6, completion_tokens);
    sqlite3_bind_int(a->insert_stmt, 7, tool_calls);
    sqlite3_bind_int64(a->insert_stmt, 8, latency_ms);

    int rc = sqlite3_step(a->insert_stmt);
    if (rc != SQLITE_DONE) {
        SC_LOG_WARN(LOG_TAG, "Failed to record turn: %s", sqlite3_errmsg(a->db));
    }
}

/* Helper: run a query and format results as a table string */
static char *run_query(sc_analytics_t *a, const char *sql)
{
    if (!a || !a->db) return sc_strdup("(analytics unavailable)");

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(a->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        SC_LOG_WARN(LOG_TAG, "Query failed: %s", sqlite3_errmsg(a->db));
        return sc_strdup("(query error)");
    }

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);

    int cols = sqlite3_column_count(stmt);

    /* Header */
    for (int i = 0; i < cols; i++) {
        if (i > 0) sc_strbuf_append(&sb, " | ");
        sc_strbuf_appendf(&sb, "%-16s", sqlite3_column_name(stmt, i));
    }
    sc_strbuf_append(&sb, "\n");
    for (int i = 0; i < cols; i++) {
        if (i > 0) sc_strbuf_append(&sb, "-+-");
        sc_strbuf_append(&sb, "----------------");
    }
    sc_strbuf_append(&sb, "\n");

    /* Rows */
    int row_count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        for (int i = 0; i < cols; i++) {
            if (i > 0) sc_strbuf_append(&sb, " | ");
            const char *val = (const char *)sqlite3_column_text(stmt, i);
            sc_strbuf_appendf(&sb, "%-16s", val ? val : "");
        }
        sc_strbuf_append(&sb, "\n");
        row_count++;
    }

    sqlite3_finalize(stmt);

    if (row_count == 0)
        sc_strbuf_append(&sb, "(no data)\n");

    return sc_strbuf_finish(&sb);
}

char *sc_analytics_summary(sc_analytics_t *a)
{
    return run_query(a,
        "SELECT "
        "  COUNT(*) AS turns, "
        "  SUM(prompt_tokens) AS prompt_tok, "
        "  SUM(completion_tokens) AS compl_tok, "
        "  SUM(prompt_tokens + completion_tokens) AS total_tok, "
        "  SUM(tool_calls) AS tools, "
        "  ROUND(AVG(latency_ms)) AS avg_ms "
        "FROM turns");
}

char *sc_analytics_today(sc_analytics_t *a)
{
    return run_query(a,
        "SELECT "
        "  COUNT(*) AS turns, "
        "  SUM(prompt_tokens) AS prompt_tok, "
        "  SUM(completion_tokens) AS compl_tok, "
        "  SUM(prompt_tokens + completion_tokens) AS total_tok, "
        "  SUM(tool_calls) AS tools, "
        "  ROUND(AVG(latency_ms)) AS avg_ms "
        "FROM turns "
        "WHERE ts >= strftime('%s', 'now', 'start of day')");
}

char *sc_analytics_period(sc_analytics_t *a, int days)
{
    if (!a || !a->db) return sc_strdup("(analytics unavailable)");

    sc_strbuf_t sql;
    sc_strbuf_init(&sql);
    sc_strbuf_appendf(&sql,
        "SELECT "
        "  date(ts, 'unixepoch') AS day, "
        "  COUNT(*) AS turns, "
        "  SUM(prompt_tokens) AS prompt_tok, "
        "  SUM(completion_tokens) AS compl_tok, "
        "  SUM(tool_calls) AS tools "
        "FROM turns "
        "WHERE ts >= strftime('%%s', 'now', '-%d days') "
        "GROUP BY day ORDER BY day", days);
    char *q = sc_strbuf_finish(&sql);
    char *result = run_query(a, q);
    free(q);
    return result;
}

char *sc_analytics_by_model(sc_analytics_t *a, int days)
{
    if (!a || !a->db) return sc_strdup("(analytics unavailable)");

    sc_strbuf_t sql;
    sc_strbuf_init(&sql);
    sc_strbuf_appendf(&sql,
        "SELECT "
        "  model, "
        "  COUNT(*) AS turns, "
        "  SUM(prompt_tokens) AS prompt_tok, "
        "  SUM(completion_tokens) AS compl_tok, "
        "  SUM(tool_calls) AS tools, "
        "  ROUND(AVG(latency_ms)) AS avg_ms "
        "FROM turns "
        "WHERE ts >= strftime('%%s', 'now', '-%d days') "
        "GROUP BY model ORDER BY turns DESC", days);
    char *q = sc_strbuf_finish(&sql);
    char *result = run_query(a, q);
    free(q);
    return result;
}

char *sc_analytics_by_channel(sc_analytics_t *a, int days)
{
    if (!a || !a->db) return sc_strdup("(analytics unavailable)");

    sc_strbuf_t sql;
    sc_strbuf_init(&sql);
    sc_strbuf_appendf(&sql,
        "SELECT "
        "  COALESCE(channel, '(none)') AS channel, "
        "  COUNT(*) AS turns, "
        "  SUM(prompt_tokens) AS prompt_tok, "
        "  SUM(completion_tokens) AS compl_tok, "
        "  SUM(tool_calls) AS tools "
        "FROM turns "
        "WHERE ts >= strftime('%%s', 'now', '-%d days') "
        "GROUP BY channel ORDER BY turns DESC", days);
    char *q = sc_strbuf_finish(&sql);
    char *result = run_query(a, q);
    free(q);
    return result;
}

int sc_analytics_cleanup(sc_analytics_t *a, int retention_days)
{
    if (!a || !a->db) return 0;

    sc_strbuf_t sql;
    sc_strbuf_init(&sql);
    sc_strbuf_appendf(&sql,
        "DELETE FROM turns WHERE ts < strftime('%%s', 'now', '-%d days')",
        retention_days);
    char *q = sc_strbuf_finish(&sql);

    char *err = NULL;
    sqlite3_exec(a->db, q, NULL, NULL, &err);
    free(q);

    int deleted = sqlite3_changes(a->db);
    if (deleted > 0)
        SC_LOG_INFO(LOG_TAG, "Cleaned up %d old analytics records", deleted);
    if (err) sqlite3_free(err);
    return deleted;
}

void sc_analytics_reset(sc_analytics_t *a)
{
    if (!a || !a->db) return;
    sqlite3_exec(a->db, "DELETE FROM turns", NULL, NULL, NULL);
    SC_LOG_INFO(LOG_TAG, "Analytics data reset");
}

void sc_analytics_free(sc_analytics_t *a)
{
    if (!a) return;
    if (a->insert_stmt) sqlite3_finalize(a->insert_stmt);
    if (a->db) sqlite3_close(a->db);
    free(a);
}
