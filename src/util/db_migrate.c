/*
 * util/db_migrate.c - SQLite schema migration helper
 *
 * Uses PRAGMA user_version to track schema version.
 * Runs pending migrations in a transaction.
 */

#include "db_migrate.h"
#include "../logger.h"

#include <stdio.h>

#define LOG_TAG "db_migrate"

int
sc_db_migrate(sqlite3 *db, const char *const *migrations, int count,
              const char *tag)
{
    if (!db || !migrations || count <= 0)
        return 0;

    /* Read current schema version */
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        return -1;

    int version = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        version = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    if (version >= count)
        return 0; /* already up to date */

    SC_LOG_INFO(LOG_TAG, "[%s] migrating from v%d to v%d",
                tag ? tag : "?", version, count);

    /* Run pending migrations in a transaction */
    rc = sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        SC_LOG_ERROR(LOG_TAG, "[%s] BEGIN failed: %s",
                     tag, sqlite3_errmsg(db));
        return -1;
    }

    for (int v = version; v < count; v++) {
        char *err = NULL;
        rc = sqlite3_exec(db, migrations[v], NULL, NULL, &err);
        if (rc != SQLITE_OK) {
            SC_LOG_ERROR(LOG_TAG, "[%s] migration v%d failed: %s",
                         tag, v + 1, err ? err : "unknown");
            sqlite3_free(err);
            sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
            return -1;
        }
    }

    /* Update user_version */
    char pragma[64];
    snprintf(pragma, sizeof(pragma), "PRAGMA user_version = %d", count);
    rc = sqlite3_exec(db, pragma, NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        return -1;
    }

    rc = sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        SC_LOG_ERROR(LOG_TAG, "[%s] COMMIT failed: %s",
                     tag, sqlite3_errmsg(db));
        return -1;
    }

    SC_LOG_INFO(LOG_TAG, "[%s] migrated to v%d", tag, count);
    return 0;
}
