#ifndef SC_DB_MIGRATE_H
#define SC_DB_MIGRATE_H

#include <sqlite3.h>

/*
 * Run schema migrations on a SQLite database.
 *
 * Uses PRAGMA user_version to track the current schema version.
 * Each migration is a SQL string that advances the schema by one version.
 * Migrations are run in a transaction; on failure the DB is left unchanged.
 *
 * migrations: array of SQL strings, one per version step.
 *             migrations[0] runs when user_version == 0 (sets version to 1).
 *             migrations[1] runs when user_version == 1 (sets version to 2).
 * count: number of entries in the migrations array.
 * tag: label for log messages (e.g. "analytics", "memory_index").
 *
 * Returns 0 on success (all migrations applied), -1 on error.
 */
int sc_db_migrate(sqlite3 *db, const char *const *migrations, int count,
                  const char *tag);

#endif /* SC_DB_MIGRATE_H */
