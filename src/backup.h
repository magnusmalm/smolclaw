#ifndef SC_BACKUP_H
#define SC_BACKUP_H

/*
 * Backup/restore for smolclaw state directory (~/.smolclaw/).
 *
 * Default scope: config.json, vault.db, workspace/, state/
 * Optional: sessions/ (--include-sessions)
 * Minimal: config.json only (--config-only)
 *
 * Each backup lives in ~/.smolclaw/backups/<name>/ with a manifest.json
 * containing SHA256 hashes for integrity verification.
 */

/* Create a backup. Returns malloc'd backup name on success, NULL on failure.
 * name: optional tag (NULL = ISO timestamp). */
char *sc_backup_create(const char *name, int config_only, int include_sessions);

/* Verify a backup's integrity. name=NULL verifies the latest.
 * Returns 0 if all hashes match, 1 if mismatch, -1 on error. */
int sc_backup_verify(const char *name);

/* Print available backups as JSON array to stdout. Returns count, -1 on error. */
int sc_backup_list(void);

/* Restore from a backup. Returns 0 on success, 1 on failure.
 * dry_run: if true, only prints what would be restored. */
int sc_backup_restore(const char *name, int dry_run);

#endif /* SC_BACKUP_H */
