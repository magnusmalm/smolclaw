#ifndef SC_VAULT_H
#define SC_VAULT_H

/*
 * AES-256-GCM encrypted vault for API keys and secrets.
 * File format: SCVAULT\x01 | salt(16) | iv(12) | len(4 BE) | tag(16) | ciphertext
 * Key derivation: PBKDF2-HMAC-SHA256, 600000 iterations, 16-byte salt.
 */

typedef struct sc_vault sc_vault_t;

/* Create vault handle (does not open file). */
sc_vault_t *sc_vault_new(const char *path);
void sc_vault_free(sc_vault_t *v);

/* Initialize a new vault file with password. Returns 0 on success. */
int sc_vault_init(sc_vault_t *v, const char *password);

/* Unlock existing vault with password. Returns 0 on success. */
int sc_vault_unlock(sc_vault_t *v, const char *password);

/* Get/set/remove secrets. Vault must be unlocked. */
const char *sc_vault_get(const sc_vault_t *v, const char *key);
int sc_vault_set(sc_vault_t *v, const char *key, const char *value);
int sc_vault_remove(sc_vault_t *v, const char *key);

/* Get list of key names. Returns count, sets *keys to malloc'd array.
 * Caller owns the array and its strings. */
int sc_vault_list(const sc_vault_t *v, char ***keys);

/* Save vault to disk (re-encrypts with fresh IV). Returns 0 on success. */
int sc_vault_save(sc_vault_t *v);

/* Change password: re-derives key and saves. Returns 0 on success. */
int sc_vault_change_password(sc_vault_t *v, const char *new_password);

/* Check if vault file exists at path. */
int sc_vault_exists(const char *path);

/* Get vault file path (~/.smolclaw/vault.enc). Caller owns result. */
char *sc_vault_get_path(void);

/* Prompt for password with echo disabled. Caller owns result.
 * Returns NULL on failure. prompt is the message to show. */
char *sc_vault_prompt_password(const char *prompt);

#endif /* SC_VAULT_H */
