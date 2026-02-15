#ifndef SC_PAIRING_H
#define SC_PAIRING_H

/* DM access policies for channels */
typedef enum {
    SC_DM_POLICY_OPEN,      /* Allow all (default, backward compat) */
    SC_DM_POLICY_ALLOWLIST, /* Only allow_from entries */
    SC_DM_POLICY_PAIRING   /* Allowlist + challenge code for unknowns */
} sc_dm_policy_t;

sc_dm_policy_t sc_dm_policy_from_str(const char *s);
const char *sc_dm_policy_to_str(sc_dm_policy_t policy);

/* Pending pairing request */
typedef struct {
    char *sender_id;
    char *code;
    long created_ms;
} sc_pairing_request_t;

/* Opaque pairing store (one per channel) */
typedef struct sc_pairing_store sc_pairing_store_t;

/* Create/free store. store_dir is the directory for persistence files. */
sc_pairing_store_t *sc_pairing_store_new(const char *channel, const char *store_dir);
void sc_pairing_store_free(sc_pairing_store_t *ps);

/* Generate or return existing challenge code for sender_id.
 * Returns NULL if max pending reached. Caller does NOT own the string. */
const char *sc_pairing_store_challenge(sc_pairing_store_t *ps, const char *sender_id);

/* Approve a pairing code. Returns owned sender_id string or NULL. */
char *sc_pairing_store_approve(sc_pairing_store_t *ps, const char *code);

/* List pending requests. Sets *out to internal array. Returns count. */
int sc_pairing_store_list(sc_pairing_store_t *ps, sc_pairing_request_t **out);

#endif /* SC_PAIRING_H */
