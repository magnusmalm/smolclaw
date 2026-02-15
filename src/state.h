#ifndef SC_STATE_H
#define SC_STATE_H

/* Persistent state (last channel, etc.) */
typedef struct {
    char *last_channel;  /* Format: "channel:chatID" */
    char *workspace;
    long timestamp;
} sc_state_t;

/* Create state manager */
sc_state_t *sc_state_new(const char *workspace);
void sc_state_free(sc_state_t *st);

/* Get/set last channel (atomically saved) */
const char *sc_state_get_last_channel(const sc_state_t *st);
int sc_state_set_last_channel(sc_state_t *st, const char *channel);

#endif /* SC_STATE_H */
