#ifndef SC_ANALYTICS_H
#define SC_ANALYTICS_H

typedef struct sc_analytics sc_analytics_t;

/* Create analytics tracker. DB stored at {workspace}/state/analytics.db */
sc_analytics_t *sc_analytics_new(const char *workspace);

/* Record a single turn's usage data */
void sc_analytics_record(sc_analytics_t *a, const char *model,
                         const char *session_key, const char *channel,
                         int prompt_tokens, int completion_tokens,
                         int tool_calls, long latency_ms);

/* Query functions — return allocated formatted table strings (caller frees) */
char *sc_analytics_summary(sc_analytics_t *a);
char *sc_analytics_today(sc_analytics_t *a);
char *sc_analytics_period(sc_analytics_t *a, int days);
char *sc_analytics_by_model(sc_analytics_t *a, int days);
char *sc_analytics_by_channel(sc_analytics_t *a, int days);

/* Cleanup turns older than retention_days. Returns rows deleted. */
int sc_analytics_cleanup(sc_analytics_t *a, int retention_days);

/* Reset: drop all data */
void sc_analytics_reset(sc_analytics_t *a);

/* Free analytics tracker */
void sc_analytics_free(sc_analytics_t *a);

#endif /* SC_ANALYTICS_H */
