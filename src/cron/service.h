#ifndef SC_CRON_SERVICE_H
#define SC_CRON_SERVICE_H

#include "cJSON.h"
#include <event2/event.h>

typedef struct {
    char *kind;      /* "at", "every", "cron" */
    long at_ms;      /* For "at": unix ms */
    long every_ms;   /* For "every": interval ms */
    char *expr;      /* For "cron": expression */
    char *tz;
} sc_cron_schedule_t;

typedef struct {
    char *kind;      /* "agent_turn" */
    char *message;
    int deliver;
    char *channel;
    char *to;
} sc_cron_payload_t;

typedef struct {
    long next_run_ms;
    long last_run_ms;
    char *last_status;
    char *last_error;
} sc_cron_job_state_t;

typedef struct {
    char *id;
    char *name;
    int enabled;
    sc_cron_schedule_t schedule;
    sc_cron_payload_t payload;
    sc_cron_job_state_t state;
    long created_ms;
    long updated_ms;
    int delete_after_run;
} sc_cron_job_t;

/* Callback when a job fires */
typedef char *(*sc_cron_handler_t)(sc_cron_job_t *job, void *ctx);

typedef struct {
    char *store_path;
    sc_cron_job_t **jobs;
    int job_count;
    int job_cap;
    struct event *timer_event;
    struct event_base *base;
    sc_cron_handler_t handler;
    void *handler_ctx;
    volatile int running;
} sc_cron_service_t;

sc_cron_service_t *sc_cron_service_new(const char *store_path, struct event_base *base);
void sc_cron_service_free(sc_cron_service_t *cs);

int sc_cron_service_start(sc_cron_service_t *cs);
void sc_cron_service_stop(sc_cron_service_t *cs);

void sc_cron_service_set_handler(sc_cron_service_t *cs, sc_cron_handler_t handler, void *ctx);

sc_cron_job_t *sc_cron_service_add_job(sc_cron_service_t *cs, const char *name,
                                        sc_cron_schedule_t schedule,
                                        const char *message, int deliver,
                                        const char *channel, const char *to);
int sc_cron_service_remove_job(sc_cron_service_t *cs, const char *id);
sc_cron_job_t **sc_cron_service_list_jobs(sc_cron_service_t *cs, int *out_count);

#endif /* SC_CRON_SERVICE_H */
