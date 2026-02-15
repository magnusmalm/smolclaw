/*
 * smolclaw - cron service
 * Periodic job scheduling. Loads/saves jobs from JSON, checks every second.
 */

#include "cron/service.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <libgen.h>

#include "logger.h"
#include "util/str.h"
#include "util/uuid.h"
#include "util/json_helpers.h"

/* --- Forward declarations --- */
static int load_store(sc_cron_service_t *cs);
static int save_store(sc_cron_service_t *cs);
static long compute_next_run(sc_cron_schedule_t *sched, long now_ms);
static void recompute_next_runs(sc_cron_service_t *cs);
static void check_jobs(sc_cron_service_t *cs);
static void free_job(sc_cron_job_t *job);
static void timer_callback(evutil_socket_t fd, short what, void *arg);

/* --- Helpers --- */

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void ensure_dir(const char *path)
{
    char *tmp = sc_strdup(path);
    if (!tmp) return;
    char *dir = dirname(tmp);
    if (dir) {
        /* Simple mkdir -p for one level */
        mkdir(dir, 0755);
    }
    free(tmp);
}

/* --- Timer --- */

static void timer_callback(evutil_socket_t fd, short what, void *arg)
{
    (void)fd; (void)what;
    sc_cron_service_t *cs = arg;
    if (cs->running) {
        check_jobs(cs);
    }
}

/* --- Public API --- */

sc_cron_service_t *sc_cron_service_new(const char *store_path, struct event_base *base)
{
    sc_cron_service_t *cs = calloc(1, sizeof(*cs));
    if (!cs) return NULL;

    cs->store_path = sc_strdup(store_path);
    cs->base = base;
    cs->jobs = NULL;
    cs->job_count = 0;
    cs->job_cap = 0;
    cs->handler = NULL;
    cs->handler_ctx = NULL;
    cs->running = 0;
    cs->timer_event = NULL;

    /* Load existing jobs */
    load_store(cs);

    return cs;
}

void sc_cron_service_free(sc_cron_service_t *cs)
{
    if (!cs) return;

    sc_cron_service_stop(cs);

    for (int i = 0; i < cs->job_count; i++) {
        free_job(cs->jobs[i]);
        free(cs->jobs[i]);
    }
    free(cs->jobs);
    free(cs->store_path);
    free(cs);
}

int sc_cron_service_start(sc_cron_service_t *cs)
{
    if (!cs || cs->running) return 0;

    load_store(cs);
    recompute_next_runs(cs);
    save_store(cs);

    cs->running = 1;

    /* Create 1-second periodic timer via libevent */
    if (cs->base) {
        struct timeval one_sec = { .tv_sec = 1, .tv_usec = 0 };
        cs->timer_event = event_new(cs->base, -1, EV_PERSIST, timer_callback, cs);
        if (cs->timer_event) {
            event_add(cs->timer_event, &one_sec);
        }
    }

    SC_LOG_INFO("cron", "Cron service started with %d jobs", cs->job_count);
    return 0;
}

void sc_cron_service_stop(sc_cron_service_t *cs)
{
    if (!cs || !cs->running) return;

    cs->running = 0;

    if (cs->timer_event) {
        event_del(cs->timer_event);
        event_free(cs->timer_event);
        cs->timer_event = NULL;
    }

    SC_LOG_INFO("cron", "Cron service stopped");
}

void sc_cron_service_set_handler(sc_cron_service_t *cs, sc_cron_handler_t handler, void *ctx)
{
    if (!cs) return;
    cs->handler = handler;
    cs->handler_ctx = ctx;
}

sc_cron_job_t *sc_cron_service_add_job(sc_cron_service_t *cs, const char *name,
                                        sc_cron_schedule_t schedule,
                                        const char *message, int deliver,
                                        const char *channel, const char *to)
{
    if (!cs) return NULL;

    long now = now_ms();

    sc_cron_job_t *job = calloc(1, sizeof(*job));
    if (!job) return NULL;

    job->id = sc_generate_id();
    job->name = sc_strdup(name);
    job->enabled = 1;
    job->schedule = (sc_cron_schedule_t){
        .kind = sc_strdup(schedule.kind),
        .at_ms = schedule.at_ms,
        .every_ms = schedule.every_ms,
        .expr = sc_strdup(schedule.expr),
        .tz = sc_strdup(schedule.tz),
    };
    job->payload = (sc_cron_payload_t){
        .kind = sc_strdup("agent_turn"),
        .message = sc_strdup(message),
        .deliver = deliver,
        .channel = sc_strdup(channel),
        .to = sc_strdup(to),
    };
    job->state.next_run_ms = compute_next_run(&job->schedule, now);
    job->state.last_run_ms = 0;
    job->state.last_status = NULL;
    job->state.last_error = NULL;
    job->created_ms = now;
    job->updated_ms = now;
    job->delete_after_run = (schedule.kind && strcmp(schedule.kind, "at") == 0);

    /* Add to array */
    if (cs->job_count >= cs->job_cap) {
        cs->job_cap = cs->job_cap ? cs->job_cap * 2 : 8;
        cs->jobs = realloc(cs->jobs, cs->job_cap * sizeof(sc_cron_job_t *));
    }
    cs->jobs[cs->job_count++] = job;

    save_store(cs);

    SC_LOG_INFO("cron", "Added job '%s' (id=%s)", name, job->id);
    return job;
}

int sc_cron_service_remove_job(sc_cron_service_t *cs, const char *id)
{
    if (!cs || !id) return 0;

    for (int i = 0; i < cs->job_count; i++) {
        if (cs->jobs[i] && cs->jobs[i]->id && strcmp(cs->jobs[i]->id, id) == 0) {
            free_job(cs->jobs[i]);
            free(cs->jobs[i]);

            /* Shift remaining */
            for (int j = i; j < cs->job_count - 1; j++) {
                cs->jobs[j] = cs->jobs[j + 1];
            }
            cs->job_count--;

            save_store(cs);
            SC_LOG_INFO("cron", "Removed job %s", id);
            return 1;
        }
    }
    return 0;
}

sc_cron_job_t **sc_cron_service_list_jobs(sc_cron_service_t *cs, int *out_count)
{
    if (!cs) { *out_count = 0; return NULL; }
    *out_count = cs->job_count;
    return cs->jobs;
}

/* --- Internal --- */

static void free_job(sc_cron_job_t *job)
{
    if (!job) return;
    free(job->id);
    free(job->name);
    free(job->schedule.kind);
    free(job->schedule.expr);
    free(job->schedule.tz);
    free(job->payload.kind);
    free(job->payload.message);
    free(job->payload.channel);
    free(job->payload.to);
    free(job->state.last_status);
    free(job->state.last_error);
}

static long compute_next_run(sc_cron_schedule_t *sched, long now)
{
    if (!sched || !sched->kind) return 0;

    if (strcmp(sched->kind, "at") == 0) {
        return (sched->at_ms > now) ? sched->at_ms : 0;
    }

    if (strcmp(sched->kind, "every") == 0) {
        if (sched->every_ms <= 0) return 0;
        return now + sched->every_ms;
    }

    /* "cron" expressions would need a cron parser - not implemented in C version.
     * For simplicity, treat as disabled. */
    if (strcmp(sched->kind, "cron") == 0) {
        SC_LOG_WARN("cron", "Cron expressions not yet implemented");
        return 0;
    }

    return 0;
}

static void recompute_next_runs(sc_cron_service_t *cs)
{
    long now = now_ms();
    for (int i = 0; i < cs->job_count; i++) {
        if (cs->jobs[i]->enabled) {
            cs->jobs[i]->state.next_run_ms = compute_next_run(&cs->jobs[i]->schedule, now);
        }
    }
}

static void check_jobs(sc_cron_service_t *cs)
{
    long now = now_ms();

    for (int i = 0; i < cs->job_count; i++) {
        sc_cron_job_t *job = cs->jobs[i];
        if (!job->enabled) continue;
        if (job->state.next_run_ms == 0) continue;
        if (job->state.next_run_ms > now) continue;

        /* Job is due */
        SC_LOG_INFO("cron", "Executing job '%s' (id=%s)", job->name, job->id);

        long start = now_ms();
        char *result = NULL;
        if (cs->handler) {
            result = cs->handler(job, cs->handler_ctx);
        }

        job->state.last_run_ms = start;
        job->updated_ms = now_ms();

        free(job->state.last_status);
        free(job->state.last_error);
        job->state.last_status = sc_strdup("ok");
        job->state.last_error = NULL;

        /* Schedule next run or disable */
        if (job->schedule.kind && strcmp(job->schedule.kind, "at") == 0) {
            if (job->delete_after_run) {
                sc_cron_service_remove_job(cs, job->id);
                free(result);
                return; /* Array was modified */
            }
            job->enabled = 0;
            job->state.next_run_ms = 0;
        } else {
            job->state.next_run_ms = compute_next_run(&job->schedule, now_ms());
        }

        save_store(cs);
        free(result);
    }
}

/* --- JSON Persistence --- */

static int load_store(sc_cron_service_t *cs)
{
    cJSON *root = sc_json_load_file(cs->store_path);
    if (!root) return 0; /* File doesn't exist yet, that's fine */

    cJSON *jobs_arr = sc_json_get_array(root, "jobs");
    if (!jobs_arr) { cJSON_Delete(root); return 0; }

    int n = cJSON_GetArraySize(jobs_arr);
    for (int i = 0; i < n; i++) {
        cJSON *item = cJSON_GetArrayItem(jobs_arr, i);
        if (!item) continue;

        sc_cron_job_t *job = calloc(1, sizeof(*job));
        if (!job) continue;

        job->id = sc_strdup(sc_json_get_string(item, "id", ""));
        job->name = sc_strdup(sc_json_get_string(item, "name", ""));
        job->enabled = sc_json_get_bool(item, "enabled", 1);
        job->created_ms = (long)sc_json_get_double(item, "createdAtMs", 0);
        job->updated_ms = (long)sc_json_get_double(item, "updatedAtMs", 0);
        job->delete_after_run = sc_json_get_bool(item, "deleteAfterRun", 0);

        /* Schedule */
        cJSON *sched = sc_json_get_object(item, "schedule");
        if (sched) {
            job->schedule.kind = sc_strdup(sc_json_get_string(sched, "kind", ""));
            job->schedule.at_ms = (long)sc_json_get_double(sched, "atMs", 0);
            job->schedule.every_ms = (long)sc_json_get_double(sched, "everyMs", 0);
            job->schedule.expr = sc_strdup(sc_json_get_string(sched, "expr", ""));
            job->schedule.tz = sc_strdup(sc_json_get_string(sched, "tz", ""));
        }

        /* Payload */
        cJSON *payload = sc_json_get_object(item, "payload");
        if (payload) {
            job->payload.kind = sc_strdup(sc_json_get_string(payload, "kind", ""));
            job->payload.message = sc_strdup(sc_json_get_string(payload, "message", ""));
            job->payload.deliver = sc_json_get_bool(payload, "deliver", 0);
            job->payload.channel = sc_strdup(sc_json_get_string(payload, "channel", ""));
            job->payload.to = sc_strdup(sc_json_get_string(payload, "to", ""));
        }

        /* State */
        cJSON *state = sc_json_get_object(item, "state");
        if (state) {
            job->state.next_run_ms = (long)sc_json_get_double(state, "nextRunAtMs", 0);
            job->state.last_run_ms = (long)sc_json_get_double(state, "lastRunAtMs", 0);
            job->state.last_status = sc_strdup(sc_json_get_string(state, "lastStatus", ""));
            job->state.last_error = sc_strdup(sc_json_get_string(state, "lastError", ""));
        }

        /* Add to array */
        if (cs->job_count >= cs->job_cap) {
            cs->job_cap = cs->job_cap ? cs->job_cap * 2 : 8;
            cs->jobs = realloc(cs->jobs, cs->job_cap * sizeof(sc_cron_job_t *));
        }
        cs->jobs[cs->job_count++] = job;
    }

    cJSON_Delete(root);
    return 0;
}

static int save_store(sc_cron_service_t *cs)
{
    ensure_dir(cs->store_path);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "version", 1);

    cJSON *jobs_arr = cJSON_CreateArray();
    for (int i = 0; i < cs->job_count; i++) {
        sc_cron_job_t *job = cs->jobs[i];
        cJSON *item = cJSON_CreateObject();

        cJSON_AddStringToObject(item, "id", job->id ? job->id : "");
        cJSON_AddStringToObject(item, "name", job->name ? job->name : "");
        cJSON_AddBoolToObject(item, "enabled", job->enabled);
        cJSON_AddNumberToObject(item, "createdAtMs", (double)job->created_ms);
        cJSON_AddNumberToObject(item, "updatedAtMs", (double)job->updated_ms);
        cJSON_AddBoolToObject(item, "deleteAfterRun", job->delete_after_run);

        /* Schedule */
        cJSON *sched = cJSON_CreateObject();
        cJSON_AddStringToObject(sched, "kind", job->schedule.kind ? job->schedule.kind : "");
        if (job->schedule.at_ms) cJSON_AddNumberToObject(sched, "atMs", (double)job->schedule.at_ms);
        if (job->schedule.every_ms) cJSON_AddNumberToObject(sched, "everyMs", (double)job->schedule.every_ms);
        if (job->schedule.expr) cJSON_AddStringToObject(sched, "expr", job->schedule.expr);
        if (job->schedule.tz) cJSON_AddStringToObject(sched, "tz", job->schedule.tz);
        cJSON_AddItemToObject(item, "schedule", sched);

        /* Payload */
        cJSON *payload = cJSON_CreateObject();
        cJSON_AddStringToObject(payload, "kind", job->payload.kind ? job->payload.kind : "");
        cJSON_AddStringToObject(payload, "message", job->payload.message ? job->payload.message : "");
        cJSON_AddBoolToObject(payload, "deliver", job->payload.deliver);
        if (job->payload.channel) cJSON_AddStringToObject(payload, "channel", job->payload.channel);
        if (job->payload.to) cJSON_AddStringToObject(payload, "to", job->payload.to);
        cJSON_AddItemToObject(item, "payload", payload);

        /* State */
        cJSON *st = cJSON_CreateObject();
        if (job->state.next_run_ms) cJSON_AddNumberToObject(st, "nextRunAtMs", (double)job->state.next_run_ms);
        if (job->state.last_run_ms) cJSON_AddNumberToObject(st, "lastRunAtMs", (double)job->state.last_run_ms);
        if (job->state.last_status) cJSON_AddStringToObject(st, "lastStatus", job->state.last_status);
        if (job->state.last_error) cJSON_AddStringToObject(st, "lastError", job->state.last_error);
        cJSON_AddItemToObject(item, "state", st);

        cJSON_AddItemToArray(jobs_arr, item);
    }

    cJSON_AddItemToObject(root, "jobs", jobs_arr);

    int ret = sc_json_save_file(cs->store_path, root);
    cJSON_Delete(root);
    return ret;
}
