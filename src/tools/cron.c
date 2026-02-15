/*
 * tools/cron.c - Cron scheduling tool for LLM
 *
 * Lets the agent schedule, list, and remove timed jobs.
 * Actions: add, list, remove.
 */

#include <stdlib.h>
#include <string.h>

#include "tools/cron.h"
#include "tools/types.h"
#include "util/str.h"
#include "util/json_helpers.h"
#include "logger.h"
#include "cJSON.h"

typedef struct {
    sc_cron_service_t *svc;
} cron_tool_data_t;

static void cron_destroy(sc_tool_t *self)
{
    if (!self) return;
    free(self->data);
    free(self);
}

static cJSON *cron_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "object");

    cJSON *props = cJSON_AddObjectToObject(schema, "properties");

    cJSON *action = cJSON_AddObjectToObject(props, "action");
    cJSON_AddStringToObject(action, "type", "string");
    cJSON_AddStringToObject(action, "description",
        "Action to perform: 'add', 'list', or 'remove'");
    cJSON *action_enum = cJSON_AddArrayToObject(action, "enum");
    cJSON_AddItemToArray(action_enum, cJSON_CreateString("add"));
    cJSON_AddItemToArray(action_enum, cJSON_CreateString("list"));
    cJSON_AddItemToArray(action_enum, cJSON_CreateString("remove"));

    cJSON *name = cJSON_AddObjectToObject(props, "name");
    cJSON_AddStringToObject(name, "type", "string");
    cJSON_AddStringToObject(name, "description",
        "Job name/description (required for 'add')");

    cJSON *sched_type = cJSON_AddObjectToObject(props, "schedule_type");
    cJSON_AddStringToObject(sched_type, "type", "string");
    cJSON_AddStringToObject(sched_type, "description",
        "Schedule type: 'at' (one-time, seconds from now), "
        "'every' (recurring, interval in seconds)");

    cJSON *seconds = cJSON_AddObjectToObject(props, "seconds");
    cJSON_AddStringToObject(seconds, "type", "number");
    cJSON_AddStringToObject(seconds, "description",
        "Seconds from now (for 'at') or interval seconds (for 'every')");

    cJSON *message = cJSON_AddObjectToObject(props, "message");
    cJSON_AddStringToObject(message, "type", "string");
    cJSON_AddStringToObject(message, "description",
        "Message/prompt for the job to deliver (required for 'add')");

    cJSON *job_id = cJSON_AddObjectToObject(props, "job_id");
    cJSON_AddStringToObject(job_id, "type", "string");
    cJSON_AddStringToObject(job_id, "description",
        "Job ID (required for 'remove')");

    cJSON *req = cJSON_AddArrayToObject(schema, "required");
    cJSON_AddItemToArray(req, cJSON_CreateString("action"));
    return schema;
}

static sc_tool_result_t *do_add(sc_cron_service_t *svc, cJSON *args)
{
    const char *name = sc_json_get_string(args, "name", NULL);
    if (!name) return sc_tool_result_error("'name' is required for add");

    const char *message = sc_json_get_string(args, "message", NULL);
    if (!message) return sc_tool_result_error("'message' is required for add");

    const char *sched_type = sc_json_get_string(args, "schedule_type", "at");
    double seconds = sc_json_get_double(args, "seconds", 0);

    if (seconds <= 0)
        return sc_tool_result_error("'seconds' must be a positive number");

    sc_cron_schedule_t schedule = {0};
    if (strcmp(sched_type, "every") == 0) {
        schedule.kind = "every";
        schedule.every_ms = (long)(seconds * 1000);
    } else {
        /* Default: "at" (one-time) */
        schedule.kind = "at";
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        long now = (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
        schedule.at_ms = now + (long)(seconds * 1000);
    }

    sc_cron_job_t *job = sc_cron_service_add_job(svc, name, schedule,
                                                  message, 1, "", "");
    if (!job) return sc_tool_result_error("Failed to create cron job");

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "Job created: id=%s, name=%s, type=%s, seconds=%.0f",
                       job->id, name, sched_type, seconds);
    char *result = sc_strbuf_finish(&sb);
    sc_tool_result_t *r = sc_tool_result_new(result);
    free(result);
    return r;
}

static sc_tool_result_t *do_list(sc_cron_service_t *svc)
{
    int count = 0;
    sc_cron_job_t **jobs = sc_cron_service_list_jobs(svc, &count);

    if (count == 0)
        return sc_tool_result_new("No scheduled jobs.");

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%d job(s):\n", count);

    for (int i = 0; i < count; i++) {
        sc_cron_job_t *j = jobs[i];
        sc_strbuf_appendf(&sb, "  [%s] %s - %s, enabled=%s",
                           j->id, j->name ? j->name : "(unnamed)",
                           j->schedule.kind ? j->schedule.kind : "?",
                           j->enabled ? "yes" : "no");
        if (j->payload.message)
            sc_strbuf_appendf(&sb, ", message=\"%.60s\"", j->payload.message);
        sc_strbuf_append(&sb, "\n");
    }

    char *result = sc_strbuf_finish(&sb);
    sc_tool_result_t *r = sc_tool_result_new(result);
    free(result);
    return r;
}

static sc_tool_result_t *do_remove(sc_cron_service_t *svc, cJSON *args)
{
    const char *job_id = sc_json_get_string(args, "job_id", NULL);
    if (!job_id) return sc_tool_result_error("'job_id' is required for remove");

    int removed = sc_cron_service_remove_job(svc, job_id);
    if (removed)
        return sc_tool_result_new("Job removed.");
    else
        return sc_tool_result_error("Job not found.");
}

static sc_tool_result_t *cron_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    cron_tool_data_t *d = self->data;

    if (!d->svc) return sc_tool_result_error("Cron service not available");

    const char *action = sc_json_get_string(args, "action", NULL);
    if (!action) return sc_tool_result_error("'action' is required");

    if (strcmp(action, "add") == 0)
        return do_add(d->svc, args);
    else if (strcmp(action, "list") == 0)
        return do_list(d->svc);
    else if (strcmp(action, "remove") == 0)
        return do_remove(d->svc, args);
    else
        return sc_tool_result_error("Unknown action. Use 'add', 'list', or 'remove'.");
}

sc_tool_t *sc_tool_cron_new(sc_cron_service_t *cron_svc)
{
    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    cron_tool_data_t *d = calloc(1, sizeof(*d));
    if (!d) { free(t); return NULL; }
    d->svc = cron_svc;

    t->name = "cron";
    t->description = "Schedule, list, or remove timed jobs. "
                     "Use action 'add' to schedule a reminder or recurring task, "
                     "'list' to see all jobs, 'remove' to delete a job by ID.";
    t->parameters = cron_parameters;
    t->execute = cron_execute;
    t->destroy = cron_destroy;
    t->data = d;
    return t;
}
