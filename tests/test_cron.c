/*
 * smolclaw - cron service tests
 * Tests job CRUD, handler firing via libevent timer, "at" job auto-deletion,
 * and JSON persistence round-trip.
 */

#include "test_main.h"
#include "cron/service.h"
#include "util/str.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <event2/event.h>

/* --- Mock handler --- */

static int handler_called;
static char *handler_job_message;

static char *test_handler(sc_cron_job_t *job, void *ctx)
{
    (void)ctx;
    handler_called++;
    free(handler_job_message);
    handler_job_message = job->payload.message
        ? sc_strdup(job->payload.message) : NULL;
    return sc_strdup("ok");
}

static void cleanup_dir(const char *dir)
{
    sc_strbuf_t p;
    sc_strbuf_init(&p);
    sc_strbuf_appendf(&p, "rm -rf %s", dir);
    char *cmd = sc_strbuf_finish(&p);
    system(cmd);
    free(cmd);
}

/* --- Tests --- */

static void test_cron_add_list_remove(void)
{
    char tmpdir[] = "/tmp/sc_test_cron_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/cron.json", tmpdir);
    char *store = sc_strbuf_finish(&sb);

    struct event_base *base = event_base_new();
    sc_cron_service_t *cs = sc_cron_service_new(store, base);
    ASSERT_NOT_NULL(cs);

    /* Initially no jobs */
    int count = 0;
    sc_cron_service_list_jobs(cs, &count);
    ASSERT_INT_EQ(count, 0);

    /* Add an "every" job */
    sc_cron_schedule_t sched = { .kind = "every", .every_ms = 60000 };
    sc_cron_job_t *job = sc_cron_service_add_job(cs, "test-job", sched,
                                                   "test message", 0, NULL, NULL);
    ASSERT_NOT_NULL(job);
    ASSERT_NOT_NULL(job->id);
    ASSERT_STR_EQ(job->name, "test-job");
    ASSERT_INT_EQ(job->enabled, 1);
    ASSERT_INT_EQ(job->delete_after_run, 0); /* "every" jobs don't auto-delete */

    /* List should have 1 job */
    sc_cron_service_list_jobs(cs, &count);
    ASSERT_INT_EQ(count, 1);

    /* Add a second job */
    sc_cron_schedule_t sched2 = { .kind = "at", .at_ms = 9999999999L };
    sc_cron_job_t *job2 = sc_cron_service_add_job(cs, "at-job", sched2,
                                                    "at message", 0, NULL, NULL);
    ASSERT_NOT_NULL(job2);
    ASSERT_INT_EQ(job2->delete_after_run, 1); /* "at" jobs auto-delete */

    sc_cron_service_list_jobs(cs, &count);
    ASSERT_INT_EQ(count, 2);

    /* Remove first job by ID */
    char *id_copy = sc_strdup(job->id);
    int removed = sc_cron_service_remove_job(cs, id_copy);
    ASSERT_INT_EQ(removed, 1);
    free(id_copy);

    sc_cron_service_list_jobs(cs, &count);
    ASSERT_INT_EQ(count, 1);

    /* Remove nonexistent job */
    removed = sc_cron_service_remove_job(cs, "nonexistent-id");
    ASSERT_INT_EQ(removed, 0);

    sc_cron_service_free(cs);
    event_base_free(base);
    free(store);
    cleanup_dir(tmpdir);
}

static void test_cron_every_job_fires(void)
{
    char tmpdir[] = "/tmp/sc_test_cron_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/cron.json", tmpdir);
    char *store = sc_strbuf_finish(&sb);

    struct event_base *base = event_base_new();
    sc_cron_service_t *cs = sc_cron_service_new(store, base);
    ASSERT_NOT_NULL(cs);

    handler_called = 0;
    free(handler_job_message);
    handler_job_message = NULL;
    sc_cron_service_set_handler(cs, test_handler, NULL);

    /* Start FIRST, then add job (avoids double-load from start's load_store) */
    sc_cron_service_start(cs);

    /* Add "every" job with 1ms interval — fires on first check_jobs() */
    sc_cron_schedule_t sched = { .kind = "every", .every_ms = 1 };
    sc_cron_job_t *job = sc_cron_service_add_job(cs, "fast-job", sched,
                                                   "hello from cron", 0, NULL, NULL);
    ASSERT_NOT_NULL(job);

    /* Run event loop ~1.5s — cron timer fires every 1s */
    struct timeval tv = { .tv_sec = 1, .tv_usec = 500000 };
    event_base_loopexit(base, &tv);
    event_base_dispatch(base);

    ASSERT(handler_called > 0, "Handler should have been called");
    ASSERT_NOT_NULL(handler_job_message);
    ASSERT_STR_EQ(handler_job_message, "hello from cron");

    /* Job should still be present (every jobs repeat) */
    int count = 0;
    sc_cron_service_list_jobs(cs, &count);
    ASSERT_INT_EQ(count, 1);

    /* State should be updated */
    ASSERT(job->state.last_run_ms > 0, "last_run_ms should be set");
    ASSERT_NOT_NULL(job->state.last_status);
    ASSERT_STR_EQ(job->state.last_status, "ok");

    sc_cron_service_free(cs);
    event_base_free(base);
    free(store);
    free(handler_job_message);
    handler_job_message = NULL;
    cleanup_dir(tmpdir);
}

static void test_cron_at_job_deletes(void)
{
    char tmpdir[] = "/tmp/sc_test_cron_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/cron.json", tmpdir);
    char *store = sc_strbuf_finish(&sb);

    struct event_base *base = event_base_new();
    sc_cron_service_t *cs = sc_cron_service_new(store, base);
    ASSERT_NOT_NULL(cs);

    handler_called = 0;
    free(handler_job_message);
    handler_job_message = NULL;
    sc_cron_service_set_handler(cs, test_handler, NULL);

    /* Start FIRST, then add job (avoids double-load from start's load_store) */
    sc_cron_service_start(cs);

    /* Add "at" job scheduled 1ms in the future (will be past by timer fire) */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    long now = (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;

    sc_cron_schedule_t sched = { .kind = "at", .at_ms = now + 1 };
    sc_cron_job_t *job = sc_cron_service_add_job(cs, "once-job", sched,
                                                   "fire once", 0, NULL, NULL);
    ASSERT_NOT_NULL(job);
    ASSERT_INT_EQ(job->delete_after_run, 1);

    int count = 0;
    sc_cron_service_list_jobs(cs, &count);
    ASSERT_INT_EQ(count, 1);

    /* Run event loop ~1.5s */
    struct timeval tv = { .tv_sec = 1, .tv_usec = 500000 };
    event_base_loopexit(base, &tv);
    event_base_dispatch(base);

    ASSERT(handler_called > 0, "At-job handler should have been called");
    ASSERT_STR_EQ(handler_job_message, "fire once");

    /* Job should be auto-deleted (delete_after_run = 1) */
    sc_cron_service_list_jobs(cs, &count);
    ASSERT_INT_EQ(count, 0);

    sc_cron_service_free(cs);
    event_base_free(base);
    free(store);
    free(handler_job_message);
    handler_job_message = NULL;
    cleanup_dir(tmpdir);
}

static void test_cron_persistence(void)
{
    char tmpdir[] = "/tmp/sc_test_cron_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/cron.json", tmpdir);
    char *store = sc_strbuf_finish(&sb);

    /* Create service and add jobs */
    {
        struct event_base *base = event_base_new();
        sc_cron_service_t *cs = sc_cron_service_new(store, base);
        ASSERT_NOT_NULL(cs);

        sc_cron_schedule_t s1 = { .kind = "every", .every_ms = 3600000 };
        sc_cron_job_t *j1 = sc_cron_service_add_job(cs, "hourly", s1,
                                                       "hourly msg", 1, "telegram", "12345");
        ASSERT_NOT_NULL(j1);

        sc_cron_schedule_t s2 = { .kind = "every", .every_ms = 60000 };
        sc_cron_job_t *j2 = sc_cron_service_add_job(cs, "minutely", s2,
                                                       "minute msg", 0, NULL, NULL);
        ASSERT_NOT_NULL(j2);

        int count = 0;
        sc_cron_service_list_jobs(cs, &count);
        ASSERT_INT_EQ(count, 2);

        sc_cron_service_free(cs);
        event_base_free(base);
    }

    /* Recreate from same store path — should load saved jobs */
    {
        struct event_base *base = event_base_new();
        sc_cron_service_t *cs = sc_cron_service_new(store, base);
        ASSERT_NOT_NULL(cs);

        int count = 0;
        sc_cron_job_t **jobs = sc_cron_service_list_jobs(cs, &count);
        ASSERT_INT_EQ(count, 2);
        ASSERT_NOT_NULL(jobs);

        /* Verify first job's data persisted */
        ASSERT_STR_EQ(jobs[0]->name, "hourly");
        ASSERT_STR_EQ(jobs[0]->schedule.kind, "every");
        ASSERT(jobs[0]->schedule.every_ms == 3600000,
               "every_ms should be 3600000");
        ASSERT_STR_EQ(jobs[0]->payload.message, "hourly msg");
        ASSERT_INT_EQ(jobs[0]->payload.deliver, 1);
        ASSERT_STR_EQ(jobs[0]->payload.channel, "telegram");
        ASSERT_STR_EQ(jobs[0]->payload.to, "12345");

        /* Second job */
        ASSERT_STR_EQ(jobs[1]->name, "minutely");

        sc_cron_service_free(cs);
        event_base_free(base);
    }

    free(store);
    cleanup_dir(tmpdir);
}

static void test_cron_null_safety(void)
{
    /* NULL service should not crash */
    sc_cron_service_free(NULL);
    sc_cron_service_stop(NULL);
    sc_cron_service_set_handler(NULL, NULL, NULL);

    int removed = sc_cron_service_remove_job(NULL, "test");
    ASSERT_INT_EQ(removed, 0);

    int count = 0;
    sc_cron_job_t **jobs = sc_cron_service_list_jobs(NULL, &count);
    ASSERT_INT_EQ(count, 0);
    ASSERT_NULL(jobs);

    /* NULL id should not crash */
    char tmpdir[] = "/tmp/sc_test_cron_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/cron.json", tmpdir);
    char *store = sc_strbuf_finish(&sb);

    struct event_base *base = event_base_new();
    sc_cron_service_t *cs = sc_cron_service_new(store, base);
    removed = sc_cron_service_remove_job(cs, NULL);
    ASSERT_INT_EQ(removed, 0);

    sc_cron_service_free(cs);
    event_base_free(base);
    free(store);
    cleanup_dir(tmpdir);
}

int main(void)
{
    printf("test_cron\n");

    RUN_TEST(test_cron_add_list_remove);
    RUN_TEST(test_cron_every_job_fires);
    RUN_TEST(test_cron_at_job_deletes);
    RUN_TEST(test_cron_persistence);
    RUN_TEST(test_cron_null_safety);

    TEST_REPORT();
}
