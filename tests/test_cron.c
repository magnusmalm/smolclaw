/*
 * smolclaw - cron service tests
 * Tests job CRUD, handler firing via libevent timer, "at" job auto-deletion,
 * and JSON persistence round-trip.
 */

#include "test_main.h"
#include "cron/service.h"
#include "cron/cron_parse.h"
#include "util/str.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
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
    sc_cron_schedule_t sched2 = { .kind = "at", .at_ms = 2000000000L };
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

/* --- cron expression parser (task 2.9) --- */

/* A fixed UTC reference: 2026-01-01 00:00:00 UTC (divisible by 60). All
 * expression tests use tz="UTC" and verify via gmtime_r so they are
 * independent of the host's local timezone. */
#define CRON_REF 1767225600L

static void test_cron_parse_daily(void)
{
    sc_cron_expr_t e;
    ASSERT_INT_EQ(sc_cron_parse("0 9 * * *", &e), 0);

    long next = sc_cron_next_after(&e, CRON_REF, "UTC");
    ASSERT(next > CRON_REF, "next must be after the reference");
    ASSERT(next <= CRON_REF + 24L * 3600, "daily job within 24h");

    time_t tt = (time_t)next;
    struct tm tm;
    gmtime_r(&tt, &tm);
    ASSERT_INT_EQ(tm.tm_hour, 9);
    ASSERT_INT_EQ(tm.tm_min, 0);
    ASSERT_INT_EQ(tm.tm_sec, 0);
}

static void test_cron_parse_weekly(void)
{
    sc_cron_expr_t e;
    ASSERT_INT_EQ(sc_cron_parse("30 14 * * 1", &e), 0);  /* Mondays 14:30 */

    long next = sc_cron_next_after(&e, CRON_REF, "UTC");
    ASSERT(next > CRON_REF, "after");
    ASSERT(next <= CRON_REF + 8L * 24 * 3600, "within a week");

    time_t tt = (time_t)next;
    struct tm tm;
    gmtime_r(&tt, &tm);
    ASSERT_INT_EQ(tm.tm_wday, 1);   /* Monday */
    ASSERT_INT_EQ(tm.tm_hour, 14);
    ASSERT_INT_EQ(tm.tm_min, 30);
}

static void test_cron_parse_interval(void)
{
    sc_cron_expr_t e;
    ASSERT_INT_EQ(sc_cron_parse("*/15 * * * *", &e), 0);
    ASSERT(e.minute[0] && e.minute[15] && e.minute[30] && e.minute[45],
           "quarter-hour minutes set");
    ASSERT(!e.minute[1] && !e.minute[16], "non-quarter minutes unset");

    /* CRON_REF is on a :00 boundary → next match is +15 min. */
    long next = sc_cron_next_after(&e, CRON_REF, "UTC");
    ASSERT(next == CRON_REF + 15 * 60, "next quarter hour is 15 min later");
}

static void test_cron_parse_sunday7(void)
{
    sc_cron_expr_t e;
    ASSERT_INT_EQ(sc_cron_parse("0 0 * * 7", &e), 0);  /* 7 == Sunday */
    ASSERT(e.dow[0], "dow 7 maps to Sunday (0)");
    ASSERT(!e.dow_star, "dow is restricted");
}

static void test_cron_parse_invalid(void)
{
    sc_cron_expr_t e;
    ASSERT_INT_EQ(sc_cron_parse("0 9 * *", &e), -1);      /* 4 fields */
    ASSERT_INT_EQ(sc_cron_parse("0 9 * * * *", &e), -1);  /* 6 fields */
    ASSERT_INT_EQ(sc_cron_parse("60 9 * * *", &e), -1);   /* minute > 59 */
    ASSERT_INT_EQ(sc_cron_parse("0 24 * * *", &e), -1);   /* hour > 23 */
    ASSERT_INT_EQ(sc_cron_parse("0 9 32 * *", &e), -1);   /* dom > 31 */
    ASSERT_INT_EQ(sc_cron_parse("0 9 * 13 *", &e), -1);   /* month > 12 */
    ASSERT_INT_EQ(sc_cron_parse("0 9 * * 8", &e), -1);    /* dow > 7 */
    ASSERT_INT_EQ(sc_cron_parse("abc 9 * * *", &e), -1);  /* non-numeric */
    ASSERT_INT_EQ(sc_cron_parse("", &e), -1);             /* empty */
}

static void test_cron_parse_impossible_date(void)
{
    sc_cron_expr_t e;
    /* Feb 31 never occurs → no match within the one-year search bound. */
    ASSERT_INT_EQ(sc_cron_parse("0 0 31 2 *", &e), 0);
    ASSERT(sc_cron_next_after(&e, CRON_REF, "UTC") == -1,
           "impossible date yields no next run");
}

/* The cron *kind* is re-enabled end-to-end: adding a job computes next_run. */
static void test_cron_kind_enabled_in_service(void)
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

    sc_cron_schedule_t sched = {
        .kind = "cron", .expr = "0 9 * * *", .tz = "UTC"
    };
    sc_cron_job_t *job = sc_cron_service_add_job(cs, "daily", sched,
                                                 "morning", 0, NULL, NULL);
    ASSERT_NOT_NULL(job);
    ASSERT(job->state.next_run_ms > 0, "cron job has a computed next_run (enabled)");

    /* An invalid expression disables the job (next_run == 0). */
    sc_cron_schedule_t bad = { .kind = "cron", .expr = "nope", .tz = "UTC" };
    sc_cron_job_t *job2 = sc_cron_service_add_job(cs, "bad", bad,
                                                  "x", 0, NULL, NULL);
    ASSERT_NOT_NULL(job2);
    ASSERT_INT_EQ((int)job2->state.next_run_ms, 0);

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
    RUN_TEST(test_cron_parse_daily);
    RUN_TEST(test_cron_parse_weekly);
    RUN_TEST(test_cron_parse_interval);
    RUN_TEST(test_cron_parse_sunday7);
    RUN_TEST(test_cron_parse_invalid);
    RUN_TEST(test_cron_parse_impossible_date);
    RUN_TEST(test_cron_kind_enabled_in_service);

    TEST_REPORT();
}
