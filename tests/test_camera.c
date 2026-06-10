/*
 * smolclaw — camera tool tests (SC_ENABLE_CAMERA).
 *
 * snap uses `cp` as the capture command so no camera hardware is
 * needed; describe runs against the mock HTTP server emulating an
 * ollama /api/chat vision response.
 */

#include "test_main.h"
#include "mock_http.h"

#include "tools/camera.h"
#include "tools/types.h"
#include "util/str.h"

#include <cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utime.h>

static char *make_workspace(void)
{
    static char tmpl[64];
    snprintf(tmpl, sizeof(tmpl), "/tmp/sc_test_camera_XXXXXX");
    return mkdtemp(tmpl);
}

static void rm_rf(const char *path)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", path);
    system(cmd);
}

static void write_file_at(const char *dir, const char *name,
                          const char *content, time_t mtime)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "w");
    if (f) { fputs(content, f); fclose(f); }
    if (mtime) {
        struct utimbuf t = { mtime, mtime };
        utime(path, &t);
    }
}

static sc_tool_result_t *run_action(sc_tool_t *tool, const char *action,
                                     const char *image, const char *question,
                                     int limit)
{
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "action", action);
    if (image)    cJSON_AddStringToObject(args, "image", image);
    if (question) cJSON_AddStringToObject(args, "question", question);
    if (limit)    cJSON_AddNumberToObject(args, "limit", limit);
    sc_tool_result_t *r = tool->execute(tool, args, NULL);
    cJSON_Delete(args);
    return r;
}

static void test_camera_events_listing(void)
{
    char *ws = make_workspace();
    ASSERT_NOT_NULL(ws);

    char events[512];
    snprintf(events, sizeof(events), "%s/camera/motion", ws);
    char mk[600];
    snprintf(mk, sizeof(mk), "mkdir -p %s", events);
    system(mk);

    time_t now = time(NULL);
    write_file_at(events, "old.jpg",   "x", now - 3600);
    write_file_at(events, "newer.jpg", "x", now - 60);
    write_file_at(events, "newest.jpg","x", now - 5);
    write_file_at(events, "notes.txt", "x", now);  /* ignored: not image */

    sc_tool_t *tool = sc_tool_camera_new(ws, NULL, "camera/motion",
                                         NULL, NULL, 0);
    ASSERT_NOT_NULL(tool);

    sc_tool_result_t *r = run_action(tool, "events", NULL, NULL, 2);
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "newest.jpg") != NULL, "lists newest");
    ASSERT(strstr(r->for_llm, "newer.jpg") != NULL, "lists second");
    ASSERT(strstr(r->for_llm, "old.jpg") == NULL, "limit=2 drops oldest");
    ASSERT(strstr(r->for_llm, "notes.txt") == NULL, "non-image ignored");
    ASSERT(strstr(r->for_llm, "newest.jpg") < strstr(r->for_llm, "newer.jpg"),
           "newest first");
    sc_tool_result_free(r);

    tool->destroy(tool);
    rm_rf(ws);
}

static void test_camera_events_empty(void)
{
    char *ws = make_workspace();
    ASSERT_NOT_NULL(ws);

    sc_tool_t *tool = sc_tool_camera_new(ws, NULL, NULL, NULL, NULL, 0);
    ASSERT_NOT_NULL(tool);

    /* Missing events dir is not an error — just an explanation */
    sc_tool_result_t *r = run_action(tool, "events", NULL, NULL, 0);
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "No motion events") != NULL, "explains absence");
    sc_tool_result_free(r);

    tool->destroy(tool);
    rm_rf(ws);
}

static void test_camera_snap_with_cp(void)
{
    char *ws = make_workspace();
    ASSERT_NOT_NULL(ws);

    /* Fixture the "camera" copies from */
    write_file_at(ws, "fixture.jpg", "JPEGDATA", 0);

    char snap_cmd[600];
    snprintf(snap_cmd, sizeof(snap_cmd), "cp %s/fixture.jpg", ws);

    sc_tool_t *tool = sc_tool_camera_new(ws, snap_cmd, NULL, NULL, NULL, 0);
    ASSERT_NOT_NULL(tool);

    sc_tool_result_t *r = run_action(tool, "snap", NULL, NULL, 0);
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "Captured") != NULL, "reports capture");
    ASSERT(strstr(r->for_llm, "/camera/snap-") != NULL, "timestamped path");
    sc_tool_result_free(r);

    /* Failing capture command -> error */
    sc_tool_t *bad = sc_tool_camera_new(ws, "false", NULL, NULL, NULL, 0);
    ASSERT_NOT_NULL(bad);
    r = run_action(bad, "snap", NULL, NULL, 0);
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 1);
    sc_tool_result_free(r);
    bad->destroy(bad);

    /* Unconfigured snap -> error */
    sc_tool_t *none = sc_tool_camera_new(ws, NULL, NULL, NULL, NULL, 0);
    r = run_action(none, "snap", NULL, NULL, 0);
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 1);
    sc_tool_result_free(r);
    none->destroy(none);

    tool->destroy(tool);
    rm_rf(ws);
}

static void test_camera_describe_mock(void)
{
    char *ws = make_workspace();
    ASSERT_NOT_NULL(ws);

    write_file_at(ws, "shot.jpg", "JPEGDATA", 0);

    sc_mock_route_t routes[] = {
        { "POST", "/api/chat", 200, NULL,
          "{\"message\":{\"role\":\"assistant\","
          "\"content\":\"A cat sitting on a doormat.\"}}" },
    };
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    sc_tool_t *tool = sc_tool_camera_new(ws, NULL, NULL,
                                         sc_mock_http_url(mock),
                                         "test-vision", 30);
    ASSERT_NOT_NULL(tool);

    sc_tool_result_t *r = run_action(tool, "describe", "shot.jpg",
                                     "what is this?", 0);
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "A cat sitting on a doormat.") != NULL,
           "returns vision content");
    sc_tool_result_free(r);

    /* The request must carry the model, question, and base64 image */
    sc_mock_request_t req = sc_mock_http_last_request(mock);
    ASSERT_NOT_NULL(req.body);
    ASSERT(strstr(req.body, "\"model\":\"test-vision\"") != NULL,
           "sends configured model");
    ASSERT(strstr(req.body, "what is this?") != NULL, "sends question");
    ASSERT(strstr(req.body, "\"images\":[\"") != NULL, "sends images array");
    sc_mock_request_free(&req);

    tool->destroy(tool);
    sc_mock_http_stop(mock);
    rm_rf(ws);
}

static void test_camera_describe_path_safety(void)
{
    char *ws = make_workspace();
    ASSERT_NOT_NULL(ws);

    sc_tool_t *tool = sc_tool_camera_new(ws, NULL, NULL,
                                         "http://127.0.0.1:1",
                                         "test-vision", 5);
    ASSERT_NOT_NULL(tool);

    /* Absolute path outside the workspace */
    sc_tool_result_t *r = run_action(tool, "describe", "/etc/passwd",
                                     NULL, 0);
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 1);
    sc_tool_result_free(r);

    /* Traversal out of the workspace */
    r = run_action(tool, "describe", "../../../etc/passwd", NULL, 0);
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 1);
    sc_tool_result_free(r);

    /* Missing file */
    r = run_action(tool, "describe", "nope.jpg", NULL, 0);
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 1);
    sc_tool_result_free(r);

    /* describe unconfigured (no vision_url) -> clear error */
    sc_tool_t *novis = sc_tool_camera_new(ws, NULL, NULL, NULL, NULL, 0);
    write_file_at(ws, "x.jpg", "d", 0);
    r = run_action(novis, "describe", "x.jpg", NULL, 0);
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 1);
    ASSERT(strstr(r->for_llm, "not configured") != NULL, "explains config");
    sc_tool_result_free(r);
    novis->destroy(novis);

    tool->destroy(tool);
    rm_rf(ws);
}

int main(void)
{
    printf("test_camera:\n");
    RUN_TEST(test_camera_events_listing);
    RUN_TEST(test_camera_events_empty);
    RUN_TEST(test_camera_snap_with_cp);
    RUN_TEST(test_camera_describe_mock);
    RUN_TEST(test_camera_describe_path_safety);
    TEST_REPORT();
}
