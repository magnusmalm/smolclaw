/*
 * smolclaw - voice transcription tests
 * Tests transcriber creation, availability checks, and error handling.
 */

#include "test_main.h"
#include "voice/transcriber.h"
#include "mock_http.h"
#include "util/str.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

static void test_transcriber_null_key(void)
{
    /* NULL or empty API key -> no transcriber */
    sc_transcriber_t *t = sc_transcriber_new(NULL, NULL);
    ASSERT_NULL(t);

    t = sc_transcriber_new("", NULL);
    ASSERT_NULL(t);
}

static void test_transcriber_create(void)
{
    sc_transcriber_t *t = sc_transcriber_new("test-api-key-123", NULL);
    ASSERT_NOT_NULL(t);
    ASSERT_INT_EQ(sc_transcriber_is_available(t), 1);

    sc_transcriber_free(t);
}

static void test_transcriber_not_available(void)
{
    ASSERT_INT_EQ(sc_transcriber_is_available(NULL), 0);
}

static void test_transcribe_null_args(void)
{
    /* NULL transcriber or file_path -> NULL result */
    char *result = sc_transcribe(NULL, "/tmp/test.ogg");
    ASSERT_NULL(result);

    sc_transcriber_t *t = sc_transcriber_new("test-key", NULL);
    ASSERT_NOT_NULL(t);

    result = sc_transcribe(t, NULL);
    ASSERT_NULL(result);

    sc_transcriber_free(t);
}

static void test_transcribe_nonexistent_file(void)
{
    /* Transcribing a nonexistent file should fail gracefully (curl error) */
    sc_transcriber_t *t = sc_transcriber_new("fake-key-for-test", NULL);
    ASSERT_NOT_NULL(t);

    /* This will try to POST to Groq API with a bad file - should fail */
    char *result = sc_transcribe(t, "/tmp/nonexistent_audio_file_xyz.ogg");
    ASSERT_NULL(result);

    sc_transcriber_free(t);
}

static void test_download_null_url(void)
{
    char *path = sc_download_to_temp(NULL, NULL);
    ASSERT_NULL(path);
}

static void test_download_bad_url(void)
{
    /* Downloading from an unreachable URL should fail gracefully */
    char *path = sc_download_to_temp("http://localhost:1/nonexistent", NULL);
    ASSERT_NULL(path);
}

static void test_transcriber_free_null(void)
{
    /* Should not crash */
    sc_transcriber_free(NULL);
}

/* ======================================================================
 * Mock HTTP tests — E2E transcription and download via mock server
 * ====================================================================== */

static void test_transcribe_mock_server(void)
{
    /* Create a dummy audio file (content doesn't matter — mock doesn't parse it) */
    char tmpfile[] = "/tmp/sc_test_audio_XXXXXX";
    int fd = mkstemp(tmpfile);
    ASSERT(fd >= 0, "mkstemp should succeed");
    (void)write(fd, "fake OGG audio data", 19);
    close(fd);

    /* Mock server returns canned transcription JSON */
    sc_mock_route_t routes[] = {
        { "POST", "/audio/transcriptions", 200, "application/json",
          "{\"text\":\"Hello from mock transcriber\"}" },
    };
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    /* Create transcriber with api_base pointing at mock */
    sc_transcriber_t *t = sc_transcriber_new("test-api-key", sc_mock_http_url(mock));
    ASSERT_NOT_NULL(t);
    ASSERT_INT_EQ(sc_transcriber_is_available(t), 1);

    char *result = sc_transcribe(t, tmpfile);
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "Hello from mock transcriber");

    /* Verify request was a POST to the correct endpoint */
    sc_mock_request_t req = sc_mock_http_last_request(mock);
    ASSERT_STR_EQ(req.method, "POST");
    ASSERT(strstr(req.uri, "/audio/transcriptions") != NULL,
           "Should POST to /audio/transcriptions");
    sc_mock_request_free(&req);

    free(result);
    sc_transcriber_free(t);
    sc_mock_http_stop(mock);
    remove(tmpfile);
}

static void test_transcribe_mock_error(void)
{
    /* Mock returns HTTP 401 — transcriber should return NULL */
    char tmpfile[] = "/tmp/sc_test_audio_XXXXXX";
    int fd = mkstemp(tmpfile);
    ASSERT(fd >= 0, "mkstemp should succeed");
    (void)write(fd, "data", 4);
    close(fd);

    sc_mock_route_t routes[] = {
        { "POST", "/audio/transcriptions", 401, "application/json",
          "{\"error\":{\"message\":\"Invalid API key\"}}" },
    };
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    sc_transcriber_t *t = sc_transcriber_new("bad-key", sc_mock_http_url(mock));
    ASSERT_NOT_NULL(t);

    char *result = sc_transcribe(t, tmpfile);
    ASSERT_NULL(result); /* Should fail on 401 */

    sc_transcriber_free(t);
    sc_mock_http_stop(mock);
    remove(tmpfile);
}

static void test_transcribe_mock_empty_text(void)
{
    /* Mock returns 200 but empty text field — should return NULL */
    char tmpfile[] = "/tmp/sc_test_audio_XXXXXX";
    int fd = mkstemp(tmpfile);
    ASSERT(fd >= 0, "mkstemp should succeed");
    (void)write(fd, "data", 4);
    close(fd);

    sc_mock_route_t routes[] = {
        { "POST", "/audio/transcriptions", 200, "application/json",
          "{\"text\":\"\"}" },
    };
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    sc_transcriber_t *t = sc_transcriber_new("test-key", sc_mock_http_url(mock));
    ASSERT_NOT_NULL(t);

    char *result = sc_transcribe(t, tmpfile);
    ASSERT_NULL(result); /* Empty text should be treated as no transcription */

    sc_transcriber_free(t);
    sc_mock_http_stop(mock);
    remove(tmpfile);
}

static void test_download_mock_server(void)
{
    /* Mock serves a file download */
    sc_mock_route_t routes[] = {
        { "GET", "/file/test.ogg", 200, "audio/ogg",
          "fake-ogg-binary-content" },
    };
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    sc_strbuf_t urlbuf;
    sc_strbuf_init(&urlbuf);
    sc_strbuf_appendf(&urlbuf, "%s/file/test.ogg", sc_mock_http_url(mock));
    char *url = sc_strbuf_finish(&urlbuf);

    char *path = sc_download_to_temp(url, "Authorization: Bearer test-key");
    ASSERT_NOT_NULL(path);

    /* Verify downloaded file content */
    FILE *f = fopen(path, "r");
    ASSERT_NOT_NULL(f);
    char buf[256];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    fclose(f);
    ASSERT_STR_EQ(buf, "fake-ogg-binary-content");

    /* Verify mock received the GET request */
    sc_mock_request_t req = sc_mock_http_last_request(mock);
    ASSERT_STR_EQ(req.method, "GET");
    ASSERT(strstr(req.uri, "/file/test.ogg") != NULL,
           "Should GET /file/test.ogg");
    sc_mock_request_free(&req);

    remove(path);
    free(path);
    free(url);
    sc_mock_http_stop(mock);
}

int main(void)
{
    printf("test_voice\n");

    RUN_TEST(test_transcriber_null_key);
    RUN_TEST(test_transcriber_create);
    RUN_TEST(test_transcriber_not_available);
    RUN_TEST(test_transcribe_null_args);
    RUN_TEST(test_transcribe_nonexistent_file);
    RUN_TEST(test_download_null_url);
    RUN_TEST(test_download_bad_url);
    RUN_TEST(test_transcriber_free_null);
    RUN_TEST(test_transcribe_mock_server);
    RUN_TEST(test_transcribe_mock_error);
    RUN_TEST(test_transcribe_mock_empty_text);
    RUN_TEST(test_download_mock_server);

    TEST_REPORT();
}
