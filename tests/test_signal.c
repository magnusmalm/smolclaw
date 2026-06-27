/*
 * smolclaw - Signal channel tests (task 3.1).
 *
 * Two layers:
 *   1. Pure helpers (signal_internal.h) — identifier normalization, group-id
 *      handling, group-trigger filtering, id validation, recipient
 *      decomposition, base-url building, and envelope extraction. These cover
 *      the security-critical logic the design doc emphasizes (§6.2, §7.6) and
 *      run with no I/O.
 *   2. send + lifecycle via the mock HTTP server (tests/mock_http.h), modeled
 *      on test_telegram.c. The polling/receive thread is exercised indirectly
 *      through sc_signal_envelope_extract (the same function it calls per
 *      envelope), since a live background thread is not deterministically
 *      testable — matching how test_telegram.c omits the poll loop.
 *
 * Covers design §8.2 cases: DM from phone (2), DM from UUID (3), group chat_id
 * normalization (4), allow_from for both phone and uuid forms (6), group
 * trigger filtering (7), send to DM and group (8), error handling (9). The
 * pairing flow (5) is channels/base.c logic covered by the pairing tests.
 */

#include "test_main.h"
#include "mock_http.h"
#include "channels/signal.h"
#include "channels/signal_internal.h"
#include "constants.h"
#include "util/str.h"
#include "cJSON.h"

#include <stdlib.h>
#include <string.h>

/* ---- normalize_sender ------------------------------------------------ */

static void test_normalize_sender_prefers_uuid(void)
{
    char *s = sc_signal_normalize_sender("+15551234567",
                                         "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    ASSERT_NOT_NULL(s);
    ASSERT_STR_EQ(s, "uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    free(s);
}

static void test_normalize_sender_phone_fallback(void)
{
    char *s = sc_signal_normalize_sender("+15551234567", NULL);
    ASSERT_NOT_NULL(s);
    ASSERT_STR_EQ(s, "+15551234567");
    free(s);

    char *e = sc_signal_normalize_sender("+15551234567", "");
    ASSERT_NOT_NULL(e);
    ASSERT_STR_EQ(e, "+15551234567");
    free(e);
}

static void test_normalize_sender_rejects_empty_and_garbage(void)
{
    ASSERT_NULL(sc_signal_normalize_sender(NULL, NULL));
    ASSERT_NULL(sc_signal_normalize_sender("", ""));
    /* Spaces are not valid id chars. */
    ASSERT_NULL(sc_signal_normalize_sender("not a number", NULL));
}

/* ---- group chat_id + trigger ----------------------------------------- */

static void test_normalize_group_chat_id(void)
{
    char *g = sc_signal_normalize_group_chat_id("aWQ9PQ==");
    ASSERT_NOT_NULL(g);
    ASSERT_STR_EQ(g, "signal:group:aWQ9PQ==");
    free(g);

    ASSERT_NULL(sc_signal_normalize_group_chat_id(NULL));
    ASSERT_NULL(sc_signal_normalize_group_chat_id(""));
    ASSERT_NULL(sc_signal_normalize_group_chat_id("bad id with spaces"));
}

static void test_group_should_handle(void)
{
    /* No trigger configured -> always handle. */
    ASSERT_INT_EQ(sc_signal_group_should_handle("anything", NULL), 1);
    ASSERT_INT_EQ(sc_signal_group_should_handle("anything", ""), 1);
    /* Trigger present as substring -> handle. */
    ASSERT_INT_EQ(sc_signal_group_should_handle("hey @bot help", "@bot"), 1);
    /* Trigger absent -> ignore. */
    ASSERT_INT_EQ(sc_signal_group_should_handle("just chatting", "@bot"), 0);
    ASSERT_INT_EQ(sc_signal_group_should_handle(NULL, "@bot"), 0);
}

/* ---- id validation --------------------------------------------------- */

static void test_id_looks_valid(void)
{
    ASSERT_INT_EQ(sc_signal_id_looks_valid("+15551234567"), 1);
    ASSERT_INT_EQ(sc_signal_id_looks_valid("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"), 1);
    ASSERT_INT_EQ(sc_signal_id_looks_valid("base64+/=ID"), 1);
    ASSERT_INT_EQ(sc_signal_id_looks_valid(""), 0);
    ASSERT_INT_EQ(sc_signal_id_looks_valid(NULL), 0);
    ASSERT_INT_EQ(sc_signal_id_looks_valid("has space"), 0);
    ASSERT_INT_EQ(sc_signal_id_looks_valid("newline\n"), 0);
}

/* ---- recipient_from_chat_id ------------------------------------------ */

static void test_recipient_from_chat_id(void)
{
    int is_group = -1;
    const char *r;

    r = sc_signal_recipient_from_chat_id("signal:group:GID==", &is_group);
    ASSERT_INT_EQ(is_group, 1);
    ASSERT_STR_EQ(r, "GID==");

    r = sc_signal_recipient_from_chat_id("uuid:abc-123", &is_group);
    ASSERT_INT_EQ(is_group, 0);
    ASSERT_STR_EQ(r, "abc-123");

    r = sc_signal_recipient_from_chat_id("+15551234567", &is_group);
    ASSERT_INT_EQ(is_group, 0);
    ASSERT_STR_EQ(r, "+15551234567");

    ASSERT_NULL(sc_signal_recipient_from_chat_id(NULL, &is_group));
    ASSERT_NULL(sc_signal_recipient_from_chat_id("", &is_group));
}

/* ---- build_base_url -------------------------------------------------- */

static void test_build_base_url(void)
{
    char *a = sc_signal_build_base_url(NULL, "127.0.0.1", 7583);
    ASSERT_NOT_NULL(a);
    ASSERT_STR_EQ(a, "http://127.0.0.1:7583");
    free(a);

    char *b = sc_signal_build_base_url(NULL, NULL, 0);
    ASSERT_NOT_NULL(b);
    ASSERT_STR_EQ(b, "http://127.0.0.1:7583");
    free(b);

    /* Explicit URL wins, trailing slashes trimmed. */
    char *c = sc_signal_build_base_url("http://signal.local:8080/", "ignored", 1);
    ASSERT_NOT_NULL(c);
    ASSERT_STR_EQ(c, "http://signal.local:8080");
    free(c);
}

/* ---- envelope_extract ------------------------------------------------ */

static void test_envelope_extract_dm_phone(void)
{
    cJSON *env = cJSON_CreateObject();
    cJSON_AddStringToObject(env, "source", "+15551234567");
    cJSON *dm = cJSON_AddObjectToObject(env, "dataMessage");
    cJSON_AddStringToObject(dm, "message", "hello bot");

    sc_signal_inbound_t in;
    ASSERT_INT_EQ(sc_signal_envelope_extract(env, &in), 1);
    ASSERT_INT_EQ(in.is_group, 0);
    ASSERT_STR_EQ(in.sender, "+15551234567");
    ASSERT_STR_EQ(in.chat_id, "+15551234567");
    ASSERT_STR_EQ(in.content, "hello bot");
    sc_signal_inbound_free(&in);
    cJSON_Delete(env);
}

static void test_envelope_extract_dm_uuid(void)
{
    cJSON *env = cJSON_CreateObject();
    cJSON_AddStringToObject(env, "source", "+15551234567");
    cJSON_AddStringToObject(env, "sourceUuid", "11112222-3333-4444-5555-666677778888");
    cJSON *dm = cJSON_AddObjectToObject(env, "dataMessage");
    cJSON_AddStringToObject(dm, "message", "hi");

    sc_signal_inbound_t in;
    ASSERT_INT_EQ(sc_signal_envelope_extract(env, &in), 1);
    ASSERT_INT_EQ(in.is_group, 0);
    ASSERT_STR_EQ(in.sender, "uuid:11112222-3333-4444-5555-666677778888");
    ASSERT_STR_EQ(in.chat_id, "uuid:11112222-3333-4444-5555-666677778888");
    sc_signal_inbound_free(&in);
    cJSON_Delete(env);
}

static void test_envelope_extract_group(void)
{
    cJSON *env = cJSON_CreateObject();
    cJSON_AddStringToObject(env, "sourceUuid", "11112222-3333-4444-5555-666677778888");
    cJSON *dm = cJSON_AddObjectToObject(env, "dataMessage");
    cJSON_AddStringToObject(dm, "message", "group hello");
    cJSON *gi = cJSON_AddObjectToObject(dm, "groupInfo");
    cJSON_AddStringToObject(gi, "groupId", "Z3JvdXBpZA==");

    sc_signal_inbound_t in;
    ASSERT_INT_EQ(sc_signal_envelope_extract(env, &in), 1);
    ASSERT_INT_EQ(in.is_group, 1);
    ASSERT_STR_EQ(in.sender, "uuid:11112222-3333-4444-5555-666677778888");
    ASSERT_STR_EQ(in.chat_id, "signal:group:Z3JvdXBpZA==");
    ASSERT_STR_EQ(in.content, "group hello");
    sc_signal_inbound_free(&in);
    cJSON_Delete(env);
}

static void test_envelope_extract_rejects_non_data(void)
{
    /* No dataMessage (e.g. a sync/receipt) -> not extracted. */
    cJSON *sync = cJSON_CreateObject();
    cJSON_AddStringToObject(sync, "source", "+15551234567");
    cJSON_AddObjectToObject(sync, "syncMessage");
    sc_signal_inbound_t in;
    ASSERT_INT_EQ(sc_signal_envelope_extract(sync, &in), 0);
    cJSON_Delete(sync);

    /* dataMessage with empty text (attachment-only) -> not extracted. */
    cJSON *empty = cJSON_CreateObject();
    cJSON_AddStringToObject(empty, "source", "+15551234567");
    cJSON *dm = cJSON_AddObjectToObject(empty, "dataMessage");
    cJSON_AddStringToObject(dm, "message", "");
    ASSERT_INT_EQ(sc_signal_envelope_extract(empty, &in), 0);
    cJSON_Delete(empty);

    /* No sender at all -> not extracted. */
    cJSON *nosender = cJSON_CreateObject();
    cJSON *dm2 = cJSON_AddObjectToObject(nosender, "dataMessage");
    cJSON_AddStringToObject(dm2, "message", "orphan");
    ASSERT_INT_EQ(sc_signal_envelope_extract(nosender, &in), 0);
    cJSON_Delete(nosender);

    ASSERT_INT_EQ(sc_signal_envelope_extract(NULL, &in), 0);
}

/* ---- channel construction -------------------------------------------- */

static void test_signal_channel_create(void)
{
    ASSERT_NULL(sc_channel_signal_new(NULL, NULL));

    sc_signal_config_t no_acct = { .enabled = 1, .account = NULL };
    ASSERT_NULL(sc_channel_signal_new(&no_acct, NULL));

    sc_signal_config_t cfg = {
        .enabled = 1,
        .account = "+15551234567",
        .http_host = "127.0.0.1",
        .http_port = 7583,
    };
    sc_channel_t *ch = sc_channel_signal_new(&cfg, NULL);
    ASSERT_NOT_NULL(ch);
    ASSERT_STR_EQ(ch->name, SC_CHANNEL_SIGNAL);
    ASSERT_INT_EQ(ch->running, 0);
    ASSERT_NOT_NULL(ch->start);
    ASSERT_NOT_NULL(ch->stop);
    ASSERT_NOT_NULL(ch->send);
    ASSERT_NOT_NULL(ch->destroy);
    ch->destroy(ch);
}

static void test_signal_allow_list_phone_and_uuid(void)
{
    char *allow[] = { "+15551234567", "uuid:abc-123" };
    sc_signal_config_t cfg = {
        .enabled = 1,
        .account = "+15550000000",
        .allow_from = allow,
        .allow_from_count = 2,
    };
    sc_channel_t *ch = sc_channel_signal_new(&cfg, NULL);
    ASSERT_NOT_NULL(ch);
    ASSERT_INT_EQ(ch->allow_list_count, 2);
    ASSERT_STR_EQ(ch->allow_list[0], "+15551234567");
    ASSERT_STR_EQ(ch->allow_list[1], "uuid:abc-123");
    ch->destroy(ch);
}

/* ---- send via mock --------------------------------------------------- */

static void test_signal_send_dm(void)
{
    sc_mock_route_t routes[] = {{
        .method = "POST",
        .path = NULL,
        .status = 200,
        .body = "{\"jsonrpc\":\"2.0\",\"result\":{\"timestamp\":1},\"id\":\"1\"}",
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    sc_signal_config_t cfg = {
        .enabled = 1,
        .account = "+15550000000",
        .http_url = (char *)sc_mock_http_url(mock),
    };
    sc_channel_t *ch = sc_channel_signal_new(&cfg, NULL);
    ASSERT_NOT_NULL(ch);
    ch->running = 1;

    sc_outbound_msg_t msg = {
        .channel = "signal",
        .chat_id = "+15551234567",
        .content = "Hello over Signal",
    };
    ASSERT_INT_EQ(ch->send(ch, &msg), 0);

    sc_mock_request_t req = sc_mock_http_last_request(mock);
    ASSERT_STR_EQ(req.method, "POST");
    ASSERT(strstr(req.uri, "/api/v1/rpc") != NULL, "POST to JSON-RPC endpoint");
    ASSERT(strstr(req.body, "\"method\":\"send\"") != NULL, "method=send");
    ASSERT(strstr(req.body, "+15551234567") != NULL, "body has recipient");
    ASSERT(strstr(req.body, "Hello over Signal") != NULL, "body has message");
    ASSERT(strstr(req.body, "recipient") != NULL, "DM uses recipient field");
    sc_mock_request_free(&req);

    ch->running = 0;
    ch->destroy(ch);
    sc_mock_http_stop(mock);
}

static void test_signal_send_group(void)
{
    sc_mock_route_t routes[] = {{
        .method = "POST",
        .path = NULL,
        .status = 200,
        .body = "{\"jsonrpc\":\"2.0\",\"result\":{\"timestamp\":1},\"id\":\"1\"}",
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    sc_signal_config_t cfg = {
        .enabled = 1,
        .account = "+15550000000",
        .http_url = (char *)sc_mock_http_url(mock),
    };
    sc_channel_t *ch = sc_channel_signal_new(&cfg, NULL);
    ASSERT_NOT_NULL(ch);
    ch->running = 1;

    sc_outbound_msg_t msg = {
        .channel = "signal",
        .chat_id = "signal:group:Z3JvdXBpZA==",
        .content = "group reply",
    };
    ASSERT_INT_EQ(ch->send(ch, &msg), 0);

    sc_mock_request_t req = sc_mock_http_last_request(mock);
    ASSERT(strstr(req.body, "\"groupId\":\"Z3JvdXBpZA==\"") != NULL,
           "group send uses bare groupId");
    ASSERT(strstr(req.body, "recipient") == NULL, "group send has no recipient");
    sc_mock_request_free(&req);

    ch->running = 0;
    ch->destroy(ch);
    sc_mock_http_stop(mock);
}

static void test_signal_send_not_running(void)
{
    sc_signal_config_t cfg = { .enabled = 1, .account = "+15550000000" };
    sc_channel_t *ch = sc_channel_signal_new(&cfg, NULL);
    ASSERT_NOT_NULL(ch);

    sc_outbound_msg_t msg = {
        .channel = "signal", .chat_id = "+15551234567", .content = "x",
    };
    ASSERT_INT_EQ(ch->send(ch, &msg), -1);
    ch->destroy(ch);
}

static void test_signal_send_rpc_error(void)
{
    /* Daemon returns a JSON-RPC error object -> send fails. */
    sc_mock_route_t routes[] = {{
        .method = "POST",
        .path = NULL,
        .status = 200,
        .body = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32000,"
                "\"message\":\"unregistered user\"},\"id\":\"1\"}",
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    sc_signal_config_t cfg = {
        .enabled = 1,
        .account = "+15550000000",
        .http_url = (char *)sc_mock_http_url(mock),
    };
    sc_channel_t *ch = sc_channel_signal_new(&cfg, NULL);
    ASSERT_NOT_NULL(ch);
    ch->running = 1;

    sc_outbound_msg_t msg = {
        .channel = "signal", .chat_id = "+15551234567", .content = "x",
    };
    ASSERT_INT_EQ(ch->send(ch, &msg), -1);

    ch->running = 0;
    ch->destroy(ch);
    sc_mock_http_stop(mock);
}

int main(void)
{
    printf("test_signal:\n");

    RUN_TEST(test_normalize_sender_prefers_uuid);
    RUN_TEST(test_normalize_sender_phone_fallback);
    RUN_TEST(test_normalize_sender_rejects_empty_and_garbage);
    RUN_TEST(test_normalize_group_chat_id);
    RUN_TEST(test_group_should_handle);
    RUN_TEST(test_id_looks_valid);
    RUN_TEST(test_recipient_from_chat_id);
    RUN_TEST(test_build_base_url);
    RUN_TEST(test_envelope_extract_dm_phone);
    RUN_TEST(test_envelope_extract_dm_uuid);
    RUN_TEST(test_envelope_extract_group);
    RUN_TEST(test_envelope_extract_rejects_non_data);
    RUN_TEST(test_signal_channel_create);
    RUN_TEST(test_signal_allow_list_phone_and_uuid);
    RUN_TEST(test_signal_send_dm);
    RUN_TEST(test_signal_send_group);
    RUN_TEST(test_signal_send_not_running);
    RUN_TEST(test_signal_send_rpc_error);

    TEST_REPORT();
}
