/*
 * smolclaw - prompt prefix warmup tests (Phase 1.8)
 *
 * Unit-tests the warmup decision logic (enable / allowlist / fingerprint skip)
 * with a fake provider. The live time-to-first-token benefit on a real local
 * model (Ollama/vLLM) is a manual acceptance check.
 */
#include "test_main.h"
#include "providers/warmup.h"
#include "providers/types.h"
#include "agent.h"
#include "util/str.h"
#include "cJSON.h"

static int fake_chat_calls;
static int fake_last_max_tokens;

static sc_llm_response_t *fake_chat(sc_provider_t *self,
                                    sc_llm_message_t *msgs, int msg_count,
                                    sc_tool_definition_t *tools, int tool_count,
                                    const char *model, cJSON *options)
{
    (void)self; (void)msgs; (void)msg_count;
    (void)tools; (void)tool_count; (void)model;
    fake_chat_calls++;
    cJSON *mt = cJSON_GetObjectItem(options, "max_tokens");
    fake_last_max_tokens = mt ? mt->valueint : -1;
    sc_llm_response_t *r = calloc(1, sizeof(*r));
    r->http_status = 200;
    r->content = sc_strdup("ok");
    return r;
}

static void test_warmup_decision(void)
{
    fake_chat_calls = 0;
    fake_last_max_tokens = 0;

    const char *provs[] = { "ollama", "vllm" };
    sc_agent_t agent = {0};
    agent.warmup_providers = (char **)provs;
    agent.warmup_provider_count = 2;
    agent.last_warmup_fingerprint = 0;

    sc_provider_t prov = {0};
    prov.name = "ollama";
    prov.chat = fake_chat;

    sc_llm_message_t msgs[1] = {0};
    msgs[0].role = "system";
    msgs[0].content = "You are a helpful assistant.";

    /* Disabled → no warmup. */
    agent.warmup = 0;
    ASSERT_INT_EQ(sc_warmup_maybe(&agent, &prov, "qwen", msgs, 1, NULL, 0), 0);
    ASSERT_INT_EQ(fake_chat_calls, 0);

    /* Enabled + allowlisted → fires once, max_tokens=1. */
    agent.warmup = 1;
    ASSERT_INT_EQ(sc_warmup_maybe(&agent, &prov, "qwen", msgs, 1, NULL, 0), 1);
    ASSERT_INT_EQ(fake_chat_calls, 1);
    ASSERT_INT_EQ(fake_last_max_tokens, 1);

    /* Same fingerprint → skip. */
    ASSERT_INT_EQ(sc_warmup_maybe(&agent, &prov, "qwen", msgs, 1, NULL, 0), 0);
    ASSERT_INT_EQ(fake_chat_calls, 1);

    /* Different model → fingerprint changes → fires again. */
    ASSERT_INT_EQ(sc_warmup_maybe(&agent, &prov, "llama", msgs, 1, NULL, 0), 1);
    ASSERT_INT_EQ(fake_chat_calls, 2);

    /* Provider not in allowlist → no warmup. */
    sc_provider_t prov2 = {0};
    prov2.name = "anthropic";
    prov2.chat = fake_chat;
    ASSERT_INT_EQ(sc_warmup_maybe(&agent, &prov2, "claude", msgs, 1, NULL, 0), 0);
    ASSERT_INT_EQ(fake_chat_calls, 2);
}

int main(void)
{
    printf("test_warmup\n");
    RUN_TEST(test_warmup_decision);
    TEST_REPORT();
}
