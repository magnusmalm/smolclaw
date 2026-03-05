/*
 * util/secrets.c - Secret scanning and redaction
 *
 * Regex-based detection of API keys, PEM private keys, and key=value secrets.
 */

#include "util/secrets.h"
#include "util/str.h"

#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define REDACTED_STR "[REDACTED]"
#define REDACTED_LEN 10

/* Pattern definitions (POSIX ERE) */
static const char *secret_patterns[] = {
    /* OpenAI/Anthropic API keys */
    "sk-[A-Za-z0-9_-]{20,}",
    /* PEM private keys */
    "-----BEGIN[[:space:]][A-Z ]*PRIVATE KEY-----",
    /* Key=value secrets (expanded set) */
    "(password|secret|token|api_key|apikey|secret_key|access_key|client_secret|auth_token|refresh_token)[[:space:]]*[:=][[:space:]]*[^[:space:]\"',}{]+",
    /* JWT tokens (three base64url segments) */
    "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}",
    /* AWS access key IDs */
    "AKIA[0-9A-Z]{16}",
    /* GitHub tokens */
    "(ghp|gho|ghs|ghr|github_pat)_[A-Za-z0-9_]{30,}",
    /* Bearer tokens in headers */
    "[Bb]earer[[:space:]]+[A-Za-z0-9._~+/=-]{20,}",
    /* Slack tokens */
    "xox[bpras]-[0-9A-Za-z-]{10,}",
    /* Google API keys */
    "AIza[0-9A-Za-z_-]{35}",
    /* Stripe keys */
    "(sk_live|sk_test|rk_live|rk_test)_[0-9a-zA-Z]{10,}",
    /* Database connection strings */
    "(postgres|mysql|mongodb|redis)://[^[:space:]\"']+",
    /* Anthropic API keys */
    "sk-ant-api[0-9a-zA-Z_-]{20,}",
    /* SSH key variants (DSA, ECDSA, EC, OPENSSH) */
    "-----BEGIN[[:space:]](DSA|ECDSA|EC|OPENSSH) PRIVATE KEY-----",
};

#define PATTERN_COUNT (sizeof(secret_patterns) / sizeof(secret_patterns[0]))

/* Compiled patterns (lazy init, thread-safe via pthread_once) */
static regex_t compiled[PATTERN_COUNT];
static int compiled_ok[PATTERN_COUNT];
static pthread_once_t init_once = PTHREAD_ONCE_INIT;

static void do_init(void)
{
    for (int i = 0; i < (int)PATTERN_COUNT; i++) {
        compiled_ok[i] = (regcomp(&compiled[i], secret_patterns[i],
                                   REG_EXTENDED | REG_ICASE) == 0);
    }
}

static void ensure_init(void)
{
    pthread_once(&init_once, do_init);
}

int sc_scan_secrets(const char *text)
{
    if (!text || !text[0]) return 0;
    ensure_init();

    int count = 0;
    for (int i = 0; i < (int)PATTERN_COUNT; i++) {
        if (!compiled_ok[i]) continue;
        regmatch_t match;
        const char *pos = text;
        while (regexec(&compiled[i], pos, 1, &match, 0) == 0) {
            count++;
            pos += match.rm_eo;
            if (!*pos) break;
        }
    }
    return count;
}

char *sc_redact_secrets(const char *text)
{
    if (!text || !text[0]) return NULL;
    ensure_init();

    /* Check if there are any matches first */
    if (sc_scan_secrets(text) == 0) return NULL;

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);

    const char *pos = text;
    while (*pos) {
        regmatch_t best_match = { -1, -1 };
        int found = 0;

        /* Find the earliest matching pattern */
        for (int i = 0; i < (int)PATTERN_COUNT; i++) {
            if (!compiled_ok[i]) continue;
            regmatch_t m;
            if (regexec(&compiled[i], pos, 1, &m, 0) == 0) {
                if (!found || m.rm_so < best_match.rm_so) {
                    best_match = m;
                    found = 1;
                }
            }
        }

        if (!found) {
            /* No more matches — append rest */
            sc_strbuf_append(&sb, pos);
            break;
        }

        /* Append text before match */
        if (best_match.rm_so > 0) {
            char *prefix = malloc((size_t)best_match.rm_so + 1);
            if (prefix) {
                memcpy(prefix, pos, (size_t)best_match.rm_so);
                prefix[best_match.rm_so] = '\0';
                sc_strbuf_append(&sb, prefix);
                free(prefix);
            }
        }

        sc_strbuf_append(&sb, REDACTED_STR);
        pos += best_match.rm_eo;
    }

    return sc_strbuf_finish(&sb);
}
