/*
 * util/prompt_guard.c - Prompt injection detection
 *
 * Scans tool output for common prompt injection patterns.
 * Detection + audit logging only — CDATA wrapping is the active defense.
 */

#include "util/prompt_guard.h"

#include <ctype.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Case-insensitive substring search (POSIX) */
extern char *strcasestr(const char *, const char *);

static const char *patterns[] = {
    "ignore previous",
    "ignore all previous",
    "ignore the above",
    "disregard previous",
    "forget your instructions",
    "you are now",
    "act as",
    "pretend to be",
    "roleplay as",
    "new instructions:",
    "system prompt:",
    "override:",
    "jailbreak",
    "do anything now",
    "[system]",
    "<|im_start|>",
    "```system",
};

#define PATTERN_COUNT (sizeof(patterns) / sizeof(patterns[0]))

/* Collapse runs of whitespace to single space, strip leading/trailing */
static char *normalize_whitespace(const char *text)
{
    if (!text) return NULL;
    size_t len = strlen(text);
    char *out = malloc(len + 1);
    if (!out) return NULL;
    char *dst = out;
    int in_space = 1; /* skip leading whitespace */
    for (const char *p = text; *p; p++) {
        if (isspace((unsigned char)*p)) {
            if (!in_space) { *dst++ = ' '; in_space = 1; }
        } else {
            *dst++ = *p;
            in_space = 0;
        }
    }
    /* Trim trailing space */
    if (dst > out && *(dst - 1) == ' ') dst--;
    *dst = '\0';
    return out;
}

int sc_prompt_guard_scan(const char *text)
{
    if (!text || !text[0]) return 0;

    char *normalized = normalize_whitespace(text);
    const char *check = normalized ? normalized : text;

    int count = 0;
    for (int i = 0; i < (int)PATTERN_COUNT; i++) {
        if (strcasestr(check, patterns[i]) != NULL)
            count++;
    }
    free(normalized);
    return count;
}

/* High-confidence patterns — definite injection attempts */
static const char *high_patterns[] = {
    "ignore previous",
    "ignore all previous",
    "ignore the above",
    "disregard previous",
    "forget your instructions",
    "system prompt:",
    "jailbreak",
    "<|im_start|>",
    "<|endoftext|>",
    "<|im_end|>",
    "[/inst]",
    "<s>",
    "</s>",
    "[system]",
};
#define HIGH_PATTERN_COUNT (sizeof(high_patterns) / sizeof(high_patterns[0]))

int sc_prompt_guard_scan_high(const char *text)
{
    if (!text || !text[0]) return 0;

    char *normalized = normalize_whitespace(text);
    const char *check = normalized ? normalized : text;

    for (int i = 0; i < (int)HIGH_PATTERN_COUNT; i++) {
        if (strcasestr(check, high_patterns[i]) != NULL) {
            free(normalized);
            return 1;
        }
    }
    free(normalized);
    return 0;
}
