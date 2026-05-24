/*
 * smolclaw — session-isolation Stage 3 tests.
 *
 * Cover the sc_context_builder_t isolation flag added for Phase 4.
 * Ensures the shared "# Memory" block is omitted from the system prompt
 * when the builder is constructed via sc_context_builder_new_isolated,
 * and that the back-compat path (sc_context_builder_new) still includes
 * memory as before.
 */

#include "test_main.h"

#include "context.h"
#include "memory.h"
#include "util/str.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---- helpers ---- */

static char *make_workspace(void)
{
    static char tmpl[64];
    snprintf(tmpl, sizeof(tmpl), "/tmp/sc_test_ctx_iso_XXXXXX");
    return mkdtemp(tmpl);
}

static void rm_rf(const char *path)
{
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "rm -rf %s", path);
    char *cmd = sc_strbuf_finish(&sb);
    if (cmd) { system(cmd); free(cmd); }
}

static void write_text(const char *path, const char *content)
{
    /* ensure parent dir tree */
    char *dup = sc_strdup(path);
    if (dup) {
        for (char *p = dup + 1; *p; p++) {
            if (*p == '/') { *p = '\0'; mkdir(dup, 0755); *p = '/'; }
        }
        char *slash = strrchr(dup, '/');
        if (slash) { *slash = '\0'; mkdir(dup, 0755); }
        free(dup);
    }
    FILE *f = fopen(path, "w");
    if (f) { fputs(content, f); fclose(f); }
}

/* ---- Tests ---- */

static void test_isolated_constructor_rejects_bad_ns(void)
{
    char *ws = make_workspace();
    ASSERT_NOT_NULL(ws);
    ASSERT_NULL(sc_context_builder_new_isolated(ws, NULL));
    ASSERT_NULL(sc_context_builder_new_isolated(ws, ""));
    ASSERT_NULL(sc_context_builder_new_isolated(ws, "bad/ns"));
    sc_context_builder_t *ok =
        sc_context_builder_new_isolated(ws, "deadbeef00112233");
    ASSERT_NOT_NULL(ok);
    ASSERT_INT_EQ(sc_context_builder_is_isolated(ok), 1);
    sc_context_builder_free(ok);
    rm_rf(ws);
}

static void test_isolated_skips_memory_block(void)
{
    char *ws = make_workspace();
    ASSERT_NOT_NULL(ws);

    /* Populate shared MEMORY.md AND a shared today.md so any leakage is
     * detectable. */
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/memory/MEMORY.md", ws);
    char *long_term_path = sc_strbuf_finish(&sb);
    write_text(long_term_path,
               "POISON-LONG-TERM-MARKER smolchat retention notes");

    /* Build an isolated context and confirm the system prompt has no
     * "# Memory" header and none of the poison markers. */
    sc_context_builder_t *iso =
        sc_context_builder_new_isolated(ws, "isofa11");
    ASSERT_NOT_NULL(iso);

    /* Also write content via the isolated memory store so we can confirm
     * even per-session memory does not surface in the system prompt. */
    sc_memory_t *ns_mem = sc_memory_new_namespaced(ws, "isofa11");
    ASSERT_NOT_NULL(ns_mem);
    sc_memory_append_today(ns_mem, "PER-SESSION-NOTES-MARKER current task");
    sc_memory_free(ns_mem);

    char *prompt = sc_context_build_system_prompt(iso);
    ASSERT_NOT_NULL(prompt);
    ASSERT(strstr(prompt, "# Memory") == NULL,
           "isolated prompt omits memory header");
    ASSERT(strstr(prompt, "POISON-LONG-TERM-MARKER") == NULL,
           "isolated prompt does not leak shared long-term");
    ASSERT(strstr(prompt, "PER-SESSION-NOTES-MARKER") == NULL,
           "isolated prompt does not include per-session notes either");
    ASSERT(strstr(prompt, "isolated session") != NULL,
           "isolated prompt declares isolation in workspace block");

    free(long_term_path);
    free(prompt);
    sc_context_builder_free(iso);
    rm_rf(ws);
}

static void test_non_isolated_includes_memory_block(void)
{
    char *ws = make_workspace();
    ASSERT_NOT_NULL(ws);

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/memory/MEMORY.md", ws);
    char *long_term_path = sc_strbuf_finish(&sb);
    write_text(long_term_path,
               "SHARED-LONG-TERM-MARKER durable knowledge");

    sc_context_builder_t *shared = sc_context_builder_new(ws);
    ASSERT_NOT_NULL(shared);
    ASSERT_INT_EQ(sc_context_builder_is_isolated(shared), 0);

    char *prompt = sc_context_build_system_prompt(shared);
    ASSERT_NOT_NULL(prompt);
    ASSERT(strstr(prompt, "# Memory") != NULL,
           "shared prompt includes memory header");
    ASSERT(strstr(prompt, "SHARED-LONG-TERM-MARKER") != NULL,
           "shared prompt includes shared long-term content");
    ASSERT(strstr(prompt, "isolated session") == NULL,
           "shared prompt does not declare isolation");

    free(long_term_path);
    free(prompt);
    sc_context_builder_free(shared);
    rm_rf(ws);
}

static void test_isolated_constructor_uses_namespaced_memory(void)
{
    char *ws = make_workspace();
    ASSERT_NOT_NULL(ws);

    sc_context_builder_t *iso =
        sc_context_builder_new_isolated(ws, "namespacedmem");
    ASSERT_NOT_NULL(iso);

    /* The isolated builder's memory should be at
     * <ws>/memory/_sessions/namespacedmem/ — which means a last_access
     * file should already exist (created by sc_memory_new_namespaced). */
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/memory/_sessions/namespacedmem/last_access", ws);
    char *la_path = sc_strbuf_finish(&sb);
    struct stat st;
    ASSERT_INT_EQ(stat(la_path, &st), 0);

    free(la_path);
    sc_context_builder_free(iso);
    rm_rf(ws);
}

int main(void)
{
    printf("test_context_isolation:\n");
    RUN_TEST(test_isolated_constructor_rejects_bad_ns);
    RUN_TEST(test_isolated_skips_memory_block);
    RUN_TEST(test_non_isolated_includes_memory_block);
    RUN_TEST(test_isolated_constructor_uses_namespaced_memory);
    TEST_REPORT();
}
