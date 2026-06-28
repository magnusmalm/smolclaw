#ifndef SC_DOCTOR_LOCAL_H
#define SC_DOCTOR_LOCAL_H

/*
 * doctor_local.h - Live provider capability probing (task 4.6, `doctor --local`)
 *
 * `smolclaw doctor --local [--model M]` actively probes the configured (or
 * named) model for the capabilities the agent depends on — basic chat,
 * streaming, tool calls, and inline-JSON output — and caches the result under
 * {SMOLCLAW_HOME}/capabilities/<model>.json. Explicit invocation only; nothing
 * here runs at startup.
 *
 * The pure helpers (report (de)serialization, cache path, JSON detection) and
 * the provider-driven probe are split from the live `sc_provider_create_for_model`
 * wiring so they can be unit-tested with a mock provider and no network.
 *
 * Note: the spec also lists a "models list" probe, but the provider vtable has
 * no models-list method and `--local` targets a single configured model, so the
 * models-list probe is intentionally omitted (see docs/design/phases/phase-4).
 */

#include "config.h"
#include "providers/types.h"

/* Result of probing one model. Booleans are tri-state via SC_CAP_*:
 * 0 = unsupported/failed, 1 = supported, -1 = not probed (e.g. streaming
 * compiled out). */
#define SC_CAP_NO       0
#define SC_CAP_YES      1
#define SC_CAP_SKIPPED  (-1)

typedef struct {
    char *model;        /* model probed (owned) */
    int   chat_ok;      /* basic chat round-trip */
    int   stream_ok;    /* streaming deltas received */
    int   tool_calls_ok;/* model emitted a tool call when asked */
    int   json_ok;      /* model returned parseable JSON when asked */
    long  checked_at;   /* unix time of the probe (0 = unknown) */
} sc_capability_report_t;

/* Free owned fields (not the struct itself). Safe on a zeroed struct. */
void sc_capability_report_free(sc_capability_report_t *r);

/* --- Pure helpers (no I/O; unit-tested directly) --- */

/* Serialize a report to a JSON object string (caller frees), or NULL. */
char *sc_capabilities_to_json(const sc_capability_report_t *r);

/* Parse a cached report JSON into *out (caller frees with
 * sc_capability_report_free). Returns 1 on success, 0 on malformed input. */
int sc_capabilities_from_json(const char *json, sc_capability_report_t *out);

/* Build the cache path "{home}/capabilities/<sanitized-model>.json".
 * Model characters outside [A-Za-z0-9._-] are replaced with '_' to keep the
 * filename safe. Returns a malloc'd string (caller frees), or NULL. */
char *sc_capabilities_cache_path(const char *home, const char *model);

/* True if `content` parses as a JSON object/array once any surrounding Markdown
 * code fence (```json ... ```) is stripped. Used for the inline-JSON probe. */
int sc_capabilities_response_is_json(const char *content);

/* --- Provider-driven probe (mockable: pass any sc_provider_t) --- */

/* Run the capability probes against an already-built provider, filling *out
 * (caller frees with sc_capability_report_free). Returns 1 if at least the
 * basic chat probe succeeded, 0 otherwise. Does no caching and no printing. */
int sc_doctor_probe_provider(sc_provider_t *provider, const char *model,
                             sc_capability_report_t *out);

/* --- Live entry point --- */

/* Build a provider for `model` (or cfg->model when NULL/empty) from `cfg`,
 * probe it, cache the report under {home}/capabilities/, and print PASS/FAIL.
 * Returns 0 if the basic chat probe passed, 1 otherwise. */
int sc_doctor_local(const sc_config_t *cfg, const char *model);

#endif /* SC_DOCTOR_LOCAL_H */
