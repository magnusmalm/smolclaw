# Known issue: SIGILL at exit on armv7 CLI runs (2026-06-10)

On the camera host (armv7l musl-static build, commit
`4bbf539` era), every `smolclaw agent -m "..."` one-shot run prints its
response correctly and then dies with `Illegal instruction` (exit 132)
during process teardown. `smolclaw doctor` and the long-running
`gateway` mode are unaffected — the gateway serves health, IRC, web,
and camera-tool turns normally (verified end-to-end 2026-06-10).

Scope: exit/cleanup path only, armv7 only (x86_64 builds exit clean).
Likely a compiler-inserted trap (`__builtin_trap`-style udf) in an
atexit/destructor path, possibly in the rebuilt armv7 musl deps rather
than smolclaw code. Not investigated further yet.

Repro (on the camera host): `smolclaw agent -m "Reply OK"` → exit 132.

Priority: low (CLI one-shots on the camera host are not a production
surface), but should be fixed before the camera build is advertised.
