#!/usr/bin/env bash
# Land PR-8: docs validation, commit, update review record.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== doc sanity checks =="
test -f docs/operations/gateway-threat-model.md
grep -q '"cron"' README.md
grep -q 'SC_ENABLE_ANALYTICS' README.md
grep -q 'tls_cert' Kconfig
grep -q '256 KB' RELEASE_NOTES.md
! grep -q 'cronjob' README.md
echo "OK"

echo "== full ctest (regression) =="
ctest --test-dir build --output-on-failure -j"$(nproc)"
PASS=$(ctest --test-dir build -N | grep -c '^  Test #' || true)
PASS=$((PASS))

git add \
  docs/operations/gateway-threat-model.md \
  docs/SECURITY.md \
  README.md \
  Kconfig \
  RELEASE_NOTES.md

git commit -m "docs: gateway threat model + README/Kconfig fixes (PR-8)

Add gateway-threat-model.md (auto_confirm, web auth, rate limits).
Fix README cron tool name and analytics build flag. Update Kconfig
web TLS help and RELEASE_NOTES minimal size (256 KB).

Closes P1-2, P1-6, P2-3."

HASH=$(git rev-parse --short HEAD)
RECORD=docs/plans/repo-audit-4298ba13-review-record.md

python3 - "$HASH" "$PASS" "$RECORD" <<'PY'
import sys, re
hash_, total, path = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path).read()
text = re.sub(
    r'\| PR-8 \| docs threat model \| \| \| \| \|',
    f'| PR-8 | docs threat model | {hash_} | ctest {total}/{total} | 0 | landed |',
    text, count=1)
text = re.sub(
    r'\| P1-2 \| PR-8 \| \| \| open \|',
    f'| P1-2 | PR-8 | {hash_} | gateway-threat-model.md | closed |',
    text, count=1)
text = re.sub(
    r'\| P1-6 \| PR-8 \| \| \| open \|',
    f'| P1-6 | PR-8 | {hash_} | README + Kconfig | closed |',
    text, count=1)
text = re.sub(
    r'\| P2-3 \| PR-8 \| \| \| open \|',
    f'| P2-3 | PR-8 | {hash_} | RELEASE_NOTES | closed |',
    text, count=1)
open(path, 'w').write(text)
PY

git add "$RECORD"
git commit --amend --no-edit

echo "== done =="
git log -1 --stat
echo "Commit: $HASH"