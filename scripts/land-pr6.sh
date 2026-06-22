#!/usr/bin/env bash
# Land PR-6: build, test, commit, update review record.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== build =="
cmake --build build -j"$(nproc)"

echo "== test_web_auth =="
./build/test_web_auth

echo "== ctest web auth =="
ctest --test-dir build -R test_web_auth --output-on-failure

echo "== full ctest =="
ctest --test-dir build --output-on-failure -j"$(nproc)"
PASS=$(ctest --test-dir build -N | grep -c '^  Test #' || true)
PASS=$((PASS))  # total registered

git add \
  src/channels/web.c \
  src/channels/web.h \
  tests/test_web_auth.c

git commit -m "fix(web): rate limits + health auth (PR-6)

Apply agents.defaults rate_limiter to POST /api/message keyed by
client IP and bearer-token hash. Require bearer auth on /api/health.
Add unit tests for rate-limit helpers.

Closes P1-4, P2-5."

HASH=$(git rev-parse --short HEAD)
RECORD=docs/plans/repo-audit-4298ba13-review-record.md

# Update review record in place
python3 - "$HASH" "$PASS" "$RECORD" <<'PY'
import sys, re
hash_, total, path = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path).read()
text = re.sub(
    r'\| PR-6 \| web rate limits \+ health \| \| \| \| \|',
    f'| PR-6 | web rate limits + health | {hash_} | ctest {total}/{total} | 0 | landed |',
    text, count=1)
text = re.sub(
    r'\| P1-4 \| PR-6 \| \| \| open \|',
    f'| P1-4 | PR-6 | {hash_} | test_web_auth | closed |',
    text, count=1)
text = re.sub(
    r'\| P2-5 \| PR-6 \| \| \| open \|',
    f'| P2-5 | PR-6 | {hash_} | test_web_auth | closed |',
    text, count=1)
open(path, 'w').write(text)
PY

git add "$RECORD"
git commit --amend --no-edit

echo "== done =="
git log -1 --stat
echo "Commit: $HASH"