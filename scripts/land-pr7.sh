#!/usr/bin/env bash
# Land PR-7: build, test, commit, update review record.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== build =="
cmake --build build -j"$(nproc)"

echo "== grep gate: curl_easy_init only in curl_common.c =="
if grep -rn 'curl_easy_init' src/ --include='*.c' | grep -v 'util/curl_common.c'; then
    echo "FAIL: raw curl_easy_init outside curl_common.c"
    exit 1
fi
echo "OK"

echo "== test_curl_common =="
./build/test_curl_common

echo "== ctest curl common =="
ctest --test-dir build -R test_curl_common --output-on-failure

echo "== full ctest =="
ctest --test-dir build --output-on-failure -j"$(nproc)"
PASS=$(ctest --test-dir build -N | grep -c '^  Test #' || true)
PASS=$((PASS))  # total registered

git add \
  src/tools/notify.c \
  tests/test_curl_common.c

git commit -m "fix(notify): use sc_curl_init (PR-7)

Route notify HTTP posts through centralized curl init for CA bundle
and protocol restrictions. Add grep gate test in test_curl_common.

Closes P1-5."

HASH=$(git rev-parse --short HEAD)
RECORD=docs/plans/repo-audit-4298ba13-review-record.md

python3 - "$HASH" "$PASS" "$RECORD" <<'PY'
import sys, re
hash_, total, path = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path).read()
text = re.sub(
    r'\| PR-7 \| notify sc_curl_init \| \| \| \| \|',
    f'| PR-7 | notify sc_curl_init | {hash_} | ctest {total}/{total} | 0 | landed |',
    text, count=1)
text = re.sub(
    r'\| P1-5 \| PR-7 \| \| \| open \|',
    f'| P1-5 | PR-7 | {hash_} | test_curl_common | closed |',
    text, count=1)
open(path, 'w').write(text)
PY

git add "$RECORD"
git commit --amend --no-edit

echo "== done =="
git log -1 --stat
echo "Commit: $HASH"