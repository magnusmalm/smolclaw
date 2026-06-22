#!/usr/bin/env bash
# Land PR-9: build, test, commit, update review record.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== build =="
cmake --build build -j"$(nproc)"

echo "== test_e2e =="
./build/test_e2e

echo "== ctest e2e =="
ctest --test-dir build -R test_e2e --output-on-failure

echo "== full ctest =="
ctest --test-dir build --output-on-failure -j"$(nproc)"
PASS=$(ctest --test-dir build -N | grep -c '^  Test #' || true)
PASS=$((PASS))

git add \
  src/doctor.c \
  src/doctor.h \
  src/main.c \
  tests/test_e2e.c \
  CMakeLists.txt

git commit -m "refactor(cli): extract doctor.c + e2e bin path (PR-9)

Move smolclaw doctor checks from main.c to doctor.c. test_e2e honors
SMOLCLAW_BIN env and CMake SMOLCLAW_BIN cache variable.

Closes P2-1, P2-4."

HASH=$(git rev-parse --short HEAD)
RECORD=docs/plans/repo-audit-4298ba13-review-record.md

python3 - "$HASH" "$PASS" "$RECORD" <<'PY'
import sys, re
hash_, total, path = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path).read()
text = re.sub(
    r'\| PR-9 \| optional main\.c / e2e \| \| \| \| \|',
    f'| PR-9 | optional main.c / e2e | {hash_} | ctest {total}/{total} | 0 | landed |',
    text, count=1)
text = re.sub(
    r'\| P2-1 \| PR-9 \| \| \| open \|',
    f'| P2-1 | PR-9 | {hash_} | doctor.c extract | closed |',
    text, count=1)
text = re.sub(
    r'\| P2-4 \| PR-9 \| \| \| open \|',
    f'| P2-4 | PR-9 | {hash_} | test_e2e SMOLCLAW_BIN | closed |',
    text, count=1)
open(path, 'w').write(text)
PY

git add "$RECORD"
git commit --amend --no-edit

echo "== done =="
git log -1 --stat
echo "Commit: $HASH"