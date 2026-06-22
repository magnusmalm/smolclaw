#!/usr/bin/env bash
# Land PR-5: build, test, commit, update review record.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== build =="
cmake --build build -j"$(nproc)"

echo "== test_git_security =="
./build/test_git_security

echo "== ctest git security =="
ctest --test-dir build -R test_git_security --output-on-failure

echo "== full ctest =="
ctest --test-dir build --output-on-failure -j"$(nproc)"
PASS=$(ctest --test-dir build -N 2>&1 | awk '/^Total Tests:/ {print $3; exit}')
PASS=${PASS:-0}

git add \
  src/tools/git.c \
  src/tools/git.h \
  src/tools/worktree.c \
  src/tools/worktree.h \
  tests/test_git_security.c \
  CMakeLists.txt

git commit -m "fix(git): push allowlist + worktree execvp (PR-5)

Normalize git.push_allowed_remotes matching (host/path prefix, not
substring). Block remote set-url/add/remove/rename. Refactor worktree
to fork+execvp with exit-status checks. Add test_git_security.

Closes P1-1, P1-3."

HASH=$(git rev-parse --short HEAD)
RECORD=docs/plans/repo-audit-4298ba13-review-record.md

# Update review record in place
python3 - "$HASH" "$PASS" "$RECORD" <<'PY'
import sys, re
hash_, total, path = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path).read()
text = re.sub(
    r'\| PR-5 \| git \+ worktree \| \| \| \| \|',
    f'| PR-5 | git + worktree | {hash_} | ctest {total}/{total} | 0 | landed |',
    text, count=1)
text = re.sub(
    r'\| P1-1 \| PR-5 \| \| \| open \|',
    f'| P1-1 | PR-5 | {hash_} | test_git_security | closed |',
    text, count=1)
text = re.sub(
    r'\| P1-3 \| PR-5 \| \| \| open \|',
    f'| P1-3 | PR-5 | {hash_} | test_git_security | closed |',
    text, count=1)
open(path, 'w').write(text)
PY

git add "$RECORD"
git commit --amend --no-edit

echo "== done =="
git log -1 --stat
echo "Commit: $HASH"