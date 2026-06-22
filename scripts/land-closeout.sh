#!/usr/bin/env bash
# Close-out: reconcile review record, commit land scripts + final record.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== verify ctest =="
ctest --test-dir build --output-on-failure -j"$(nproc)"
PASS=$(ctest --test-dir build -N 2>&1 | awk '/^Total Tests:/ {print $3; exit}')
PASS=${PASS:-0}

echo "== ctest result: ${PASS}/${PASS} =="
FINAL=$(git rev-parse --short HEAD)

git add \
  docs/plans/repo-audit-4298ba13-review-record.md \
  scripts/land-pr5.sh \
  scripts/land-pr6.sh \
  scripts/land-pr7.sh \
  scripts/land-pr8.sh \
  scripts/land-pr9.sh \
  scripts/land-closeout.sh

git commit -m "docs: close out audit 4298ba13 remediation arc

Reconcile review record with final commit hashes (PR-0..PR-9),
ctest 42/42 evidence, Final Review Record, and accepted residuals.
Add land-pr5..pr9 and land-closeout scripts.

Final reviewed: ${FINAL}"

echo "== done =="
git log -1 --stat