#!/usr/bin/env bash
# Build musl-static release artifacts for x86_64 and aarch64.
# Used locally and by .gitea/workflows/release.yml on v* tag push.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TAG="${RELEASE_TAG:-${GITHUB_REF_NAME:-}}"
if [[ -z "$TAG" ]]; then
  echo "Set RELEASE_TAG or GITHUB_REF_NAME (e.g. v1.0.0)" >&2
  exit 1
fi

OUTDIR="${RELEASE_OUTDIR:-$ROOT/dist/release}"
QEMU_AARCH64="${QEMU_AARCH64:-qemu-aarch64-static}"
JOBS="$(nproc)"
ARCHES=(x86_64 aarch64)

log() { printf '==> %s\n' "$*"; }

# Reuse pre-built musl trees on the host runner (symlink, no copy).
# Set MUSL_HOST_DEPS in act_runner config (e.g. ~/devel/smolclaw/deps).
seed_host_musl_deps() {
  local host="${MUSL_HOST_DEPS:-}"
  local name

  [[ -n "$host" && -d "$host" ]] || return 0

  mkdir -p "$ROOT/deps"
  for name in musl-cross-make \
      musl-build-x86_64 musl-build-aarch64 \
      musl-toolchain-x86_64 musl-toolchain-aarch64 \
      musl-static-x86_64 musl-static-aarch64; do
    if [[ -d "$host/$name" && ! -e "$ROOT/deps/$name" ]]; then
      log "Linking deps/$name from host musl cache"
      ln -s "$host/$name" "$ROOT/deps/$name"
    fi
  done
}

require_qemu() {
  if ! command -v "$QEMU_AARCH64" >/dev/null; then
    echo "Missing $QEMU_AARCH64 (needed for aarch64 release tests)" >&2
    echo "  sudo apt-get install -y qemu-user-static" >&2
    exit 1
  fi
}

musl_build() {
  local arch="$1"
  local build_dir="$2"
  local toolchain="$ROOT/deps/musl-toolchain-${arch}"
  local prefix="$ROOT/deps/musl-static-${arch}"
  local triple
  local compiler

  if [[ ! -d "$toolchain/bin" ]]; then
    echo "Missing toolchain dir: $toolchain" >&2
    exit 1
  fi

  triple="$(basename "$(ls "$toolchain/bin/"*-gcc | head -1)" | sed 's/-gcc$//')"
  compiler="$toolchain/bin/${triple}-gcc"

  cmake -B "$build_dir" \
    -DCMAKE_BUILD_TYPE=Release \
    -DSC_MUSL_STATIC=ON \
    -DSC_STRIP=ON \
    -DCMAKE_VERBOSE_MAKEFILE=OFF \
    -DCMAKE_C_COMPILER="$compiler" \
    -DCMAKE_PREFIX_PATH="$prefix"

  cmake --build "$build_dir" -j"$JOBS"
}

run_tests() {
  local arch="$1"
  local build_dir="$2"

  if [[ "$arch" == "x86_64" ]]; then
    log "Running native ctest ($arch)"
    ctest --test-dir "$build_dir" --output-on-failure
    return
  fi

  require_qemu
  log "Running qemu tests ($arch via $QEMU_AARCH64)"

  local total=0 pass=0 fail=0
  local test_bin
  while IFS= read -r test_bin; do
    total=$((total + 1))
    if "$QEMU_AARCH64" "$test_bin"; then
      pass=$((pass + 1))
    else
      fail=$((fail + 1))
      echo "FAIL: $(basename "$test_bin")" >&2
    fi
  done < <(find "$build_dir" -maxdepth 1 -name 'test_*' -executable -type f | sort)

  log "Tests: $pass/$total passed"
  if (( fail > 0 )); then
    exit 1
  fi
}

package_arch() {
  local arch="$1"
  local build_dir="$2"
  local artifact="smolclaw-${TAG}-linux-${arch}"

  mkdir -p "$OUTDIR"
  rm -rf "$OUTDIR/$artifact"
  mkdir -p "$OUTDIR/$artifact"
  cp "$build_dir/smolclaw" "$OUTDIR/$artifact/"
  cp LICENSE README.md "$OUTDIR/$artifact/"
  (
    cd "$OUTDIR"
    tar czf "${artifact}.tar.gz" "$artifact"
    sha256sum "${artifact}.tar.gz" > "${artifact}.tar.gz.sha256"
  )
  log "Packaged $OUTDIR/${artifact}.tar.gz"
}

rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

seed_host_musl_deps

for arch in "${ARCHES[@]}"; do
  log "Building musl deps ($arch)"
  MUSL_DEPS_QUIET=1 ./scripts/build_musl_deps.sh "$arch"

  build_dir="build-release-${arch}"
  rm -rf "$build_dir"

  log "Configure + build ($arch)"
  musl_build "$arch" "$build_dir"

  ls -lh "$build_dir/smolclaw"
  file "$build_dir/smolclaw"

  run_tests "$arch" "$build_dir"
  package_arch "$arch" "$build_dir"
done

log "Release artifacts in $OUTDIR"
ls -la "$OUTDIR"