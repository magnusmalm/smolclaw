#!/usr/bin/env bash
# Ensure CI dependencies on the self-hosted CI runner (no sudo).
set -euo pipefail

profile="${1:?usage: $0 <base|gcc|clang>}"

pkg_present() {
  dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed' && return 0
  dpkg-query -W -f='${Status}' "$1:amd64" 2>/dev/null | grep -q 'install ok installed'
}

require_pkgs() {
  local missing=()
  for p in "$@"; do
    pkg_present "$p" || missing+=("$p")
  done
  if ((${#missing[@]})); then
    echo "Host runner missing packages. Install once on the CI runner:"
    echo "  sudo apt-get install -y --no-install-recommends ${missing[*]}"
    exit 1
  fi
}

require_cmds() {
  local missing=()
  for c in "$@"; do
    command -v "$c" >/dev/null || missing+=("$c")
  done
  if ((${#missing[@]})); then
    echo "Host runner missing commands: ${missing[*]}"
    exit 1
  fi
}

ensure_kconfiglib() {
  if ! python3 -c 'import kconfiglib' 2>/dev/null; then
    pip3 install --user kconfiglib
  fi
}

base_pkgs=(
  cmake build-essential python3-pip
  libcurl4-openssl-dev libevent-dev libssl-dev
  libreadline-dev libsqlite3-dev
)

case "$profile" in
  base|gcc)
    require_pkgs "${base_pkgs[@]}"
    ensure_kconfiglib
    ;;
  clang)
    require_pkgs "${base_pkgs[@]}"
    require_cmds clang
    ensure_kconfiglib
    ;;
  *)
    echo "unknown profile: $profile" >&2
    exit 2
    ;;
esac

echo "Host deps OK ($profile)"