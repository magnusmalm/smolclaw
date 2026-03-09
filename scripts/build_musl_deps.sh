#!/bin/bash
# Build all dependencies for a fully static musl-linked smolclaw binary.
# Builds cross-compiler toolchains from source via richfelker/musl-cross-make
# (GCC 14.2.0, musl 1.2.5, binutils 2.44, kernel 6.15 headers). Works for
# native x86_64 builds and cross-compilation to aarch64 / armv7l.
#
# Output: deps/musl-static-$ARCH/     (prefix with lib/*.a and include/)
#         deps/musl-toolchain-$ARCH/   (musl cross-compiler)
#
# Usage: ./scripts/build_musl_deps.sh [ARCH]
#   ARCH = x86_64 (default), aarch64, armv7l
#
# First build per architecture takes ~15-30 min (building GCC from source).
# Subsequent runs are cached — only needs to build once per architecture.
# The results are not checked into git.

set -euo pipefail

# -- Target architecture ------------------------------------------------------

ARCH="${1:-$(uname -m)}"

case "${ARCH}" in
    x86_64)
        MUSL_TRIPLE="x86_64-linux-musl"
        OPENSSL_TARGET="linux-x86_64"
        ;;
    aarch64)
        MUSL_TRIPLE="aarch64-linux-musl"
        OPENSSL_TARGET="linux-aarch64"
        ;;
    armv7l)
        MUSL_TRIPLE="armv7l-linux-musleabihf"
        OPENSSL_TARGET="linux-armv4"
        ;;
    *)
        echo "Error: unsupported architecture '${ARCH}'" >&2
        echo "Supported: x86_64, aarch64, armv7l" >&2
        exit 1
        ;;
esac

MUSL_CC="${MUSL_TRIPLE}-gcc"

echo "=== Building musl static deps for ${ARCH} (${MUSL_TRIPLE}) ==="

# -- Versions and checksums ---------------------------------------------------

ZLIB_VERSION="1.3.2"
ZLIB_SHA256="bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16"
ZLIB_URL="https://zlib.net/zlib-${ZLIB_VERSION}.tar.gz"

OPENSSL_VERSION="3.0.16"
OPENSSL_SHA256="57e03c50feab5d31b152af2b764f10379aecd8ee92f16c985983ce4a99f7ef86"
OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"

LIBEVENT_VERSION="2.1.12"
LIBEVENT_SHA256="92e6de1be9ec176428fd2367677e61ceffc2ee1cb119035037a27d346b0403bb"
LIBEVENT_URL="https://github.com/libevent/libevent/releases/download/release-${LIBEVENT_VERSION}-stable/libevent-${LIBEVENT_VERSION}-stable.tar.gz"

CURL_VERSION="7.88.1"
CURL_SHA256="1dae31b2a7c1fe269de99c0c31bb488346aab3459b5ffca909d6938249ae415f"
CURL_URL="https://curl.se/download/curl-${CURL_VERSION}.tar.xz"

# -- Paths (arch-suffixed) ----------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TOOLCHAIN_DIR="${PROJECT_DIR}/deps/musl-toolchain-${ARCH}"
BUILD_DIR="${PROJECT_DIR}/deps/musl-build-${ARCH}"
PREFIX="${PROJECT_DIR}/deps/musl-static-${ARCH}"
NPROC="$(nproc)"

# The musl toolchain always produces musl-linked binaries (not glibc), so
# autotools configure cannot run test programs even on a native x86_64 host.
# Always pass --host to tell autotools this is a cross-compile.
CROSS_HOST="--host=${MUSL_TRIPLE}"

# armv7l (32-bit ARM) needs libatomic for OpenSSL's 64-bit atomic operations
EXTRA_LIBS=""
if [ "${ARCH}" = "armv7l" ]; then
    EXTRA_LIBS="-latomic"
fi

# -- Idempotency check -------------------------------------------------------

REQUIRED_LIBS=(
    "${PREFIX}/lib/libz.a"
    "${PREFIX}/lib/libssl.a"
    "${PREFIX}/lib/libcrypto.a"
    "${PREFIX}/lib/libevent.a"
    "${PREFIX}/lib/libevent_openssl.a"
    "${PREFIX}/lib/libcurl.a"
)

all_exist=true
for lib in "${REQUIRED_LIBS[@]}"; do
    if [ ! -f "$lib" ]; then
        all_exist=false
        break
    fi
done

if $all_exist; then
    echo "All musl static libraries already built in ${PREFIX}/"
    echo "Delete ${PREFIX}/ to rebuild."
    exit 0
fi

# -- Helper functions ---------------------------------------------------------

download() {
    local url="$1" dest="$2" expected="$3" algo="${4:-sha256}"
    if [ ! -f "$dest" ]; then
        echo "  Downloading $(basename "$dest")..."
        curl -fSL -o "$dest" "$url"
    fi
    echo "  Verifying $(basename "$dest") (${algo})..."
    echo "${expected}  ${dest}" | "${algo}sum" -c -
}

# =============================================================================
# Step 1: Build musl cross-compiler toolchain via musl-cross-make
# =============================================================================

# musl-cross-make versions — pinned for reproducibility
MCM_REPO="https://github.com/richfelker/musl-cross-make.git"
MCM_COMMIT="e5147dde912478dd32ad42a25003e82d4f5733aa"  # 2025-07-11
MCM_DIR="${PROJECT_DIR}/deps/musl-cross-make"

MCM_GCC_VER="14.2.0"
MCM_MUSL_VER="1.2.5"
MCM_BINUTILS_VER="2.44"
MCM_LINUX_VER="6.15.7"

setup_toolchain() {
    local cc="${TOOLCHAIN_DIR}/bin/${MUSL_CC}"
    if [ -x "$cc" ]; then
        echo "=== Toolchain already set up: ${cc} ==="
        return
    fi

    echo "=== Building musl-cross-make toolchain for ${ARCH} ==="
    echo "  Target: ${MUSL_TRIPLE}"
    echo "  GCC ${MCM_GCC_VER}, musl ${MCM_MUSL_VER}, binutils ${MCM_BINUTILS_VER}, linux ${MCM_LINUX_VER}"
    echo "  This takes ~15-30 minutes on first build..."

    # Clone musl-cross-make (shared across architectures)
    if [ ! -d "${MCM_DIR}/.git" ]; then
        echo "  Cloning musl-cross-make..."
        git clone "${MCM_REPO}" "${MCM_DIR}"
    fi
    (cd "${MCM_DIR}" && git checkout -q "${MCM_COMMIT}")

    # Generate config.mak
    local config_mak="${MCM_DIR}/config.mak"
    cat > "$config_mak" <<CONFIGEOF
TARGET = ${MUSL_TRIPLE}
GCC_VER = ${MCM_GCC_VER}
MUSL_VER = ${MCM_MUSL_VER}
BINUTILS_VER = ${MCM_BINUTILS_VER}
LINUX_VER = ${MCM_LINUX_VER}
OUTPUT = ${TOOLCHAIN_DIR}
CONFIGEOF

    # armv7l: target ARMv7-A hardware (RPi 2+), not the default ARMv5TE
    if [ "${ARCH}" = "armv7l" ]; then
        cat >> "$config_mak" <<'ARMEOF'
COMMON_CONFIG += --with-arch=armv7-a --with-fpu=vfpv3-d16 --with-float=hard
ARMEOF
    fi

    echo "  Building toolchain (output: ${TOOLCHAIN_DIR})..."
    make -C "${MCM_DIR}" -j"${NPROC}"
    make -C "${MCM_DIR}" install

    # Clean build artifacts to save disk space (keeps installed toolchain)
    make -C "${MCM_DIR}" clean

    # Verify the compiler works
    if [ ! -x "$cc" ]; then
        echo "Error: compiler not found after build: ${cc}" >&2
        exit 1
    fi
    echo "int main(){return 0;}" | "$cc" -x c - -o /dev/null -static
    echo "  Toolchain ready: ${cc}"
}

# =============================================================================
# Step 2: Build zlib
# =============================================================================

build_zlib() {
    if [ -f "${PREFIX}/lib/libz.a" ]; then
        echo "=== zlib already built ==="
        return
    fi

    echo "=== Building zlib ${ZLIB_VERSION} ==="
    local tarball="${BUILD_DIR}/zlib-${ZLIB_VERSION}.tar.gz"
    download "$ZLIB_URL" "$tarball" "$ZLIB_SHA256"

    rm -rf "${BUILD_DIR}/zlib-${ZLIB_VERSION}"
    tar -xf "$tarball" -C "${BUILD_DIR}"
    cd "${BUILD_DIR}/zlib-${ZLIB_VERSION}"

    CC="${TOOLCHAIN_DIR}/bin/${MUSL_CC}" \
    AR="${TOOLCHAIN_DIR}/bin/${MUSL_TRIPLE}-ar" \
    RANLIB="${TOOLCHAIN_DIR}/bin/${MUSL_TRIPLE}-ranlib" \
    CFLAGS="-fPIC -O2" \
    ./configure \
        --prefix="${PREFIX}" \
        --static \
        > /dev/null

    make -j"${NPROC}" > /dev/null
    make install > /dev/null
    echo "  Built: ${PREFIX}/lib/libz.a"
}

# =============================================================================
# Step 3: Build OpenSSL
# =============================================================================

build_openssl() {
    if [ -f "${PREFIX}/lib/libssl.a" ] && [ -f "${PREFIX}/lib/libcrypto.a" ]; then
        echo "=== OpenSSL already built ==="
        return
    fi

    echo "=== Building OpenSSL ${OPENSSL_VERSION} ==="
    local tarball="${BUILD_DIR}/openssl-${OPENSSL_VERSION}.tar.gz"
    download "$OPENSSL_URL" "$tarball" "$OPENSSL_SHA256"

    rm -rf "${BUILD_DIR}/openssl-${OPENSSL_VERSION}"
    tar -xf "$tarball" -C "${BUILD_DIR}"
    cd "${BUILD_DIR}/openssl-${OPENSSL_VERSION}"

    CC="${TOOLCHAIN_DIR}/bin/${MUSL_CC}" \
    AR="${TOOLCHAIN_DIR}/bin/${MUSL_TRIPLE}-ar" \
    RANLIB="${TOOLCHAIN_DIR}/bin/${MUSL_TRIPLE}-ranlib" \
    ./Configure \
        "${OPENSSL_TARGET}" \
        --prefix="${PREFIX}" \
        --libdir=lib \
        --openssldir="${PREFIX}/ssl" \
        --with-zlib-include="${PREFIX}/include" \
        --with-zlib-lib="${PREFIX}/lib" \
        no-shared \
        no-dso \
        no-engine \
        no-tests \
        -fPIC \
        > /dev/null

    make -j"${NPROC}" > /dev/null 2>&1
    make install_sw > /dev/null 2>&1
    echo "  Built: ${PREFIX}/lib/libssl.a, libcrypto.a"
}

# =============================================================================
# Step 4: Build libevent
# =============================================================================

build_libevent() {
    if [ -f "${PREFIX}/lib/libevent.a" ] && [ -f "${PREFIX}/lib/libevent_openssl.a" ]; then
        echo "=== libevent already built ==="
        return
    fi

    echo "=== Building libevent ${LIBEVENT_VERSION} ==="
    local tarball="${BUILD_DIR}/libevent-${LIBEVENT_VERSION}-stable.tar.gz"
    download "$LIBEVENT_URL" "$tarball" "$LIBEVENT_SHA256"

    rm -rf "${BUILD_DIR}/libevent-${LIBEVENT_VERSION}-stable"
    tar -xf "$tarball" -C "${BUILD_DIR}"
    cd "${BUILD_DIR}/libevent-${LIBEVENT_VERSION}-stable"

    CC="${TOOLCHAIN_DIR}/bin/${MUSL_CC}" \
    AR="${TOOLCHAIN_DIR}/bin/${MUSL_TRIPLE}-ar" \
    RANLIB="${TOOLCHAIN_DIR}/bin/${MUSL_TRIPLE}-ranlib" \
    CFLAGS="-fPIC -O2 -I${PREFIX}/include" \
    LDFLAGS="-L${PREFIX}/lib" \
    ./configure \
        ${CROSS_HOST} \
        --prefix="${PREFIX}" \
        --enable-static \
        --disable-shared \
        --enable-openssl \
        --disable-samples \
        --disable-libevent-regress \
        > /dev/null

    make -j"${NPROC}" > /dev/null
    make install > /dev/null
    echo "  Built: ${PREFIX}/lib/libevent.a, libevent_openssl.a"
}

# =============================================================================
# Step 5: Build curl
# =============================================================================

build_curl() {
    if [ -f "${PREFIX}/lib/libcurl.a" ]; then
        echo "=== curl already built ==="
        return
    fi

    echo "=== Building curl ${CURL_VERSION} ==="
    local tarball="${BUILD_DIR}/curl-${CURL_VERSION}.tar.xz"
    download "$CURL_URL" "$tarball" "$CURL_SHA256"

    rm -rf "${BUILD_DIR}/curl-${CURL_VERSION}"
    tar -xf "$tarball" -C "${BUILD_DIR}"
    cd "${BUILD_DIR}/curl-${CURL_VERSION}"

    CC="${TOOLCHAIN_DIR}/bin/${MUSL_CC}" \
    AR="${TOOLCHAIN_DIR}/bin/${MUSL_TRIPLE}-ar" \
    RANLIB="${TOOLCHAIN_DIR}/bin/${MUSL_TRIPLE}-ranlib" \
    CFLAGS="-fPIC -O2" \
    LDFLAGS="-L${PREFIX}/lib ${EXTRA_LIBS}" \
    LIBS="${EXTRA_LIBS}" \
    CPPFLAGS="-I${PREFIX}/include" \
    PKG_CONFIG_PATH="${PREFIX}/lib/pkgconfig" \
    ./configure \
        ${CROSS_HOST} \
        --prefix="${PREFIX}" \
        --enable-static \
        --disable-shared \
        --with-openssl="${PREFIX}" \
        --with-zlib="${PREFIX}" \
        --enable-proxy \
        --enable-mime \
        --disable-ldap \
        --disable-ldaps \
        --disable-ftp \
        --disable-ftps \
        --disable-tftp \
        --disable-pop3 \
        --disable-imap \
        --disable-smtp \
        --disable-gopher \
        --disable-mqtt \
        --disable-dict \
        --disable-telnet \
        --disable-rtsp \
        --disable-smb \
        --disable-manual \
        --disable-docs \
        --disable-ntlm \
        --disable-tls-srp \
        --disable-doh \
        --without-nghttp2 \
        --without-libidn2 \
        --without-libpsl \
        --without-brotli \
        --without-zstd \
        --without-libssh2 \
        --without-librtmp \
        --without-gssapi \
        > /dev/null

    make -j"${NPROC}" > /dev/null
    make install > /dev/null
    echo "  Built: ${PREFIX}/lib/libcurl.a"
}

# =============================================================================
# Main
# =============================================================================

mkdir -p "${BUILD_DIR}" "${PREFIX}"

setup_toolchain
build_zlib
build_openssl
build_libevent
build_curl

echo ""
echo "=== All musl static dependencies built for ${ARCH} ==="
echo "Prefix:    ${PREFIX}/"
echo "Toolchain: ${TOOLCHAIN_DIR}/bin/${MUSL_CC}"
echo ""
for lib in "${REQUIRED_LIBS[@]}"; do
    ls -lh "$lib"
done
echo ""
echo "Next: cmake --preset musl  (or musl-aarch64 / musl-armv7)"
