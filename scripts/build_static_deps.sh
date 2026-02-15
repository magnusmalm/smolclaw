#!/bin/bash
# Build minimal static libcurl with OpenSSL backend for smolclaw static linking.
# Output: deps/static/ (prefix with lib/libcurl.a and include/curl/)
#
# Usage: ./scripts/build_static_deps.sh
#
# Only needs to run once. The result is not checked into git.

set -euo pipefail

CURL_VERSION="7.88.1"
CURL_SHA256="1dae31b2a7c1fe269de99c0c31bb488346aab3459b5ffca909d6938249ae415f"
CURL_URL="https://curl.se/download/curl-${CURL_VERSION}.tar.xz"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${PROJECT_DIR}/deps/static-build"
PREFIX="${PROJECT_DIR}/deps/static"
TARBALL="${BUILD_DIR}/curl-${CURL_VERSION}.tar.xz"

echo "=== Building static libcurl ${CURL_VERSION} ==="

# Skip if already built
if [ -f "${PREFIX}/lib/libcurl.a" ]; then
    echo "Already built: ${PREFIX}/lib/libcurl.a"
    echo "Delete deps/static/ to rebuild."
    exit 0
fi

mkdir -p "${BUILD_DIR}"

# Download
if [ ! -f "${TARBALL}" ]; then
    echo "Downloading curl-${CURL_VERSION}..."
    curl -fSL -o "${TARBALL}" "${CURL_URL}"
fi

# Verify SHA256
echo "Verifying checksum..."
echo "${CURL_SHA256}  ${TARBALL}" | sha256sum -c -

# Extract
echo "Extracting..."
tar -xf "${TARBALL}" -C "${BUILD_DIR}"

cd "${BUILD_DIR}/curl-${CURL_VERSION}"

# Configure: HTTP/HTTPS only, OpenSSL backend, static library
echo "Configuring..."
./configure \
    --prefix="${PREFIX}" \
    --enable-static \
    --disable-shared \
    --with-openssl \
    --with-zlib \
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

# Build and install
echo "Building..."
make -j"$(nproc)" > /dev/null

echo "Installing to ${PREFIX}..."
make install > /dev/null

echo ""
echo "=== Done ==="
echo "Static libcurl: ${PREFIX}/lib/libcurl.a"
ls -lh "${PREFIX}/lib/libcurl.a"
