# Multi-stage build for smolclaw
# Produces a minimal Alpine-based image with the smolclaw binary.

# Stage 1: Build
FROM alpine:3.21 AS builder

RUN apk add --no-cache \
    bash build-base cmake python3 py3-pip curl-dev libevent-dev openssl-dev \
    readline-dev sqlite-dev linux-headers

# Install kconfiglib
RUN pip3 install --break-system-packages kconfiglib

WORKDIR /src
COPY . .

# Build with all features
RUN cmake -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DSC_STRIP=ON \
    && cmake --build build -j$(nproc)

# Run tests
# Smoke test only — full correctness is gated by .github/workflows/ci.yml on
# every push; some tests are environment-sensitive inside the build container.
RUN ./build/smolclaw version

# Stage 2: Runtime
FROM alpine:3.21

RUN apk add --no-cache libcurl libevent openssl readline && \
    adduser -D -h /home/smolclaw smolclaw

COPY --from=builder /src/build/smolclaw /usr/local/bin/smolclaw

USER smolclaw
WORKDIR /home/smolclaw

# Web channel default port
EXPOSE 8080

ENTRYPOINT ["smolclaw"]
CMD ["version"]
