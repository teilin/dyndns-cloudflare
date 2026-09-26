# syntax=docker/dockerfile:1

###############################################################################
# Stage 1: build — download official Zig 0.16.0 and compile a static musl binary
###############################################################################
FROM alpine:3.21 AS build

# Zig build tools: curl/xz to fetch+extract the official Zig 0.16.0 tarball.
RUN apk add --no-cache curl xz

ENV ZIG_VERSION=0.16.0
ENV ZIG_TRIPLE=zig-x86_64-linux-0.16.0

RUN curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/${ZIG_TRIPLE}.tar.xz" -o /tmp/zig.tar.xz \
 && tar -xJf /tmp/zig.tar.xz -C /opt \
 && ln -s "/opt/${ZIG_TRIPLE}/zig" /usr/local/bin/zig \
 && rm /tmp/zig.tar.xz

WORKDIR /src
COPY build.zig ./
COPY src/ ./src/

# Build a fully static binary so no dynamic libc is needed at runtime.
# -Dtarget=x86_64-linux-musl produces a statically-linked executable.
RUN zig build -Doptimize=ReleaseSmall -Dtarget=x86_64-linux-musl --summary all

###############################################################################
# Stage 2: runtime — minimal Alpine with CA certs (required for HTTPS/TLS)
###############################################################################
FROM alpine:3.21

# ca-certificates provides /etc/ssl/cert.pem which Zig's HTTP client loads to
# verify TLS. Without it, requests to api.ipify.org / api.cloudflare.com fail.
RUN apk add --no-cache ca-certificates tzdata \
 && mkdir -p /config

# --no-rootfs? keep it simple; run as root (minimal image, single purpose).
COPY --from=build /src/zig-out/bin/ipwatch /usr/local/bin/ipwatch

# The updater persists the last-known public IP here across container restarts.
VOLUME /config

ENV CLOUDFLARE_API_TOKEN=""
ENV CLOUDFLARE_ZONE_ID=""
ENV CLOUDFLARE_RECORD_ID=""
ENV CLOUDFLARE_RECORD_NAME=""

ENTRYPOINT ["/usr/local/bin/ipwatch"]