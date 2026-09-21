# syntax=docker/dockerfile:1
# ==============================================================================
# Elise Multi-Arch Dockerfile
# Supports linux/amd64 and linux/arm64
# ==============================================================================

FROM --platform=$BUILDPLATFORM rust:1.80-alpine AS builder

ARG TARGETPLATFORM
ARG TARGETARCH

RUN apk add --no-cache musl-dev gcc make perl git ca-certificates

WORKDIR /build
COPY . .

RUN case "$TARGETARCH" in \
        amd64) RUST_TARGET="x86_64-unknown-linux-musl" ;; \
        arm64) RUST_TARGET="aarch64-unknown-linux-musl" ;; \
        *) echo "Unsupported target: $TARGETARCH"; exit 1 ;; \
    esac && \
    rustup target add $RUST_TARGET && \
    cargo build --release --target $RUST_TARGET && \
    cp target/$RUST_TARGET/release/elise /build/elise-binary

# Final runtime image
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata iptables

WORKDIR /etc/elise

# Copy executable and example configurations
COPY --from=builder /build/elise-binary /usr/local/bin/elise
COPY example/elise.conf /etc/elise/elise.conf
COPY example/dns.yml /etc/elise/dns.yml
COPY example/blockList /etc/elise/blockList
COPY example/whiteList /etc/elise/whiteList

EXPOSE 443 80 8443 2083 2087 2096 8080/tcp 8080/udp

VOLUME ["/etc/elise", "/var/log/elise"]

ENTRYPOINT ["/usr/local/bin/elise"]
CMD ["run", "-c", "/etc/elise/elise.conf"]
