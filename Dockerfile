# syntax=docker/dockerfile:1

# Keelson ships only as this image. It is kept small: the final stage is Alpine with
# the Node.js binary and the C++ runtime it needs, nothing else from Node's image
# (no npm, Yarn or Corepack, which also keeps their dependencies out of image scans),
# and the scanners Keelson runs (Syft, Grype, Grant, Trivy and Amass).

# The build runs on the build machine's own platform, even for the arm64 image: its
# output is plain JavaScript, and so are the runtime dependencies (test/env.test.ts
# checks), so nothing here has to run under emulation.
FROM --platform=$BUILDPLATFORM node:26-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
COPY web ./web
RUN npm run build \
 && npm prune --omit=dev --no-audit --no-fund \
 && find node_modules \( -name '*.d.ts' -o -name '*.d.mts' -o -name '*.d.cts' -o -name '*.map' -o -name '*.md' \) -delete \
 && find node_modules -type d -empty -delete \
 && rm -f node_modules/.package-lock.json

# The scanners Keelson runs beside itself: Anchore's Syft, Grype and Grant for each
# repository's SBOM, vulnerabilities and licenses (src/core/anchore.ts), Aqua's Trivy
# for container images (src/core/trivy.ts), and OWASP Amass for Sonar's subdomains
# (src/providers/internet/amass.ts). Their release archives for the target platform
# are checked against the SHA-256 sums published with each release; to move to a
# newer one, change its version and both sums together. They are Go binaries without
# C dependencies, so they run on Alpine as they are. Downloading runs on the build
# machine's platform: nothing in this stage executes them.
FROM --platform=$BUILDPLATFORM alpine:3.24 AS scanners
ARG TARGETARCH
ARG SYFT_VERSION=1.57.2 \
    SYFT_AMD64=ad92bd3ec1b94a3df01d4d0aec199afa9c42b72e86da436ff5f837914d32706b \
    SYFT_ARM64=8efe605309c98798e1ee0cffdcf8c05ca26819b4cd44c0b03650f1e963e9bdb6 \
    GRYPE_VERSION=0.122.1 \
    GRYPE_AMD64=f1ba7e2917ee1395618de20a98da0aa7c0fb1788927797651047c50502a37538 \
    GRYPE_ARM64=819e5be3d9516432fedb7b6b56df7306c3a16607606dfc05826eefbb00e471da \
    GRANT_VERSION=0.8.0 \
    GRANT_AMD64=d0e545dd4ce42566c1a0fc97c355777a4ad0375f67508359ade40d1d80a11074 \
    GRANT_ARM64=be8f254217797aeedbc2211fbf9f6160b3f871891a511b2fddb1b2326fed44d6 \
    TRIVY_VERSION=0.76.2 \
    TRIVY_AMD64=bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf \
    TRIVY_ARM64=ab9d51f86e6a5fb936f605faff6b593ac51bc378fff4d3e8b9d58358b9c367c3 \
    AMASS_VERSION=5.1.3 \
    AMASS_AMD64=4c12b725e4ce4981ece93a5e1566bd7391be1f349468856a79d31a43012ae201 \
    AMASS_ARM64=02316f4e5703420cd86890c3c61f6d56ed10277d2bfea076d4e5cfd1a6b6099a
# Each archive is unpacked in a folder of its own and only the tool's binary is kept,
# wherever the archive puts it (Amass's sits in a folder named after the platform).
RUN set -eu; mkdir -p /out; \
    case "$TARGETARCH" in amd64) TRIVY_ARCH=64bit ;; arm64) TRIVY_ARCH=ARM64 ;; *) echo "No scanners for $TARGETARCH" >&2; exit 1 ;; esac; \
    fetch() { \
      tool=$1 url=$2; \
      if [ "$TARGETARCH" = amd64 ]; then sum=$3; else sum=$4; fi; \
      mkdir "/tmp/$tool"; \
      wget -q -O "/tmp/$tool.tar.gz" "$url"; \
      echo "$sum  /tmp/$tool.tar.gz" | sha256sum -c -; \
      tar -xzf "/tmp/$tool.tar.gz" -C "/tmp/$tool"; \
      find "/tmp/$tool" -type f -name "$tool" -exec mv {} /out/ \; ; \
      test -f "/out/$tool" || { echo "No $tool binary in its archive" >&2; exit 1; }; \
    }; \
    fetch syft "https://github.com/anchore/syft/releases/download/v$SYFT_VERSION/syft_${SYFT_VERSION}_linux_$TARGETARCH.tar.gz" "$SYFT_AMD64" "$SYFT_ARM64"; \
    fetch grype "https://github.com/anchore/grype/releases/download/v$GRYPE_VERSION/grype_${GRYPE_VERSION}_linux_$TARGETARCH.tar.gz" "$GRYPE_AMD64" "$GRYPE_ARM64"; \
    fetch grant "https://github.com/anchore/grant/releases/download/v$GRANT_VERSION/grant_${GRANT_VERSION}_linux_$TARGETARCH.tar.gz" "$GRANT_AMD64" "$GRANT_ARM64"; \
    fetch trivy "https://github.com/aquasecurity/trivy/releases/download/v$TRIVY_VERSION/trivy_${TRIVY_VERSION}_Linux-$TRIVY_ARCH.tar.gz" "$TRIVY_AMD64" "$TRIVY_ARM64"; \
    fetch amass "https://github.com/owasp-amass/amass/releases/download/v$AMASS_VERSION/amass_linux_$TARGETARCH.tar.gz" "$AMASS_AMD64" "$AMASS_ARM64"; \
    chmod 755 /out/*

# Node.js for the target platform. Keep its Alpine version the same as the stage below,
# so the binary and the libraries installed there come from the same release.
FROM node:26-alpine3.24 AS node

FROM alpine:3.24
LABEL org.opencontainers.image.source="https://github.com/r4reetik/keelson" \
      org.opencontainers.image.description="One place for the security of your whole infrastructure. Self-hosted and read-only: checks your cloud, edge and hosting platforms, finds the risks between them, and tracks every finding until it's fixed." \
      org.opencontainers.image.licenses="MIT"
# The libraries are the ones Node's own Alpine image installs for its binary
# (github.com/nodejs/docker-node, 26/alpine3.24/Dockerfile). The node user has uid
# 1000, as in Node's own images, so /data volumes made with earlier images stay readable.
RUN apk add --no-cache libatomic libstdc++ \
 && addgroup -g 1000 node \
 && adduser -u 1000 -G node -s /bin/sh -D node \
 && mkdir -p /data && chown node:node /data && chmod 700 /data
COPY --from=node /usr/local/bin/node /usr/local/bin/node
# On the PATH, where Keelson finds them without KEELSON_SYFT, KEELSON_GRYPE, KEELSON_GRANT,
# KEELSON_TRIVY or KEELSON_AMASS. Grype's and Trivy's databases aren't in the image: they
# are downloaded into /data/tools on the first scan that needs them. Amass's engine
# listens on port 4000 inside the container while Sonar runs; it isn't published.
COPY --from=scanners /out/ /usr/local/bin/
# Fails the build, not the first start or scan, when a binary can't run here.
RUN node --version && syft version >/dev/null && grype version >/dev/null && grant version >/dev/null \
 && trivy --version >/dev/null && test -x /usr/local/bin/amass
# Only the install marker: in the image, Keelson defaults to 0.0.0.0 and /data itself (src/env.ts).
ENV NODE_ENV=production \
    KEELSON_INSTALL=docker
WORKDIR /app
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
USER node
VOLUME ["/data"]
EXPOSE 4317
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD ["node", "-e", "fetch('http://127.0.0.1:' + (process.env.KEELSON_PORT || process.env.PORT || 4317) + '/api/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"]
CMD ["node", "dist/bin.js", "--no-open"]
