# syntax=docker/dockerfile:1

# Keelson ships only as this image. It is kept small: the final stage is Alpine with
# the Node.js binary and the C++ runtime it needs, nothing else from Node's image
# (no npm, Yarn or Corepack, which also keeps their dependencies out of image scans),
# and the scanners Keelson runs for dependencies (Syft, Grype and Grant).

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

# Anchore's Syft, Grype and Grant, which make each repository's SBOM and judge its
# vulnerabilities and licenses (src/core/anchore.ts). Their release archives for the
# target platform are checked against the SHA-256 sums published with each release;
# to move to a newer one, change its version and both sums together. They are Go
# binaries without C dependencies, so they run on Alpine as they are. Downloading
# runs on the build machine's platform: nothing here executes the binaries.
FROM --platform=$BUILDPLATFORM alpine:3.24 AS anchore
ARG TARGETARCH
ARG SYFT_VERSION=1.57.2 \
    SYFT_AMD64=ad92bd3ec1b94a3df01d4d0aec199afa9c42b72e86da436ff5f837914d32706b \
    SYFT_ARM64=8efe605309c98798e1ee0cffdcf8c05ca26819b4cd44c0b03650f1e963e9bdb6 \
    GRYPE_VERSION=0.122.1 \
    GRYPE_AMD64=f1ba7e2917ee1395618de20a98da0aa7c0fb1788927797651047c50502a37538 \
    GRYPE_ARM64=819e5be3d9516432fedb7b6b56df7306c3a16607606dfc05826eefbb00e471da \
    GRANT_VERSION=0.8.0 \
    GRANT_AMD64=d0e545dd4ce42566c1a0fc97c355777a4ad0375f67508359ade40d1d80a11074 \
    GRANT_ARM64=be8f254217797aeedbc2211fbf9f6160b3f871891a511b2fddb1b2326fed44d6
RUN set -eu; mkdir -p /out; \
    fetch() { \
      tool=$1 version=$2; \
      case "$TARGETARCH" in amd64) sum=$3 ;; arm64) sum=$4 ;; *) echo "No $tool build for $TARGETARCH" >&2; exit 1 ;; esac; \
      file="${tool}_${version}_linux_${TARGETARCH}.tar.gz"; \
      wget -q -O "/tmp/$file" "https://github.com/anchore/$tool/releases/download/v$version/$file"; \
      echo "$sum  /tmp/$file" | sha256sum -c -; \
      tar -xzf "/tmp/$file" -C /out "$tool"; \
      rm "/tmp/$file"; \
    }; \
    fetch syft "$SYFT_VERSION" "$SYFT_AMD64" "$SYFT_ARM64"; \
    fetch grype "$GRYPE_VERSION" "$GRYPE_AMD64" "$GRYPE_ARM64"; \
    fetch grant "$GRANT_VERSION" "$GRANT_AMD64" "$GRANT_ARM64"

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
# On the PATH, where Keelson finds them without KEELSON_SYFT, KEELSON_GRYPE or KEELSON_GRANT.
# Grype's database (about 3 GB) isn't in the image: it is downloaded into /data/tools on the first scan.
COPY --from=anchore /out/ /usr/local/bin/
# Fails the build, not the first start or scan, when a binary can't run here.
RUN node --version && syft version >/dev/null && grype version >/dev/null && grant version >/dev/null
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
