// Image fixtures for the providers' check cases: one scanned image that a workload
// the internet reaches runs, failing the image check asked for. The image checks are
// shared (src/core/image-checks.ts), so each provider's cases build on these.

import { summarize, IMAGE_FORMAT } from "../../src/core/images.ts";
import type { ImageEntry, ImageScan, ImagesSnapshot, ImageVuln, WorkloadLink } from "../../src/shared/images.ts";
import type { ProviderId } from "../../src/shared/providers.ts";

export const IMAGE_DIGEST = `sha256:${"ab".repeat(32)}`;

const vuln = (extra: Partial<ImageVuln>): ImageVuln => ({
  id: "CVE-2026-0001",
  pkg: "openssl",
  version: "1.1.1",
  type: "debian",
  layer: "os",
  path: null,
  fixedIn: "1.1.2",
  status: "fixed",
  severity: "critical",
  cvss: 9.8,
  kev: false,
  title: "A crafted handshake runs code.",
  url: null,
  ...extra,
});

export function imageScan(registry: string, repository: string, extra: Partial<ImageScan> = {}): ImageScan {
  return {
    format: IMAGE_FORMAT,
    registry,
    repository,
    digest: IMAGE_DIGEST,
    os: { family: "debian", name: "12.8", eol: false },
    architecture: "amd64",
    created: "2026-05-01T00:00:00Z",
    size: 1000,
    user: "app",
    source: null,
    revision: null,
    packages: [{ name: "openssl", version: "1.1.1", type: "debian", layer: "os", path: null, purl: null, licenses: [] }],
    vulns: [],
    secrets: [],
    scannedAt: "2026-06-01T00:00:00Z",
    dbUpdated: null,
    trivy: "0.0.0",
    platform: null,
    layers: [],
    baseLayers: null,
    baseName: null,
    runtimes: [],
    ...extra,
  };
}

/** What makes each image check fail, by its number. */
const FAILING: Record<1 | 2 | 3 | 4, Partial<ImageScan>> = {
  1: { vulns: [vuln({ kev: true })] },
  2: { vulns: [vuln({})] },
  3: { os: { family: "debian", name: "9.13", eol: true } },
  4: { secrets: [{ kind: "AWS Access Key ID", where: "/app/.env", likely: false }] },
};

/** An image in the account's own registry, run by a workload the internet reaches, failing image check `n` (0: none). */
export function imageCase(
  provider: ProviderId,
  registry: string,
  n: 0 | 1 | 2 | 3 | 4,
  entry: Partial<ImageEntry> = {},
): { snapshot: ImagesSnapshot; scans: Map<string, ImageScan>; workloads: WorkloadLink[] } {
  const repository = entry.repository ?? "web";
  const scan = imageScan(registry, repository, n ? FAILING[n] : {});
  const key = `img:${registry}/${repository}@${IMAGE_DIGEST}`;
  const image: ImageEntry = {
    key,
    registry,
    repository,
    region: null,
    digest: IMAGE_DIGEST,
    tags: ["1.0.0"],
    pushedAt: "2026-05-01T00:00:00Z",
    pulledAt: null,
    public: false,
    own: true,
    why: ["runs in a workload the internet reaches"],
    summary: summarize(scan),
    error: null,
    ...entry,
  };
  const workload: WorkloadLink = {
    provider,
    kind: "service",
    name: "web",
    group: null,
    account: "example",
    region: image.region ?? "",
    link: null,
    containers: [{ name: "web", image: `${registry}/${repository}:1.0.0` }],
    running: 1,
    internet: true,
    via: ["load balancer web"],
    loadBalancers: [],
  };
  return { snapshot: { images: [image], repositories: 1, waiting: 0, trivy: "0.0.0", dbUpdated: null }, scans: new Map([[key, scan]]), workloads: [workload] };
}
