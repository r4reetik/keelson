// Container images: what Keelson keeps about an image it scanned with Trivy, the
// workloads that run images, the repositories that build them, and the shapes the
// Images page reads. An image is followed from the repository that builds it,
// through the registry that stores it, to the workloads that run it and how the
// internet reaches them. Portable: used by the server and the web.

import type { ProviderId } from "./providers.ts";
import type { Coverage, ScanMeta } from "./api.ts";

/** An image reference as a workload or a workflow writes it, taken apart. */
export interface ImageRef {
  /** The registry's host, lowercase: "docker.io" when the reference names none. */
  registry: string;
  /** The repository inside the registry: "library/nginx", "team/web". */
  repository: string;
  tag: string | null;
  /** "sha256:…" when the reference pins one. */
  digest: string | null;
}

/**
 * Reads an image reference the way container runtimes do: `nginx` is docker.io/library/nginx:latest, a first part with a
 * dot, a colon or "localhost" is a registry. Null for text that isn't a reference (an unresolved variable, a space).
 */
export function parseImageRef(text: string): ImageRef | null {
  let s = text.trim().replace(/^docker:\/\//, "");
  if (!s || /[\s${}<>"'`|]/.test(s)) return null;
  let digest: string | null = null;
  const at = s.indexOf("@");
  if (at >= 0) {
    digest = s.slice(at + 1).toLowerCase();
    s = s.slice(0, at);
    if (!/^[a-z0-9]+:[a-f0-9]{32,}$/.test(digest)) return null;
  }
  let tag: string | null = null;
  const slash = s.lastIndexOf("/");
  const colon = s.lastIndexOf(":");
  if (colon > slash) {
    tag = s.slice(colon + 1);
    s = s.slice(0, colon);
    if (!/^[\w][\w.-]{0,127}$/.test(tag)) return null;
  }
  const parts = s.split("/");
  let registry = "docker.io";
  if (parts.length > 1 && (/[.:]/.test(parts[0]) || parts[0] === "localhost")) registry = parts.shift()!.toLowerCase();
  if (registry === "index.docker.io" || registry === "registry-1.docker.io") registry = "docker.io";
  if (registry === "docker.io" && parts.length === 1) parts.unshift("library");
  const repository = parts.join("/").toLowerCase();
  if (!repository || !/^[a-z0-9]+([._-]+[a-z0-9]+)*(\/[a-z0-9]+([._-]+[a-z0-9]+)*)*$/.test(repository)) return null;
  return { registry, repository, tag: tag ?? (digest ? null : "latest"), digest };
}

/** "registry/repository", the name an image is known by whatever its tag. */
export const imageName = (r: Pick<ImageRef, "registry" | "repository">): string => `${r.registry}/${r.repository}`;

/** The reference to pull: by digest when one is known, else by tag. */
export const pullRef = (r: ImageRef): string => `${imageName(r)}${r.digest ? `@${r.digest}` : `:${r.tag ?? "latest"}`}`;

/** The kinds of registry Keelson tells apart by their host. */
export type RegistryKind = "ecr" | "ecr-public" | "acr" | "ghcr" | "dockerhub" | "other";

export const REGISTRY_LABEL: Record<RegistryKind, string> = {
  ecr: "Amazon ECR",
  "ecr-public": "Amazon ECR Public",
  acr: "Alibaba Cloud Container Registry",
  ghcr: "GitHub Container Registry",
  dockerhub: "Docker Hub",
  other: "Other registry",
};

/** The platform whose accounts hold a kind of registry; null for registries no connected account can own. */
export const REGISTRY_PROVIDER: Record<RegistryKind, ProviderId | null> = {
  ecr: "aws",
  "ecr-public": null,
  acr: "alibaba",
  ghcr: "github",
  dockerhub: null,
  other: null,
};

export function registryKind(host: string): RegistryKind {
  const h = host.toLowerCase();
  if (/^\d{12}\.dkr\.ecr(-fips)?\.[a-z0-9-]+\.amazonaws\.com(\.cn)?$/.test(h)) return "ecr";
  if (h === "public.ecr.aws") return "ecr-public";
  if (h === "ghcr.io") return "ghcr";
  if (h === "docker.io") return "dockerhub";
  if (/(^|[.-])registry(-vpc|-intl|-intl-vpc|-internal)?\.[a-z0-9-]+\.(cr\.)?aliyuncs\.com$/.test(h)) return "acr";
  return "other";
}

/** The AWS account and region in a private ECR registry's host; null for any other host. */
export function ecrHost(host: string): { account: string; region: string } | null {
  const m = /^(\d{12})\.dkr\.ecr(?:-fips)?\.([a-z0-9-]+)\.amazonaws\.com/.exec(host.toLowerCase());
  return m ? { account: m[1], region: m[2] } : null;
}

/**
 * Alibaba Cloud serves one registry under several hosts (public, VPC, international): "registry-vpc.cn-hangzhou.aliyuncs.com"
 * and "registry.cn-hangzhou.aliyuncs.com" hold the same images. Returns the host without the network it is reached over.
 */
export const canonicalRegistry = (host: string): string =>
  registryKind(host) === "acr" ? host.toLowerCase().replace(/registry-(vpc|intl-vpc|intl|internal)\./, "registry.") : host.toLowerCase();

export type VulnSeverity = "critical" | "high" | "medium" | "low" | "unknown";
export const VULN_SEVERITIES: VulnSeverity[] = ["critical", "high", "medium", "low", "unknown"];
export type VulnCounts = Record<VulnSeverity, number>;
export const NO_VULNS: VulnCounts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };

/** One known vulnerability in one package of an image, as Trivy matched it. */
export interface ImageVuln {
  id: string;
  pkg: string;
  version: string;
  /** Trivy's package type: "alpine", "debian", "npm", "node-pkg", "jar", "gobinary", "python-pkg"… */
  type: string;
  /** "os": a package of the operating system, which the base image brings. "app": a dependency of the application itself. */
  layer: "os" | "app";
  /** The file that records the package, for application packages ("app/package-lock.json"). */
  path: string | null;
  fixedIn: string | null;
  /** Trivy's status: "fixed", "affected", "will_not_fix", "fix_deferred", "end_of_life", "under_investigation". */
  status: string;
  severity: VulnSeverity;
  cvss: number | null;
  /** In CISA's catalog of vulnerabilities attackers are known to exploit. */
  kev: boolean;
  title: string;
  url: string | null;
  /** The package is in a layer of the base image the image is built on, not one its own build added. */
  base?: boolean;
}

export interface ImagePackage {
  name: string;
  version: string;
  type: string;
  layer: "os" | "app";
  path: string | null;
  purl: string | null;
  licenses: string[];
  /** It is in a layer of the base image, not one the image's own build added. */
  base?: boolean;
}

/**
 * A runtime an image is built around, as official images record it (NODE_VERSION, NGINX_VERSION…). Most are installed
 * from a tarball, so no package list names them and Trivy matches no vulnerability to them: Keelson says whether the
 * release line still gets fixes instead.
 */
export interface ImageRuntime {
  /** "Node.js", "nginx", "Python". */
  name: string;
  version: string;
  /** Its release line no longer gets fixes (endoflife.date); null when unknown. */
  eol: boolean | null;
  /** When the line stops getting fixes, when a date is set. */
  until: string | null;
  /** The newest release of its line, when this one is behind it. */
  latest: string | null;
}

/** A credential found inside an image: the kind and the file, never the value. */
export interface ImageSecret {
  /** What Trivy's rule calls it: "AWS Access Key ID", "GitHub Personal Access Token". */
  kind: string;
  /** The file in the image, or "environment variable NAME" for one set in the image's configuration. */
  where: string;
  /** Only the variable's name says so: its value matched no known credential format. */
  likely: boolean;
}

/** What Keelson keeps of one scanned image: its packages, their vulnerabilities and a few facts of its configuration. Never its files. */
export interface ImageScan {
  format: number;
  registry: string;
  repository: string;
  /** The digest Trivy scanned ("sha256:…"); null when the registry didn't say. */
  digest: string | null;
  os: { family: string; name: string; eol: boolean } | null;
  architecture: string | null;
  /** When the image was built. */
  created: string | null;
  size: number | null;
  /** The user its processes run as; "" or "root" or "0" is root. Null when the image doesn't say. */
  user: string | null;
  /** The repository it was built from and the commit, from its OCI labels (org.opencontainers.image.source and .revision). */
  source: string | null;
  revision: string | null;
  packages: ImagePackage[];
  vulns: ImageVuln[];
  secrets: ImageSecret[];
  /** When the image was pulled and read. One named by its digest is read once: it never changes. */
  scannedAt: string;
  /** Trivy's vulnerability database its vulnerabilities were last matched against (when that database was updated). */
  dbUpdated: string | null;
  /** The version of Trivy that read it. */
  trivy: string | null;
  /** The platform scanned ("linux/arm64") when it isn't Trivy's default, linux/amd64. */
  platform: string | null;
  /** Each layer's ID (the start of its diff ID), bottom first: an image built on another starts with that one's layers. */
  layers: string[];
  /** How many of those layers the base image brought, read from the build history; null when it can't be told. */
  baseLayers: number | null;
  /** The base image's name, when the image says so itself (org.opencontainers.image.base.name). */
  baseName: string | null;
  runtimes: ImageRuntime[];
}

/** How much an image is in use: reached from the internet, run by a workload, pulled lately by something Keelson can't see, or only stored. */
export type ImageUse = "internet" | "running" | "pulled" | "stored";
export const IMAGE_USE_LABEL: Record<ImageUse, string> = {
  internet: "Internet-facing",
  running: "Running",
  pulled: "Pulled lately",
  stored: "Stored only",
};
const USE_RANK: Record<ImageUse, number> = { internet: 3, running: 2, pulled: 1, stored: 0 };
export const moreInUse = (a: ImageUse, b: ImageUse): ImageUse => (USE_RANK[a] >= USE_RANK[b] ? a : b);
export const usageRank = (u: ImageUse): number => USE_RANK[u];

/** One image a scan knows of, as its snapshot lists it: where it is, its tags, and a summary of what Trivy found. */
export interface ImageEntry {
  /** Names the image's stored result in its account's cache ("img:…"). */
  key: string;
  registry: string;
  repository: string;
  /** The region of the registry, for registries that have one. */
  region: string | null;
  digest: string | null;
  tags: string[];
  pushedAt: string | null;
  /** When it was last pulled, where the registry records it (ECR). */
  pulledAt: string | null;
  /** Anyone can pull it: a public package, or a repository policy that allows everyone. Null when unknown. */
  public: boolean | null;
  /** The account's own registry holds it; false for an image a workload runs from somewhere else (Docker Hub…). */
  own: boolean;
  /** The GitHub repository a GitHub package is linked to ("org/name"). */
  linkedRepo?: string | null;
  /** The platforms a multi-platform image was built for ("linux/amd64", "linux/arm64"), where the registry says. */
  platforms?: string[];
  /** Why it was picked for scanning: "runs in a workload", "newest in its repository", "pulled lately". */
  why: string[];
  /** Null when it wasn't scanned: `error` says why, or it waits for a later scan. */
  summary: ImageSummary | null;
  error: string | null;
}

export interface ImageSummary {
  os: string | null;
  eol: boolean;
  created: string | null;
  size: number | null;
  packages: number;
  vulns: VulnCounts;
  /** Vulnerabilities with a fixed version, by severity. */
  fixable: VulnCounts;
  /** Known exploited vulnerabilities (CISA KEV), by ID. */
  exploited: string[];
  secrets: number;
  source: string | null;
  revision: string | null;
  scannedAt: string;
  /** Runtimes the image is built around, with whether each still gets fixes. Absent on scans from before Keelson read them. */
  runtimes?: ImageRuntime[];
  /** The base image's name, when the image says so itself. */
  baseName?: string | null;
  /** Packages, and vulnerabilities, that came with the base image; null when the base's layers can't be told apart. */
  fromBase?: { packages: number; vulns: number } | null;
}

/** What a scan stores about images: the list, and how the scan went. */
export interface ImagesSnapshot {
  images: ImageEntry[];
  /** Repositories in the account's own registries, and images in them. */
  repositories: number;
  /**
   * Images picked but not read by this scan, because its time ran out. They are read in the background once no scan is
   * running, and show with the scan that follows.
   */
  waiting: number;
  /** Images this scan pulled and read: new ones, and ones named by a tag that may have moved. Absent on scans from before Keelson counted them. */
  pulled?: number;
  /** Images this scan didn't pull: their stored packages were checked against the current database. */
  checked?: number;
  trivy: string | null;
  /** When Trivy's vulnerability database was last updated. */
  dbUpdated: string | null;
}

/** A workload that runs images, as its platform's scan publishes it for the entity. */
export interface WorkloadLink {
  provider: ProviderId;
  /** In the platform's words: "ECS service", "Lambda function", "ECI container group", "Function Compute function". */
  kind: string;
  name: string;
  /** What holds it: an ECS cluster. */
  group: string | null;
  /** The account's name, and its ID at the platform. */
  account: string;
  region: string;
  /** Its page in the platform's console. */
  link: string | null;
  containers: { name: string; image: string }[];
  /** Copies running, where the platform says. */
  running: number | null;
  /** The internet can reach it; null when Keelson can't tell. */
  internet: boolean | null;
  /** How, in words: "load balancer web-alb", "public address with tcp 8080 open to anyone". */
  via: string[];
  /** DNS names of the load balancers in front of it, so hostnames can be followed to it. */
  loadBalancers: string[];
}

/** An image a GitHub repository's workflows build and push. */
export interface ImageBuildLink {
  /** "org/name", lowercase. */
  repo: string;
  /** The registry's host, or null when the workflow takes it from a secret, a variable or a login step. */
  registry: string | null;
  /** The kind of registry the workflow signs in to, when the host itself is unknown. */
  kind: RegistryKind | null;
  repository: string;
  workflow: string;
}

/** Whether a build names an image: by registry and repository, or by repository alone when the workflow doesn't say the registry. */
export function buildMatches(b: ImageBuildLink, image: Pick<ImageRef, "registry" | "repository">): boolean {
  if (b.repository !== image.repository) return false;
  if (b.registry) return canonicalRegistry(b.registry) === canonicalRegistry(image.registry);
  return !b.kind || b.kind === registryKind(image.registry);
}

/** Whether a container's image reference names this image: same registry and repository, and its digest or one of its tags. */
export function runsImage(ref: ImageRef, image: Pick<ImageEntry, "registry" | "repository" | "digest" | "tags">): boolean {
  if (ref.repository !== image.repository || canonicalRegistry(ref.registry) !== canonicalRegistry(image.registry)) return false;
  if (ref.digest) return ref.digest === image.digest;
  return image.tags.includes(ref.tag ?? "latest");
}

// ---- the Images page

export interface ImageWorkloadRef {
  kind: string;
  name: string;
  group: string | null;
  account: string;
  provider: ProviderId;
  region: string;
  link: string | null;
  container: string;
  /** The reference as the workload writes it. */
  image: string;
  /** It names a tag, which can move: the workload may still run an older image. */
  byTag: boolean;
  internet: boolean | null;
  via: string[];
  /** Hostnames in the entity's DNS that point at a load balancer in front of it. */
  hosts: string[];
}

export interface ImageBuildRef {
  /** "org/name", lowercase. */
  repo: string;
  /** The repository's name as GitHub spells it, which its page in Keelson is under; absent when its organization isn't connected. */
  name?: string;
  /** The GitHub account in Keelson that holds it; null when the repository isn't in a connected organization. */
  accountId: string | null;
  /**
   * "label": the image says so itself. "package": GitHub links the package to it. "workflow": a workflow pushes an image
   * of this name. "name": nothing says, and one repository of the entity has the image repository's own name.
   */
  how: "label" | "package" | "workflow" | "name";
  workflow: string | null;
  revision: string | null;
}

export interface ImageFindingRef {
  fingerprint: string;
  checkId: string;
  severity: string;
  status: string;
  title: string;
}

/** An image in one line of the Images page. */
export interface ImageRow extends ImageEntry {
  /** Names the image for its page: the account that scanned it and its cache key. */
  id: string;
  accountId: string;
  account: string;
  provider: ProviderId;
  kind: RegistryKind;
  use: ImageUse;
  /** The workloads that run it. A list's rows carry the first few; `workloadCount` says how many there are. */
  workloads: ImageWorkloadRef[];
  workloadCount: number;
  builtBy: ImageBuildRef[];
  findings: ImageFindingRef[];
}

/** A workload in one line of the Images page's Running tab. */
export interface WorkloadRow extends Omit<WorkloadLink, "containers"> {
  accountId: string;
  hosts: string[];
  containers: {
    name: string;
    image: string;
    /** The scanned image it runs; null when Keelson didn't scan it (`unscanned` says why). */
    imageId: string | null;
    unscanned: string | null;
    vulns: VulnCounts | null;
    exploited: number;
  }[];
}

export interface ImagesSummary {
  /** Images Keelson knows of, and how many it scanned. */
  images: number;
  scanned: number;
  repositories: number;
  waiting: number;
  /** Images by how they're in use. */
  uses: Record<ImageUse, number>;
  /** Scanned images with at least one critical or high vulnerability that has a fix. */
  fixable: number;
  /** Images with a known exploited vulnerability, and how many of them the internet reaches. */
  exploited: number;
  exploitedInternet: number;
  secrets: number;
  /** Images on an operating system or a runtime past its end of life. */
  eol: number;
  /** Different components across the scanned images: each package, runtime and operating system at each version. */
  components: number;
  /** Of those, the ones with a known vulnerability or past their end of life. */
  componentsAtRisk: number;
  workloads: number;
  workloadsInternet: number;
  /** Workloads whose image Keelson didn't scan. */
  workloadsUnscanned: number;
  /** What the latest scans did: images pulled and read, and images only checked against the database. Null before Keelson counted them. */
  pulled: number | null;
  checked: number | null;
  trivy: string | null;
  dbUpdated: string | null;
}

/** GET /api/images: the page's numbers and what its filters offer. Rows come a page at a time from the list endpoints. */
export interface ImagesResponse {
  scan: ScanMeta | null;
  coverage: Coverage[];
  summary: ImagesSummary | null;
  /** The kinds of registry in view, and the package types among the components. */
  registries: RegistryKind[];
  types: string[];
}

/** An image as other rows name it. */
export interface ImageBrief {
  id: string;
  name: string;
  tag: string | null;
  use: ImageUse;
}

/** A vulnerability across the images in view. */
export interface ImageVulnRow {
  id: string;
  severity: VulnSeverity;
  cvss: number | null;
  kev: boolean;
  title: string;
  url: string | null;
  /** The packages it is in, each at each version, with the smallest version that fixes it. A list's rows carry the first few. */
  packages: { name: string; version: string; type: string; layer: "os" | "app"; fixedIn: string | null }[];
  packageCount: number;
  /** The images it is in, most exposed first. A list's rows carry the first few; `imageCount` says how many there are. */
  images: ImageBrief[];
  imageCount: number;
  /** Every occurrence is in a layer the base image brought. */
  base: boolean;
  /** The most exposed image it is in. */
  use: ImageUse;
}

/** What a component of an image is. */
export type ComponentKind = "os" | "runtime" | "os-package" | "app-package";
export const COMPONENT_KIND_LABEL: Record<ComponentKind, string> = {
  os: "Operating system",
  runtime: "Runtime",
  "os-package": "Operating system package",
  "app-package": "Application package",
};

/**
 * One component at one version across the images in view: the inventory of what the images are made of. A package, or
 * the operating system release an image is built on, or the runtime it is built around.
 */
export interface ComponentRow {
  /** Names the row: kind, type, name and version. */
  key: string;
  kind: ComponentKind;
  name: string;
  version: string;
  /** Trivy's package type ("alpine", "npm", "jar"…), the operating system's family, or "runtime". */
  type: string;
  licenses: string[];
  vulns: VulnCounts;
  worst: VulnSeverity | null;
  kev: boolean;
  /** The version that fixes every vulnerability with a fix; for a runtime, the newest release of its line. */
  fixedIn: string | null;
  /** Past its end of life (an operating system release, a runtime's release line); null where that isn't known or doesn't apply. */
  eol: boolean | null;
  /** It came with the base image wherever it is found. */
  base: boolean;
  images: ImageBrief[];
  imageCount: number;
  use: ImageUse;
}

export interface ImageList<T> {
  rows: T[];
  total: number;
}

/** Where a vulnerability in an image is fixed. */
export type FixPlace = "base" | "code" | "rebuild" | "build" | "app";
export const FIX_PLACES: FixPlace[] = ["code", "rebuild", "base", "build", "app"];
export const FIX_PLACE_LABEL: Record<FixPlace, string> = {
  base: "Base image",
  code: "In the code",
  rebuild: "Rebuild",
  build: "Image build",
  app: "Application",
};
/** The base image an image is built on, as far as Keelson can tell. */
export interface ImageBase {
  /** Its name: from the image's own label, else the FROM lines of the Dockerfiles in the repository that builds it. */
  names: string[];
  /** Where the names come from. */
  from: "label" | "dockerfile" | null;
  /** Another scanned image of the entity whose layers this one starts with: it is built on that image. */
  image: ImageBrief | null;
  /** Layers in all, and how many the base image brought; null when the build history doesn't show where the base ends. */
  layers: number;
  baseLayers: number | null;
  /** Packages and vulnerabilities that came with the base image. */
  packages: number;
  vulns: VulnCounts;
}

export const FIX_PLACE_HINT: Record<FixPlace, string> = {
  app: "A dependency of the application: upgrade it where the image is built. Keelson doesn't know which repository builds this image, or hasn't read its dependencies.",
  base: "It came with the base image: move the Dockerfile's FROM line to a newer tag of it, or to a release that has the fix, and rebuild.",
  code: "The repository still depends on a vulnerable version: upgrade it there, then rebuild.",
  rebuild: "The repository already depends on a fixed version: rebuild the image and deploy it.",
  build:
    "The image's own build adds it (a package the Dockerfile installs, or something it downloads), and it isn't among the repository's dependencies: update that step.",
};

export interface ImageVulnDetail extends ImageVuln {
  where: FixPlace;
  /** The version the repository that builds the image depends on now, when it has the package. */
  inCode: string | null;
}

/** One image, everything about it: what's in it, who builds it, where it runs. */
export interface ImageDetailResponse {
  image: ImageRow;
  scan: (Omit<ImageScan, "vulns" | "format" | "layers"> & { vulns: ImageVulnDetail[] }) | null;
  /** Vulnerabilities by where they are fixed. */
  places: Record<FixPlace, number>;
  /** What it is built on; null when it wasn't scanned. */
  base: ImageBase | null;
  /** Other scanned images of the same repository, newest first. */
  siblings: { id: string; tags: string[]; digest: string | null; pushedAt: string | null; vulns: VulnCounts | null; use: ImageUse }[];
}

export const IMAGE_STATUSES = {
  exploited: "Exploited",
  fixable: "Has a fix",
  nofix: "No fix yet",
} as const;
export type ImageVulnStatus = keyof typeof IMAGE_STATUSES;

/** Counts vulnerabilities by severity. */
export function countVulns(vulns: Pick<ImageVuln, "severity">[]): VulnCounts {
  const out = { ...NO_VULNS };
  for (const v of vulns) out[v.severity]++;
  return out;
}

/** "3 critical, 12 high" for the severities that count, or "" when there are none. */
export function vulnText(c: VulnCounts, levels: VulnSeverity[] = ["critical", "high"]): string {
  return levels
    .filter((l) => c[l] > 0)
    .map((l) => `${c[l]} ${l}`)
    .join(", ");
}

/** The first 12 characters of a digest's hash, as registries show it. */
export const shortDigest = (digest: string | null): string => (digest ? digest.replace(/^sha256:/, "").slice(0, 12) : "");
