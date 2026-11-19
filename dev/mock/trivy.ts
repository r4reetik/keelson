// A stand-in for Aqua's Trivy and for CISA's list of known exploited
// vulnerabilities, so image scanning runs end to end in tests and
// `npm run dev -- --mock` without the real tool, its database or any registry.
// It answers for a few fictional images with documents shaped like Trivy 0.76's
// JSON report (checked against a real run), including the parts Keelson must
// drop: environment variable values, the text a secret rule matched, and labels
// other than the source repository. The packages and CVE IDs are fictional.
//
// Like the real one it also writes a bill of materials for a report (with the
// parts Keelson drops from it: Trivy's description of the image, where labels
// are, and its list of vulnerabilities) and matches one against its database
// again, which pulls nothing.

import { eol } from "../../src/core/eol.ts";
import { kev } from "../../src/core/kev.ts";
import { trivy, TrivyError, trivyFailure, type RegistryLogin } from "../../src/core/trivy.ts";

export interface MockTrivyOptions {
  /** Pretend Trivy isn't installed. */
  missing?: boolean;
  /** Called with each image Trivy is asked for, the login it was given and the platform asked for. */
  onImage?: (ref: string, login: RegistryLogin | null, platform: string | null) => void;
  /** References (regex) that aren't images: build attestations a registry lists beside them. */
  notImage?: RegExp[];
  /** Images (regex on the reference) built for arm64 only, when the registry's index didn't say so. */
  armOnly?: RegExp[];
  /** Images (regex on the reference) the registry refuses to hand over. */
  deny?: RegExp[];
  /** Print something that isn't a report. */
  garbled?: boolean;
  /** CISA's list can't be read. */
  noKev?: boolean;
  /** When Trivy's database was last updated. Scans made with the same one have nothing new to match. */
  db?: string;
  /** Vulnerabilities published since the images were built, by the image (regex on its reference) they are in. */
  published?: { image: RegExp; vuln: { id: string; pkg: string; severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"; fix?: string; title: string } }[];
  /** Called with the report Trivy is asked to write a bill of materials for. */
  onSbom?: (report: string) => void;
  /** Called with the name of each image whose bill of materials is matched against the database again. */
  onMatch?: (name: string) => void;
  /** Matching a bill of materials fails: the image is read again. */
  matchFails?: boolean;
}

/** Values the mock puts where Keelson must not keep them. */
export const MOCK_IMAGE_ENV_SECRET = "mock-image-env-value-DO-NOT-STORE";
export const MOCK_IMAGE_FILE_SECRET = "AKIAMOCKIMAGEFILE0001";
export const MOCK_IMAGE_BUILD_SECRET = "mock-build-arg-token-DO-NOT-STORE";
export const MOCK_IMAGE_LABEL = "mock-maintainer-label-DO-NOT-STORE";
/** The one fictional CVE on the mock's list of known exploited vulnerabilities. */
export const MOCK_KEV = "CVE-2026-91001";

export const MOCK_DIGEST = {
  web: `sha256:${"a1".repeat(32)}`,
  /** The web image is an index: its one platform's image and its build attestation are listed beside it, untagged. */
  webArm: `sha256:${"a2".repeat(32)}`,
  webAttestation: `sha256:${"a3".repeat(32)}`,
  webOld: `sha256:${"a0".repeat(32)}`,
  api: `sha256:${"b2".repeat(32)}`,
  tools: `sha256:${"c3".repeat(32)}`,
  ghcrWeb: `sha256:${"d4".repeat(32)}`,
  shipper: `sha256:${"e5".repeat(32)}`,
  acrShop: `sha256:${"f6".repeat(32)}`,
};

interface MockVuln {
  id: string;
  pkg: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  fix?: string;
  title: string;
}
interface MockImage {
  /** Matches the reference Trivy is given: the repository, and a tag or digest when several images share it. */
  match: RegExp;
  digest: string;
  os: { Family: string; Name: string; EOSL?: boolean };
  created: number;
  labels?: Record<string, string>;
  env?: string[];
  user?: string;
  /** Operating system packages, as "name@version". */
  osPackages: string[];
  /** Its layers by name, when it has no base of its own to speak of (a base image itself). */
  layers?: string[];
  /** The layers the base image brought, by name; the image's own build adds one more. Without it the history shows no base. */
  base?: string[];
  /** Packages its own build added to the operating system's (apt-get install in its Dockerfile): the rest came with the base. */
  added?: string[];
  /** The application's packages by the file that records them. */
  app?: { target: string; type: string; packages: string[] }[];
  vulns: MockVuln[];
  secrets?: { target: string; rule: string; title: string }[];
}

const DAY = 86_400_000;
const WEB_VULNS: MockVuln[] = [
  { id: MOCK_KEV, pkg: "mock-openssl@1.1.1d-0", severity: "CRITICAL", fix: "1.1.1n-0", title: "A crafted handshake runs code in the server." },
  { id: "CVE-2026-91002", pkg: "mock-zlib@1.2.11-1", severity: "HIGH", title: "Memory corruption when inflating a crafted stream." },
  { id: "CVE-2026-90003", pkg: "mock-router@1.4.0", severity: "HIGH", fix: "1.4.2", title: "Encoded slashes bypass route guards." },
  { id: "CVE-2026-91010", pkg: "mock-path-match@0.1.0", severity: "CRITICAL", fix: "0.1.5", title: "A crafted path reads files outside the web root." },
  { id: "CVE-2026-91011", pkg: "mock-supervisor@4.0.0", severity: "MEDIUM", fix: "4.0.3", title: "The control socket accepts commands from any local user." },
];

const IMAGES: MockImage[] = [
  // The web service's image: an end-of-life base, a known exploited vulnerability, and a credential left in a file.
  {
    match: /\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com\/web(@sha256:a1|:1\.4\.2$)/,
    digest: MOCK_DIGEST.web,
    os: { Family: "debian", Name: "10.13", EOSL: true },
    created: 20,
    labels: {
      "org.opencontainers.image.source": "https://github.com/mock-org/web",
      "org.opencontainers.image.revision": "0123456789abcdef0123456789abcdef01234567",
      maintainer: MOCK_IMAGE_LABEL,
    },
    // An official Node.js image underneath: its release line reached its end, and it brought the operating system's packages.
    env: ["PATH=/usr/local/bin:/usr/bin", "NODE_ENV=production", "NODE_VERSION=18.20.8", `SESSION_SECRET=${MOCK_IMAGE_ENV_SECRET}`],
    osPackages: ["mock-openssl@1.1.1d-0", "mock-zlib@1.2.11-1", "mock-libc@2.28-10"],
    base: ["debian-10", "node-18"],
    added: ["mock-zlib@1.2.11-1"],
    app: [
      { target: "app/package-lock.json", type: "npm", packages: ["mock-router@1.4.0", "mock-path-match@0.1.0", "mock-xml-parser@0.9.4"] },
      { target: "Python", type: "python-pkg", packages: ["mock-supervisor@4.0.0"] },
    ],
    vulns: WEB_VULNS,
    secrets: [{ target: "/app/.env", rule: "aws-access-key-id", title: "AWS Access Key ID" }],
  },
  // The build before it, still tagged: nothing runs it.
  {
    match: /\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com\/web(@sha256:a0|:1\.4\.1$)/,
    digest: MOCK_DIGEST.webOld,
    os: { Family: "debian", Name: "10.13", EOSL: true },
    created: 60,
    osPackages: ["mock-openssl@1.1.1d-0", "mock-zlib@1.2.11-1"],
    vulns: WEB_VULNS.slice(0, 2),
  },
  // The worker's image: a supported base, one high vulnerability in a Go binary.
  {
    match: /\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com\/api[@:]/,
    digest: MOCK_DIGEST.api,
    os: { Family: "alpine", Name: "3.20.3" },
    created: 6,
    user: "app",
    osPackages: ["mock-musl@1.2.5-r0", "mock-busybox@1.36.1-r29"],
    // Built on the team's own "tools" image, which is in the same registry.
    base: ["tools-1", "tools-2"],
    app: [{ target: "usr/local/bin/api", type: "gobinary", packages: ["mock.example/httpkit@v1.2.0", "mock.example/log@v0.3.0"] }],
    vulns: [
      { id: "CVE-2026-90007", pkg: "mock.example/httpkit@v1.2.0", severity: "HIGH", fix: "1.2.3", title: "Request smuggling through duplicate headers." },
    ],
  },
  // An image nothing runs or pulls any more.
  {
    match: /\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com\/tools[@:]/,
    digest: MOCK_DIGEST.tools,
    os: { Family: "ubuntu", Name: "18.04", EOSL: true },
    created: 420,
    osPackages: ["mock-openssl@1.1.1d-0", "mock-curl@7.58.0-2"],
    layers: ["tools-1", "tools-2"],
    vulns: [
      { id: MOCK_KEV, pkg: "mock-openssl@1.1.1d-0", severity: "CRITICAL", fix: "1.1.1n-0", title: "A crafted handshake runs code in the server." },
      { id: "CVE-2026-91020", pkg: "mock-curl@7.58.0-2", severity: "CRITICAL", fix: "7.58.0-9", title: "A redirect leaks credentials to another host." },
    ],
  },
  // The public package the web repository publishes to GitHub's registry.
  {
    match: /^ghcr\.io\/mock-org\/web[@:]/,
    digest: MOCK_DIGEST.ghcrWeb,
    os: { Family: "alpine", Name: "3.20.3" },
    created: 3,
    labels: {
      "org.opencontainers.image.source": "https://github.com/mock-org/web",
      "org.opencontainers.image.revision": "89abcdef0123456789abcdef0123456789abcdef",
      "org.opencontainers.image.base.name": "docker.io/library/node:22-alpine",
    },
    env: ["PATH=/usr/local/bin:/usr/bin", "NODE_VERSION=22.11.0"],
    osPackages: ["mock-musl@1.2.5-r0"],
    app: [{ target: "app/package-lock.json", type: "npm", packages: ["mock-router@1.4.0", "mock-path-match@0.2.0", "mock-xml-parser@0.9.1"] }],
    vulns: [
      { id: "CVE-2026-90003", pkg: "mock-router@1.4.0", severity: "HIGH", fix: "1.4.2", title: "Encoded slashes bypass route guards." },
      {
        id: "CVE-2026-90001",
        pkg: "mock-xml-parser@0.9.1",
        severity: "CRITICAL",
        fix: "0.9.4",
        title: "External entities let a request read files on the server.",
      },
    ],
  },
  // A sidecar from Docker Hub.
  {
    match: /^docker\.io\/mock\/log-shipper[@:]/,
    digest: MOCK_DIGEST.shipper,
    os: { Family: "alpine", Name: "3.19.1" },
    created: 150,
    osPackages: ["mock-musl@1.2.4-r2", "mock-busybox@1.36.1-r15"],
    vulns: [
      {
        id: "CVE-2026-91030",
        pkg: "mock-busybox@1.36.1-r15",
        severity: "MEDIUM",
        fix: "1.36.1-r19",
        title: "A crafted archive overwrites files outside its folder.",
      },
    ],
  },
  // The shop's image in Alibaba Cloud Container Registry.
  {
    match: /^mock-registry-registry(-vpc)?\.cn-hangzhou\.cr\.aliyuncs\.com\/shop\/storefront[@:]/,
    digest: MOCK_DIGEST.acrShop,
    os: { Family: "alpine", Name: "3.16.2", EOSL: true },
    created: 200,
    osPackages: ["mock-musl@1.2.3-r0", "mock-openssl@1.1.1d-0"],
    app: [{ target: "app/requirements.txt", type: "pip", packages: ["mock-celery@4.0.0"] }],
    vulns: [
      { id: MOCK_KEV, pkg: "mock-openssl@1.1.1d-0", severity: "CRITICAL", fix: "1.1.1n-0", title: "A crafted handshake runs code in the server." },
      { id: "CVE-2026-91040", pkg: "mock-celery@4.0.0", severity: "HIGH", fix: "4.0.2", title: "A crafted task message runs code in the worker." },
    ],
    secrets: [{ target: "/app/certs/server.key", rule: "private-key", title: "Asymmetric Private Key" }],
  },
];

const purl = (type: string, name: string, version: string) =>
  `pkg:${type === "gobinary" ? "golang" : type === "python-pkg" || type === "pip" ? "pypi" : ["npm", "node-pkg"].includes(type) ? "npm" : "deb/mock"}/${name}@${version}`;

function report(ref: string, img: MockImage): string {
  const split = (p: string) => {
    const at = p.lastIndexOf("@");
    return { name: p.slice(0, at), version: p.slice(at + 1) };
  };
  // Layers, bottom first: the base image's, then the one the image's own build adds.
  const diff = (name: string) => `sha256:${Buffer.from(name.padEnd(32, "-")).toString("hex").slice(0, 64)}`;
  const own = diff(`build-${img.digest.slice(7, 15)}`);
  const layers = img.layers ? img.layers.map(diff) : [...(img.base ?? []).map(diff), own];
  const layerOf = (p: string, app: boolean) => ((app || img.added?.includes(p) || !img.base) && !img.layers ? own : layers[0]);
  const pkgs = (list: string[], type: string, filePath?: string, app = false) =>
    list.map((p) => {
      const { name, version } = split(p);
      return {
        ID: p,
        Name: name,
        Version: version,
        Identifier: { PURL: purl(type, name, version), UID: "0000000000000000" },
        Licenses: ["MIT"],
        Layer: { DiffID: layerOf(p, app) },
        ...(filePath ? { FilePath: filePath } : {}),
        InstalledFiles: ["usr/lib/mock.so"],
      };
    });
  const known = [...img.vulns, ...(current.published ?? []).filter((p) => p.image.test(ref)).map((p) => p.vuln)];
  const vulnsFor = (list: string[], app = false) =>
    known
      .filter((v) => list.includes(v.pkg))
      .map((v) => {
        const { name, version } = split(v.pkg);
        return {
          Layer: { DiffID: layerOf(v.pkg, app) },
          VulnerabilityID: v.id,
          PkgID: v.pkg,
          PkgName: name,
          InstalledVersion: version,
          ...(v.fix ? { FixedVersion: v.fix } : {}),
          Status: v.fix ? "fixed" : "affected",
          PrimaryURL: `https://avd.aquasec.com/nvd/${v.id.toLowerCase()}`,
          Title: v.title,
          Description: `${v.title} (a fictional advisory)`,
          Severity: v.severity,
          CVSS: { nvd: { V3Vector: "CVSS:3.1/AV:N", V3Score: v.severity === "CRITICAL" ? 9.8 : v.severity === "HIGH" ? 7.5 : 5.3 } },
          References: ["https://mock.example/advisory"],
        };
      });
  const name = ref.split(/[@:](?=[^/]*$)/)[0];
  return JSON.stringify({
    SchemaVersion: 2,
    Trivy: { Version: "0.0.0-mock" },
    ArtifactName: ref,
    ArtifactType: "container_image",
    Metadata: {
      Size: 80_000_000,
      OS: img.os,
      ImageID: "sha256:0000",
      RepoTags: [ref],
      RepoDigests: [`${name}@${img.digest}`],
      ImageConfig: {
        architecture: "amd64",
        created: new Date(Date.now() - img.created * DAY).toISOString(),
        os: "linux",
        rootfs: { type: "layers", diff_ids: layers },
        // As a build records it: the base image's layers and its CMD, then the image's own steps.
        history: [
          ...(img.layers ?? img.base ?? []).map((name) => ({ created_by: `ADD ${name}.tar.gz / # buildkit` })),
          ...(img.base ? [{ created_by: 'CMD ["node"]', empty_layer: true }] : []),
          ...(img.layers ? [] : [{ created_by: "COPY .env /app/.env" }]),
          ...(img.secrets ? [{ created_by: `RUN npm config set //registry.mock.example/:_authToken=${MOCK_IMAGE_BUILD_SECRET}`, empty_layer: true }] : []),
          { created_by: 'CMD ["/app/start"]', empty_layer: true },
        ],
        config: {
          Env: img.env ?? ["PATH=/usr/bin"],
          Cmd: ["/app/start"],
          ...(img.user ? { User: img.user } : {}),
          ...(img.labels ? { Labels: img.labels } : {}),
        },
      },
    },
    Results: [
      {
        Target: `${ref} (${img.os.Family} ${img.os.Name})`,
        Class: "os-pkgs",
        Type: img.os.Family,
        Packages: pkgs(img.osPackages, img.os.Family),
        Vulnerabilities: vulnsFor(img.osPackages),
      },
      ...(img.app ?? []).map((a) => ({
        Target: a.target,
        Class: "lang-pkgs",
        Type: a.type,
        // A language package nothing in the application names came with the base image (a tool it ships).
        Packages: pkgs(a.packages, a.type, /[/.]/.test(a.target) ? undefined : `usr/lib/${a.packages[0].split("@")[0]}/METADATA`, /[/.]/.test(a.target)),
        Vulnerabilities: vulnsFor(a.packages, /[/.]/.test(a.target)),
      })),
      ...(img.secrets ?? []).map((s) => ({
        Target: s.target,
        Class: "secret",
        Secrets: [
          {
            RuleID: s.rule,
            Category: "AWS",
            Severity: "CRITICAL",
            Title: s.title,
            StartLine: 3,
            EndLine: 3,
            // Trivy masks the match, but the lines around it are the file's own text.
            Code: {
              Lines: [
                { Number: 2, Content: "DATABASE_URL=postgres://mock" },
                { Number: 3, Content: `AWS_ACCESS_KEY_ID=${MOCK_IMAGE_FILE_SECRET}` },
              ],
            },
            Match: "AWS_ACCESS_KEY_ID=********************",
          },
        ],
      })),
    ],
  });
}

/** A CycloneDX document as Trivy's `convert` writes one for a report, with the parts Keelson must drop from it. */
function cyclonedx(reportText: string): string {
  const doc = JSON.parse(reportText);
  const components = [
    { "bom-ref": "os", type: "operating-system", name: doc.Metadata?.OS?.Family, version: doc.Metadata?.OS?.Name },
    ...(doc.Results ?? []).flatMap((r: any) =>
      (r.Packages ?? []).map((p: any) => ({
        "bom-ref": `${r.Target}#${p.ID}`,
        type: "library",
        name: p.Name,
        version: p.Version,
        purl: p.Identifier?.PURL,
        properties: [
          { name: "aquasecurity:trivy:PkgType", value: r.Type },
          { name: "aquasecurity:trivy:LayerDiffID", value: p.Layer?.DiffID },
        ],
      })),
    ),
  ];
  return JSON.stringify({
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: "urn:uuid:00000000-0000-4000-8000-000000000000",
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      component: {
        "bom-ref": "image",
        type: "container",
        name: doc.ArtifactName,
        // Trivy writes every label of the image it scanned here.
        properties: [{ name: "aquasecurity:trivy:Labels:maintainer", value: MOCK_IMAGE_LABEL }],
      },
    },
    components,
    dependencies: [{ ref: "image", dependsOn: components.map((c) => c["bom-ref"]) }],
    vulnerabilities: [{ id: "CVE-2026-00000", description: MOCK_IMAGE_LABEL }],
  });
}

/** Trivy's report for a bill of materials: the same packages, matched against today's database. No configuration, no files. */
function matched(sbomText: string): string {
  const name = String(JSON.parse(sbomText)?.metadata?.component?.name ?? "");
  current.onMatch?.(name);
  const img = IMAGES.find((i) => i.match.test(name));
  if (current.matchFails || !img) throw new TrivyError("Trivy failed: SBOM decode error");
  const doc = JSON.parse(report(name, img));
  return JSON.stringify({
    SchemaVersion: 2,
    ArtifactName: "/tmp/image.cdx.json",
    ArtifactType: "cyclonedx",
    Metadata: { OS: doc.Metadata.OS },
    Results: doc.Results.filter((r: any) => r.Class !== "secret"),
  });
}

/**
 * Set while the mock runs: `beforeImage` is awaited before an image is handed over, so a test can hold a pull and the
 * mock dev server can make one slow enough to watch.
 */
export const mockTrivy: { beforeImage: ((ref: string) => Promise<void> | void) | null } = { beforeImage: null };

let installed = 0;
let restore: (() => void) | null = null;
let current: MockTrivyOptions = {};

/** Replaces Trivy and CISA's list until the returned function is called. The provider mocks each install it; the last options given win. */
export function installMockTrivy(o: MockTrivyOptions = {}): () => void {
  current = o;
  if (!installed++) {
    const real = { ...trivy };
    const realKev = kev.load;
    trivy.path = () => (current.missing ? null : "/mock/trivy");
    trivy.updateDb = async () => {};
    // The database is published every six hours.
    trivy.version = async () => ({
      version: "0.0.0-mock",
      dbUpdated: current.db ?? new Date(Math.floor(Date.now() / (6 * 3600_000)) * 6 * 3600_000).toISOString(),
    });
    trivy.sbom = async (_bin, reportText) => {
      current.onSbom?.(reportText);
      return cyclonedx(reportText);
    };
    trivy.match = async (_bin, sbomText) => matched(sbomText);
    trivy.image = async (_bin, ref, login, _toolDir, platform = null) => {
      current.onImage?.(ref, login, platform);
      await mockTrivy.beforeImage?.(ref);
      const denied = () =>
        Object.assign(new TrivyError("The registry answered DENIED: requested access to the resource is denied"), { denied: true, image: true });
      if (current.deny?.some((re) => re.test(ref))) throw denied();
      // As the real one fails on them (src/core/trivy.ts tells them apart by Trivy's own words).
      if (current.notImage?.some((re) => re.test(ref)) || ref.includes(MOCK_DIGEST.webAttestation))
        throw trivyFailure('Trivy failed: * remote error: unsupported artifact type "application/vnd.docker.attestation.manifest.v1+json" for image');
      if (current.armOnly?.some((re) => re.test(ref)) && platform !== "linux/arm64")
        throw trivyFailure("Trivy failed: * remote error: no child with platform linux/amd64 in index");
      // Like a registry: a private one refuses a pull without a login.
      if (/\.dkr\.ecr\.|\.cr\.aliyuncs\.com/.test(ref) && !login?.password) throw denied();
      if (current.garbled) return "1 image scanned\n";
      const img = IMAGES.find((i) => i.match.test(ref));
      if (!img) throw Object.assign(new TrivyError("The registry answered MANIFEST_UNKNOWN: manifest unknown"), { missing: true, image: true });
      return report(ref, img);
    };
    kev.load = async () => {
      if (current.noKev) throw new Error("CISA's list of known exploited vulnerabilities couldn't be read: the mock says so");
      return new Set([MOCK_KEV]);
    };
    const realEol = eol.load;
    // Support dates as endoflife.date gives them: Node.js 18 ended, 22 has not and has a newer patch release.
    eol.load = async () => ({
      nodejs: [
        { cycle: "22", eol: new Date(Date.now() + 400 * DAY).toISOString().slice(0, 10), latest: "22.12.1" },
        { cycle: "18", eol: "2025-04-30", latest: "18.20.8" },
      ],
    });
    restore = () => {
      Object.assign(trivy, real);
      kev.load = realKev;
      eol.load = realEol;
    };
  }
  return () => {
    if (!--installed) {
      restore?.();
      restore = null;
      current = {};
    }
  };
}
