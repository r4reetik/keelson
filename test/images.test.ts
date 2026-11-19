// Container images: reading references, which images a scan picks, what is kept
// of Trivy's report (and what never is), the registry login Trivy is given, and
// the Images page's join of an image with the workloads that run it, the
// repository that builds it and where each vulnerability is fixed, inside one
// entity. Trivy and CISA's list are the mock's (dev/mock/trivy.ts); one test runs
// the real runner against a stand-in script to check what it hands a scanner.

import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { installMockAlibaba, MOCK_ALIBABA_ACCOUNT, MOCK_ALIBABA_POD_SECRET, MOCK_ALIBABA_REGISTRY_PASSWORD, MOCK_ALIBABA_TOKEN } from "../dev/mock/alibaba.ts";
import { installMockAws, MOCK_AWS_ACCOUNT, MOCK_AWS_REGISTRY_PASSWORD, MOCK_AWS_TOKEN, mockAws } from "../dev/mock/aws.ts";
import { installMockCloudflare } from "../dev/mock/cloudflare.ts";
import { installMockGithub, MOCK_GITHUB_ACCOUNT } from "../dev/mock/github.ts";
import { seedAccount, seedAlibaba, seedAws, seedGithub } from "../dev/mock/accounts.ts";
import {
  MOCK_DIGEST,
  MOCK_IMAGE_BUILD_SECRET,
  MOCK_IMAGE_ENV_SECRET,
  MOCK_IMAGE_FILE_SECRET,
  MOCK_IMAGE_LABEL,
  MOCK_KEV,
  mockTrivy,
  type MockTrivyOptions,
} from "../dev/mock/trivy.ts";
import { scannerCpus } from "../src/core/anchore.ts";
import { supportOf } from "../src/core/eol.ts";
import { buildersOf, imageCheckMeta } from "../src/core/image-checks.ts";
import {
  baseLayerCount,
  imageCacheKey,
  INDEX_KEY,
  inScanOrder,
  parseReport,
  pickImages,
  readInScan,
  reduceReport,
  runtimesIn,
  sbomCacheKey,
  scanImages,
  type ImageTarget,
  type RegistryImage,
} from "../src/core/images.ts";
import { trivy, trivyFailure, trivyLimits, TrivyError } from "../src/core/trivy.ts";
import { imageBuilds } from "../src/providers/github/sbom/builds.ts";
import { fixPlaces } from "../src/server/images.ts";
import type { RepoDependencies } from "../src/shared/dependencies.ts";
import {
  buildMatches,
  canonicalRegistry,
  parseImageRef,
  registryKind,
  runsImage,
  type ComponentRow,
  type ImageEntry,
  type ImageList,
  type ImageRow,
  type ImageScan,
  type ImagesResponse,
  type ImagesSnapshot,
  type ImageVuln,
  type ImageVulnRow,
  type WorkloadLink,
  type WorkloadRow,
} from "../src/shared/images.ts";
import type { Finding } from "../src/shared/api.ts";
import { makeApp } from "./helpers/app.ts";

const ECR = `${MOCK_AWS_ACCOUNT}.dkr.ecr.eu-west-1.amazonaws.com`;
/** A GitHub Actions expression, as a workflow file writes it. */
const E = (expr: string) => `\${{ ${expr} }}`;

test("image references are read the way container runtimes read them", () => {
  assert.deepEqual(parseImageRef("nginx"), { registry: "docker.io", repository: "library/nginx", tag: "latest", digest: null });
  assert.deepEqual(parseImageRef("team/app:1.2"), { registry: "docker.io", repository: "team/app", tag: "1.2", digest: null });
  assert.deepEqual(parseImageRef("ghcr.io/Org/App:v1"), { registry: "ghcr.io", repository: "org/app", tag: "v1", digest: null });
  const pinned = parseImageRef(`${ECR}/web@sha256:${"ab".repeat(32)}`)!;
  assert.equal(pinned.tag, null, "a reference pinned to a digest names no tag");
  assert.equal(pinned.digest, `sha256:${"ab".repeat(32)}`);
  assert.equal(parseImageRef("localhost:5000/app")!.registry, "localhost:5000");
  for (const bad of ["", "$IMAGE", E("secrets.IMAGE"), "two words", "repo@sha256:short"]) assert.equal(parseImageRef(bad), null, bad);

  assert.equal(registryKind(ECR), "ecr");
  assert.equal(registryKind("public.ecr.aws"), "ecr-public");
  assert.equal(registryKind("ghcr.io"), "ghcr");
  assert.equal(registryKind("docker.io"), "dockerhub");
  assert.equal(registryKind("mock-registry-registry-vpc.cn-hangzhou.cr.aliyuncs.com"), "acr");
  assert.equal(registryKind("registry.cn-hangzhou.aliyuncs.com"), "acr");
  assert.equal(registryKind("quay.io"), "other");
  // One registry instance answers on a public host and a VPC host: both name the same images.
  assert.equal(canonicalRegistry("mock-registry-registry-vpc.cn-hangzhou.cr.aliyuncs.com"), "mock-registry-registry.cn-hangzhou.cr.aliyuncs.com");
  const image = { registry: "mock-registry-registry.cn-hangzhou.cr.aliyuncs.com", repository: "shop/storefront", digest: MOCK_DIGEST.acrShop, tags: ["3.2.0"] };
  assert.ok(runsImage(parseImageRef("mock-registry-registry-vpc.cn-hangzhou.cr.aliyuncs.com/shop/storefront:3.2.0")!, image));
  assert.ok(!runsImage(parseImageRef("mock-registry-registry-vpc.cn-hangzhou.cr.aliyuncs.com/shop/storefront:9.9")!, image), "another tag is another image");
  assert.ok(!runsImage(parseImageRef(`${image.registry}/shop/storefront@sha256:${"00".repeat(32)}`)!, image), "another digest is another image");
});

test("a workflow's images are read from metadata and build steps and from docker commands, with the file's own variables filled in", () => {
  const files = new Map([
    [
      ".github/workflows/publish.yml",
      [
        "env:",
        "  REGISTRY: ghcr.io",
        `  IMAGE_NAME: ${E("github.repository")}`,
        "jobs:",
        "  build:",
        "    steps:",
        "      - id: meta",
        "        uses: docker/metadata-action@v6",
        "        with:",
        `          images: ${E("env.REGISTRY")}/${E("env.IMAGE_NAME")}`,
        "      - uses: docker/build-push-action@v7",
        "        with:",
        "          push: true",
        `          tags: ${E("steps.meta.outputs.tags")}`,
      ].join("\n"),
    ],
    [
      ".github/workflows/deploy.yml",
      [
        "env:",
        "  ECR_REPOSITORY: web           # set this to your repository",
        "jobs:",
        "  deploy:",
        "    steps:",
        "      - id: login-ecr",
        "        uses: aws-actions/amazon-ecr-login@v2",
        "      - env:",
        `          ECR_REGISTRY: ${E("steps.login-ecr.outputs.registry")}`,
        `          IMAGE_TAG: ${E("github.sha")}`,
        "        run: |",
        "          docker build -t $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG .",
        "          docker push $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG",
      ].join("\n"),
    ],
    [
      ".github/workflows/other.yaml",
      [
        "jobs:",
        "  x:",
        "    steps:",
        "      - uses: docker/build-push-action@v7",
        "        with:",
        "          tags: |",
        "            user/app:latest",
        `            111122223333.dkr.ecr.eu-west-1.amazonaws.com/api:${E("github.sha")}`,
        '      - run: docker tag app registry.cn-hangzhou.aliyuncs.com/shop/storefront:$TAG && docker push "registry.cn-hangzhou.aliyuncs.com/shop/storefront:$TAG"',
        `      - run: docker push ${E("secrets.IMAGE")}`,
      ].join("\n"),
    ],
    // Not a workflow: never read for images.
    ["deploy/compose.yml", "services:\n  web:\n    image: ghcr.io/example/ignored\n    tags: ghcr.io/example/ignored\n"],
  ]);
  const builds = imageBuilds(files, "Example/Web");
  const names = builds.map((b) => `${b.registry ?? `(${b.kind})`}/${b.repository}`).sort();
  assert.deepEqual(names, [
    "(ecr)/web",
    "111122223333.dkr.ecr.eu-west-1.amazonaws.com/api",
    "docker.io/user/app",
    "ghcr.io/example/web",
    "registry.cn-hangzhou.aliyuncs.com/shop/storefront",
  ]);
  // A registry that comes from a login step is unknown: the image is matched by its repository within that kind of registry.
  const unknown = { repo: "example/web", ...builds.find((b) => !b.registry)! };
  assert.ok(buildMatches(unknown, { registry: ECR, repository: "web" }));
  assert.ok(!buildMatches(unknown, { registry: "ghcr.io", repository: "web" }), "an ECR login doesn't push to GitHub's registry");
  assert.ok(!buildMatches(unknown, { registry: ECR, repository: "api" }));
});

test("Trivy's failures are told apart by the registry's own answer", () => {
  const denied = trivyFailure(
    "Trivy failed: * remote error: GET https://ghcr.io/token?scope=repository%3Ax%2Fy%3Apull&service=ghcr.io: DENIED: requested access to the resource is denied",
  );
  assert.ok(denied instanceof TrivyError && denied.denied && !denied.missing);
  assert.equal(denied.message, "The registry answered DENIED: requested access to the resource is denied");
  assert.ok(trivyFailure("GET https://index.docker.io/v2/library/alpine/manifests/x: MANIFEST_UNKNOWN: manifest unknown").missing);
  assert.ok(!trivyFailure("Trivy didn't finish within 15 minutes.").denied);
  // As a real pull failed from behind a Container Registry allowlist, and as a VPC host fails outside its VPC.
  const away = trivyFailure(
    'Trivy failed: * remote error: Get "https://mock-registry.cn-hangzhou.cr.aliyuncs.com/v2/": dial tcp 192.0.2.10:443: connect: operation timed out',
  );
  assert.equal(away.unreachable, "mock-registry.cn-hangzhou.cr.aliyuncs.com");
  assert.equal(away.message, "Keelson couldn't connect to mock-registry.cn-hangzhou.cr.aliyuncs.com from where it runs: the connection timed out.");
  assert.ok(away.image && !away.denied, "it is the registry's, not a missing permission or Trivy's failure");
  const lookup = trivyFailure("Trivy failed: * remote error: dial tcp: lookup mock-registry-vpc.cn-hangzhou.cr.aliyuncs.com on 192.0.2.53:53: no such host");
  assert.equal(lookup.unreachable, "mock-registry-vpc.cn-hangzhou.cr.aliyuncs.com");
  assert.match(lookup.message, /its name doesn't resolve here/);
  assert.equal(denied.unreachable, null);
  assert.throws(() => parseReport("1 image scanned\n"), /wasn't the image report/, "anything but a report is the tool's failure, never an empty result");
});

test("a scan picks the images that run, the ones pulled lately and the newest of each repository, most exposed first", () => {
  const now = Date.parse("2026-06-01T00:00:00Z");
  const image = (repository: string, tag: string, n: number, extra: Partial<RegistryImage> = {}): RegistryImage => ({
    registry: ECR,
    repository,
    region: "eu-west-1",
    digest: `sha256:${String(n).padStart(2, "0").repeat(32)}`,
    tags: tag ? [tag] : [],
    pushedAt: new Date(now - n * 86_400_000).toISOString(),
    pulledAt: null,
    public: false,
    ...extra,
  });
  const workload = (name: string, ref: string, internet: boolean): WorkloadLink => ({
    provider: "aws",
    kind: "ECS service",
    name,
    group: "main",
    account: "example",
    region: "eu-west-1",
    link: null,
    containers: [{ name, image: ref }],
    running: 1,
    internet,
    via: [],
    loadBalancers: [],
  });
  const own = [
    workload("web", `${ECR}/web:1.0`, true),
    workload("cron", "redis:7", false),
    workload("legacy", "999900001111.dkr.ecr.eu-west-1.amazonaws.com/x:1", false),
  ];
  const targets = pickImages({
    registry: [
      image("web", "1.1", 1),
      image("web", "1.0", 9),
      image("web", "0.9", 30),
      image("batch", "5", 3, { pulledAt: new Date(now - 86_400_000).toISOString() }),
      image("batch", "", 2),
    ],
    workloads: own,
    ownWorkloads: own,
    login: () => async () => ({ username: "AWS", password: "x" }),
    foreign: (ref) => (ref.registry === "docker.io" ? "public" : "private"),
    now,
  });
  const picked = targets.map((t) => `${t.repository}:${t.tags[0] ?? "untagged"} ${t.why.join("+")}`);
  assert.deepEqual(picked, [
    "web:1.0 runs in a workload the internet reaches",
    "library/redis:7 runs in a workload",
    "x:1 runs in a workload",
    "batch:5 pulled lately+newest in its repository",
    "web:1.1 newest in its repository",
  ]);
  assert.ok(!picked.some((p) => p.startsWith("web:0.9")), "an old tag nothing runs or pulls isn't scanned");
  assert.equal(targets.find((t) => t.repository === "library/redis")!.login, null, "a public image is pulled without a login");
  assert.match(targets.find((t) => t.repository === "x")!.unreadable ?? "", /private registry that no connected account holds/);
});

test("a repository deployed every day keeps its newest few pulled images, and a scan starts with what it never scanned", () => {
  const now = Date.parse("2026-06-01T00:00:00Z");
  const day = (n: number) => new Date(now - n * 86_400_000).toISOString();
  const image = (repository: string, tag: string, n: number, pulled: boolean): RegistryImage => ({
    registry: ECR,
    repository,
    region: "eu-west-1",
    digest: `sha256:${String(n).padStart(2, "0").repeat(32)}`,
    tags: [tag],
    pushedAt: day(n),
    pulledAt: pulled ? day(1) : null,
    public: false,
  });
  const web: WorkloadLink = {
    provider: "aws",
    kind: "ECS service",
    name: "web",
    group: "main",
    account: "example",
    region: "eu-west-1",
    link: null,
    containers: [{ name: "web", image: `${ECR}/api:b9` }],
    running: 1,
    internet: false,
    via: [],
    loadBalancers: [],
  };
  // Nine builds of one repository, all pulled within the month, the oldest of them still running.
  const targets = pickImages({
    registry: [...Array.from({ length: 9 }, (_, i) => image("api", `b${i + 1}`, i + 1, true)), image("tools", "1", 20, false)],
    workloads: [web],
    ownWorkloads: [web],
    login: () => null,
    foreign: () => "private",
    now,
  });
  assert.deepEqual(
    targets.map((t) => `${t.repository}:${t.tags[0]}`),
    ["api:b9", "api:b1", "tools:1", "api:b2", "api:b3"],
    "what runs and each repository's newest, which a scan reads itself, then the other two of the newest three pulled lately",
  );
  assert.deepEqual(
    targets.filter(readInScan).map((t) => t.tags[0]),
    ["b9", "b1", "1"],
  );

  const at = (tag: string) => targets.find((t) => t.tags[0] === tag)!;
  const seen = (tag: string, scannedAt: string) => ({ key: imageCacheKey(at(tag)), summary: { scannedAt } });
  const previous = { images: [seen("b9", day(1)), seen("b2", day(1)), seen("1", day(3))] } as unknown as ImagesSnapshot;
  assert.deepEqual(
    inScanOrder(targets, previous).map((t) => t.tags[0]),
    ["b1", "b9", "1", "b3", "b2"],
    "what a scan reads itself first, the never scanned before the scanned; then the rest, never scanned and then from the stalest",
  );
  assert.deepEqual(
    inScanOrder(targets, null).map((t) => t.tags[0]),
    ["b9", "b1", "1", "b2", "b3"],
    "a first scan reads what runs, then each repository's newest, then the older builds",
  );
  // Among images that run, a new one comes before one to refresh.
  const both = [
    { ...at("b9"), priority: 120 },
    { ...at("b1"), priority: 100 },
  ];
  assert.deepEqual(
    inScanOrder(both, previous).map((t) => t.tags[0]),
    ["b1", "b9"],
  );
});

test("what is kept of Trivy's report: packages, vulnerabilities and the kind of each credential, never a value", async () => {
  const { installMockTrivy } = await import("../dev/mock/trivy.ts");
  const restore = installMockTrivy();
  try {
    const text = await trivy.image("/mock/trivy", `${ECR}/web:1.4.2`, { username: "AWS", password: "x" }, null);
    assert.ok(
      text.includes(MOCK_IMAGE_ENV_SECRET) && text.includes(MOCK_IMAGE_FILE_SECRET) && text.includes(MOCK_IMAGE_BUILD_SECRET),
      "the mock's report holds values to drop",
    );
    const scan = reduceReport(parseReport(text), { registry: ECR, repository: "web", digest: null }, "0.0.0", Date.now());
    const kept = JSON.stringify(scan);
    for (const secret of [MOCK_IMAGE_ENV_SECRET, MOCK_IMAGE_FILE_SECRET, MOCK_IMAGE_BUILD_SECRET, MOCK_IMAGE_LABEL])
      assert.ok(!kept.includes(secret), `dropped: ${secret}`);
    assert.deepEqual(
      scan.secrets.map((s) => `${s.kind} in ${s.where}${s.likely ? " (likely)" : ""}`),
      [
        "AWS Access Key ID in /app/.env",
        "a secret-looking value in environment variable SESSION_SECRET (likely)",
        "an npm auth token in the image's build history",
      ],
    );
    assert.equal(scan.digest, MOCK_DIGEST.web, "the digest comes from the registry when the reference named a tag");
    assert.deepEqual(scan.os, { family: "debian", name: "10.13", eol: true });
    assert.equal(scan.source, "https://github.com/mock-org/web");
    assert.equal(scan.user, "", "an image that names no user runs as root");
    assert.deepEqual([...new Set(scan.packages.map((p) => p.layer))].sort(), ["app", "os"]);
    const router = scan.vulns.find((v) => v.pkg === "mock-router")!;
    assert.deepEqual([router.layer, router.path, router.fixedIn, router.severity, router.cvss], ["app", "app/package-lock.json", "1.4.2", "high", 7.5]);
    assert.equal(scan.vulns.find((v) => v.pkg === "mock-zlib")!.fixedIn, null);
    // A source label can carry a token: only its host and path are kept.
    const labelled = JSON.parse(text);
    labelled.Metadata.ImageConfig.config.Labels["org.opencontainers.image.source"] = "https://x-access-token:ghs_mocktoken@github.com/Mock-Org/Web.git";
    assert.equal(reduceReport(labelled, { registry: ECR, repository: "web", digest: null }, "0", 0).source, "https://github.com/Mock-Org/Web");
  } finally {
    restore();
  }
});

test("the real runner gives a scanner the registry login for that one host only, and nothing of Keelson's environment", async () => {
  // A stand-in for Trivy that prints what it was given: its arguments, its environment and its Docker configuration.
  const dir = mkdtempSync(join(tmpdir(), "keelson-fake-trivy-"));
  const bin = join(dir, "fake-trivy");
  writeFileSync(bin, '#!/bin/sh\necho "ARGS $*"\nenv\necho "CONFIG $(cat "$DOCKER_CONFIG/config.json")"\n');
  chmodSync(bin, 0o755);
  process.env.KEELSON_TEST_SECRET = "must-not-reach-the-scanner";
  try {
    const out = await trivy.image(bin, `${ECR}/web@${MOCK_DIGEST.web}`, { username: "AWS", password: "registry-password" }, dir);
    assert.match(out, /ARGS image --format json .*--scanners vuln,secret .*--image-src remote /);
    assert.ok(!out.includes("must-not-reach-the-scanner"), "Keelson's environment stays out");
    // Trivy offers TRIVY_USERNAME and TRIVY_PASSWORD to every registry it contacts, the ones its database comes from included.
    assert.ok(!/TRIVY_(USERNAME|PASSWORD)/.test(out), "the login isn't in the environment");
    const config = JSON.parse(/CONFIG (.*)/.exec(out)![1]);
    assert.deepEqual(Object.keys(config.auths), [ECR], "the login is offered to the image's registry and no other");
    assert.equal(Buffer.from(config.auths[ECR].auth, "base64").toString(), "AWS:registry-password");
    assert.match(out, /TRIVY_DISABLE_TELEMETRY=true/);
    assert.match(out, /AWS_EC2_METADATA_DISABLED=true/, "Trivy can't borrow the role of the machine Keelson runs on");
    // A scan mustn't take the machine it runs on: Go spreads over this many cores and no more, and memory has a ceiling.
    assert.match(out, new RegExp(`GOMAXPROCS=${scannerCpus()}\\b`));
    assert.match(out, new RegExp(`--parallel ${scannerCpus()} `));
    assert.match(out, /GOMEMLIMIT=\d+MiB/);
    assert.ok(scannerCpus() >= 1 && scannerCpus() <= 4, "half the cores, at most four");
    assert.match(await trivy.image(bin, "docker.io/library/alpine:3", null, dir, "linux/arm64"), /--platform linux\/arm64 /);
    const anonymous = await trivy.image(bin, "docker.io/library/alpine:3", null, dir);
    assert.deepEqual(JSON.parse(/CONFIG (.*)/.exec(anonymous)![1]).auths, {}, "a public image is pulled without a login");
    // Matching a stored bill of materials again contacts nothing: no registry, so no login, and no database download.
    const again = await trivy.match(bin, '{"bomFormat":"CycloneDX"}', dir);
    assert.match(again, /ARGS sbom --format json .*--skip-db-update .*--offline-scan .*image\.cdx\.json/);
    assert.ok(!/DOCKER_CONFIG=|TRIVY_(USERNAME|PASSWORD)/.test(again), "there is no login to give");
    assert.ok(!again.includes("must-not-reach-the-scanner"));
    assert.match(again, new RegExp(`GOMAXPROCS=${scannerCpus()}\\b`));
    assert.match(await trivy.sbom(bin, "{}"), /ARGS convert --format cyclonedx .*report\.json/);

    // Two processes can't share Trivy's cache: whatever opens it waits its turn, so the background reader can finish
    // its image while a scan that just started asks for the database.
    const log = join(dir, "turns.log");
    const slow = join(dir, "slow-trivy");
    writeFileSync(slow, `#!/bin/sh\necho start >> "${log}"\nsleep 0.2\necho end >> "${log}"\n`);
    chmodSync(slow, 0o755);
    await Promise.all([trivy.image(slow, "docker.io/library/alpine:3", null, dir), trivy.match(slow, "{}", dir), trivy.updateDb(slow, dir)]);
    assert.deepEqual(readFileSync(log, "utf8").trim().split("\n"), ["start", "end", "start", "end", "start", "end"]);
  } finally {
    delete process.env.KEELSON_TEST_SECRET;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("where a vulnerability is fixed: the base image, the repository's code, a rebuild, or the image's own build", () => {
  const vuln = (pkg: string, version: string, extra: Partial<ImageVuln> = {}): ImageVuln => ({
    id: `CVE-${pkg}`,
    pkg,
    version,
    type: "npm",
    layer: "app",
    path: "app/package-lock.json",
    fixedIn: "9.9.9",
    status: "fixed",
    severity: "high",
    cvss: null,
    kev: false,
    title: "",
    url: null,
    ...extra,
  });
  const pkg = (name: string, version: string, vulns: string[] = []) => ({
    name,
    version,
    type: "npm",
    ecosystem: "npm",
    purl: null,
    locations: [],
    licenses: [],
    licenseRisk: null,
    usedBy: [],
    devOnly: false,
    vulns: vulns.map((id) => ({ id, aliases: [] }) as never),
  });
  const deps = [
    { repo: "web", packages: [pkg("router", "1.4.0"), pkg("matcher", "0.2.0"), pkg("parser", "2.0.0", ["CVE-parser"])] } as unknown as RepoDependencies,
  ];
  const places = fixPlaces(
    [
      vuln("openssl", "1.1", { layer: "os", type: "debian" }),
      vuln("router", "1.4.0"),
      vuln("matcher", "0.1.0"),
      vuln("parser", "1.9.0"),
      vuln("supervisor", "4.0", { type: "python-pkg" }),
    ],
    deps,
  );
  assert.deepEqual(
    places.map((v) => `${v.pkg} ${v.where} ${v.inCode ?? "-"}`),
    ["openssl base -", "router code 1.4.0", "matcher rebuild 0.2.0", "parser code 2.0.0", "supervisor build -"],
    "the same version, or a newer one with the same vulnerability, is still in the code; a fixed one only needs a rebuild",
  );
  assert.deepEqual(
    fixPlaces([vuln("router", "1.4.0")], []).map((v) => v.where),
    ["app"],
    "without the repository's dependencies it is only known to be the application's",
  );
  // Once the build history shows where the base image ends, what came with it is the base's, whatever kind of package it is,
  // and an operating system package the image's own build installed is that build's.
  assert.deepEqual(
    fixPlaces(
      [
        vuln("openssl", "1.1", { layer: "os", type: "debian", base: true }),
        vuln("curl", "7", { layer: "os", type: "debian" }),
        vuln("npm", "9", { base: true }),
      ],
      deps,
      true,
    ).map((v) => `${v.pkg} ${v.where}`),
    ["openssl base", "curl build", "npm base"],
  );
});

test("the image checks have the same four rules on every platform, under the platform's own prefix and documentation", () => {
  const meta = imageCheckMeta("ZIM", { images: ["images"], kev: ["kev"] }, { scanning: "https://example.com/scan", secrets: "https://example.com/secrets" });
  assert.deepEqual(Object.keys(meta), ["ZIM-001", "ZIM-002", "ZIM-003", "ZIM-004"]);
  assert.deepEqual(meta["ZIM-001"].requires, ["images", "kev"], "only the known-exploited check needs CISA's list");
  assert.deepEqual(meta["ZIM-002"].requires, ["images"]);
  assert.equal(meta["ZIM-004"].category, "Secrets");
});

test("the base image's layers are told from the image's own by its build history", () => {
  const layer = (created_by: string) => ({ created_by });
  const empty = (created_by: string) => ({ created_by, empty_layer: true });
  // A base image ends with its own CMD line, which adds no layer; the build's steps come after it.
  const history = [
    layer("ADD rootfs.tar.gz /"),
    empty('CMD ["/bin/sh"]'),
    empty("ENV NODE_VERSION=18.20.8"),
    layer("RUN install node"),
    empty('CMD ["node"]'),
    layer("COPY . /app"),
    empty('CMD ["node","server.js"]'),
  ];
  assert.equal(baseLayerCount(history), 2, "the layers before the last CMD that still has a layer after it");
  assert.equal(baseLayerCount([layer("ADD rootfs.tar.gz /"), empty('/bin/sh -c #(nop)  CMD ["bash"]'), layer("RUN make")]), 1, "as older builders write it");
  assert.equal(baseLayerCount([layer("ADD rootfs.tar.gz /"), empty('CMD ["/bin/sh"]')]), null, "a base image itself: nothing was built on it");
  assert.equal(baseLayerCount([layer("COPY app /"), layer("RUN chmod +x /app")]), null, "no CMD line, no telling");
  assert.equal(baseLayerCount([]), null);
});

test("a runtime is read from the variables official images record it in, and only its version is kept", () => {
  const found = runtimesIn({
    NODE_VERSION: "18.20.8",
    JAVA_VERSION: "jdk-17.0.9+9",
    PG_VERSION: "16.2-1.pgdg120+2",
    MARIADB_VERSION: "1:11.2.2+maria~ubu2204",
    NGINX_VERSION: "not a version",
    SESSION_SECRET: "7.7.7",
    APP_VERSION: "1.2.3",
  });
  assert.deepEqual(
    found.map((r) => `${r.name} ${r.version}`),
    ["Node.js 18.20.8", "Java 17.0.9", "PostgreSQL 16.2", "MariaDB 11.2.2"],
    "known runtimes only: no other variable's value is read",
  );
  // Its release line says whether it still gets fixes, and how far behind it is.
  const lines = [
    { cycle: "22", eol: "2027-04-30", latest: "22.12.1" },
    { cycle: "18", eol: "2025-04-30", latest: "18.20.8" },
    { cycle: "1.25", eol: true, latest: "1.25.5" },
    { cycle: "1", eol: false, latest: "1.99.0" },
  ];
  const now = Date.parse("2026-06-01T00:00:00Z");
  assert.deepEqual(supportOf(lines, "18.20.8", now), { eol: true, until: "2025-04-30", latest: null });
  assert.deepEqual(supportOf(lines, "22.11.0", now), { eol: false, until: "2027-04-30", latest: "22.12.1" });
  assert.deepEqual(supportOf(lines, "1.25.3", now), { eol: true, until: null, latest: "1.25.5" }, "the longest release line that starts the version");
  assert.deepEqual(supportOf(lines, "20.1.0", now), { eol: null, until: null, latest: null }, "an unknown line says nothing");
  assert.deepEqual(supportOf(undefined, "18.20.8", now), { eol: null, until: null, latest: null });
});

test("nothing names the builder: one repository of the entity with the image repository's name is taken, never a guess between two", () => {
  const image = (repository: string) =>
    ({ repository, registry: "111122223333.dkr.ecr.eu-west-1.amazonaws.com", linkedRepo: null, summary: null }) as unknown as ImageEntry;
  const repos = ["example/payments", "example/web", "other-org/web", "example/api"];
  assert.deepEqual(buildersOf(image("prod/payments"), null, [], repos), [{ repo: "example/payments", how: "name", workflow: null }]);
  assert.deepEqual(
    buildersOf(image("api-staging"), null, [], repos),
    [{ repo: "example/api", how: "name", workflow: null }],
    "without the word that says where it is deployed",
  );
  assert.deepEqual(buildersOf(image("team/web"), null, [], repos), [], "two repositories are called web");
  assert.deepEqual(buildersOf(image("unknown"), null, [], repos), []);
  // What the image or a workflow says comes first.
  const said = buildersOf(image("payments"), { source: "https://github.com/example/billing" }, [], repos);
  assert.deepEqual(said, [{ repo: "example/billing", how: "label", workflow: null }]);
});

test("a scan asks for an arm64-only image by its own platform, and forgets what turns out not to be an image", async () => {
  const { installMockTrivy } = await import("../dev/mock/trivy.ts");
  const asked: string[] = [];
  const restore = installMockTrivy({
    armOnly: [/log-shipper/],
    notImage: [/attestation/],
    onImage: (ref, _login, platform) => asked.push(`${ref} ${platform ?? "default"}`),
  });
  try {
    const store = new Map<string, unknown>();
    const cache = {
      get: <T>(k: string) => (store.get(k) as T) ?? null,
      put: (k: string, v: unknown) => void store.set(k, v),
      keys: (prefix: string) => [...store.keys()].filter((k) => k.startsWith(prefix)),
      delete: (k: string) => void store.delete(k),
    };
    const target = (repository: string, tag: string): ImageTarget => ({
      registry: "docker.io",
      repository,
      region: null,
      digest: null,
      tags: [tag],
      pushedAt: null,
      pulledAt: null,
      public: true,
      own: false,
      why: ["runs in a workload"],
      priority: 100,
      latest: false,
      login: null,
    });
    const notes: string[] = [];
    const scan = () =>
      scanImages([target("mock/log-shipper", "2.1"), target("mock/attestation", "1")], {
        repositories: 0,
        cache,
        toolDir: null,
        onProgress: () => {},
        note: (source, ok) => notes.push(`${source}:${ok}`),
      });
    const first = await scan();
    assert.deepEqual(asked, ["docker.io/mock/log-shipper:2.1 default", "docker.io/mock/log-shipper:2.1 linux/arm64", "docker.io/mock/attestation:1 default"]);
    assert.deepEqual(
      first.snapshot.images.map((i) => i.repository),
      ["mock/log-shipper"],
      "what isn't an image isn't listed as one",
    );
    assert.equal(cache.get<{ platform: string }>("img:docker.io/mock/log-shipper:2.1")!.platform, "linux/arm64");
    assert.ok(!notes.includes("trivy:false"), "neither is a failure of Trivy");
    asked.length = 0;
    await scan();
    assert.deepEqual(asked, [], "and neither is asked for again");
  } finally {
    restore();
  }
});

test("a registry host Keelson can't connect to is tried once a scan, and each of its images says why", async () => {
  const { installMockTrivy } = await import("../dev/mock/trivy.ts");
  const asked: string[] = [];
  const restore = installMockTrivy({ unreachable: [/^mock-registry\./], onImage: (ref) => asked.push(ref) });
  try {
    const store = new Map<string, unknown>();
    const cache = {
      get: <T>(k: string) => (store.get(k) as T) ?? null,
      put: (k: string, v: unknown) => void store.set(k, v),
      keys: (prefix: string) => [...store.keys()].filter((k) => k.startsWith(prefix)),
      delete: (k: string) => void store.delete(k),
    };
    const target = (registry: string, repository: string): ImageTarget => ({
      registry,
      repository,
      region: null,
      digest: null,
      tags: ["1"],
      pushedAt: null,
      pulledAt: null,
      public: true,
      own: true,
      why: ["newest in its repository"],
      priority: 40,
      latest: true,
      login: null,
      reach: "Its internet access admits only the addresses on its allowlist.",
    });
    const notes: string[] = [];
    const out = await scanImages(
      [
        target("mock-registry.cn-hangzhou.cr.aliyuncs.com", "shop/a"),
        target("mock-registry.cn-hangzhou.cr.aliyuncs.com", "shop/b"),
        target("docker.io", "mock/web"),
      ],
      {
        repositories: 2,
        cache,
        toolDir: null,
        onProgress: () => {},
        note: (source, ok, err) => notes.push(`${source}:${ok}${err ? ` ${(err as Error).message}` : ""}`),
      },
    );
    assert.deepEqual(asked, ["mock-registry.cn-hangzhou.cr.aliyuncs.com/shop/a:1", "docker.io/mock/web:1"], "the second image of that host isn't tried");
    const [a, b] = out.snapshot.images;
    assert.equal(a.error, b.error);
    assert.equal(
      a.error,
      "Keelson couldn't connect to mock-registry.cn-hangzhou.cr.aliyuncs.com from where it runs: the connection timed out. Its internet access admits only the addresses on its allowlist.",
    );
    assert.ok(notes.includes(`network:false ${a.error}`), "a gap of its own, not a missing permission");
    assert.ok(!notes.includes("pull:false") && !notes.includes("trivy:false"));
  } finally {
    restore();
  }
});

test("an image is pulled once: later scans match its stored packages against the database, and only a tag is asked for again", async () => {
  const { installMockTrivy } = await import("../dev/mock/trivy.ts");
  const pulled: string[] = [];
  const matched: string[] = [];
  const converted: string[] = [];
  const options: MockTrivyOptions = {
    db: "2026-11-01T00:00:00Z",
    onImage: (ref) => pulled.push(ref),
    onMatch: (name) => matched.push(name),
    onSbom: (report) => converted.push(report),
  };
  const restore = installMockTrivy(options);
  try {
    const store = new Map<string, unknown>();
    const cache = {
      get: <T>(k: string) => (store.has(k) ? (structuredClone(store.get(k)) as T) : null),
      put: (k: string, v: unknown) => void store.set(k, structuredClone(v)),
      keys: (prefix: string) => [...store.keys()].filter((k) => k.startsWith(prefix)),
      delete: (k: string) => void store.delete(k),
    };
    const target = (registry: string, repository: string, digest: string | null, tag: string): ImageTarget => ({
      registry,
      repository,
      region: null,
      digest,
      tags: [tag],
      pushedAt: null,
      pulledAt: null,
      public: true,
      own: false,
      why: ["runs in a workload"],
      priority: 100,
      latest: false,
      login: digest ? async () => ({ username: "AWS", password: "x" }) : null,
    });
    const web = target(ECR, "web", MOCK_DIGEST.web, "1.4.2");
    const shipper = target("docker.io", "mock/log-shipper", null, "2.1");
    const day = 86_400_000;
    const start = Date.parse("2026-11-01T06:00:00Z");
    const scan = (now: number) => scanImages([web, shipper], { repositories: 1, cache, toolDir: null, onProgress: () => {}, note: () => {}, now });
    const key = imageCacheKey(web);
    const reset = () => [pulled, matched, converted].forEach((l) => l.splice(0));

    const one = await scan(start);
    assert.deepEqual(pulled, [`${ECR}/web@${MOCK_DIGEST.web}`, "docker.io/mock/log-shipper:2.1"]);
    assert.deepEqual([one.snapshot.pulled, one.snapshot.checked], [2, 0]);
    // What Trivy writes its bill of materials from holds the packages and nothing of the image's configuration.
    assert.equal(converted.length, 2);
    for (const secret of [MOCK_IMAGE_ENV_SECRET, MOCK_IMAGE_FILE_SECRET, MOCK_IMAGE_BUILD_SECRET, MOCK_IMAGE_LABEL])
      assert.ok(!converted.join().includes(secret), `not given to Trivy again: ${secret}`);
    assert.ok(converted[0].includes("mock-openssl"));
    // And of what Trivy writes, its description of the image (labels) and its list of vulnerabilities aren't kept.
    const sbom = cache.get<{ metadata: { component: { name: string } }; components: unknown[]; vulnerabilities?: unknown }>(sbomCacheKey(key))!;
    assert.ok(!JSON.stringify(sbom).includes(MOCK_IMAGE_LABEL), "no label in the stored bill of materials");
    assert.equal(sbom.vulnerabilities, undefined);
    assert.equal(sbom.metadata.component.name, `${ECR}/web@${MOCK_DIGEST.web}`);
    assert.ok(sbom.components.length >= 7);
    const first = cache.get<ImageScan>(key)!;
    assert.equal(first.dbUpdated, "2026-11-01T00:00:00Z");

    // The same database an hour later: nothing to pull and nothing new to match.
    reset();
    const two = await scan(start + 3600_000);
    assert.deepEqual([pulled, matched], [[], []]);
    assert.deepEqual([two.snapshot.pulled, two.snapshot.checked], [0, 2], "the scan says what it did");

    // Three days later the database knows a new vulnerability in a package of the image. The image, named by its digest,
    // isn't pulled: its stored packages are matched again. The one named by a tag may have changed, so it is asked for.
    reset();
    options.db = "2026-11-04T00:00:00Z";
    options.published = [
      { image: /\/web@/, vuln: { id: "CVE-2026-99001", pkg: "mock-libc@2.28-10", severity: "CRITICAL", fix: "2.28-11", title: "Published after the scan." } },
    ];
    const later = await scan(start + 3 * day);
    assert.deepEqual(pulled, ["docker.io/mock/log-shipper:2.1"]);
    assert.deepEqual(matched, [`${ECR}/web@${MOCK_DIGEST.web}`]);
    assert.deepEqual([later.snapshot.pulled, later.snapshot.checked], [1, 1]);
    const second = cache.get<ImageScan>(key)!;
    const found = second.vulns.find((v) => v.id === "CVE-2026-99001")!;
    assert.deepEqual(
      [found.pkg, found.fixedIn, found.severity, found.base],
      ["mock-libc", "2.28-11", "critical", true],
      "with its layer: the base image brought it",
    );
    assert.equal(second.vulns.length, first.vulns.length + 1);
    assert.ok(second.vulns.find((v) => v.id === MOCK_KEV)!.kev, "CISA's list is applied to what was matched");
    assert.equal(second.scannedAt, first.scannedAt, "the image was read once");
    assert.equal(second.dbUpdated, "2026-11-04T00:00:00Z");
    assert.deepEqual([second.packages, second.secrets, second.runtimes.map((r) => r.name)], [first.packages, first.secrets, ["Node.js"]]);
    assert.equal(later.snapshot.images.find((i) => i.key === key)!.summary!.vulns.critical, first.vulns.filter((v) => v.severity === "critical").length + 1);
    assert.ok(
      later.scans.get(key)!.vulns.some((v) => v.id === "CVE-2026-99001"),
      "the checks read it",
    );

    // Trivy can't match the stored list (a newer Trivy that reads it differently): the image is read again.
    reset();
    options.db = "2026-11-05T00:00:00Z";
    options.matchFails = true;
    await scan(start + 4 * day);
    assert.deepEqual(pulled, [`${ECR}/web@${MOCK_DIGEST.web}`, "docker.io/mock/log-shipper:2.1"]);
    assert.equal(cache.get<ImageScan>(key)!.dbUpdated, "2026-11-05T00:00:00Z");

    // An image that is gone takes its bill of materials with it.
    await scanImages([shipper], { repositories: 1, cache, toolDir: null, onProgress: () => {}, note: () => {}, now: start + 4 * day });
    assert.deepEqual(cache.keys("imgsbom:"), [sbomCacheKey(imageCacheKey(shipper))]);
  } finally {
    restore();
  }
});

test("a scan always reads what runs and each repository's latest image, and hands the rest to the background", async () => {
  const { installMockTrivy } = await import("../dev/mock/trivy.ts");
  const pulled: string[] = [];
  const restore = installMockTrivy({
    onImage: (ref) =>
      pulled.push(
        ref
          .split("/")
          .pop()!
          .replace(/@sha256:(..).*/, "@$1"),
      ),
  });
  const limit = trivyLimits.totalSeconds;
  // No time at all for the images that can wait.
  trivyLimits.totalSeconds = -1;
  try {
    const store = new Map<string, unknown>();
    const cache = {
      get: <T>(k: string) => (store.has(k) ? (structuredClone(store.get(k)) as T) : null),
      put: (k: string, v: unknown) => void store.set(k, structuredClone(v)),
      keys: (prefix: string) => [...store.keys()].filter((k) => k.startsWith(prefix)),
      delete: (k: string) => void store.delete(k),
    };
    let logins = 0;
    const login = async () => ({ username: "AWS", password: `x${++logins}` });
    const target = (repository: string, digest: string, tag: string, priority: number, latest: boolean): ImageTarget => ({
      registry: ECR,
      repository,
      region: "eu-west-1",
      digest,
      tags: [tag],
      pushedAt: null,
      pulledAt: null,
      public: false,
      own: true,
      why: [],
      priority,
      latest,
      login,
    });
    // An older build that was pulled lately, listed first; the image a service runs; another older build; a repository's latest nothing runs.
    const old = target("web", MOCK_DIGEST.webOld, "1.4.1", 60, false);
    const older = target("api", MOCK_DIGEST.api, "2026.10.1", 60, false);
    const targets = [old, target("web", MOCK_DIGEST.web, "1.4.2", 120, true), older, target("tools", MOCK_DIGEST.tools, "latest", 40, true)];
    const start = Date.parse("2026-11-01T06:00:00Z");
    const scan = (now: number) => scanImages(targets, { repositories: 3, cache, toolDir: null, onProgress: () => {}, note: () => {}, now });

    const first = await scan(start);
    assert.deepEqual(pulled, ["web@a1", "tools@c3"], "the running image and each repository's latest are read whatever the time");
    assert.equal(first.snapshot.waiting, 2);
    assert.equal(first.later?.total, 2, "the older builds are handed back for the background");
    assert.deepEqual(
      first.snapshot.images.map((i) => `${i.repository}:${i.tags[0]} ${i.summary ? "read" : "waiting"}`),
      ["web:1.4.2 read", "tools:latest read", "web:1.4.1 waiting", "api:2026.10.1 waiting"],
    );
    assert.equal(cache.get(imageCacheKey(old)), null);

    // The background reads one image, then gives way to a scan that was asked for.
    const progress: string[] = [];
    let asked = 0;
    const later = first.later!;
    const paused = await later.run({ stop: () => asked++ > 0, onProgress: (done, total) => progress.push(`${done}/${total}`), now: () => start + 3600_000 });
    assert.deepEqual(paused, { finished: false, read: 1 });
    assert.deepEqual(pulled.slice(2), ["web@a0"]);
    const kept = cache.get<ImageScan>(imageCacheKey(old))!;
    assert.equal(kept.scannedAt, new Date(start + 3600_000).toISOString(), "read when the background got to it");
    assert.ok(
      kept.vulns.some((v) => v.id === MOCK_KEV && v.kev),
      "with CISA's list applied, as in a scan",
    );
    assert.ok(cache.get(sbomCacheKey(imageCacheKey(old))), "and its bill of materials kept, so it is never pulled again");
    // It goes on from where it stopped.
    assert.deepEqual(await later.run({ stop: () => false, onProgress: (done, total) => progress.push(`${done}/${total}`) }), { finished: true, read: 2 });
    assert.deepEqual(pulled.slice(3), ["api@b2"]);
    assert.deepEqual(progress, ["0/2", "1/2", "1/2", "2/2"]);
    assert.equal(logins, 1, "one registry login serves the scan and the background that follows it");

    // The scan that follows pulls nothing and has every image.
    pulled.length = 0;
    const second = await scan(start + 2 * 3600_000);
    assert.deepEqual(pulled, []);
    assert.equal(second.later, null);
    assert.deepEqual([second.snapshot.waiting, second.snapshot.pulled, second.snapshot.checked], [0, 0, 4]);
    assert.ok(second.snapshot.images.every((i) => i.summary));
    assert.ok(second.scans.get(imageCacheKey(old))!.vulns.length, "and the checks read what the background found");
  } finally {
    trivyLimits.totalSeconds = limit;
    restore();
  }
});

describe("image scans against the mocked platforms", () => {
  let restore: () => void = () => {};
  const pulls: { ref: string; login: string | null; platform: string | null }[] = [];
  const install = (o: MockTrivyOptions = {}) => {
    const onImage: MockTrivyOptions["onImage"] = (ref, login, platform) =>
      pulls.push({ ref, login: login ? `${login.username}:${login.password}` : null, platform });
    const mocks = [
      installMockCloudflare(),
      installMockAws({ trivy: { ...o, onImage } }),
      installMockAlibaba({ trivy: { ...o, onImage } }),
      installMockGithub({ trivy: { ...o, onImage } }),
    ];
    restore = () => mocks.reverse().forEach((r) => r());
  };
  /** The mock entity: Cloudflare DNS, an AWS account, an Alibaba Cloud account and a GitHub organization. */
  const entity = async (only?: "aws") => {
    const t = makeApp();
    if (!only) seedAccount(t.repo, t.vault, { entity: "Mock Group" });
    seedAws(t.repo, t.vault, { entity: "Mock Group" });
    if (!only) {
      seedAlibaba(t.repo, t.vault, { entity: "Mock Group" });
      seedGithub(t.repo, t.vault, { entity: "Mock Group" });
    }
    await t.scanner.start("test").done;
    return t;
  };
  /** Every image, or workload, of a view: the lists are served a page at a time. */
  const imagesOf = async (t: { json: (path: string) => Promise<any> }, scope = "all", query = "") =>
    ((await t.json(`/api/images/list?scope=${scope}&limit=200${query}`)) as ImageList<ImageRow>).rows;
  const workloadsOf = async (t: { json: (path: string) => Promise<any> }, scope = "all") =>
    ((await t.json(`/api/images/workloads?scope=${scope}&limit=200`)) as ImageList<WorkloadRow>).rows;
  const findings = async (t: Awaited<ReturnType<typeof entity>>, scope = "all") =>
    ((await t.json(`/api/findings?scope=${scope}&status=all`)).findings as Finding[]).filter((f) => /^[A-Z]IM-/.test(f.checkId));
  before(() => install());
  after(() => restore());

  test("an AWS scan scans the images that matter with a registry login, never the access key, and stores no secret", async () => {
    pulls.length = 0;
    const t = await entity("aws");
    try {
      assert.deepEqual(
        pulls.map((p) => p.ref.replace(ECR, "ecr")).sort(),
        [`docker.io/mock/log-shipper:2.1`, `ecr/api@${MOCK_DIGEST.api}`, `ecr/tools@${MOCK_DIGEST.tools}`, `ecr/web@${MOCK_DIGEST.web}`],
        "the running images by digest, the newest of a repository nothing runs, and the sidecar from Docker Hub; not the old tag or the untagged leftover",
      );
      // The web image was pushed as an index with one arm64 image and a build attestation: the index is scanned once, for
      // the platform it has, and its parts aren't images of their own.
      assert.equal(pulls.find((p) => p.ref.includes("/web@"))!.platform, "linux/arm64");
      assert.ok(!pulls.some((p) => p.ref.includes(MOCK_DIGEST.webArm) || p.ref.includes(MOCK_DIGEST.webAttestation)));
      assert.ok(
        pulls.filter((p) => !p.ref.includes("/web@")).every((p) => p.platform === null),
        "every other image is asked for as Trivy does by default",
      );
      for (const p of pulls) {
        if (p.ref.startsWith("docker.io")) assert.equal(p.login, null, "a public image is pulled without a login");
        else assert.equal(p.login, `AWS:${MOCK_AWS_REGISTRY_PASSWORD}`, "ECR's own short-lived login");
        assert.ok(!p.login?.includes(MOCK_AWS_TOKEN.split(":")[1]), "Trivy never gets the access key");
      }
      const scan = t.repo.scans.latest(MOCK_AWS_ACCOUNT)!;
      const cached = t.repo.cache.keys(MOCK_AWS_ACCOUNT, "img:").map((k) => t.repo.cache.get(MOCK_AWS_ACCOUNT, k));
      const stored = JSON.stringify({ snap: scan.snap, cached, findings: t.repo.findings.forScan(scan.id, t.repo.settings.get().slaDays) });
      for (const secret of [MOCK_IMAGE_ENV_SECRET, MOCK_IMAGE_FILE_SECRET, MOCK_IMAGE_BUILD_SECRET, MOCK_IMAGE_LABEL, MOCK_AWS_REGISTRY_PASSWORD])
        assert.ok(!stored.includes(secret), `never stored: ${secret}`);
      assert.equal(cached.length, 4);
      const index = t.repo.cache.get<{ keys: string[]; has: number[]; hits: number[] }>(MOCK_AWS_ACCOUNT, INDEX_KEY)!;
      assert.equal(index.keys.length, 4, "what is in which image is kept in one compact index for the lists across images");
      assert.ok(index.has.length % 3 === 0 && index.hits.length % 5 === 0 && index.hits.length > 0);

      const web = (await findings(t)).filter((f) => f.resource === "web");
      assert.deepEqual(
        web.map((f) => `${f.checkId} ${f.severity}`).sort(),
        ["AIM-001 critical", "AIM-002 high", "AIM-003 medium", "AIM-004 critical"],
        "the web service's image, which the internet reaches through the load balancer and anyone can pull",
      );
      assert.match(
        web.find((f) => f.checkId === "AIM-001")!.detail,
        new RegExp(`${MOCK_KEV}.*ECS service web.*which the internet reaches through load balancer web-alb`),
      );
      const api = (await findings(t)).filter((f) => f.resource === "api");
      assert.deepEqual(
        api.map((f) => `${f.checkId} ${f.severity}`),
        ["AIM-002 low"],
        "one high vulnerability with a fix, in a service inside the network: two steps down from an internet-facing critical",
      );
      assert.equal((await findings(t)).filter((f) => f.resource === "tools").length, 0, "an image nothing runs or pulls shows on the page, not as a finding");

      // A second scan the same day doesn't pull anything again.
      pulls.length = 0;
      await t.scanner.start("again").done;
      assert.deepEqual(pulls, []);
      assert.equal((await findings(t)).length, web.length + api.length, "and reports the same findings from what it kept");
    } finally {
      t.cleanup();
    }
  });

  test("images a scan had no time for are read in the background once no scan runs, and the account is then scanned again", async () => {
    const limit = trivyLimits.totalSeconds;
    // The build before the current one was pulled lately, and the scan has no time for images that can wait.
    mockAws.oldBuildPulled = true;
    trivyLimits.totalSeconds = -1;
    let release = () => {};
    const held = new Promise<void>((done) => {
      release = done;
    });
    let reached = () => {};
    const reading = new Promise<void>((done) => {
      reached = done;
    });
    mockTrivy.beforeImage = (ref) => {
      if (!ref.includes(MOCK_DIGEST.webOld)) return;
      reached();
      return held;
    };
    pulls.length = 0;
    const t = makeApp();
    try {
      seedAws(t.repo, t.vault, { entity: "Mock Group" });
      const other = seedAccount(t.repo, t.vault, { entity: "Other Ltd" });
      await t.scanner.start("test", [MOCK_AWS_ACCOUNT]).done;
      const first = t.repo.scans.latest(MOCK_AWS_ACCOUNT)!;
      assert.equal(first.snap.images!.waiting, 1);
      const old = (await imagesOf(t)).find((i) => i.digest === MOCK_DIGEST.webOld)!;
      assert.deepEqual([old.use, old.summary], ["pulled", null], "listed, and not read yet");

      // The scan is over; the image is being read.
      await reading;
      const status = await t.json("/api/scan/status?scope=all");
      assert.equal(status.running, false);
      assert.deepEqual(status.background, { accountId: MOCK_AWS_ACCOUNT, done: 0, total: 1, queued: 0, inScope: true });
      assert.equal((await t.json(`/api/scan/status?scope=a:${other.id}`)).background.inScope, false, "another view isn't told its images are being read");
      const outsider = t.limitedAs("viewer", [other.entityId]);
      assert.equal((await outsider.json("/api/scan/status?scope=all")).background, null, "someone who can't see the account isn't told of it at all");

      // A scan that is asked for doesn't wait for the background, which goes on when the queue is empty again.
      await t.scanner.start("manual", [other.id]).done;
      assert.equal((await t.json("/api/scan/status?scope=all")).background.total, 1);

      release();
      await t.scanner.idle();
      const scans = (await t.json("/api/scans?scope=all")).scans as { trigger: string; status: string; accountId: string }[];
      assert.deepEqual(
        scans.map((s) => `${s.accountId === other.id ? "other" : "aws"} ${s.trigger} ${s.status}`),
        ["aws images done", "other manual done", "aws test done"],
        "one more scan of the account, for what the images hold",
      );
      const second = t.repo.scans.latest(MOCK_AWS_ACCOUNT)!;
      assert.deepEqual([second.snap.images!.waiting, second.snap.images!.pulled], [0, 0], "which pulled nothing");
      assert.equal(pulls.filter((p) => p.ref.includes(MOCK_DIGEST.webOld)).length, 1, "the image was pulled once, by the background");
      assert.ok((await imagesOf(t)).find((i) => i.digest === MOCK_DIGEST.webOld)!.summary);
      assert.equal((await t.json("/api/scan/status?scope=all")).background, null);
      assert.equal(t.scanner.background, null);
    } finally {
      release();
      await t.scanner.idle();
      mockTrivy.beforeImage = null;
      mockAws.oldBuildPulled = false;
      trivyLimits.totalSeconds = limit;
      t.cleanup();
    }
  });

  test("without Trivy, or without permission to pull, images are listed and their checks skipped, never passed", async () => {
    restore();
    install({ missing: true });
    let t = await entity("aws");
    try {
      const snap = t.repo.scans.latest(MOCK_AWS_ACCOUNT)!.snap;
      const gap = snap.coverage!.find((c) => c.key === "trivy")!;
      assert.equal(gap.ok, false);
      assert.match(gap.message ?? "", /Trivy isn't installed/);
      assert.deepEqual(gap.skippedChecks, ["AIM-001", "AIM-002", "AIM-003", "AIM-004"]);
      assert.equal(snap.images!.images.length, 4, "the images are still listed");
      assert.ok(snap.images!.images.every((i) => !i.summary));
      assert.equal(snap.checks!["AIM-002"], undefined, "nothing was judged");
    } finally {
      t.cleanup();
    }
    restore();
    install({ deny: [/\.dkr\.ecr\./] });
    t = await entity("aws");
    try {
      const snap = t.repo.scans.latest(MOCK_AWS_ACCOUNT)!.snap;
      const gap = snap.coverage!.find((c) => c.key === "imagePull")!;
      assert.equal(gap.ok, false);
      assert.match(gap.permission ?? "", /ecr:GetAuthorizationToken, ecr:BatchGetImage, ecr:GetDownloadUrlForLayer/);
      assert.equal((await findings(t)).length, 0, "a registry that refuses the pull skips the image checks");
      const web = snap.images!.images.find((i) => i.repository === "web")!;
      assert.match(web.error ?? "", /DENIED/);
      assert.ok(snap.images!.images.find((i) => i.registry === "docker.io")!.summary, "the public sidecar was still scanned");
    } finally {
      t.cleanup();
      restore();
      install();
    }
  });

  test("a Container Registry instance Keelson can't connect to is a gap that says the instance has an allowlist", async () => {
    restore();
    install({ unreachable: [/\.cr\.aliyuncs\.com/] });
    const t = await entity();
    try {
      const snap = t.repo.scans.latest(MOCK_ALIBABA_ACCOUNT)!.snap;
      const gap = snap.coverage!.find((c) => c.key === "registryNetwork")!;
      assert.equal(gap.ok, false);
      assert.match(gap.message ?? "", /couldn't connect to mock-registry-registry\.cn-hangzhou\.cr\.aliyuncs\.com.*admits only the addresses on its allowlist/);
      assert.match(gap.permission ?? "", /Access Control/, "it says what to change, not which permission is missing");
      assert.ok(gap.skippedChecks!.includes("LIM-002"), "the image checks are skipped, never passed");
      assert.ok(snap.coverage!.find((c) => c.key === "imagePull")?.ok !== false, "the login and pull permissions aren't blamed");
    } finally {
      t.cleanup();
      restore();
      install();
    }
  });

  test("the Images page follows each image from the repository that builds it to the workloads that run it, inside its entity", async () => {
    pulls.length = 0;
    const t = await entity();
    try {
      // Twice, so each account has read what its siblings published: GitHub's scan learns that a container group runs its package.
      await t.scanner.start("again").done;
      for (const p of pulls) {
        assert.ok(
          !p.login?.includes(MOCK_ALIBABA_TOKEN.split(":")[1]) && !p.login?.includes(MOCK_AWS_TOKEN.split(":")[1]),
          "no scanner gets an account's own credential",
        );
        if (p.ref.includes(".cr.aliyuncs.com")) assert.equal(p.login, `cr_temp_user:${MOCK_ALIBABA_REGISTRY_PASSWORD}`, "Container Registry's temporary login");
        if (p.ref.startsWith("ghcr.io")) assert.equal(p.login, null, "GitHub's public packages are pulled without a login");
      }
      assert.ok(!pulls.some((p) => p.ref.includes("internal-tools")), "a private GitHub package isn't tried: GitHub refuses an App there");
      const stored = JSON.stringify(t.repo.scans.latest(MOCK_ALIBABA_ACCOUNT)!.snap);
      assert.ok(
        !stored.includes(MOCK_ALIBABA_POD_SECRET) && !stored.includes(MOCK_ALIBABA_REGISTRY_PASSWORD),
        "a container group's variables are dropped as they're read",
      );

      const page: ImagesResponse = await t.json("/api/images?scope=all");
      const list = await imagesOf(t);
      const running = await workloadsOf(t);
      const by = (provider: string, repository: string) => list.find((i) => i.provider === provider && i.repository === repository)!;
      const web = by("aws", "web");
      assert.equal(web.use, "internet");
      assert.deepEqual(
        web.workloads.map((w) => `${w.kind} ${w.name} ${w.via[0]}`),
        ["ECS service web load balancer web-alb"],
      );
      assert.ok(web.workloads[0].hosts.includes("shop.mock.example"), "the hostname Cloudflare points at the load balancer");
      assert.ok(web.workloads[0].byTag, "the service names a tag, which can move");
      assert.deepEqual(
        web.builtBy.map((b) => `${b.repo} ${b.how} ${b.accountId}`),
        [`mock-org/web label ${MOCK_GITHUB_ACCOUNT}`],
      );
      assert.deepEqual(
        by("aws", "api").builtBy.map((b) => `${b.repo} ${b.how} ${b.workflow}`),
        ["mock-org/api workflow .github/workflows/release.yml"],
      );
      assert.equal(by("aws", "api").use, "running");
      assert.equal(by("aws", "tools").use, "stored");
      assert.equal(by("aws", "mock/log-shipper").own, false, "an image a service runs from Docker Hub");

      const shop = by("alibaba", "shop/storefront");
      assert.equal(shop.use, "internet");
      assert.match(shop.workloads[0].via[0], /a public address, with all traffic/);
      assert.equal(running.find((w) => w.name === "storefront")!.running, 2, "two pods of one deployment are one workload");

      const ghcr = by("github", "mock-org/web");
      assert.equal(ghcr.use, "running", "an Alibaba Cloud container group runs GitHub's package");
      assert.deepEqual(
        ghcr.workloads.map((w) => `${w.provider} ${w.name}`),
        ["alibaba report-job"],
      );
      const hidden = by("github", "mock-org/internal-tools");
      assert.equal(hidden.summary, null);
      assert.match(hidden.error ?? "", /doesn't let a GitHub App pull private packages/);
      assert.deepEqual(
        (await findings(t)).filter((f) => f.checkId.startsWith("GIM")).map((f) => `${f.checkId} ${f.severity} ${f.zone}`),
        ["GIM-002 medium web"],
      );
      assert.ok(
        web.findings.some((f) => f.checkId === "AIM-001"),
        "an image carries its findings",
      );

      assert.equal(page.summary!.images, 7);
      assert.equal(page.summary!.scanned, 6);
      assert.deepEqual(page.summary!.uses, { internet: 3, running: 2, pulled: 0, stored: 2 });
      assert.equal(page.summary!.exploited, 3);
      assert.equal(page.summary!.exploitedInternet, 2);
      assert.equal(running.length, 4);
      assert.ok(
        running.every((w) => w.containers.every((c) => c.imageId)),
        "every running image was scanned",
      );
      assert.deepEqual(page.registries.sort(), ["acr", "dockerhub", "ecr", "ghcr"]);

      // One image in full: what is fixed where, from the dependencies of the repository that builds it.
      const detail = await t.json(`/api/images/detail?scope=all&id=${encodeURIComponent(web.id)}`);
      assert.deepEqual(detail.places, { base: 2, code: 1, rebuild: 1, build: 1, app: 0 });
      const where = Object.fromEntries(
        detail.scan.vulns.map((v: { pkg: string; where: string; inCode: string | null }) => [v.pkg, `${v.where} ${v.inCode ?? "-"}`]),
      );
      assert.equal(where["mock-router"], "code 1.4.0", "the repository still depends on the vulnerable version");
      assert.equal(where["mock-path-match"], "rebuild 0.2.0", "the repository moved on: the image is behind its code");
      assert.equal(where["mock-openssl"], "base -", "it came with the base image");
      assert.equal(where["mock-supervisor"], "base -", "so did a tool the base image ships, though it isn't an operating system package");
      assert.equal(where["mock-zlib"], "build -", "an operating system package the image's own build installed");
      assert.equal((await t.call("/api/images/detail?scope=all&id=nope")).status, 404);

      // Across images.
      const exploited = await t.json("/api/images/vulnerabilities?scope=all&status=exploited");
      assert.deepEqual(
        (exploited.rows as ImageVulnRow[]).map((v) => `${v.id} ${v.use} ${v.imageCount} ${v.images[0].use}`),
        [`${MOCK_KEV} internet 3 internet`],
        "the most exposed image it is in comes first",
      );
      const inUse = await t.json("/api/images/vulnerabilities?scope=all&status=exploited&use=running");
      assert.equal(inUse.rows[0].imageCount, 2, "the stored image is left out");
      assert.equal((await t.json("/api/images/vulnerabilities?scope=all&layer=app&severity=critical")).total, 2);
      assert.deepEqual(
        ((await t.json("/api/images/vulnerabilities?scope=all&from=base&severity=critical")).rows as ImageVulnRow[]).map((v) => `${v.id} ${v.base}`),
        [`${MOCK_KEV} true`],
        "what a newer base image would fix",
      );

      // The inventory: every package, runtime and operating system the images are made of, at each version.
      const components = (q: string) => t.json(`/api/images/components?scope=all&${q}`) as Promise<ImageList<ComponentRow>>;
      assert.deepEqual(
        (await components("q=mock-router")).rows.map((c) => `${c.kind} ${c.name}@${c.version} ${c.imageCount} ${c.worst} → ${c.fixedIn}`),
        ["app-package mock-router@1.4.0 2 high → 1.4.2"],
      );
      assert.deepEqual(
        (await components("kind=runtime")).rows.map((c) => `${c.name} ${c.version} eol=${c.eol} latest=${c.fixedIn} in ${c.imageCount}`),
        ["Node.js 18.20.8 eol=true latest=null in 1", "Node.js 22.11.0 eol=false latest=22.12.1 in 1"],
        "the runtime an official image is built around is in no package list: its release line's support says what a scanner can't",
      );
      assert.deepEqual((await components("kind=os&eol=yes")).rows.map((c) => `${c.name} ${c.version} in ${c.imageCount}`).sort(), [
        "alpine 3.16.2 in 1",
        "debian 10.13 in 1",
        "ubuntu 18.04 in 1",
      ]);
      const openssl = (await components("q=mock-openssl&kind=os-package")).rows;
      assert.deepEqual(openssl.map((c) => `${c.type} ${c.imageCount} ${c.kev}`).sort(), ["alpine 1 true", "debian 1 true", "ubuntu 1 true"]);
      assert.equal(openssl.find((c) => c.type === "debian")!.base, true, "it came with the base image");
      const everything = await components("limit=200");
      assert.equal(page.summary!.components, everything.total);
      assert.equal(page.summary!.componentsAtRisk, everything.rows.filter((c) => c.worst || c.eol).length);
      assert.ok(everything.rows.findIndex((c) => !c.worst && !c.eol) > everything.rows.findIndex((c) => c.kev), "what needs attention comes first");
      assert.equal((await components("limit=2&offset=1")).rows.length, 2);
      assert.match(await (await t.call("/api/images/components.csv?scope=all&kind=runtime")).text(), /"Node.js","18.20.8","runtime","runtime","1","internet"/);

      // Lists are served a page at a time, and a row names only the first few images: a selection asks for them in full.
      assert.equal((await t.json("/api/images/list?scope=all&limit=3")).rows.length, 3);
      assert.equal((await t.json("/api/images/list?scope=all&limit=3")).total, 7);
      assert.deepEqual((await imagesOf(t, "all", "&has=exploited&use=internet")).map((i) => i.repository).sort(), ["shop/storefront", "web"]);
      assert.deepEqual(
        (await imagesOf(t, "all", "&q=node.js")).map((i) => `${i.provider} ${i.repository}`).sort(),
        ["aws web", "github mock-org/web"],
        "found by what they are built on",
      );
      assert.deepEqual(
        (await imagesOf(t, "all", `&key=${encodeURIComponent(web.id)}`)).map((i) => i.id),
        [web.id],
      );
      const picked = await t.json(`/api/images/vulnerabilities?scope=all&full=1&key=${MOCK_KEV}&key=CVE-2026-90003`);
      assert.deepEqual((picked.rows as ImageVulnRow[]).map((v) => `${v.id} ${v.images.length}`).sort(), ["CVE-2026-90003 2", `${MOCK_KEV} 3`]);
      assert.equal((await t.call(`/api/images/list?scope=all&${Array.from({ length: 201 }, (_, i) => `key=${i}`).join("&")}`)).status, 400);

      // What an image is built on: what it says itself, another image whose layers it starts with, or its repository's Dockerfiles.
      assert.deepEqual(detail.base.names, ["node:20-alpine", "gcr.io/distroless/nodejs20"]);
      assert.equal(detail.base.from, "dockerfile");
      assert.deepEqual([detail.base.layers, detail.base.baseLayers, detail.base.packages], [3, 2, 3]);
      assert.equal(detail.base.vulns.critical, 1);
      assert.deepEqual(detail.scan.runtimes, [{ name: "Node.js", version: "18.20.8", eol: true, until: "2025-04-30", latest: null }]);
      assert.equal(detail.scan.platform, "linux/arm64");
      const api = await t.json(`/api/images/detail?scope=all&id=${encodeURIComponent(by("aws", "api").id)}`);
      assert.equal(api.base.image.name, `${ECR}/tools`, "it starts with every layer of the team's own tools image");
      const ghcrDetail = await t.json(`/api/images/detail?scope=all&id=${encodeURIComponent(ghcr.id)}`);
      assert.deepEqual([ghcrDetail.base.names, ghcrDetail.base.from], [["docker.io/library/node:22-alpine"], "label"]);
      assert.match(
        (await findings(t)).find((f) => f.checkId === "AIM-003")!.detail,
        /debian 10\.13 and Node\.js 18\.20\.8, which no longer get security fixes/,
      );

      // The image's software bill of materials, from what the scan kept.
      const cdx = await t.json(`/api/images/sbom?scope=all&format=cyclonedx&id=${encodeURIComponent(web.id)}`);
      assert.deepEqual([cdx.bomFormat, cdx.specVersion, cdx.metadata.component.type], ["CycloneDX", "1.6", "container"]);
      assert.match(cdx.metadata.component.purl, /^pkg:oci\/web@sha256%3Aa1a1.*repository_url=.*%2Fweb&tag=1\.4\.2$/);
      assert.deepEqual(
        cdx.components
          .filter((c: { type: string }) => c.type !== "library")
          .map((c: { type: string; name: string; version: string }) => `${c.type} ${c.name} ${c.version}`),
        ["operating-system debian 10.13", "platform Node.js 18.20.8"],
      );
      assert.equal(cdx.components.length, 9, "the operating system, the runtime and seven packages");
      const kevInBom = cdx.vulnerabilities.find((v: { id: string }) => v.id === MOCK_KEV);
      assert.deepEqual([kevInBom.ratings[0].severity, kevInBom.affects.length, kevInBom.recommendation], ["critical", 1, "Upgrade mock-openssl to 1.1.1n-0"]);
      assert.ok(
        cdx.components.some((c: { "bom-ref": string }) => c["bom-ref"] === kevInBom.affects[0].ref),
        "a vulnerability names a component of the document",
      );
      const spdxDoc = await t.json(`/api/images/sbom?scope=all&format=spdx&id=${encodeURIComponent(web.id)}`);
      assert.equal(spdxDoc.spdxVersion, "SPDX-2.3");
      assert.equal(spdxDoc.packages.length, 10, "the image itself and everything in it");
      assert.equal(spdxDoc.relationships.filter((r: { relationshipType: string }) => r.relationshipType === "CONTAINS").length, 9);
      for (const secret of [MOCK_IMAGE_ENV_SECRET, MOCK_IMAGE_FILE_SECRET, MOCK_IMAGE_BUILD_SECRET, MOCK_IMAGE_LABEL])
        assert.ok(!JSON.stringify([cdx, spdxDoc]).includes(secret), "a bill of materials lists components, never what the image holds");
      assert.equal((await t.call(`/api/images/sbom?scope=all&format=pdf&id=${encodeURIComponent(web.id)}`)).status, 400);
      assert.equal(
        (await t.call(`/api/images/sbom?scope=all&id=${encodeURIComponent(hidden.id)}`)).status,
        404,
        "nothing to list for an image that wasn't scanned",
      );

      // An account scanned before the index was kept gets one made when a list is first asked for.
      t.repo.cache.delete(MOCK_AWS_ACCOUNT, INDEX_KEY);
      await t.scanner.start("once more", [MOCK_GITHUB_ACCOUNT]).done;
      assert.equal((await t.json("/api/images/components?scope=all&limit=1")).total, everything.total);
      assert.ok(t.repo.cache.get(MOCK_AWS_ACCOUNT, INDEX_KEY), "and keeps it");
      const csv = await (await t.call("/api/images/vulnerabilities.csv?scope=all&status=exploited")).text();
      assert.equal(csv.split("\r\n").length, 4, "a header and one line per image the vulnerability is in");
      assert.match(csv, /"internet","ECS service web","mock-org\/web"/);

      // A repository's page lists the images it builds, wherever in the entity they are kept.
      const built = await t.json(`/api/images/built-by?account=${MOCK_GITHUB_ACCOUNT}&repo=web`);
      assert.deepEqual(built.images.map((i: { provider: string; repository: string }) => `${i.provider} ${i.repository}`).sort(), [
        "aws web",
        "github mock-org/web",
      ]);

      // A view of the GitHub organization alone lists its own images, still joined with the entity's workloads.
      const narrow = await imagesOf(t, `a:${MOCK_GITHUB_ACCOUNT}`);
      assert.deepEqual(narrow.map((i) => i.repository).sort(), ["mock-org/internal-tools", "mock-org/web"]);
      assert.equal(narrow.find((i) => i.repository === "mock-org/web")!.use, "running");
      assert.equal((await workloadsOf(t, `a:${MOCK_GITHUB_ACCOUNT}`)).length, 0, "the workloads belong to the other accounts");
    } finally {
      t.cleanup();
    }
  });

  test("entities never see each other's images or workloads, and a user limited to another entity gets 404", async () => {
    const t = makeApp();
    try {
      // The registry in one company, the service that runs its image in another.
      seedGithub(t.repo, t.vault, { entity: "Builder Ltd" });
      const aws = seedAws(t.repo, t.vault, { entity: "Runner Ltd" });
      await t.scanner.start("test").done;
      await t.scanner.start("again").done;
      const list = await imagesOf(t);
      const web = list.find((i) => i.provider === "aws" && i.repository === "web")!;
      assert.deepEqual(
        web.builtBy.map((b) => `${b.repo} ${b.how} ${b.accountId}`),
        ["mock-org/web label null"],
        "the image's own label is all that names its repository",
      );
      assert.ok(!list.find((i) => i.repository === "api")!.builtBy.length, "the other entity's workflows and repository names aren't read for it");
      const detail = await t.json(`/api/images/detail?scope=all&id=${encodeURIComponent(web.id)}`);
      assert.equal(detail.places.app, 2, "nor are the other entity's dependencies");
      assert.deepEqual(detail.base.names, [], "or its Dockerfiles");
      assert.deepEqual(
        (await t.json(`/api/images/built-by?account=${MOCK_GITHUB_ACCOUNT}&repo=web`)).images.map((i: { provider: string }) => i.provider),
        ["github"],
      );

      const other = t.repo.entities.list().find((e) => e.name === "Builder Ltd")!;
      const limited = t.limitedAs("viewer", [other.id]);
      assert.ok((await imagesOf(limited)).every((i) => i.provider === "github") && !(await workloadsOf(limited)).length);
      assert.equal((await limited.call(`/api/images/sbom?scope=all&id=${encodeURIComponent(web.id)}`)).status, 404);
      assert.equal((await limited.call(`/api/images/list?scope=a:${aws.id}`)).status, 404);
      assert.equal((await limited.call(`/api/images/detail?scope=all&id=${encodeURIComponent(web.id)}`)).status, 404);
      assert.equal((await limited.call(`/api/images?scope=a:${aws.id}`)).status, 404);
      assert.equal((await limited.call(`/api/images/built-by?account=${aws.id}&repo=web`)).status, 404);
    } finally {
      t.cleanup();
    }
  });
});
