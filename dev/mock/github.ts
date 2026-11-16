// A fetch replacement that serves a small, fictional GitHub API, so GitHub scans
// run end to end without network access (tests and `npm run dev -- --mock`). It
// chains onto whatever fetch is installed, so it works with the other mocks.
//
// The mock App has its own RSA key, made when this module loads, and the mock
// checks the JWT Keelson signs with it as GitHub would. The App is installed on
// one organization, "mock-org" (whose Pages site docs.mock.example also sits in
// the Cloudflare mock), and on a personal account that Keelson doesn't offer. As
// with the other mocks, the data is deliberately imperfect so every check family
// has something to find, and dates are relative to now.

import { createHash, createPublicKey, createVerify, generateKeyPairSync } from "node:crypto";
import { installMockAnchore } from "./anchore.ts";

const DAY = 86_400_000;
const iso = (daysAgo: number) => new Date(Date.now() - daysAgo * DAY).toISOString();

export const MOCK_GITHUB_APP_ID = "424242";
const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const PEM = privateKey.export({ type: "pkcs1", format: "pem" }).toString();
const PUBLIC = createPublicKey(privateKey);
/** The credential as Add accounts sends it: App ID and private key, joined. */
export const MOCK_GITHUB_TOKEN = `${MOCK_GITHUB_APP_ID}:${PEM}`;
/** The same key pasted into a one-line input, which drops the line breaks. */
export const MOCK_GITHUB_TOKEN_ONE_LINE = `${MOCK_GITHUB_APP_ID}:${PEM.replace(/\n/g, "")}`;
export const MOCK_GITHUB_ORG_ID = 1000001;
export const MOCK_GITHUB_ACCOUNT = `gh_${MOCK_GITHUB_ORG_ID}`;
const INSTALLATION = 9001;
const INSTALLATION_TOKEN = "mock-installation-token-0123456789";
/** A leaked secret's value as GitHub would send it without hide_secret. The scanner must never store it. */
export const MOCK_LEAKED_SECRET = "mock-leaked-secret-value-SECRET";

interface MockOptions {
  onRequest?: (url: URL, init?: RequestInit) => void;
  /** Paths (regex) that answer 403, to simulate a permission the App wasn't given. */
  deny?: RegExp[];
  /** Options for the mock Syft, Grype and Grant (dev/mock/anchore.ts), installed with the API. */
  anchore?: Parameters<typeof installMockAnchore>[0];
  /** Permissions the installation was granted, instead of the usual ones. */
  granted?: Record<string, string>;
}

/** What the organization granted the App: more than Keelson asks for, and write where it shouldn't be, so the token request is tested. */
const GRANTED = {
  metadata: "read",
  administration: "write",
  repository_hooks: "read",
  pages: "read",
  vulnerability_alerts: "read",
  security_events: "read",
  secret_scanning_alerts: "read",
  organization_administration: "read",
  members: "read",
  organization_hooks: "read",
  organization_self_hosted_runners: "read",
  contents: "write",
};

const installations = [
  {
    id: INSTALLATION,
    app_id: Number(MOCK_GITHUB_APP_ID),
    target_type: "Organization",
    account: { login: "mock-org", id: MOCK_GITHUB_ORG_ID, type: "Organization" },
    repository_selection: "all",
    permissions: GRANTED,
  },
  {
    id: 9002,
    app_id: Number(MOCK_GITHUB_APP_ID),
    target_type: "User",
    account: { login: "mock-person", id: 2000002, type: "User" },
    repository_selection: "all",
    permissions: { metadata: "read" },
  },
];

const org = {
  login: "mock-org",
  id: MOCK_GITHUB_ORG_ID,
  name: "Mock Org",
  plan: { name: "team" },
  two_factor_requirement_enabled: false,
  default_repository_permission: "write",
  members_can_create_public_repositories: true,
  members_can_fork_private_repositories: true,
  members_can_change_repo_visibility: true,
  members_can_delete_repositories: true,
};

// Fork pull requests: on public repositories only accounts new to GitHub wait for approval (GitHub's default);
// on private ones they run workflows with secrets and no approval.
const FORK_PR_APPROVAL = { approval_policy: "first_time_contributors_new_to_github" };
const FORK_PR_PRIVATE = {
  run_workflows_from_fork_pull_requests: true,
  send_write_tokens_to_workflows: false,
  send_secrets_and_variables: true,
  require_approval_for_fork_pr_workflows: false,
};

// The default group is closed to public repositories; "build-farm" is open to "web", and its runner keeps state between jobs.
const RUNNER_GROUPS = [
  { id: 1, name: "Default", visibility: "all", default: true, inherited: false, allows_public_repositories: false, restricted_to_workflows: false },
  { id: 2, name: "build-farm", visibility: "selected", default: false, inherited: false, allows_public_repositories: true, restricted_to_workflows: false },
];
const GROUP_REPOS: Record<number, string[]> = { 2: ["web", "api"] };
const RUNNERS = [
  { id: 1, name: "mock-build-1", os: "Linux", status: "online", busy: false, ephemeral: false, runner_group_id: 2, labels: [] },
  { id: 2, name: "mock-deploy-1", os: "Linux", status: "online", busy: false, ephemeral: false, runner_group_id: 1, labels: [] },
];
// "handbook" has an ephemeral runner of its own.
const REPO_RUNNERS: Record<string, unknown[]> = {
  handbook: [{ id: 3, name: "mock-docs-1", os: "Linux", status: "online", busy: false, ephemeral: true, labels: [] }],
};
// "handbook" publishes releases, and they can still change; "web" publishes none.
const RELEASES: Record<string, unknown[]> = { handbook: [{ id: 1, tag_name: "v1.0.0", draft: false, prerelease: false }] };

const repo = (name: string, o: Record<string, unknown> = {}) => ({
  id: name.length * 1000,
  name,
  full_name: `mock-org/${name}`,
  private: true,
  visibility: "private",
  archived: false,
  fork: false,
  size: 1200,
  default_branch: "main",
  pushed_at: iso(3),
  has_pages: false,
  ...o,
});

const security = (o: { scanning: boolean; push: boolean; updates: boolean }) => ({
  advanced_security: { status: "disabled" },
  secret_scanning: { status: o.scanning ? "enabled" : "disabled" },
  secret_scanning_push_protection: { status: o.push ? "enabled" : "disabled" },
  dependabot_security_updates: { status: o.updates ? "enabled" : "disabled" },
});

const REPOS = [
  // Public, unprotected, secret scanning off, with a Pages site on docs.mock.example and an http webhook.
  repo("web", { private: false, visibility: "public", has_pages: true, security_and_analysis: security({ scanning: false, push: false, updates: false }) }),
  // Protected by an organization ruleset; push protection off, a deploy key that can push.
  repo("api", { security_and_analysis: security({ scanning: true, push: false, updates: true }) }),
  // Classic protection that allows force pushes and lets administrators past it.
  repo("infra", { security_and_analysis: security({ scanning: true, push: true, updates: true }) }),
  repo("old-site", { archived: true, pushed_at: iso(800) }),
  repo("scratch", { size: 0, pushed_at: null, security_and_analysis: security({ scanning: true, push: true, updates: true }) }),
  repo("handbook", { private: false, visibility: "public", security_and_analysis: security({ scanning: true, push: true, updates: true }) }),
];

const PROTECTION: Record<string, unknown> = {
  // An approval survives new commits.
  infra: {
    required_pull_request_reviews: { required_approving_review_count: 1, dismiss_stale_reviews: false, require_last_push_approval: false },
    enforce_admins: { enabled: false },
    allow_force_pushes: { enabled: true },
    allow_deletions: { enabled: false },
  },
  handbook: {
    required_pull_request_reviews: { required_approving_review_count: 1, dismiss_stale_reviews: true, require_last_push_approval: false },
    enforce_admins: { enabled: true },
    allow_force_pushes: { enabled: false },
    allow_deletions: { enabled: false },
  },
};

const RULES: Record<string, unknown[]> = {
  api: [
    {
      type: "pull_request",
      parameters: { required_approving_review_count: 2, dismiss_stale_reviews_on_push: true, require_last_push_approval: true },
      ruleset_source_type: "Organization",
      ruleset_id: 7,
    },
    { type: "non_fast_forward", ruleset_source_type: "Organization", ruleset_id: 7 },
    { type: "deletion", ruleset_source_type: "Organization", ruleset_id: 7 },
  ],
};

const KEYS: Record<string, unknown[]> = {
  api: [
    { id: 1, title: "deploy-bot", key: "ssh-ed25519 AAAAmockpublickey", read_only: false, created_at: iso(400) },
    { id: 2, title: "mirror", key: "ssh-ed25519 AAAAmockpublickey2", read_only: true, created_at: iso(100) },
  ],
};

const HOOKS: Record<string, unknown[]> = {
  web: [
    {
      id: 31,
      active: true,
      events: ["push"],
      config: { url: "http://ci.mock.example/github?token=mock-hook-secret", insecure_ssl: "0", content_type: "json" },
    },
  ],
};
const ORG_HOOKS = [
  {
    id: 21,
    active: true,
    events: ["*"],
    config: { url: "https://siem.mock.example/ingest/github?key=mock-hook-secret", insecure_ssl: "1", content_type: "json" },
  },
];

const PAGES: Record<string, unknown> = { web: { url: "https://api.github.com/repos/mock-org/web/pages", cname: "docs.mock.example", https_enforced: false } };

const OTHER_APPS = [
  { id: INSTALLATION, app_id: Number(MOCK_GITHUB_APP_ID), app_slug: "keelson-mock-org", repository_selection: "all", permissions: GRANTED },
  {
    id: 9101,
    app_id: 777,
    app_slug: "mock-ci",
    repository_selection: "all",
    permissions: { metadata: "read", contents: "write", workflows: "write", checks: "write" },
  },
  { id: 9102, app_id: 778, app_slug: "mock-linter", repository_selection: "selected", permissions: { metadata: "read", pull_requests: "write" } },
];

const OWNERS = ["owner-a", "owner-b", "owner-c", "owner-d"].map((login, i) => ({ login, id: 5000 + i }));

const at = (name: string) => ({ name, full_name: `mock-org/${name}` });
const DEPENDABOT = [
  {
    number: 1,
    state: "open",
    repository: at("api"),
    dependency: { package: { name: "mock-xml-parser" } },
    security_advisory: { ghsa_id: "GHSA-mock-0001-0001", severity: "critical" },
    security_vulnerability: { severity: "critical" },
    created_at: iso(20),
  },
  {
    number: 2,
    state: "open",
    repository: at("web"),
    dependency: { package: { name: "mock-router" } },
    security_advisory: { ghsa_id: "GHSA-mock-0002-0002", severity: "high" },
    security_vulnerability: { severity: "high" },
    created_at: iso(40),
  },
  {
    number: 3,
    state: "open",
    repository: at("infra"),
    dependency: { package: { name: "mock-colors" } },
    security_advisory: { ghsa_id: "GHSA-mock-0003-0003", severity: "low" },
    security_vulnerability: { severity: "low" },
    created_at: iso(10),
  },
];
const CODE_SCANNING = [
  {
    number: 4,
    state: "open",
    repository: at("api"),
    rule: { id: "js/sql-injection", description: "Database query built from user-controlled sources", security_severity_level: "high" },
    tool: { name: "CodeQL" },
    created_at: iso(15),
  },
];
const SECRET_SCANNING = [
  {
    number: 1,
    state: "open",
    repository: at("web"),
    secret_type: "mock_cloud_api_token",
    secret_type_display_name: "Mock Cloud API Token",
    secret: MOCK_LEAKED_SECRET,
    validity: "active",
    push_protection_bypassed: true,
    created_at: iso(5),
  },
];

// What the repositories hold, as far as Keelson reads them: manifests, lock files, workflows and Dockerfiles, plus
// one source file that Keelson must never fetch. "web" is an npm workspace monorepo (two apps sharing a lock file)
// with a vulnerable XML parser that attackers exploit, a GPL package and a workflow that uses an action by its tag;
// "api" is a Go service with a Python worker that installs a malicious package and a package without a pinned
// version; "infra" has scripts installed without a lock file.
const lock = (packages: Record<string, unknown>) => JSON.stringify({ name: "mock-web", lockfileVersion: 3, requires: true, packages }, null, 2);
export const MOCK_SOURCE_FILE = "apps/site/src/server.ts";
export const MOCK_SOURCE_CONTENT = "const secret = 'mock-source-code-SECRET';";
const FILES: Record<string, Record<string, string>> = {
  web: {
    "package.json": JSON.stringify({ name: "mock-web", private: true, workspaces: ["apps/*", "packages/*"], devDependencies: { "mock-test-runner": "2.0.0" } }),
    "package-lock.json": lock({
      "": { name: "mock-web", workspaces: ["apps/*", "packages/*"], devDependencies: { "mock-test-runner": "2.0.0" } },
      "apps/site": { name: "@mock/site", version: "1.0.0", dependencies: { "mock-router": "1.4.0", "mock-xml-parser": "0.9.1" } },
      "packages/ui": { name: "@mock/ui", version: "1.0.0", dependencies: { "mock-router": "1.4.0", "mock-readline": "3.0.0" } },
      "node_modules/@mock/site": { resolved: "apps/site", link: true },
      "node_modules/@mock/ui": { resolved: "packages/ui", link: true },
      "node_modules/mock-router": { version: "1.4.0", license: "MIT", dependencies: { "mock-path-match": "^0.2.0" } },
      "node_modules/mock-path-match": { version: "0.2.0", license: "MIT" },
      "node_modules/mock-xml-parser": { version: "0.9.1", license: "Apache-2.0" },
      "node_modules/mock-readline": { version: "3.0.0", license: "GPL-3.0-only" },
      "node_modules/mock-test-runner": { version: "2.0.0", dev: true, license: "MIT" },
    }),
    "apps/site/package.json": JSON.stringify({ name: "@mock/site", version: "1.0.0", dependencies: { "mock-router": "1.4.0", "mock-xml-parser": "0.9.1" } }),
    "apps/site/Dockerfile": "FROM node:20-alpine AS build\nFROM gcr.io/distroless/nodejs20\n",
    [MOCK_SOURCE_FILE]: MOCK_SOURCE_CONTENT,
    "packages/ui/package.json": JSON.stringify({ name: "@mock/ui", version: "1.0.0", dependencies: { "mock-router": "1.4.0", "mock-readline": "3.0.0" } }),
    "node_modules/mock-router/package.json": JSON.stringify({ name: "mock-router", version: "1.4.0" }),
    ".github/workflows/ci.yml": [
      "name: ci",
      "on: push",
      "jobs:",
      "  build:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: actions/checkout@v4",
      "      - uses: mock-actions/cache@0123456789abcdef0123456789abcdef01234567 # v3",
      "      - uses: mock-actions/deploy@v2",
      "",
    ].join("\n"),
  },
  api: {
    "go.mod": "module example.com/mock/api\n\ngo 1.22\n\nrequire (\n\tmock.example/httpkit v1.2.0\n\tmock.example/log v0.3.0 // indirect\n)\n",
    "go.sum": "mock.example/httpkit v1.2.0 h1:mock=\nmock.example/log v0.3.0 h1:mock=\n",
    "main.go": "package main",
    "worker/requirements.txt": "mock-celery==4.0.0\nmock-colorz==1.0.0\nmock-requests>=2.0\n",
    "worker/Dockerfile": "FROM python:3.12-slim\n",
  },
  infra: {
    "scripts/package.json": JSON.stringify({ name: "mock-infra-scripts", dependencies: { "mock-cli": "^1.0.0" } }),
    "scripts/deploy.js": "console.log('deploy')",
  },
};
const blobSha = (text: string) =>
  createHash("sha1")
    .update(`blob ${Buffer.byteLength(text)}\0${text}`)
    .digest("hex");
const LANGUAGES: Record<string, Record<string, number>> = {
  web: { TypeScript: 52000, CSS: 8000, Dockerfile: 300 },
  api: { Go: 41000, Python: 9000 },
  infra: { JavaScript: 1200, HCL: 5400 },
};

/** Checks the App's JWT as GitHub does: signed with the App's key, issued for this App, not expired. */
function validJwt(auth: string): boolean {
  const [h, p, sig] = auth.replace(/^Bearer /, "").split(".");
  if (!h || !p || !sig) return false;
  try {
    if (!createVerify("RSA-SHA256").update(`${h}.${p}`).verify(PUBLIC, sig, "base64url")) return false;
    const claims = JSON.parse(Buffer.from(p, "base64url").toString());
    const now = Date.now() / 1000;
    return String(claims.iss) === MOCK_GITHUB_APP_ID && claims.exp > now && claims.iat <= now && claims.exp - claims.iat <= 600;
  } catch {
    return false;
  }
}

/** A page of a list, with a Link header like GitHub's when there is more. Small pages, so pagination is exercised. */
function paged(url: URL, items: unknown[], wrap?: string): Response {
  const per = Math.min(Number(url.searchParams.get("per_page") || 30), 4);
  const page = Number(url.searchParams.get("page") || 1);
  const slice = items.slice((page - 1) * per, page * per);
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (page * per < items.length) {
    const next = new URL(url);
    next.searchParams.set("page", String(page + 1));
    headers.link = `<${next}>; rel="next", <${url.origin}${url.pathname}?page=${Math.ceil(items.length / per)}>; rel="last"`;
  }
  return new Response(JSON.stringify(wrap ? { total_count: items.length, [wrap]: slice } : slice), { status: 200, headers });
}

export function installMockGithub(o: MockOptions = {}): () => void {
  const real = globalThis.fetch;
  const restoreAnchore = installMockAnchore(o.anchore);
  const granted = o.granted ?? GRANTED;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
    if (url.hostname !== "api.github.com") return real(input as string, init);
    o.onRequest?.(url, init);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    const fail = (status: number, message: string) => json({ message, documentation_url: "https://docs.github.com/rest", status: String(status) }, status);
    const auth = String(new Headers(init?.headers).get("authorization") || "");
    const method = init?.method || "GET";
    const path = url.pathname;

    // Requests as the App itself: listing installations and asking for an installation token.
    if (path.startsWith("/app/")) {
      if (!validJwt(auth)) return fail(401, "A JSON web token could not be decoded");
      if (method === "GET" && path === "/app/installations")
        return paged(
          url,
          installations.map((i) => (i.id === INSTALLATION ? { ...i, permissions: granted } : i)),
        );
      const m = /^\/app\/installations\/(\d+)\/access_tokens$/.exec(path);
      if (method === "POST" && m) {
        const found = installations.find((i) => i.id === Number(m[1]));
        if (!found) return fail(404, "Not Found");
        const inst = found.id === INSTALLATION ? { ...found, permissions: granted } : found;
        const asked = (JSON.parse(String(init?.body ?? "{}")).permissions ?? {}) as Record<string, string>;
        // GitHub refuses a permission the installation doesn't have.
        if (Object.keys(asked).some((k) => !(inst.permissions as Record<string, string>)[k]))
          return fail(422, "The permissions requested are not granted to this installation.");
        // Like GitHub's, the token can read only what it was asked for: one without contents can't list files.
        const token = asked.contents ? `${INSTALLATION_TOKEN}-contents` : INSTALLATION_TOKEN;
        return json({ token, expires_at: new Date(Date.now() + 3600_000).toISOString(), permissions: asked }, 201);
      }
      return fail(404, "Not Found");
    }

    if (auth !== `Bearer ${INSTALLATION_TOKEN}` && auth !== `Bearer ${INSTALLATION_TOKEN}-contents`) return fail(401, "Bad credentials");
    if (/^\/repos\/[^/]+\/[^/]+\/git\//.test(url.pathname) && !auth.endsWith("-contents")) return fail(403, "Resource not accessible by integration");
    if (method !== "GET") return fail(405, "The mock only reads");
    if (o.deny?.some((re) => re.test(path))) return fail(403, "Resource not accessible by integration");

    if (path === "/installation/repositories") return paged(url, REPOS, "repositories");
    if (path === "/orgs/mock-org") return json(org);
    if (path === "/orgs/mock-org/members") return paged(url, url.searchParams.get("role") === "admin" ? OWNERS : [...OWNERS, { login: "dev-a", id: 6000 }]);
    if (path === "/orgs/mock-org/actions/permissions") return json({ enabled_repositories: "all", allowed_actions: "all" });
    if (path === "/orgs/mock-org/actions/permissions/workflow") return json({ default_workflow_permissions: "write", can_approve_pull_request_reviews: true });
    if (path === "/orgs/mock-org/actions/permissions/fork-pr-contributor-approval") return json(FORK_PR_APPROVAL);
    if (path === "/orgs/mock-org/actions/permissions/fork-pr-workflows-private-repos") return json(FORK_PR_PRIVATE);
    if (path === "/orgs/mock-org/actions/runner-groups") return paged(url, RUNNER_GROUPS, "runner_groups");
    const group = /^\/orgs\/mock-org\/actions\/runner-groups\/(\d+)\/repositories$/.exec(path);
    if (group)
      return paged(
        url,
        (GROUP_REPOS[Number(group[1])] ?? []).map((name) => REPOS.find((x) => x.name === name)),
        "repositories",
      );
    if (path === "/orgs/mock-org/actions/runners") return paged(url, RUNNERS, "runners");
    if (path === "/orgs/mock-org/hooks") return paged(url, ORG_HOOKS);
    if (path === "/orgs/mock-org/installations") return paged(url, OTHER_APPS, "installations");
    if (path === "/orgs/mock-org/dependabot/alerts") return paged(url, DEPENDABOT);
    if (path === "/orgs/mock-org/code-scanning/alerts") return paged(url, CODE_SCANNING);
    if (path === "/orgs/mock-org/secret-scanning/alerts")
      return paged(
        url,
        // Like GitHub, the value is left out only when asked to.
        url.searchParams.get("hide_secret") === "true" ? SECRET_SCANNING.map(({ secret: _s, ...a }) => a) : SECRET_SCANNING,
      );

    const m = /^\/repos\/mock-org\/([^/]+)(\/.*)?$/.exec(path);
    const r = m && REPOS.find((x) => x.name === decodeURIComponent(m[1]));
    if (!m || !r) return fail(404, "Not Found");
    const rest = m[2] ?? "";
    if (!rest) return json(r);
    if (rest === `/branches/${r.default_branch}/protection`) return PROTECTION[r.name] ? json(PROTECTION[r.name]) : fail(404, "Branch not protected");
    if (rest === `/rules/branches/${r.default_branch}`) return json(RULES[r.name] ?? []);
    if (rest === "/keys") return paged(url, KEYS[r.name] ?? []);
    if (rest === "/hooks") return paged(url, HOOKS[r.name] ?? []);
    if (rest === "/pages") return PAGES[r.name] ? json(PAGES[r.name]) : fail(404, "Not Found");
    if (rest === "/actions/runners") return paged(url, REPO_RUNNERS[r.name] ?? [], "runners");
    if (rest === "/releases") return paged(url, RELEASES[r.name] ?? []);
    if (rest === "/immutable-releases") return fail(404, "Not Found");
    if (rest === "/languages") return json(LANGUAGES[r.name] ?? {});
    if (rest === `/git/trees/${r.default_branch}`) {
      if (r.size === 0) return fail(409, "Git Repository is empty.");
      const files = Object.entries(FILES[r.name] ?? { "README.md": "# mock" });
      return json({
        sha: `tree-${r.name}`,
        truncated: false,
        tree: files.map(([p, text]) => ({ path: p, mode: "100644", type: "blob", sha: blobSha(text), size: Buffer.byteLength(text) })),
      });
    }
    const blob = /^\/git\/blobs\/([0-9a-f]{40})$/.exec(rest);
    if (blob) {
      const text = Object.values(FILES[r.name] ?? {}).find((t) => blobSha(t) === blob[1]);
      return text == null
        ? fail(404, "Not Found")
        : json({ sha: blob[1], size: Buffer.byteLength(text), encoding: "base64", content: Buffer.from(text).toString("base64") });
    }
    // Dependabot alerts are on everywhere but "web"; code scanning has run on "api" only, and private repositories without Code Security say so.
    if (rest === "/vulnerability-alerts") return r.name === "web" ? fail(404, "Vulnerability alerts are disabled.") : new Response(null, { status: 204 });
    if (rest === "/code-scanning/analyses") {
      if (r.name === "api") return json([{ id: 1, tool: { name: "CodeQL" }, created_at: iso(2) }]);
      return r.private ? fail(403, "Code Security must be enabled for this repository to use code scanning.") : fail(404, "no analysis found");
    }
    return fail(404, `No mock for ${path}`);
  }) as typeof fetch;
  return () => {
    globalThis.fetch = real;
    restoreAnchore();
  };
}
