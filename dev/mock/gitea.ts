// A fictional Gitea instance for tests and the mock dev server: one
// organization with an owners team that has grown, a second team that
// administers everything, members without two-factor authentication, webhooks
// (one over plain HTTP, with a secret in its address) and repositories whose
// default branches are protected well, badly or not at all. It answers only
// GET, checks the token, pages like Gitea does, and holds a few values that must
// never reach a scan's stored data.

import { createHash } from "node:crypto";
import { accountIdOf } from "../../src/providers/gitea/client.ts";
import { installMockAnchore } from "./anchore.ts";

export const MOCK_GITEA_BASE = "https://git.mock-group.example";
const KEY = "mock0gitea0token0123456789abcdef01234567";
/** The credential as the vault stores it: the instance's address and the token. */
export const MOCK_GITEA_TOKEN = `${MOCK_GITEA_BASE}:${KEY}`;
const ORG = { id: 7, username: "platform", name: "platform", full_name: "Mock Platform", visibility: "public", repo_admin_change_team_access: false };
export const MOCK_GITEA_ACCOUNT = accountIdOf(MOCK_GITEA_BASE, ORG.id);
/** Values the mock returns that a scan must drop. */
export const MOCK_GITEA_SECRETS = ["hook-path-secret-71", "mock-hook-authorization", "mock-hook-secret", "mock-mirror-password", "ssh-ed25519 AAAAMOCK"];

/** A source file in the mock: a scan lists it and must never fetch it. */
export const MOCK_GITEA_SOURCE_FILE = "src/server.ts";
export const MOCK_GITEA_SOURCE_CONTENT = "const key = 'mock-gitea-source-SECRET';";
const lock = (packages: Record<string, unknown>) => JSON.stringify({ name: "mock-shop", lockfileVersion: 3, requires: true, packages }, null, 2);
/** Each repository's files on its default branch. Dependency files are fictional packages the mock Syft and Grype know. */
const FILES: Record<string, Record<string, string>> = {
  web: {
    "package.json": JSON.stringify({ name: "mock-shop", private: true, dependencies: { "mock-xml-parser": "0.9.1", "mock-readline": "3.0.0" } }),
    "package-lock.json": lock({
      "": { name: "mock-shop", dependencies: { "mock-xml-parser": "0.9.1", "mock-readline": "3.0.0" } },
      "node_modules/mock-xml-parser": { version: "0.9.1", license: "Apache-2.0" },
      "node_modules/mock-readline": { version: "3.0.0", license: "GPL-3.0-only" },
    }),
    [MOCK_GITEA_SOURCE_FILE]: MOCK_GITEA_SOURCE_CONTENT,
    "README.md": "# web",
    // Gitea Actions reads this folder first; one action is pinned to a commit, one moves with its tag.
    ".gitea/workflows/ci.yml": [
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
  infra: { "requirements.txt": "mock-requests>=2.0\n", "deploy.py": "print('mock')" },
  payments: {
    "go.mod": "module example.com/mock/payments\n\ngo 1.22\n\nrequire mock.example/httpkit v1.2.0\n",
    "go.sum": "mock.example/httpkit v1.2.0 h1:mock=\n",
    "main.go": "package main",
  },
};
const blobSha = (text: string) => createHash("sha1").update(text).digest("hex");

export interface MockGiteaOptions {
  /** How the stand-ins for Syft, Grype and Grant behave (dev/mock/anchore.ts). */
  anchore?: Parameters<typeof installMockAnchore>[0];
  /** Files per page of a repository's file list (Gitea's is 1000). */
  treePage?: number;
  onRequest?: (url: URL, init?: RequestInit) => void;
  /** The token has the admin scope and belongs to a site administrator (default true). */
  admin?: boolean;
  /** The instance requires sign-in to see anything (default false: it shows public repositories to anyone). */
  requireSignIn?: boolean;
  /** An older instance: it ignores the two-factor filter on its list of users, and has no push mirrors. */
  legacy?: boolean;
  /** The most items the instance gives per page (its MAX_RESPONSE_ITEMS; 50 unless set). */
  pageSize?: number;
  /** Leave X-Total-Count out of every list, as an older instance does for some. */
  noTotals?: boolean;
  /** Answer every request to a repository's settings as if the token's user didn't administer it. */
  notAdmin?: boolean;
}

const user = (login: string, extra: object = {}) => ({
  id: login.length * 13,
  login,
  full_name: "",
  email: `${login}@mock-group.example`,
  is_admin: false,
  ...extra,
});
const MEMBERS = ["ana", "ben", "chloe", "deploy-bot", "erin", "farid", "gus"];
const NO_TWO_FACTOR = ["ben", "gus", "someone-else"];
const TEAMS = [
  {
    id: 1,
    name: "Owners",
    permission: "owner",
    includes_all_repositories: true,
    can_create_org_repo: true,
    members: ["ana", "ben", "chloe", "deploy-bot", "erin", "farid"],
  },
  { id: 2, name: "release", permission: "admin", includes_all_repositories: true, can_create_org_repo: false, members: ["erin", "gus"] },
  { id: 3, name: "developers", permission: "write", includes_all_repositories: false, can_create_org_repo: false, members: ["farid", "gus"] },
];
const hook = (url: string, extra: object = {}) => ({
  id: url.length,
  type: "gitea",
  active: true,
  events: ["push"],
  // What Gitea returns and Keelson never keeps: the address's path, and the header that authenticates deliveries.
  authorization_header: "Bearer mock-hook-authorization",
  config: { url, content_type: "json", secret: "mock-hook-secret" },
  ...extra,
});
const ORG_HOOKS = [hook("https://ci.mock-group.example/gitea"), hook("http://chat.mock-group.example/hooks/hook-path-secret-71", { type: "slack" })];

interface MockRepo {
  body: Record<string, unknown>;
  rules: Record<string, unknown>[];
  hooks: unknown[];
  keys: Record<string, unknown>[];
  collaborators: Record<string, string>;
  mirrors: Record<string, unknown>[];
}
const repo = (name: string, extra: Record<string, unknown> = {}, more: Partial<Omit<MockRepo, "body">> = {}): MockRepo => ({
  body: {
    id: name.length * 31,
    name,
    full_name: `${ORG.username}/${name}`,
    private: true,
    internal: false,
    archived: false,
    empty: false,
    fork: false,
    mirror: false,
    default_branch: "main",
    updated_at: new Date(Date.now() - 3 * 86_400_000).toISOString(),
    html_url: `${MOCK_GITEA_BASE}/${ORG.username}/${name}`,
    ...extra,
  },
  rules: [],
  hooks: [],
  keys: [],
  collaborators: {},
  mirrors: [],
  ...more,
});
const GOOD_RULE = {
  rule_name: "main",
  priority: 1,
  enable_push: false,
  enable_push_whitelist: false,
  required_approvals: 2,
  dismiss_stale_approvals: true,
  enable_force_push: false,
  block_admin_merge_override: true,
};
const REPOS: MockRepo[] = [
  repo("payments", {}, { rules: [GOOD_RULE], keys: [{ id: 1, title: "ci (read)", read_only: true, key: "ssh-ed25519 AAAAMOCK ci" }] }),
  // Public on an instance that shows it to anyone; its rule still lets everyone push, and a contractor administers it.
  repo(
    "web",
    { private: false },
    {
      rules: [{ rule_name: "main", enable_push: true, enable_push_whitelist: false, required_approvals: 0, enable_force_push: false }],
      hooks: [hook("https://deploy.mock-group.example/web")],
      keys: [{ id: 2, title: "deploy (write)", read_only: false, key: "ssh-ed25519 AAAAMOCK deploy" }],
      collaborators: { "contractor-x": "admin", "reviewer-y": "read", gus: "write" },
    },
  ),
  // Reviewed, but an approval survives new commits, anyone can force push and administrators merge past it.
  repo(
    "docs",
    { private: false },
    {
      rules: [
        { rule_name: "release/*", priority: 1, enable_push: false, required_approvals: 2, dismiss_stale_approvals: true },
        {
          rule_name: "ma*",
          priority: 2,
          enable_push: false,
          required_approvals: 1,
          dismiss_stale_approvals: false,
          enable_force_push: true,
          block_admin_merge_override: false,
        },
      ],
    },
  ),
  // No rule at all, and every change is pushed to a server outside the organization, with a password in the address.
  repo(
    "infra",
    {},
    {
      mirrors: [
        { remote_name: "mirror", remote_address: "https://mirror-user:mock-mirror-password@code.partner.example/mock/infra.git", sync_on_commit: true },
      ],
    },
  ),
  repo("legacy-billing", { archived: true }),
  repo("upstream-copy", { mirror: true }),
  repo("scratch", { empty: true }),
];

/** Answers requests to the mock instance. Returns a function that puts the real fetch back. */
export function installMockGitea(o: MockGiteaOptions = {}): () => void {
  const real = globalThis.fetch;
  const restoreAnchore = installMockAnchore(o.anchore);
  const host = new URL(MOCK_GITEA_BASE).hostname;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
    if (url.hostname !== host) return real(input as string, init);
    o.onRequest?.(url, init);
    const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
      new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
    const fail = (status: number, message: string) => json({ message, url: `${MOCK_GITEA_BASE}/api/swagger` }, status);
    /** Pages as Gitea does: ?page and ?limit, at most 50, with the total in a header. */
    const paged = (items: unknown[]) => {
      const limit = Math.min(Number(url.searchParams.get("limit")) || 30, o.pageSize ?? 50);
      const page = Math.max(Number(url.searchParams.get("page")) || 1, 1);
      return json(items.slice((page - 1) * limit, page * limit), 200, o.noTotals ? {} : { "x-total-count": String(items.length) });
    };
    if ((init?.method || "GET") !== "GET") return fail(405, "Method not allowed");
    // The instance's own front page: what a network test asks for.
    if (!url.pathname.startsWith("/api/v1/"))
      return new Response("<!doctype html><title>Mock Gitea</title>", { status: 200, headers: { "content-type": "text/html" } });
    const path = url.pathname.slice("/api/v1".length);
    const auth = String(new Headers(init?.headers).get("authorization") || "");
    const org = `/orgs/${ORG.username}`;
    const inRepo = /^\/repos\/platform\/([^/]+)(\/.*)?$/.exec(path);

    if (path === "/version") return json({ version: o.legacy ? "1.21.11" : "1.25.4" });
    if (!auth) {
      // Without a sign-in the instance shows what is public, unless it requires one.
      const found = inRepo && !inRepo[2] ? REPOS.find((r) => r.body.name === inRepo[1]) : null;
      if (found && found.body.private === false && !o.requireSignIn) return json(found.body);
      return fail(o.requireSignIn ? 401 : 404, o.requireSignIn ? "token is required" : "The target couldn't be found.");
    }
    if (auth !== `token ${KEY}`) return fail(401, "user does not exist [uid: 0, name: ]");

    if (path === "/settings/api") return json({ max_response_items: o.pageSize ?? 50, default_paging_num: 30 });
    if (path === "/user") return json(user("deploy-bot", { is_admin: o.admin !== false }));
    if (path === "/user/orgs") return paged([ORG]);
    if (path === org) return json(ORG);
    if (path === `${org}/members`) return paged(MEMBERS.map((m) => user(m)));
    if (path === `${org}/teams`) return paged(TEAMS.map(({ members: _members, ...t }) => t));
    const team = /^\/teams\/(\d+)\/members$/.exec(path);
    if (team) return paged((TEAMS.find((t) => t.id === Number(team[1]))?.members ?? []).map((m) => user(m)));
    if (path === `${org}/hooks`) return paged(ORG_HOOKS);
    if (path === `${org}/repos`) return paged(REPOS.map((r) => r.body));
    if (path === "/admin/users") {
      if (o.admin === false)
        return fail(
          403,
          "token does not have at least one of required scope(s), required=[read:admin], token scope=read:organization,read:repository,read:user",
        );
      const everyone = [...new Set([...MEMBERS, ...NO_TWO_FACTOR])];
      const filter = url.searchParams.get("is_2fa_enabled");
      // An instance from before the filter existed ignores it and lists everyone.
      if (o.legacy || filter == null) return paged(everyone.map((m) => user(m)));
      return paged(everyone.filter((m) => NO_TWO_FACTOR.includes(m) === (filter === "false")).map((m) => user(m)));
    }
    if (inRepo) {
      const r = REPOS.find((x) => x.body.name === decodeURIComponent(inRepo[1]));
      if (!r) return fail(404, "The target couldn't be found.");
      const rest = inRepo[2] ?? "";
      if (!rest) return json(r.body);
      // The file list, the files themselves and the languages: readable by anyone who can read the repository.
      const files = Object.entries(FILES[String(r.body.name)] ?? { "README.md": "# mock" });
      if (rest === "/languages")
        return json(files.some(([p]) => p.endsWith(".go")) ? { Go: 4000 } : files.some(([p]) => p.endsWith(".py")) ? { Python: 1200 } : { TypeScript: 9000 });
      if (rest === `/git/trees/${r.body.default_branch}`) {
        if (r.body.empty) return fail(404, "The target couldn't be found.");
        // Gitea gives a long list a page at a time, and says there is more with `truncated`.
        const per = Math.min(Number(url.searchParams.get("per_page")) || 1000, o.treePage ?? 1000);
        const page = Math.max(Number(url.searchParams.get("page")) || 1, 1);
        const entries = files.map(([p, text]) => ({ path: p, mode: "100644", type: "blob", sha: blobSha(text), size: Buffer.byteLength(text) }));
        return json({
          sha: `tree-${r.body.name}`,
          page,
          total_count: entries.length,
          truncated: page * per < entries.length,
          tree: entries.slice((page - 1) * per, page * per),
        });
      }
      const blob = /^\/git\/blobs\/([0-9a-f]{40})$/.exec(rest);
      if (blob) {
        const text = files.map(([, t]) => t).find((t) => blobSha(t) === blob[1]);
        return text == null
          ? fail(404, "The target couldn't be found.")
          : json({ sha: blob[1], size: Buffer.byteLength(text), encoding: "base64", content: Buffer.from(text).toString("base64") });
      }
      if (o.notAdmin) return fail(403, "user should be an owner or a collaborator with admin write of a repository");
      if (rest === "/branch_protections") return json(r.rules);
      if (rest === "/hooks") return paged(r.hooks);
      if (rest === "/keys") return paged(r.keys);
      if (rest === "/collaborators") return paged(Object.keys(r.collaborators).map((c) => user(c)));
      if (rest === "/push_mirrors") return o.legacy ? fail(404, "The target couldn't be found.") : paged(r.mirrors);
      const who = /^\/collaborators\/([^/]+)\/permission$/.exec(rest);
      if (who) return json({ permission: r.collaborators[decodeURIComponent(who[1])] ?? "none", role_name: "", user: user(decodeURIComponent(who[1])) });
    }
    return fail(404, "The target couldn't be found.");
  }) as typeof fetch;
  return () => {
    globalThis.fetch = real;
    restoreAnchore();
  };
}
