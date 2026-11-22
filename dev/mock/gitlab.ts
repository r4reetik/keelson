// A fictional GitLab instance for tests and the mock dev server: one top-level
// group with a subgroup, a group that doesn't require two-factor
// authentication, and projects whose default branches, webhooks, deploy keys,
// deploy tokens, CI includes, dependencies and container registries are set up
// well, badly or not at all. It answers only GET, checks the token, pages like
// GitLab does, and holds a few values that must never reach a scan's stored data.

import { createHash } from "node:crypto";
import { accountIdOf } from "../../src/providers/gitlab/client.ts";
import { installMockAnchore } from "./anchore.ts";
import { installMockTrivy, type MockTrivyOptions } from "./trivy.ts";

export const MOCK_GITLAB_BASE = "https://gitlab.mock-group.example";
const KEY = "glpat-mock0gitlab0token.01.0123456789";
/** The credential as the vault stores it: the instance's address and the token. */
export const MOCK_GITLAB_TOKEN = `${MOCK_GITLAB_BASE}:${KEY}`;
const GROUP_ID = 42;
export const MOCK_GITLAB_ACCOUNT = accountIdOf(MOCK_GITLAB_BASE, GROUP_ID);
/** Values the mock returns that a scan must drop. */
export const MOCK_GITLAB_SECRETS = ["hook-path-secret-88", "ssh-ed25519 AAAAGITLAB"];
/** A source file in the mock: a scan lists it and must never fetch it. */
export const MOCK_GITLAB_SOURCE_FILE = "app/server.rb";
export const MOCK_GITLAB_SOURCE_CONTENT = "KEY = 'mock-gitlab-source-SECRET'";
export const MOCK_GITLAB_DIGEST = `sha256:${"ab12".repeat(16)}`;

export interface MockGitlabOptions {
  onRequest?: (url: URL, init?: RequestInit) => void;
  /** The token has the Owner role (default true). Without it GitLab leaves a group's security settings out and refuses its webhooks, deploy keys and tokens. */
  owner?: boolean;
  /** The instance is on Premium or Ultimate (default true). On Free, group webhooks and approval rules don't exist. */
  premium?: boolean;
  /** Entries per page of a project's file list. */
  treePage?: number;
  anchore?: Parameters<typeof installMockAnchore>[0];
  trivy?: MockTrivyOptions;
}

const lock = (packages: Record<string, unknown>) => JSON.stringify({ name: "mock-site", lockfileVersion: 3, requires: true, packages }, null, 2);
const FILES: Record<number, Record<string, string>> = {
  1: {
    "package.json": JSON.stringify({ name: "mock-site", private: true, dependencies: { "mock-xml-parser": "0.9.1" } }),
    "package-lock.json": lock({
      "": { name: "mock-site", dependencies: { "mock-xml-parser": "0.9.1" } },
      "node_modules/mock-xml-parser": { version: "0.9.1", license: "Apache-2.0" },
    }),
    [MOCK_GITLAB_SOURCE_FILE]: MOCK_GITLAB_SOURCE_CONTENT,
    "README.md": "# web",
    // One include from another group by a branch, one from the group itself, a component at a moving version, GitLab's own template.
    ".gitlab-ci.yml": [
      "include:",
      "  - project: 'other-group/ci-templates'",
      "    ref: main",
      "    file: '/build.yml'",
      "  - project: 'mock-labs/platform/ci'",
      "    ref: main",
      "    file: '/deploy.yml'",
      "  - component: $CI_SERVER_FQDN/other-group/scanners/secret-detection@1",
      "  - component: $CI_SERVER_FQDN/other-group/scanners/pinned@0123456789abcdef0123456789abcdef01234567",
      "  - template: Jobs/SAST.gitlab-ci.yml",
      "  - local: '/ci/test.yml'",
      "stages: [build]",
      "",
    ].join("\n"),
  },
  2: {
    "go.mod": "module example.com/mock/api\n\ngo 1.22\n\nrequire mock.example/httpkit v1.2.0\n",
    "go.sum": "mock.example/httpkit v1.2.0 h1:mock=\n",
    "main.go": "package main",
  },
  3: { "requirements.txt": "mock-requests>=2.0\n", "deploy.py": "print('mock')" },
};
const blobSha = (text: string) => createHash("sha1").update(text).digest("hex");

interface MockProject {
  body: Record<string, unknown>;
  rules: unknown[];
  approvalRules: unknown[];
  approvals: Record<string, unknown>;
  hooks: unknown[];
  keys: unknown[];
  tokens: unknown[];
  domains: unknown[];
  registry: { id: number; path: string; tags: string[] }[];
  license: string | null;
}
const project = (id: number, path: string, extra: Record<string, unknown> = {}, more: Partial<Omit<MockProject, "body">> = {}): MockProject => ({
  body: {
    id,
    name: path.split("/").pop(),
    path_with_namespace: `mock-labs/${path}`,
    visibility: "private",
    archived: false,
    empty_repo: false,
    mirror: false,
    default_branch: "main",
    last_activity_at: new Date(Date.now() - 2 * 86_400_000).toISOString(),
    web_url: `${MOCK_GITLAB_BASE}/mock-labs/${path}`,
    container_registry_access_level: "enabled",
    pages_access_level: "private",
    ...extra,
  },
  rules: [],
  approvalRules: [],
  approvals: { reset_approvals_on_push: true, merge_requests_author_approval: false },
  hooks: [],
  keys: [],
  tokens: [],
  domains: [],
  registry: [],
  license: null,
  ...more,
});
const level = (n: number) => ({ access_level: n, user_id: null, group_id: null });
const PROJECTS: MockProject[] = [
  // Public: developers push to main and may force push; an insecure webhook; a deploy key that can push; a Pages domain; an image anyone can pull.
  project(
    1,
    "web",
    { visibility: "public", pages_access_level: "enabled" },
    {
      rules: [{ name: "main", push_access_levels: [level(30), level(40)], merge_access_levels: [level(30)], allow_force_push: true }],
      hooks: [{ id: 1, url: "http://chat.mock-group.example/hooks/hook-path-secret-88", enable_ssl_verification: true }],
      keys: [{ id: 1, title: "deploy (write)", can_push: true, key: "ssh-ed25519 AAAAGITLAB deploy" }],
      domains: [{ domain: "handbook.mock-group.example", verified: true }],
      registry: [{ id: 11, path: "mock-labs/web", tags: ["latest", "1.4.0"] }],
      license: "mit",
    },
  ),
  // In a subgroup: maintainers push past merge requests, approvals stay after new commits, a webhook that trusts any certificate, a lasting write token.
  project(
    2,
    "backend/api",
    {},
    {
      rules: [{ name: "ma*", push_access_levels: [level(40)], merge_access_levels: [level(30)], allow_force_push: false }],
      approvalRules: [{ id: 1, name: "Reviewers", approvals_required: 1 }],
      approvals: { reset_approvals_on_push: false, merge_requests_author_approval: true },
      hooks: [{ id: 2, url: "https://ci.mock-group.example/gitlab", enable_ssl_verification: false }],
      tokens: [
        { id: 1, name: "registry-push", scopes: ["read_registry", "write_registry"], expires_at: null, revoked: false, expired: false },
        { id: 2, name: "mirror-read", scopes: ["read_repository"], expires_at: null, revoked: false, expired: false },
      ],
      registry: [{ id: 21, path: "mock-labs/backend/api", tags: ["latest"] }],
    },
  ),
  project(3, "infra"),
  // As it should be: nobody pushes to main, approvals are removed by new commits.
  project(
    4,
    "payments",
    {},
    {
      rules: [{ name: "main", push_access_levels: [level(0)], merge_access_levels: [level(40)], allow_force_push: false }],
      approvalRules: [{ id: 2, name: "Reviewers", approvals_required: 2 }],
      keys: [{ id: 2, title: "ci (read)", can_push: false, key: "ssh-ed25519 AAAAGITLAB ci" }],
    },
  ),
  project(5, "legacy-billing", { archived: true }),
  project(6, "upstream-copy", { mirror: true }),
];
const user = (username: string, access_level: number) => ({ id: username.length * 7, username, name: username, state: "active", access_level });
const MEMBERS = [
  ...["ana", "ben", "chloe", "dev", "erin", "farid"].map((u) => user(u, 50)),
  user("gus", 30),
  // A group access token's own user: not a person.
  user("group_42_bot_0123abcd", 50),
];

/** Answers requests to the mock instance. Returns a function that puts the real fetch back. */
export function installMockGitlab(o: MockGitlabOptions = {}): () => void {
  const real = globalThis.fetch;
  const restoreAnchore = installMockAnchore(o.anchore);
  const restoreTrivy = installMockTrivy(o.trivy);
  const host = new URL(MOCK_GITLAB_BASE).hostname;
  const owner = o.owner !== false;
  const premium = o.premium !== false;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
    if (url.hostname !== host) return real(input as string, init);
    o.onRequest?.(url, init);
    const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
      new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
    const fail = (status: number, message: string) => json({ message }, status);
    /** Pages as GitLab does: ?page and ?per_page, with the next page's number in a header (empty on the last). */
    const paged = (items: unknown[], cap = 100) => {
      const per = Math.min(Number(url.searchParams.get("per_page")) || 20, cap);
      const page = Math.max(Number(url.searchParams.get("page")) || 1, 1);
      const more = page * per < items.length;
      const next = new URL(url);
      next.searchParams.set("page", String(page + 1));
      return json(items.slice((page - 1) * per, page * per), 200, {
        "x-next-page": more ? String(page + 1) : "",
        ...(more ? { link: `<${next}>; rel="next"` } : {}),
      });
    };
    if ((init?.method || "GET") !== "GET") return fail(405, "405 Method Not Allowed");
    // The instance's own front page: what a network test asks for.
    if (!url.pathname.startsWith("/api/v4/"))
      return new Response("<!doctype html><title>Mock GitLab</title>", { status: 200, headers: { "content-type": "text/html" } });
    const path = url.pathname.slice("/api/v4".length);
    if (new Headers(init?.headers).get("private-token") !== KEY) return fail(401, "401 Unauthorized");
    const group = {
      id: GROUP_ID,
      name: "Mock Labs",
      path: "mock-labs",
      full_path: "mock-labs",
      full_name: "Mock Labs",
      visibility: "private",
      parent_id: null,
      // GitLab leaves these out for anyone but an Owner.
      ...(owner ? { require_two_factor_authentication: false, share_with_group_lock: false, project_creation_level: "developer" } : {}),
    };

    if (path === "/personal_access_tokens/self")
      return json({ id: 1, name: "Keelson", revoked: false, active: true, scopes: ["read_api"], expires_at: "2027-06-30" });
    if (path === "/groups") return paged([group]);
    if (path === `/groups/${GROUP_ID}`) return json(group);
    if (path === `/groups/${GROUP_ID}/members/all`) return paged(MEMBERS);
    if (path === `/groups/${GROUP_ID}/hooks`) return !premium ? fail(404, "404 Not Found") : owner ? paged([]) : fail(403, "403 Forbidden");
    if (path === `/groups/${GROUP_ID}/projects`) return paged(PROJECTS.map((p) => p.body));
    const m = /^\/projects\/(\d+)(\/.*)?$/.exec(path);
    const p = m ? PROJECTS.find((x) => x.body.id === Number(m[1])) : undefined;
    if (!m || !p) return fail(404, "404 Not Found");
    const rest = m[2] ?? "";
    if (!rest) return json({ ...p.body, license: p.license ? { key: p.license, spdx_id: p.license.toUpperCase() } : null });
    if (rest === "/protected_branches") return paged(p.rules);
    if (rest === "/approval_rules") return premium ? paged(p.approvalRules) : fail(404, "404 Not Found");
    if (rest === "/approvals") return premium ? json(p.approvals) : fail(404, "404 Not Found");
    // Maintainers and up only.
    if (["/hooks", "/deploy_keys", "/deploy_tokens", "/pages/domains"].includes(rest) && !owner) return fail(403, "403 Forbidden");
    if (rest === "/hooks") return paged(p.hooks);
    if (rest === "/deploy_keys") return paged(p.keys);
    if (rest === "/deploy_tokens") return paged(p.tokens);
    if (rest === "/pages/domains") return paged(p.domains);
    const files = Object.entries(FILES[Number(p.body.id)] ?? { "README.md": "# mock" });
    if (rest === "/languages")
      return json(
        files.some(([f]) => f.endsWith(".go")) ? { Go: 100 } : files.some(([f]) => f.endsWith(".py")) ? { Python: 100 } : { Ruby: 61.5, JavaScript: 38.5 },
      );
    if (rest === "/repository/tree") {
      // Every folder and file, as GitLab lists them: folders are entries of their own, and a file has no size.
      const dirs = new Set<string>();
      for (const [f] of files) for (let d = f; d.includes("/"); ) dirs.add((d = d.slice(0, d.lastIndexOf("/"))));
      const all = [
        ...[...dirs].map((d) => ({ id: blobSha(`dir:${d}`), name: d.split("/").pop(), type: "tree", path: d, mode: "040000" })),
        ...files.map(([f, text]) => ({ id: blobSha(text), name: f.split("/").pop(), type: "blob", path: f, mode: "100644" })),
      ];
      const within = url.searchParams.get("path") ?? "";
      const listed =
        url.searchParams.get("recursive") === "true"
          ? all
          : all.filter((e) => (e.path.includes("/") ? e.path.slice(0, e.path.lastIndexOf("/")) : "") === within);
      return paged(listed, o.treePage ?? 100);
    }
    const blob = /^\/repository\/blobs\/([0-9a-f]{40})$/.exec(rest);
    if (blob) {
      const text = files.map(([, t]) => t).find((t) => blobSha(t) === blob[1]);
      return text == null
        ? fail(404, "404 Not Found")
        : json({ sha: blob[1], size: Buffer.byteLength(text), encoding: "base64", content: Buffer.from(text).toString("base64") });
    }
    if (rest === "/registry/repositories")
      return paged(
        p.registry.map((r) => ({
          id: r.id,
          path: r.path,
          location: `registry.mock-group.example/${r.path}`,
          tags: r.tags.map((t) => ({ name: t, path: `${r.path}:${t}`, location: `registry.mock-group.example/${r.path}:${t}` })),
        })),
      );
    const tag = /^\/registry\/repositories\/(\d+)\/tags\/([^/]+)$/.exec(rest);
    if (tag && p.registry.some((r) => r.id === Number(tag[1]) && r.tags.includes(decodeURIComponent(tag[2]))))
      // Both of web's tags name one image.
      return json({
        name: decodeURIComponent(tag[2]),
        digest: Number(tag[1]) === 11 ? MOCK_GITLAB_DIGEST : `sha256:${"cd34".repeat(16)}`,
        created_at: new Date(Date.now() - 86_400_000).toISOString(),
        total_size: 1,
      });
    return fail(404, "404 Not Found");
  }) as typeof fetch;
  return () => {
    globalThis.fetch = real;
    restoreAnchore();
    restoreTrivy();
  };
}
