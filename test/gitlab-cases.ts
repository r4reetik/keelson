// A well-configured GitLab group, and one failing case per GitLab check. The
// type is Record<GitlabCheckId, …>, so a new check without a case doesn't
// compile, and test/gitlab-checks.test.ts asserts each case really makes its
// check fail.

import { imageCase } from "./helpers/images.ts";
import type { GitlabCheckId } from "../src/providers/gitlab/checks/index.ts";
import type { GitlabBranchRule, GitlabInventory, GitlabProject } from "../src/providers/gitlab/types.ts";
import type { DepPackage } from "../src/shared/dependencies.ts";
import { dependencies, pkg, repoDeps, vuln } from "./github-cases.ts";

export const NOW = Date.parse("2026-06-01T00:00:00Z");
const BASE = "https://gitlab.example.com";

export const rule = (extra: Partial<GitlabBranchRule> = {}): GitlabBranchRule => ({ rule: "main", pushLevel: 0, pushNamed: false, forcePush: false, ...extra });

export function project(extra: Partial<GitlabProject> = {}): GitlabProject {
  return {
    id: 1,
    name: "web",
    fullPath: "example/web",
    visibility: "private",
    archived: false,
    empty: false,
    mirror: false,
    defaultBranch: "main",
    updatedAt: NOW - 2 * 86_400_000,
    url: `${BASE}/example/web`,
    license: "MIT",
    protection: rule(),
    approvals: { required: 1, resetOnPush: true, authorApproves: false },
    hooks: [{ endpoint: "https://ci.example.com", verifiesTls: true }],
    deployKeys: [{ title: "ci", canPush: false }],
    deployTokens: [{ name: "pull", scopes: ["read_registry"], expiresAt: null }],
    pagesDomains: [],
    registry: true,
    ...extra,
  };
}

export function gitlabInventory(extra: Partial<GitlabInventory> = {}): GitlabInventory {
  return {
    accountId: "gl_0a1b2c3d_1",
    accountName: "Example",
    login: "example",
    base: BASE,
    now: NOW,
    group: { visibility: "private", requireTwoFactor: true, shareLock: true },
    members: [
      { username: "ana", level: 50 },
      { username: "ben", level: 40 },
    ],
    hooks: [{ endpoint: "https://audit.example.com", verifiesTls: true }],
    groupHooksAbsent: false,
    projects: [project()],
    // The same fixtures as GitHub's: the pipeline and its checks are shared.
    dependencies: dependencies([repoDeps({ actions: [{ action: "example/ci", ref: "main", workflow: ".gitlab-ci.yml" }] })]),
    unreadable: [],
    images: imageCase("gitlab", "registry.gitlab.com", 0, { repository: "example/web", public: true, linkedRepo: "example/web" }),
    ...extra,
  };
}

const withProject = (extra: Partial<GitlabProject>) => gitlabInventory({ projects: [project(extra)] });
const withPackages = (...packages: DepPackage[]) => gitlabInventory({ dependencies: dependencies([repoDeps({ packages })]) });
const withImage = (n: 1 | 2 | 3 | 4) =>
  gitlabInventory({ images: imageCase("gitlab", "registry.gitlab.com", n, { repository: "example/web", public: true, linkedRepo: "example/web" }) });

export const GITLAB_CASES: Record<GitlabCheckId, () => GitlabInventory> = {
  "GLG-001": () => gitlabInventory({ group: { visibility: "private", requireTwoFactor: false, shareLock: true } }),
  "GLG-002": () => gitlabInventory({ members: ["a", "b", "c", "d", "e", "f"].map((username) => ({ username, level: 50 })) }),
  "GLG-003": () => gitlabInventory({ group: { visibility: "private", requireTwoFactor: true, shareLock: false } }),
  "GLB-001": () => withProject({ protection: null }),
  "GLB-002": () => withProject({ protection: rule({ forcePush: true }) }),
  "GLB-003": () => withProject({ approvals: { required: 1, resetOnPush: false, authorApproves: false } }),
  "GLB-004": () => withProject({ protection: rule({ pushLevel: 40 }) }),
  "GLH-001": () => withProject({ hooks: [{ endpoint: "http://chat.example.com", verifiesTls: true }] }),
  "GLH-002": () => withProject({ hooks: [{ endpoint: "https://ci.example.com", verifiesTls: false }] }),
  "GLH-003": () => withProject({ deployKeys: [{ title: "deploy", canPush: true }] }),
  "GLH-004": () => withProject({ deployTokens: [{ name: "push", scopes: ["write_repository"], expiresAt: null }] }),
  "GLD-001": () => withPackages(pkg({ vulns: [vuln({ kev: true, severity: "medium", epss: 0.9 })] })),
  "GLD-002": () => withPackages(pkg({ vulns: [vuln()] })),
  "GLD-003": () => withPackages(pkg({ name: "left-padd", vulns: [vuln({ id: "MAL-2026-1", aliases: [], severity: "critical", fixedIn: null })] })),
  "GLD-004": () =>
    gitlabInventory({ dependencies: dependencies([repoDeps({ actions: [{ action: "other-group/ci", ref: "main", workflow: ".gitlab-ci.yml" }] })]) }),
  "GLD-005": () => gitlabInventory({ dependencies: dependencies([repoDeps({ parts: [{ ...repoDeps().parts[0], lockfile: null, unpinned: ["left-pad"] }] })]) }),
  "GLD-006": () => withPackages(pkg({ name: "readline", licenses: ["GPL-3.0-only"], licenseRisk: "strong" })),
  "GLM-001": () => withImage(1),
  "GLM-002": () => withImage(2),
  "GLM-003": () => withImage(3),
  "GLM-004": () => withImage(4),
};
