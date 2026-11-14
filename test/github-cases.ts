// A well-configured GitHub organization, and one failing case per GitHub check.
// The type is Record<GithubCheckId, …>, so a new check without a case doesn't
// compile, and test/github-checks.test.ts asserts each case really makes its
// check fail.

import type { GithubCheckId } from "../src/providers/github/checks/index.ts";
import type { EngineOptions } from "../src/core/types.ts";
import type { GithubInventory, GithubRepo } from "../src/providers/github/types.ts";

export const NOW = Date.parse("2026-06-01T00:00:00Z");
const days = (n: number) => NOW + n * 86_400_000;

export function repo(extra: Partial<GithubRepo> = {}): GithubRepo {
  return {
    name: "web",
    private: false,
    visibility: "public",
    archived: false,
    fork: false,
    empty: false,
    defaultBranch: "main",
    pushedAt: days(-2),
    hasPages: true,
    security: { secretScanning: true, pushProtection: true, dependabotUpdates: true },
    protection: null,
    rules: [
      { type: "pull_request", reviews: 1 },
      { type: "non_fast_forward", reviews: null },
      { type: "deletion", reviews: null },
    ],
    deployKeys: [{ title: "mirror", readOnly: true, createdAt: days(-100) }],
    hooks: [{ id: 1, endpoint: "https://ci.example.com", insecureSsl: false, active: true }],
    pages: { cname: "docs.example.com", httpsEnforced: true },
    ...extra,
  };
}

export function githubInventory(extra: Partial<GithubInventory> = {}): GithubInventory {
  return {
    accountId: "gh_1",
    accountName: "Example",
    login: "example",
    now: NOW,
    unreadable: [],
    appId: 42,
    selectedRepos: false,
    org: {
      login: "example",
      name: "Example",
      plan: "team",
      twoFactorRequired: true,
      defaultRepoPermission: "read",
      membersCanCreatePublicRepos: false,
      membersCanForkPrivateRepos: false,
    },
    owners: ["owner-a", "owner-b"],
    actions: { enabledRepos: "all", allowedActions: "selected", defaultWorkflowPermissions: "read", canApprovePullRequests: false },
    hooks: [{ id: 2, endpoint: "https://siem.example.com", insecureSsl: false, active: true }],
    apps: [
      { slug: "keelson", appId: 42, selection: "all", writes: [] },
      { slug: "linter", appId: 7, selection: "selected", writes: ["contents"] },
    ],
    repos: [repo()],
    dependabot: [{ repo: "web", severity: "low", pkg: "colors", advisory: "GHSA-0000-0000-0000", createdAt: days(-5) }],
    codeScanning: [],
    secretScanning: [],
    ...extra,
  };
}

const base = githubInventory();
const org = base.org!;
const withRepo = (extra: Partial<GithubRepo>) => githubInventory({ repos: [repo(extra)] });

export const GITHUB_CASES: Record<GithubCheckId, () => GithubInventory> = {
  "GID-001": () => githubInventory({ org: { ...org, twoFactorRequired: false } }),
  "GID-002": () => githubInventory({ org: { ...org, defaultRepoPermission: "write" } }),
  "GID-003": () => githubInventory({ org: { ...org, membersCanCreatePublicRepos: true } }),
  "GID-004": () => githubInventory({ owners: ["a", "b", "c", "d"] }),
  "GID-005": () => githubInventory({ org: { ...org, membersCanForkPrivateRepos: true } }),

  "GBR-001": () => withRepo({ rules: [] }),
  "GBR-002": () => withRepo({ rules: [{ type: "pull_request", reviews: 1 }] }),
  "GBR-003": () => withRepo({ rules: [], protection: { reviews: 1, enforceAdmins: false, allowForcePushes: false, allowDeletions: false } }),

  "GSC-001": () => withRepo({ security: { secretScanning: false, pushProtection: false, dependabotUpdates: true } }),
  "GSC-002": () => withRepo({ security: { secretScanning: true, pushProtection: false, dependabotUpdates: true } }),
  "GSC-003": () =>
    githubInventory({
      secretScanning: [{ number: 3, repo: "web", kind: "Example API Key", validity: "active", pushProtectionBypassed: false, createdAt: days(-1) }],
    }),
  "GSC-004": () =>
    githubInventory({ dependabot: [{ repo: "web", severity: "critical", pkg: "parser", advisory: "GHSA-1111-1111-1111", createdAt: days(-9) }] }),
  "GSC-005": () => githubInventory({ codeScanning: [{ repo: "web", severity: "high", rule: "SQL injection", tool: "CodeQL", createdAt: days(-3) }] }),
  "GSC-006": () => withRepo({ security: { secretScanning: true, pushProtection: true, dependabotUpdates: false } }),

  "GAC-001": () => githubInventory({ actions: { ...base.actions!, defaultWorkflowPermissions: "write" } }),
  "GAC-002": () => githubInventory({ actions: { ...base.actions!, canApprovePullRequests: true } }),
  "GAC-003": () => githubInventory({ actions: { ...base.actions!, allowedActions: "all" } }),

  "GHK-001": () => githubInventory({ hooks: [{ id: 2, endpoint: "https://siem.example.com", insecureSsl: true, active: true }] }),
  "GHK-002": () => withRepo({ hooks: [{ id: 1, endpoint: "http://ci.example.com", insecureSsl: false, active: true }] }),
  "GHK-003": () => withRepo({ deployKeys: [{ title: "deploy", readOnly: false, createdAt: days(-300) }] }),
  "GHK-004": () => githubInventory({ apps: [...base.apps!, { slug: "ci", appId: 9, selection: "all", writes: ["contents", "workflows"] }] }),

  "GPG-001": () => withRepo({ pages: { cname: "docs.example.com", httpsEnforced: false } }),
};

/** Engine options a case needs beyond the defaults. */
export const GITHUB_CASE_OPTS: Partial<Record<GithubCheckId, Partial<EngineOptions>>> = {};
