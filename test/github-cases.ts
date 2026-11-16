// A well-configured GitHub organization, and one failing case per GitHub check.
// The type is Record<GithubCheckId, …>, so a new check without a case doesn't
// compile, and test/github-checks.test.ts asserts each case really makes its
// check fail.

import type { GithubCheckId } from "../src/providers/github/checks/index.ts";
import type { EngineOptions } from "../src/core/types.ts";
import type { DependencyInventory, DepPackage, DepVuln, GithubInventory, GithubRepo, RepoDependencies } from "../src/providers/github/types.ts";

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
    license: null,
    security: { secretScanning: true, pushProtection: true, dependabotUpdates: true },
    protection: null,
    rules: [
      { type: "pull_request", reviews: 1, dismissStale: true, lastPushApproval: true },
      { type: "non_fast_forward", reviews: null },
      { type: "deletion", reviews: null },
    ],
    deployKeys: [{ title: "mirror", readOnly: true, createdAt: days(-100) }],
    hooks: [{ id: 1, endpoint: "https://ci.example.com", insecureSsl: false, active: true }],
    dependabotAlerts: true,
    codeScanning: true,
    pages: { cname: "docs.example.com", httpsEnforced: true },
    runners: [],
    releases: true,
    immutableReleases: true,
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
      membersCanDeleteRepos: false,
      membersCanChangeVisibility: false,
    },
    owners: ["owner-a", "owner-b"],
    actions: { enabledRepos: "all", allowedActions: "selected", defaultWorkflowPermissions: "read", canApprovePullRequests: false },
    hooks: [{ id: 2, endpoint: "https://siem.example.com", insecureSsl: false, active: true }],
    apps: [
      { slug: "keelson", appId: 42, selection: "all", writes: [] },
      { slug: "linter", appId: 7, selection: "selected", writes: ["contents"] },
    ],
    forkPrs: { approval: "all_external_contributors", private: { runs: true, secrets: false, writeTokens: false, needsApproval: true } },
    runnerGroups: [
      { id: 1, name: "Default", visibility: "all", allowsPublic: false, restrictedToWorkflows: false, repos: null },
      { id: 2, name: "open", visibility: "selected", allowsPublic: true, restrictedToWorkflows: false, repos: ["docs"] },
    ],
    runners: [
      { name: "build-1", os: "Linux", ephemeral: false, groupId: 1 },
      { name: "docs-1", os: "Linux", ephemeral: true, groupId: 2 },
    ],
    repos: [repo()],
    dependabot: [{ repo: "web", severity: "low", pkg: "colors", advisory: "GHSA-0000-0000-0000", createdAt: days(-5) }],
    codeScanning: [],
    secretScanning: [],
    dependencies: dependencies(),
    ...extra,
  };
}

export function pkg(extra: Partial<DepPackage> = {}): DepPackage {
  return {
    name: "left-pad",
    version: "1.3.0",
    type: "npm",
    ecosystem: "npm",
    purl: "pkg:npm/left-pad@1.3.0",
    locations: ["package-lock.json"],
    licenses: ["MIT"],
    licenseRisk: "permissive",
    usedBy: [{ part: "", direct: true, dev: false }],
    devOnly: false,
    vulns: [],
    ...extra,
  };
}

export function vuln(extra: Partial<DepVuln> = {}): DepVuln {
  return {
    id: "GHSA-0000-1111-2222",
    aliases: ["CVE-2026-0001"],
    severity: "high",
    cvss: 7.5,
    epss: 0.02,
    percentile: 0.8,
    kev: false,
    ransomware: false,
    fixedIn: "1.3.1",
    state: "fixed",
    summary: "Prototype pollution",
    url: "https://github.com/advisories/GHSA-0000-1111-2222",
    risk: 5,
    cpeOnly: false,
    ...extra,
  };
}

/** The repository "web": one npm project with its lock file, one clean package, and a workflow pinned to a commit. */
export function repoDeps(extra: Partial<RepoDependencies> = {}): RepoDependencies {
  return {
    repo: "web",
    generatedAt: NOW,
    languages: { TypeScript: 9000, CSS: 1000 },
    parts: [
      {
        path: "",
        name: "web",
        ecosystems: ["npm"],
        files: ["package.json", "package-lock.json"],
        lockfile: "package-lock.json",
        direct: { "left-pad": { dev: false, ecosystem: "npm" } },
        unpinned: [],
        images: [],
        devOnly: false,
      },
    ],
    packages: [pkg()],
    actions: [{ action: "docker/login-action", ref: "0123456789abcdef0123456789abcdef01234567", workflow: ".github/workflows/ci.yml" }],
    partial: false,
    ...extra,
  };
}

export function dependencies(repos: RepoDependencies[] = [repoDeps()]): DependencyInventory {
  return { repos, tools: { syft: "1.0.0", grype: "0.100.0", grant: "0.7.0" }, dbBuilt: "2026-05-31T00:00:00Z" };
}

const withPackages = (...packages: DepPackage[]) => githubInventory({ dependencies: dependencies([repoDeps({ packages })]) });

const base = githubInventory();
const org = base.org!;
const withRepo = (extra: Partial<GithubRepo>) => githubInventory({ repos: [repo(extra)] });

export const GITHUB_CASES: Record<GithubCheckId, () => GithubInventory> = {
  "GID-001": () => githubInventory({ org: { ...org, twoFactorRequired: false } }),
  "GID-002": () => githubInventory({ org: { ...org, defaultRepoPermission: "write" } }),
  "GID-003": () => githubInventory({ org: { ...org, membersCanCreatePublicRepos: true } }),
  "GID-004": () => githubInventory({ owners: ["a", "b", "c", "d"] }),
  "GID-005": () => githubInventory({ org: { ...org, membersCanForkPrivateRepos: true } }),
  "GID-006": () => githubInventory({ org: { ...org, membersCanChangeVisibility: true } }),
  "GID-007": () => githubInventory({ org: { ...org, membersCanDeleteRepos: true } }),

  "GBR-001": () => withRepo({ rules: [] }),
  "GBR-002": () => withRepo({ rules: [{ type: "pull_request", reviews: 1 }] }),
  "GBR-003": () =>
    withRepo({
      rules: [],
      protection: { reviews: 1, enforceAdmins: false, allowForcePushes: false, allowDeletions: false, dismissStale: true, lastPushApproval: false },
    }),
  "GBR-004": () => withRepo({ rules: [{ type: "pull_request", reviews: 1, dismissStale: false, lastPushApproval: false }, ...repo().rules!.slice(1)] }),
  "GRL-001": () => withRepo({ immutableReleases: false }),

  "GSC-001": () => withRepo({ security: { secretScanning: false, pushProtection: false, dependabotUpdates: true } }),
  "GSC-002": () => withRepo({ security: { secretScanning: true, pushProtection: false, dependabotUpdates: true } }),
  "GSC-003": () =>
    githubInventory({
      secretScanning: [{ number: 3, repo: "web", kind: "Example API Key", validity: "active", pushProtectionBypassed: false, createdAt: days(-1) }],
    }),
  "GSC-004": () =>
    githubInventory({ dependabot: [{ repo: "web", severity: "critical", pkg: "parser", advisory: "GHSA-1111-1111-1111", createdAt: days(-9) }] }),
  "GSC-005": () => githubInventory({ codeScanning: [{ repo: "web", severity: "high", rule: "SQL injection", tool: "CodeQL", createdAt: days(-3) }] }),
  "GSC-006": () => ({ ...withRepo({ security: { secretScanning: true, pushProtection: true, dependabotUpdates: false } }), dependabot: base.dependabot }),
  "GSC-007": () => withRepo({ dependabotAlerts: false }),
  "GSC-008": () => withRepo({ codeScanning: false }),

  "GAC-001": () => githubInventory({ actions: { ...base.actions!, defaultWorkflowPermissions: "write" } }),
  "GAC-002": () => githubInventory({ actions: { ...base.actions!, canApprovePullRequests: true } }),
  "GAC-003": () => githubInventory({ actions: { ...base.actions!, allowedActions: "all" } }),
  "GAC-004": () => githubInventory({ forkPrs: { ...base.forkPrs!, private: { runs: true, secrets: true, writeTokens: false, needsApproval: false } } }),
  "GAC-005": () => withRepo({ runners: [{ name: "docs-2", os: "Linux", ephemeral: false, groupId: null }] }),

  "GHK-001": () => githubInventory({ hooks: [{ id: 2, endpoint: "https://siem.example.com", insecureSsl: true, active: true }] }),
  "GHK-002": () => withRepo({ hooks: [{ id: 1, endpoint: "http://ci.example.com", insecureSsl: false, active: true }] }),
  "GHK-003": () => withRepo({ deployKeys: [{ title: "deploy", readOnly: false, createdAt: days(-300) }] }),
  "GHK-004": () => githubInventory({ apps: [...base.apps!, { slug: "ci", appId: 9, selection: "all", writes: ["contents", "workflows"] }] }),

  "GPG-001": () => withRepo({ pages: { cname: "docs.example.com", httpsEnforced: false } }),

  "GDP-001": () => withPackages(pkg({ vulns: [vuln({ kev: true, severity: "medium", epss: 0.9 })] })),
  "GDP-002": () => withPackages(pkg({ vulns: [vuln()] })),
  "GDP-003": () => withPackages(pkg({ name: "left-padd", vulns: [vuln({ id: "MAL-2026-1", aliases: [], severity: "critical", fixedIn: null })] })),
  "GDP-004": () =>
    githubInventory({ dependencies: dependencies([repoDeps({ actions: [{ action: "someone/deploy", ref: "v2", workflow: ".github/workflows/ci.yml" }] })]) }),
  "GDP-005": () =>
    githubInventory({
      dependencies: dependencies([
        repoDeps({ parts: [{ ...repoDeps().parts[0], files: ["requirements.txt"], ecosystems: ["PyPI"], lockfile: null, unpinned: ["requests"] }] }),
      ]),
    }),
  "GLI-001": () => withPackages(pkg({ name: "readline", licenses: ["GPL-3.0-only"], licenseRisk: "strong" })),
};

/** Engine options a case needs beyond the defaults. */
export const GITHUB_CASE_OPTS: Partial<Record<GithubCheckId, Partial<EngineOptions>>> = {};
