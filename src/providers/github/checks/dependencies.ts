// What each repository depends on, from its software bill of materials. The
// checks are the shared ones (src/core/dependency-checks.ts) with GitHub's IDs,
// its documentation, and what only GitHub has: whether its own Dependabot is on
// and alerting for a package, shown in a finding's evidence.

import { defineChecks } from "./define.ts";
import { dependencyCheckMeta, reportDependencies, type DependencyCheckIds } from "../../../core/dependency-checks.ts";
import type { GithubSourceKey } from "../sources.ts";

const IDS = {
  exploited: "GDP-001",
  vulnerable: "GDP-002",
  malicious: "GDP-003",
  actions: "GDP-004",
  lock: "GDP-005",
  license: "GLI-001",
} as const satisfies DependencyCheckIds<string>;
type Id = (typeof IDS)[keyof typeof IDS];

const META = dependencyCheckMeta<Id, GithubSourceKey>(
  IDS,
  { files: ["manifests"], sbom: ["syft"], vulnerabilities: ["grype"], licenses: ["grant"] },
  {
    docs: {
      supplyChain: "https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-supply-chain-security",
      advisories:
        "https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database",
      actions: "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
      lock: "https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/dependency-graph-supported-package-ecosystems",
      license: "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository",
    },
    pinning: "Dependabot or Renovate keep pinned actions up to date.",
  },
);

export default defineChecks(META, ({ inv, d }, report) => {
  const branch = (r: { defaultBranch: string }) => encodeURIComponent(r.defaultBranch);
  reportDependencies<Id>(
    IDS,
    {
      dependencies: inv.dependencies,
      org: inv.login,
      repos: inv.repos,
      dependabot: inv.dependabot,
      links: {
        dependencies: (r) => d.repo(r.name, r.dependabotAlerts ? "security/dependabot" : "network/dependencies"),
        licenses: (r) => d.repo(r.name, "network/dependencies"),
        file: (r, path) => d.repo(r.name, `blob/${branch(r)}/${path}`),
        folder: (r, path) => d.repo(r.name, `tree/${branch(r)}/${path}`),
      },
      workflowsDir: ".github/workflows",
    },
    report,
  );
});
