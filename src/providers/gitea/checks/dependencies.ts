// What each repository depends on, from its software bill of materials. The
// checks are the shared ones (src/core/dependency-checks.ts) with Gitea's IDs
// and its own links. Gitea has no advisory database or dependency alerts of its
// own, so only the check about workflows has a page of Gitea's to point at.

import { defineChecks } from "./define.ts";
import { dependencyCheckMeta, reportDependencies, type DependencyCheckIds } from "../../../core/dependency-checks.ts";
import type { GiteaSourceKey } from "../sources.ts";

const IDS = {
  exploited: "TED-001",
  vulnerable: "TED-002",
  malicious: "TED-003",
  actions: "TED-004",
  lock: "TED-005",
  license: "TED-006",
} as const satisfies DependencyCheckIds<string>;
type Id = (typeof IDS)[keyof typeof IDS];

const META = dependencyCheckMeta<Id, GiteaSourceKey>(
  IDS,
  { files: ["manifests"], sbom: ["syft"], vulnerabilities: ["grype"], licenses: ["grant"] },
  { docs: { actions: "https://docs.gitea.com/usage/actions/overview" }, pinning: "Renovate keeps pinned actions up to date." },
);

export default defineChecks(META, ({ inv, d }, report) => {
  const at = (r: { name: string; defaultBranch: string }, path: string) => d.repo(r.name, `src/branch/${encodeURIComponent(r.defaultBranch)}/${path}`);
  reportDependencies<Id>(
    IDS,
    {
      dependencies: inv.dependencies,
      org: inv.login,
      repos: inv.repos,
      links: { dependencies: (r) => d.repo(r.name), licenses: (r) => d.repo(r.name), file: at, folder: at },
      workflowsDir: ".gitea/workflows",
    },
    report,
  );
});
