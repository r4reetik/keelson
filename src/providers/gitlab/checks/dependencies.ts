// What each project depends on, from its software bill of materials. The
// checks are the shared ones (src/core/dependency-checks.ts) with GitLab's IDs
// and links. GitLab CI has no actions: what a pipeline takes from elsewhere is
// an include (another project's file at a ref, a CI/CD component at a version,
// a file at an address), so the fourth check is worded for those.

import { defineChecks } from "./define.ts";
import { dependencyCheckMeta, reportDependencies, type DependencyCheckIds } from "../../../core/dependency-checks.ts";
import type { GitlabSourceKey } from "../sources.ts";

const IDS = {
  exploited: "GLD-001",
  vulnerable: "GLD-002",
  malicious: "GLD-003",
  actions: "GLD-004",
  lock: "GLD-005",
  license: "GLD-006",
} as const satisfies DependencyCheckIds<string>;
type Id = (typeof IDS)[keyof typeof IDS];

const META = dependencyCheckMeta<Id, GitlabSourceKey>(
  IDS,
  { files: ["manifests"], sbom: ["syft"], vulnerabilities: ["grype"], licenses: ["grant"] },
  {
    docs: {
      supplyChain: "https://docs.gitlab.com/user/application_security/dependency_scanning/",
      actions: "https://docs.gitlab.com/ci/yaml/includes/",
      license: "https://docs.gitlab.com/user/compliance/license_scanning_of_cyclonedx_files/",
    },
    pinning: "Renovate keeps pinned includes up to date.",
    actions: {
      title: "Pipeline includes configuration from outside the group by a ref that can be moved",
      why: "An include is code the pipeline runs with the project's CI/CD variables and tokens. One taken from another group's project by a branch or a tag, from a component at a moving version, or from a web address, becomes whatever its owner (or whoever takes over their account) makes it next. A commit SHA can't be moved.",
      fix: "1. Pin each include from outside the group to a full commit SHA (ref: <sha> for a project, @<sha> for a component). 2. Better, copy what you need into a project of your own group and include it from there. 3. Replace remote: includes with project: includes at a commit. GitLab's own templates and your own group's projects aren't counted.",
    },
  },
);

export default defineChecks(META, ({ inv, d }, report) => {
  const at = (r: { name: string; defaultBranch: string }, path: string) => d.project(r.name, `blob/${encodeURIComponent(r.defaultBranch)}/${path}`);
  reportDependencies<Id>(
    IDS,
    {
      dependencies: inv.dependencies,
      // An include from anywhere in the top-level group is the group's own.
      org: inv.login.split("/")[0],
      repos: inv.projects,
      links: {
        dependencies: (r) => d.project(r.name, "dependencies"),
        licenses: (r) => d.project(r.name, "dependencies"),
        file: at,
        folder: (r, path) => d.project(r.name, `tree/${encodeURIComponent(r.defaultBranch)}/${path}`),
      },
      workflowsDir: ".gitlab-ci.yml",
      movable: "included by a ref that can be moved",
    },
    report,
  );
});
