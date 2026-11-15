// Releases of public repositories: whether a release, its files and its tag can
// still change after it's published. Others download those files and pin
// actions to those tags, so changing them reaches everyone who uses them.

import { active, defineChecks } from "./define.ts";

export default defineChecks(
  {
    "GRL-001": {
      category: "Change risk",
      severity: "medium",
      docs: "https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/establish-provenance-and-integrity/prevent-release-changes",
      requires: ["releases", "immutableReleases"],
      title: "Published releases can be changed",
      why: "Anyone with write access, or a stolen token that has it, can replace a published release's files or point its tag at other code. Everyone who downloads that release, or uses an action pinned to that tag, then runs the new code without any sign that it changed.",
      fix: "In the repository's Settings, under Releases, select Enable release immutability. To enforce it everywhere, under the organization's Settings → Repository → General → Releases, choose All repositories. Only releases published afterwards are immutable, so publish a new one.",
    },
  },
  ({ inv, d }, report) => {
    for (const r of active(inv)) {
      if (!r.releases || r.immutableReleases == null) continue;
      report("GRL-001", {
        zone: r.name,
        resource: r.name,
        pass: r.immutableReleases,
        detail: r.immutableReleases ? "" : "Releases are published without immutability",
        link: d.repo(r.name, "settings"),
      });
    }
  },
);
