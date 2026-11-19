// Container images: what Trivy found in the organization's public packages in
// GitHub Container Registry that are in use. The checks are the shared ones
// (src/core/image-checks.ts) with GitHub's prefix. A finding sits with the
// repository the package is linked to, when it is one of the organization's.

import { defineChecks } from "./define.ts";
import { imageCheckMeta, reportImages } from "../../../core/image-checks.ts";
import type { GithubSourceKey } from "../sources.ts";

const DOCS = "https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry";
const META = imageCheckMeta<"GIM", GithubSourceKey>("GIM", { images: ["packages", "trivy"], kev: ["kev"] }, { scanning: DOCS, secrets: DOCS });

export default defineChecks(META, ({ inv, related }, report) => {
  if (!inv.images) return;
  const org = inv.login.toLowerCase();
  // The organization's own workflows are known to this scan; the rest of the entity's come from its other organizations.
  const own = (inv.dependencies?.repos ?? []).flatMap((d) => (d.builds ?? []).map((b) => ({ ...b, repo: `${org}/${d.repo}`.toLowerCase() })));
  reportImages(
    "GIM",
    {
      ...inv.images,
      builds: [...own, ...(related.githubImageBuilds ?? [])],
      repos: [...inv.repos.map((r) => `${org}/${r.name}`.toLowerCase()), ...(related.githubRepos?.map((r) => r.repo) ?? [])],
      now: inv.now,
      where: (e) => {
        const name = e.repository.slice(org.length + 1);
        const linked = e.linkedRepo?.startsWith(`${org}/`) ? e.linkedRepo.slice(org.length + 1) : null;
        return {
          zone: inv.repos.find((r) => r.name.toLowerCase() === linked)?.name ?? null,
          resource: name,
          link: `https://github.com/orgs/${encodeURIComponent(inv.login)}/packages/container/package/${encodeURIComponent(name)}`,
        };
      },
    },
    report,
  );
});
