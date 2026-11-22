// Container images: what Trivy found in the group's public images in GitLab's
// container registry that are in use. The checks are the shared ones
// (src/core/image-checks.ts) with GitLab's prefix. A finding sits with the
// project whose registry holds the image.

import { defineChecks } from "./define.ts";
import { imageCheckMeta, reportImages } from "../../../core/image-checks.ts";
import type { GitlabSourceKey } from "../sources.ts";

const DOCS = "https://docs.gitlab.com/user/packages/container_registry/";
const META = imageCheckMeta<"GLM", GitlabSourceKey>("GLM", { images: ["registry", "trivy"], kev: ["kev"] }, { scanning: DOCS, secrets: DOCS });

export default defineChecks(META, ({ inv, related }, report) => {
  if (!inv.images) return;
  const byPath = new Map(inv.projects.map((p) => [p.fullPath.toLowerCase(), p]));
  reportImages(
    "GLM",
    {
      ...inv.images,
      builds: related.githubImageBuilds ?? [],
      repos: [...byPath.keys(), ...(related.githubRepos?.map((r) => r.repo) ?? [])],
      now: inv.now,
      where: (e) => {
        const project = e.linkedRepo ? byPath.get(e.linkedRepo) : undefined;
        return {
          zone: project?.name ?? null,
          resource: e.repository,
          link: project ? `${project.url}/container_registry` : null,
        };
      },
    },
    report,
  );
});
