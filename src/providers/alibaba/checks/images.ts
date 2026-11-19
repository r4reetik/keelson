// Container images: what Trivy found in the Container Registry images that are in
// use, and in the images the account's workloads run from public registries. The
// checks are the shared ones (src/core/image-checks.ts) with Alibaba Cloud's
// prefix; an image in a registry instance is named by its repository and region,
// one from elsewhere by its full name under "Global".

import { defineChecks } from "./define.ts";
import { imageCheckMeta, reportImages } from "../../../core/image-checks.ts";
import { imageName } from "../../../shared/images.ts";
import type { AlibabaSourceKey } from "../sources.ts";
import { GLOBAL } from "../types.ts";

const META = imageCheckMeta<"LIM", AlibabaSourceKey>(
  "LIM",
  { images: ["registries", "imagePull", "trivy"], kev: ["kev"] },
  {
    scanning: "https://www.alibabacloud.com/help/en/acr/user-guide/scan-container-images",
    secrets: "https://www.alibabacloud.com/help/en/acr/user-guide/scan-container-images",
  },
);

export default defineChecks(META, ({ inv, related }, report) => {
  if (!inv.images) return;
  reportImages(
    "LIM",
    {
      ...inv.images,
      builds: related.githubImageBuilds ?? [],
      repos: related.githubRepos?.map((r) => r.repo),
      now: inv.now,
      where: (e) => {
        const instance = e.own ? inv.registries?.find((r) => r.region === e.region && r.images.some((i) => i.registry === e.registry)) : null;
        return e.own
          ? {
              zone: e.region ?? GLOBAL,
              resource: e.repository,
              link: instance ? `https://cr.console.alibabacloud.com/repository/${e.region}/${instance.id}/${e.repository}/details` : null,
            }
          : { zone: GLOBAL, resource: imageName(e), link: null };
      },
    },
    report,
  );
});
