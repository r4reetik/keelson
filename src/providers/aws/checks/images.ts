// Container images: what Trivy found in the ECR images that are in use, and in
// the images the account's services run from public registries. The checks are
// the shared ones (src/core/image-checks.ts) with AWS's prefix; an image in a
// repository is named by the repository and its region, one from elsewhere by its
// full name under "Global".

import { defineChecks } from "./define.ts";
import { imageCheckMeta, reportImages } from "../../../core/image-checks.ts";
import { imageName } from "../../../shared/images.ts";
import type { AwsSourceKey } from "../sources.ts";
import { GLOBAL } from "../types.ts";

const META = imageCheckMeta<"AIM", AwsSourceKey>(
  "AIM",
  { images: ["ecr", "ecrImages", "imagePull", "registryNetwork", "trivy"], kev: ["kev"] },
  {
    scanning: "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html",
    secrets: "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/specifying-sensitive-data.html",
  },
);

export default defineChecks(META, ({ inv, d, related }, report) => {
  if (!inv.images) return;
  reportImages(
    "AIM",
    {
      ...inv.images,
      builds: related.githubImageBuilds ?? [],
      repos: related.githubRepos?.map((r) => r.repo),
      now: inv.now,
      where: (e) =>
        e.own
          ? {
              zone: e.region ?? GLOBAL,
              resource: e.repository,
              link: d.console(e.region ?? "us-east-1", "ecr", `/repositories/private/${inv.accountId}/${encodeURIComponent(e.repository)}`),
            }
          : { zone: GLOBAL, resource: imageName(e), link: null },
    },
    report,
  );
});
