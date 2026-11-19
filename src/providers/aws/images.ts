// Container images on AWS: which of the account's ECR images a scan looks at, the
// registry login Trivy pulls them with, and the workloads known in the entity
// that say which images run and how exposed they are.
//
// The login comes from ecr:GetAuthorizationToken: valid for 12 hours, able to do
// only what the access key's user can, and the only credential Trivy is given.
// Pulling needs three read actions SecurityAudit doesn't grant (the token,
// ecr:BatchGetImage and ecr:GetDownloadUrlForLayer); without them the images are
// listed and the pull is a coverage gap. Images the account's services run from a
// public registry (Docker Hub, ECR Public…) are scanned too, without a login.

import type { AwsClient } from "./client.ts";
import type { AwsInventory, Related } from "./types.ts";
import { registryImages, workloadLinks } from "./views.ts";
import { pickImages, scanImages, type Foreign } from "../../core/images.ts";
import type { RegistryLogin } from "../../core/trivy.ts";
import type { ProgressEvent } from "../../core/types.ts";
import type { AccountCache } from "../../store/repo.ts";
import { ecrHost, registryKind, type ImageRef, type ImagesSnapshot } from "../../shared/images.ts";

/** Whose registry an image is in, as this account sees it. */
export function foreignFor(accountId: string, related: Partial<Related>): (ref: ImageRef) => Foreign {
  return (ref) => {
    const kind = registryKind(ref.registry);
    if (kind === "ecr") {
      const owner = ecrHost(ref.registry)?.account;
      // The account's own images come from its repositories' lists; a sibling's are that account's to scan.
      return owner === accountId || related.awsAccounts?.includes(owner ?? "") ? "entity" : "private";
    }
    if (kind === "ghcr") return related.githubOrgs?.includes(ref.repository.split("/")[0]) ? "entity" : "public";
    if (kind === "acr") return related.alibabaAccounts?.length ? "entity" : "private";
    return "public";
  };
}

const INDEX_TYPES = ["application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"];

/**
 * Reads each index's manifest and folds its parts into it. An image built for several platforms, or with build
 * attestations (Docker's default since BuildKit 0.11), is pushed as an index: ECR lists the index under its tag and each
 * part as an untagged image of its own, pulled whenever the index is. Scanned as they are listed, every such image
 * would be scanned twice and its attestation refused as "not an image" (on the first real registry, 100 of 800 images
 * were attestations). The manifest is JSON that names the parts; no layer is read. Without permission for it the list
 * stays as it is, and what isn't an image is dropped when Trivy says so.
 */
export async function foldIndexes(client: AwsClient, inv: AwsInventory): Promise<void> {
  let allowed = true;
  const work: Promise<void>[] = [];
  for (const r of inv.regions)
    for (const repo of r.repositories ?? []) {
      const indexes = (repo.images ?? []).filter((i) => i.index);
      if (!indexes.length) continue;
      work.push(
        (async () => {
          const parts = new Map<string, string>();
          for (let n = 0; n < indexes.length && allowed; n += 100) {
            let body: { images?: { imageId?: { imageDigest?: string }; imageManifest?: string }[] } | null = null;
            try {
              body = await client.rpc("ecr", r.name, "BatchGetImage", {
                repositoryName: repo.name,
                imageIds: indexes.slice(n, n + 100).map((i) => ({ imageDigest: i.digest })),
                acceptedMediaTypes: INDEX_TYPES,
              });
            } catch {
              // The same permission pulling needs: its absence is reported where the pull fails.
              allowed = false;
            }
            for (const img of body?.images ?? []) {
              const index = indexes.find((i) => i.digest === img.imageId?.imageDigest);
              let manifests: { digest?: string; platform?: { os?: string; architecture?: string }; annotations?: Record<string, string> }[] = [];
              try {
                manifests = JSON.parse(String(img.imageManifest ?? "{}")).manifests ?? [];
              } catch {
                /* an unreadable manifest: the index stays an image like any other */
              }
              if (!index || !Array.isArray(manifests)) continue;
              const platforms: string[] = [];
              for (const m of manifests) {
                if (!m?.digest) continue;
                parts.set(m.digest, index.digest);
                const attestation = m.annotations?.["vnd.docker.reference.type"] === "attestation-manifest" || m.platform?.os === "unknown";
                if (!attestation && m.platform?.os && m.platform.architecture) platforms.push(`${m.platform.os}/${m.platform.architecture}`);
              }
              if (platforms.length) index.platforms = [...new Set(platforms)];
            }
          }
          if (!parts.size) return;
          // A part pulled is its index pulled; a part with a tag of its own stays an image.
          for (const part of repo.images ?? []) {
            const index = indexes.find((i) => i.digest === parts.get(part.digest));
            if (index && part.pulledAt && (!index.pulledAt || part.pulledAt > index.pulledAt)) index.pulledAt = part.pulledAt;
          }
          repo.images = (repo.images ?? []).filter((i) => i.tags.length || !parts.has(i.digest));
        })(),
      );
    }
  await Promise.all(work);
}

/** Picks and scans the account's images, and records the result on the inventory for the checks and the snapshot. */
export async function scanAwsImages(
  client: AwsClient,
  inv: AwsInventory,
  o: { cache: AccountCache; toolDir: string | null; related: Partial<Related>; onProgress: (p: ProgressEvent) => void; previous?: ImagesSnapshot | null },
): Promise<void> {
  o.onProgress({ phase: "Reading image indexes" });
  await foldIndexes(client, inv);
  const own = workloadLinks(inv) ?? [];
  const workloads = [...own, ...(o.related.awsWorkloads ?? []), ...(o.related.alibabaWorkloads ?? [])];
  // One login per region, asked for only when an image there is scanned.
  const logins = new Map<string, () => Promise<RegistryLogin | null>>();
  const loginFor = (region: string) => {
    if (!logins.has(region))
      logins.set(region, async () => {
        const body = await client.rpc("ecr", region, "GetAuthorizationToken");
        const token = Buffer.from(String(body?.authorizationData?.[0]?.authorizationToken ?? ""), "base64").toString("utf8");
        const at = token.indexOf(":");
        if (at < 1) throw new Error("ECR didn't return a registry login.");
        return { username: token.slice(0, at), password: token.slice(at + 1) };
      });
    return logins.get(region)!;
  };
  const targets = pickImages({
    registry: registryImages(inv),
    workloads,
    ownWorkloads: own,
    login: (img) => loginFor(img.region ?? ""),
    foreign: foreignFor(inv.accountId, o.related),
    now: inv.now,
  });
  const { snapshot, scans, later } = await scanImages(targets, {
    repositories: inv.regions.reduce((n, r) => n + (r.repositories?.length ?? 0), 0),
    cache: o.cache,
    toolDir: o.toolDir,
    onProgress: o.onProgress,
    note: (source, ok, err) => client.note(source === "pull" ? "imagePull" : source, ok, err),
    now: inv.now,
    previous: o.previous,
  });
  inv.images = { snapshot, scans, workloads, later };
  inv.unreadable = [...client.coverage.values()].filter((c) => !c.ok).map((c) => c.key);
}
