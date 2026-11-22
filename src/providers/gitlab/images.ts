// Container images on GitLab: each project's container registry repositories
// and their tags, and Trivy's scan of the ones anyone can pull.
//
// GitLab's registry takes a pull from Keelson's credential only as the access
// token itself, used as a password. A scanner never gets an account's own
// credential (src/core/trivy.ts), so images in private and internal projects
// are listed with the project that builds them and where they run, marked as
// not scanned, exactly like GitHub's private packages. A public project's
// images are pulled without a login.

import type { GitlabClient, Json } from "./client.ts";
import type { GitlabInventory, GitlabProject, Related } from "./types.ts";
import { pickImages, scanImages, type RegistryImage } from "../../core/images.ts";
import type { ProgressEvent } from "../../core/types.ts";
import type { AccountCache } from "../../store/repo.ts";
import type { ImagesSnapshot } from "../../shared/images.ts";

/** Projects whose registry is listed, and tags read per repository (one request each, for the digest). */
const MAX_PROJECTS = 400;
const MAX_TAGS = 12;
const PRIVATE =
  "GitLab's registry takes a pull only with the access token itself, which Keelson never hands to a scanner, so this image isn't scanned. It is scanned where it is also kept in a registry Keelson can pull from.";

/** Tags worth reading when a repository has many: "latest", then the highest names (versions and dates sort last). */
function pickTags(tags: Json[]): string[] {
  const names = tags.map((t) => String(t?.name ?? "")).filter(Boolean);
  const sorted = [...names].sort((a, b) => b.localeCompare(a, undefined, { numeric: true }));
  return [...new Set([...(names.includes("latest") ? ["latest"] : []), ...sorted])].slice(0, MAX_TAGS);
}

/** Every project's registry repositories, each tag as an image. Null when the list couldn't be read. */
export async function readRegistry(client: GitlabClient, projects: GitlabProject[]): Promise<{ images: RegistryImage[]; repositories: number } | null> {
  const images = new Map<string, RegistryImage>();
  let repositories = 0;
  for (const p of projects.filter((x) => x.registry && !x.archived).slice(0, MAX_PROJECTS)) {
    const repos = await client.list<Json>("registry", `/projects/${p.id}/registry/repositories?tags=true`, { absentOn: [403, 404] });
    if (!repos) return null;
    for (const r of repos) {
      // "registry.gitlab.com/group/project/name": the host is the instance's registry, the rest is the repository.
      const location = String(r?.location ?? "");
      const slash = location.indexOf("/");
      if (slash < 1) continue;
      repositories++;
      const host = location.slice(0, slash).toLowerCase();
      const repository = location.slice(slash + 1).toLowerCase();
      for (const tag of pickTags(Array.isArray(r.tags) ? r.tags : [])) {
        let detail: Json;
        try {
          detail = await client.raw(`/projects/${p.id}/registry/repositories/${Number(r.id)}/tags/${encodeURIComponent(tag)}`);
        } catch {
          // A tag deleted since it was listed, or one whose manifest is gone: there is nothing to say about it.
          continue;
        }
        const digest = String(detail?.digest ?? "");
        if (!/^sha256:[a-f0-9]{64}$/.test(digest)) continue;
        const key = `${host}/${repository}@${digest}`;
        const seen = images.get(key);
        if (seen) {
          seen.tags.push(tag);
          continue;
        }
        const open = p.visibility === "public";
        images.set(key, {
          registry: host,
          repository,
          region: null,
          digest,
          tags: [tag],
          pushedAt: typeof detail.created_at === "string" ? detail.created_at : null,
          pulledAt: null,
          public: open,
          // The registry's path says which project builds the image: it is that project's own.
          linkedRepo: p.fullPath.toLowerCase(),
          ...(open ? {} : { unreadable: PRIVATE }),
        });
      }
    }
  }
  return { images: [...images.values()], repositories };
}

/** Picks and scans the group's images, and records the result on the inventory for the checks and the snapshot. */
export async function scanGitlabImages(
  client: GitlabClient,
  inv: GitlabInventory,
  o: { cache: AccountCache; toolDir: string | null; related: Partial<Related>; onProgress: (p: ProgressEvent) => void; previous?: ImagesSnapshot | null },
): Promise<void> {
  o.onProgress({ phase: "Reading container registries" });
  const listed = await readRegistry(client, inv.projects);
  const workloads = [...(o.related.awsWorkloads ?? []), ...(o.related.alibabaWorkloads ?? [])];
  const targets = pickImages({ registry: listed?.images ?? [], workloads, ownWorkloads: [], login: () => null, foreign: () => "entity", now: inv.now });
  const { snapshot, scans, later } = await scanImages(targets, {
    repositories: listed?.repositories ?? 0,
    cache: o.cache,
    toolDir: o.toolDir,
    onProgress: o.onProgress,
    // Nothing here is pulled with a login, so a refused pull or an unreachable host is that image's own, and says so.
    note: (source, ok, err) => source !== "pull" && source !== "network" && client.note(source, ok, err),
    now: inv.now,
    previous: o.previous,
  });
  inv.images = { snapshot, scans, workloads, later };
  inv.unreadable = [...client.coverage.values()].filter((c) => !c.ok).map((c) => c.key);
}
