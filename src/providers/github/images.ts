// Container images on GitHub: the organization's packages in GitHub Container
// Registry (ghcr.io), with their tags, and Trivy's scan of the public ones.
//
// GitHub lists an organization's packages and their versions for an installation
// token without any extra App permission. Pulling is another matter: ghcr.io
// accepts personal access tokens (classic) and workflows' own tokens, and refuses
// a GitHub App's installation token for private packages, whatever permission the
// App has (GitHub's documentation and every report Keelson's authors could find,
// November 2026). So public packages are scanned without a login, and private
// ones are listed with who builds them and where they run, marked as not
// scanned. An image the entity's workloads run from ghcr.io/<organization> that
// the list doesn't show is tried without a login too.

import type { GithubClient, GithubError } from "./client.ts";
import type { GithubInventory, Related } from "./types.ts";
import { pickImages, scanImages, runningIn, type RegistryImage } from "../../core/images.ts";
import type { ProgressEvent } from "../../core/types.ts";
import type { AccountCache } from "../../store/repo.ts";
import { parseImageRef, type ImagesSnapshot } from "../../shared/images.ts";

const REGISTRY = "ghcr.io";
/** Packages read one request each for their versions. */
const MAX_PACKAGES = 300;
const PRIVATE =
  "GitHub's registry doesn't let a GitHub App pull private packages, so Keelson can't scan this image. It is scanned where it is also kept in a registry Keelson can pull from.";

/** The organization's container packages, each tagged version as an image. Null when the list couldn't be read. */
export async function readPackages(client: GithubClient): Promise<{ images: RegistryImage[]; packages: number } | null> {
  const org = client.org;
  // Asked page by page here, not through client.list(): a refusal is an answer of its own.
  const packages: any[] = [];
  try {
    let next: string | null = `/orgs/${org}/packages?package_type=container&per_page=100`;
    while (next && packages.length < MAX_PACKAGES) {
      const page: { body: unknown; next: string | null } = await client.page(next);
      packages.push(...(Array.isArray(page.body) ? page.body : []));
      next = page.next;
    }
    client.note("packages", true);
  } catch (e) {
    // GitHub's reference says an installation token may list an organization's packages; on the first real
    // organization it answered 400 "Invalid argument". GitHub has no permission to grant for it, so it isn't a gap the
    // organization can close: the images known from the entity's workloads are still looked at.
    if ([400, 403, 404, 422].includes((e as GithubError).status)) {
      client.note("packages", true);
      return null;
    }
    client.note("packages", false, e);
    return null;
  }
  const images: RegistryImage[] = [];
  for (const p of packages) {
    const name = String(p?.name ?? "");
    if (!name) continue;
    // The newest versions come first; a page of them covers the tags in use.
    let versions: any[] = [];
    try {
      const body = await client.raw(`/orgs/${org}/packages/container/${encodeURIComponent(name)}/versions?per_page=100`);
      versions = Array.isArray(body) ? body : [];
    } catch (e) {
      client.note("packages", false, e);
      return null;
    }
    const isPublic = p.visibility === "public";
    for (const v of versions) {
      const tags: string[] = Array.isArray(v?.metadata?.container?.tags) ? v.metadata.container.tags.map(String) : [];
      // Untagged versions are the per-platform parts of a tagged one, or what an overwritten tag left behind.
      if (!tags.length || !/^sha256:[a-f0-9]{64}$/.test(String(v?.name ?? ""))) continue;
      images.push({
        registry: REGISTRY,
        repository: `${org}/${name}`.toLowerCase(),
        region: null,
        digest: String(v.name),
        tags,
        pushedAt: typeof v.updated_at === "string" ? v.updated_at : typeof v.created_at === "string" ? v.created_at : null,
        pulledAt: null,
        public: isPublic,
        linkedRepo: typeof p.repository?.full_name === "string" ? p.repository.full_name.toLowerCase() : null,
        ...(isPublic ? {} : { unreadable: PRIVATE }),
      });
    }
  }
  return { images, packages: packages.length };
}

/** Picks and scans the organization's images, and records the result on the inventory for the checks and the snapshot. */
export async function scanGithubImages(
  client: GithubClient,
  inv: GithubInventory,
  o: { cache: AccountCache; toolDir: string | null; related: Partial<Related>; onProgress: (p: ProgressEvent) => void; previous?: ImagesSnapshot | null },
): Promise<void> {
  o.onProgress({ phase: "Reading container packages" });
  const listed = await readPackages(client);
  const workloads = [...(o.related.awsWorkloads ?? []), ...(o.related.alibabaWorkloads ?? [])];
  const registry = listed?.images ?? [];
  // Images the entity runs from this organization's namespace that the package list doesn't show.
  const prefix = `${inv.login.toLowerCase()}/`;
  for (const w of workloads)
    for (const c of w.containers) {
      const ref = parseImageRef(c.image);
      if (!ref || ref.registry !== REGISTRY || !ref.repository.startsWith(prefix)) continue;
      if (registry.some((img) => runningIn(img, [{ ...w, containers: [c] }]).length)) continue;
      registry.push({
        registry: REGISTRY,
        repository: ref.repository,
        region: null,
        digest: ref.digest,
        tags: ref.tag ? [ref.tag] : [],
        pushedAt: null,
        pulledAt: null,
        public: null,
      });
    }
  const targets = pickImages({ registry, workloads, ownWorkloads: [], login: () => null, foreign: () => "entity", now: inv.now });
  const { snapshot, scans, later } = await scanImages(targets, {
    repositories: listed?.packages ?? 0,
    cache: o.cache,
    toolDir: o.toolDir,
    onProgress: o.onProgress,
    // Nothing here is pulled with a login, so a refused pull is that image's own (a package made private since it was listed),
    // and so is a host Keelson can't reach: each image says so.
    note: (source, ok, err) => source !== "pull" && source !== "network" && client.note(source, ok, err),
    now: inv.now,
    previous: o.previous,
  });
  inv.images = { snapshot, scans, workloads, later };
  inv.unreadable = [...client.coverage.values()].filter((c) => !c.ok).map((c) => c.key);
}
