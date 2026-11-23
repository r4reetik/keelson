// Container image scanning, shared by every platform that has a registry or runs
// containers: which images a scan looks at, running Trivy over each, and reducing
// its report to what Keelson keeps.
//
// A registry can hold thousands of images, so a scan picks the ones that matter:
// every image a workload in the entity runs, images pulled lately (something runs
// them that Keelson can't see, such as a Kubernetes cluster), and the newest image
// of each repository. Images that run from a public registry (Docker Hub and the
// like) are scanned by the account that runs them. Each image is scanned by its
// digest, and its reduced result is kept in the account's cache
// (`img:<registry>/<repository>@<digest>`), so the Images page can show every
// package without the snapshot carrying them.
//
// An image named by its digest never changes, so it is pulled and read once.
// Beside its result Keelson keeps Trivy's own bill of materials for it
// (`imgsbom:…`), and every later scan hands that to Trivy to match against its
// current database: a vulnerability published since shows up without pulling
// anything, in a fraction of a second per image.
//
// Reading an image for the first time takes about half a minute, so a scan reads
// what matters most itself, however long that takes: the images workloads run and
// each repository's latest. The others get what is left of the scan's time, and
// the ones it doesn't reach are handed back as a backlog (`later`), which the
// scanner reads in the background once no scan is running.
//
// Of Trivy's report only packages, vulnerabilities and a few facts of the image's
// configuration are kept. A credential found in a file keeps its kind and the
// file's path; the image's environment variables are scanned in memory with the
// shared patterns and only a variable's name and the kind are kept. Labels other
// than the source repository and revision are dropped.

import { eol, supportOf } from "./eol.ts";
import { notInstalled } from "../shared/tools.ts";
import { IndexBuilder } from "./image-index.ts";
import { kev } from "./kev.ts";
import { secretInVariables, secretKindIn } from "./secret-patterns.ts";
import { trivy, trivyLimits, TrivyError, type RegistryLogin } from "./trivy.ts";
import { shortChain } from "./anchore.ts";
import type { ProgressEvent } from "./types.ts";
import type { AccountCache } from "../store/repo.ts";
import {
  canonicalRegistry,
  countVulns,
  imageName,
  NO_VULNS,
  parseImageRef,
  runsImage,
  type ImageEntry,
  type ImagePackage,
  type ImageRef,
  type ImageRuntime,
  type ImageScan,
  type ImagesSnapshot,
  type ImageSecret,
  type ImageSummary,
  type ImageUse,
  type ImageVuln,
  type VulnSeverity,
  type WorkloadLink,
} from "../shared/images.ts";

/** Bump when what's cached per image changes shape, so every image is scanned again. */
export const IMAGE_FORMAT = 2;
/** Older shapes that can still be shown until an image is scanned again (`upgradeScan` fills what they lack). */
const READABLE_FORMATS = [1, IMAGE_FORMAT];
/**
 * An image named by a tag alone may be another image tomorrow, so it is asked for again after this long (Trivy fetches
 * only the layers it hasn't read). One named by its digest never changes and is never pulled twice.
 */
const RESCAN_MS = 20 * 3600_000;
/** A registry login is asked for again after this long: the shortest-lived (Container Registry's) lasts an hour. */
const LOGIN_MS = 30 * 60_000;
/** Where an account's index of its images is cached (./image-index.ts). */
export const INDEX_KEY = "imgindex";
/** An image pulled within this many days is in use by something, even when Keelson can't see what. */
export const PULLED_DAYS = 30;
/** Images one scan looks at; the rest of a registry is listed by its repositories only. */
export const MAX_IMAGES = 400;
/**
 * Images of one repository kept for having been pulled lately, the newest first. Every deployment pushes a new image
 * and the registry remembers a pull for a month: on a real registry one repository had 86 "pulled lately", of which
 * the last few are what runs.
 */
export const PULLED_PER_REPOSITORY = 3;
const MAX_PACKAGES = 8000;
const MAX_VULNS = 8000;
const DAY = 86_400_000;
type Json = any;

/** An image a registry lists, before Keelson decides whether to scan it. */
export interface RegistryImage {
  registry: string;
  repository: string;
  region: string | null;
  digest: string | null;
  tags: string[];
  pushedAt: string | null;
  pulledAt: string | null;
  public: boolean | null;
  linkedRepo?: string | null;
  /** Set when Keelson can list the image but not pull it: why. */
  unreadable?: string;
  /** The platforms it was built for, when the registry's index says. */
  platforms?: string[];
}

/** An image to scan, with how to sign in to its registry. */
export interface ImageTarget extends Omit<ImageEntry, "summary" | "error" | "key"> {
  /** Higher is scanned first, so the images that matter most are done when time runs out. */
  priority: number;
  /** The newest image of its repository. */
  latest: boolean;
  /** The registry login, asked for once per registry; null to pull without one (a public image). */
  login: (() => Promise<RegistryLogin | null>) | null;
  /** Set instead of scanning: why Keelson can't pull it (a private registry no connected account holds). */
  unreadable?: string;
  /** What the registry's own settings say about reaching it, added to the error when its host can't be reached. */
  reach?: string | null;
}

/** Where an image a workload names is kept, from the scanning account's side. */
export type Foreign = "entity" | "public" | "private";

export const imageCacheKey = (e: Pick<ImageEntry, "registry" | "repository" | "digest" | "tags">): string =>
  `img:${e.registry}/${e.repository}${e.digest ? `@${e.digest}` : `:${e.tags[0] ?? "latest"}`}`;
/** Where Trivy's bill of materials for an image is cached, beside its result ("img:…"). */
export const sbomCacheKey = (imageKey: string): string => `imgsbom:${imageKey.slice(4)}`;

/** The containers of a list of workloads that run an image. */
export function runningIn(
  image: Pick<ImageEntry, "registry" | "repository" | "digest" | "tags">,
  workloads: WorkloadLink[],
): { workload: WorkloadLink; container: string; image: string; ref: ImageRef }[] {
  const out = [];
  for (const w of workloads)
    for (const c of w.containers) {
      const ref = parseImageRef(c.image);
      if (ref && runsImage(ref, image)) out.push({ workload: w, container: c.name, image: c.image, ref });
    }
  return out;
}

/** How much an image is in use, from the workloads that run it and when it was last pulled. */
export function usageOf(image: Pick<ImageEntry, "pulledAt">, uses: { workload: WorkloadLink }[], now: number): ImageUse {
  if (uses.some((u) => u.workload.internet === true)) return "internet";
  if (uses.length) return "running";
  const pulled = image.pulledAt ? Date.parse(image.pulledAt) : Number.NaN;
  return Number.isFinite(pulled) && now - pulled < PULLED_DAYS * DAY ? "pulled" : "stored";
}

/**
 * The images a scan looks at. From the account's own registries: the ones workloads run (the account's and the
 * entity's others), the ones pulled lately, and the newest of each repository. From elsewhere: the ones the account's
 * own workloads run, when no connected account holds their registry.
 */
export function pickImages(o: {
  registry: RegistryImage[];
  /** Every workload known in the entity, the account's own included. */
  workloads: WorkloadLink[];
  ownWorkloads: WorkloadLink[];
  login: (image: RegistryImage) => (() => Promise<RegistryLogin | null>) | null;
  /** What the registry's settings say about who can reach it (an allowlist, no internet access); null when nothing. */
  reach?: (image: RegistryImage) => string | null;
  foreign: (ref: ImageRef) => Foreign;
  now: number;
}): ImageTarget[] {
  const out = new Map<string, ImageTarget>();
  const newest = new Map<string, RegistryImage>();
  for (const img of o.registry) {
    const name = imageName(img);
    const prev = newest.get(name);
    // A tagged image over an untagged one, then the latest push.
    const better = !prev || Number(img.tags.length > 0) - Number(prev.tags.length > 0) || (img.pushedAt ?? "").localeCompare(prev.pushedAt ?? "");
    if (better === true || (typeof better === "number" && better > 0)) newest.set(name, img);
  }
  // Of the images only known for a recent pull, each repository's newest few.
  const pulled = new Map<string, RegistryImage[]>();
  for (const img of o.registry)
    if (usageOf(img, runningIn(img, o.workloads), o.now) === "pulled") pulled.set(imageName(img), [...(pulled.get(imageName(img)) ?? []), img]);
  const old = new Set<RegistryImage>();
  for (const list of pulled.values())
    for (const img of list.sort((a, b) => (b.pushedAt ?? "").localeCompare(a.pushedAt ?? "")).slice(PULLED_PER_REPOSITORY)) old.add(img);
  for (const img of o.registry) {
    if (old.has(img) && newest.get(imageName(img)) !== img) continue;
    const uses = runningIn(img, o.workloads);
    const use = usageOf(img, uses, o.now);
    const why = [
      uses.length && (use === "internet" ? "runs in a workload the internet reaches" : "runs in a workload"),
      use === "pulled" && "pulled lately",
      newest.get(imageName(img)) === img && "newest in its repository",
    ].filter((x): x is string => !!x);
    if (!why.length) continue;
    const priority = use === "internet" ? 120 : use === "running" ? 100 : use === "pulled" ? 60 : 40;
    const t: ImageTarget = { ...img, own: true, why, priority, latest: newest.get(imageName(img)) === img, login: o.login(img), reach: o.reach?.(img) ?? null };
    out.set(imageCacheKey(t), t);
  }
  for (const w of o.ownWorkloads)
    for (const c of w.containers) {
      const ref = parseImageRef(c.image);
      // An image the account's own registry lists was picked above, by its digest.
      if (!ref || o.registry.some((img) => runsImage(ref, img))) continue;
      const where = o.foreign(ref);
      if (where === "entity") continue;
      const t: ImageTarget = {
        registry: ref.registry,
        repository: ref.repository,
        region: null,
        digest: ref.digest,
        tags: ref.tag ? [ref.tag] : [],
        pushedAt: null,
        pulledAt: null,
        public: where === "public" ? true : null,
        own: false,
        why: [w.internet === true ? "runs in a workload the internet reaches" : "runs in a workload"],
        priority: w.internet === true ? 120 : 100,
        latest: false,
        login: null,
        ...(where === "private" ? { unreadable: "It is kept in a private registry that no connected account holds." } : {}),
      };
      const key = imageCacheKey(t);
      const prev = out.get(key);
      if (!prev || prev.priority < t.priority) out.set(key, t);
    }
  // When a registry has more than one scan looks at, what a scan reads itself is kept before a repository's older images.
  return [...out.values()]
    .sort((a, b) => Number(readInScan(b)) - Number(readInScan(a)) || b.priority - a.priority || (b.pushedAt ?? "").localeCompare(a.pushedAt ?? ""))
    .slice(0, MAX_IMAGES);
}

/**
 * The images a scan reads itself, whatever time it takes: the ones workloads run and each repository's latest. The
 * others (a repository's older images that were pulled lately) can wait for the background.
 */
export const readInScan = (t: Pick<ImageTarget, "priority" | "latest">): boolean => t.priority >= 100 || t.latest;

/** `network`: a registry's host couldn't be reached from where Keelson runs, which no permission fixes. */
export type ImageSource = "trivy" | "kev" | "pull" | "network";

/**
 * What the checks read of a scanned image: where it says it was built, the credentials in it, and the vulnerabilities a
 * finding names (known exploited, and critical or high with a fix). The full result stays in the cache: a scan of
 * hundreds of images would otherwise hold every package of each in memory until it ends.
 */
export type ImageHighlights = Pick<ImageScan, "source" | "secrets" | "vulns">;
const HIGHLIGHTS = 40;
export const highlightsOf = (scan: ImageScan): ImageHighlights => ({
  source: scan.source,
  secrets: scan.secrets,
  vulns: scan.vulns.filter((v) => v.kev || (v.fixedIn && (v.severity === "critical" || v.severity === "high"))).slice(0, HIGHLIGHTS),
});

/**
 * The images a scan didn't reach in its time, to read once it is over. Their results go to the account's cache, where
 * the account's next scan finds them without pulling anything.
 */
export interface ImageBacklog {
  /** How many images it holds. */
  total: number;
  /**
   * Reads them one at a time until none is left or `stop` says to give way; a later call goes on from where this one
   * stopped. `read` is how many images have a result so far, over every call.
   */
  run(o: { stop: () => boolean; onProgress?: (done: number, total: number) => void; now?: () => number }): Promise<{ finished: boolean; read: number }>;
}

export interface ImageScanOutput {
  snapshot: ImagesSnapshot;
  /** What the checks read of each scanned image, by cache key. */
  scans: Map<string, ImageHighlights>;
  /** The images the scan's time didn't reach; null when it read them all. */
  later: ImageBacklog | null;
}

/**
 * Scans the picked images with Trivy, most important first. The images workloads run and each repository's latest are
 * always read; the others until the time for one scan runs out, and the rest are handed back as `later`. `note` records
 * whether Trivy ran, whether CISA's list was read and whether the registry let Keelson pull, as the provider's coverage.
 */
export async function scanImages(
  targets: ImageTarget[],
  o: {
    repositories: number;
    cache: AccountCache;
    toolDir: string | null;
    onProgress: (p: ProgressEvent) => void;
    note: (source: ImageSource, ok: boolean, err?: unknown) => void;
    now?: number;
    /** What the account's last scan knew of its images, to scan first what was never scanned. */
    previous?: ImagesSnapshot | null;
  },
): Promise<ImageScanOutput> {
  const now = o.now ?? Date.now();
  targets = inScanOrder(targets, o.previous ?? null);
  const scans = new Map<string, ImageHighlights>();
  const index = new IndexBuilder();
  const entries: ImageEntry[] = [];
  const bin = trivy.path();
  const wanted = targets.some((t) => !t.unreadable);
  // Without anything to scan, a missing Trivy is no gap.
  if (!bin && wanted) o.note("trivy", false, new TrivyError(notInstalled("Trivy")));
  // The database first, on its own: without one nothing can be matched, and no registry login is around while it downloads.
  let ready = !!bin;
  if (bin && wanted) {
    o.onProgress({ phase: "Updating Trivy's vulnerability database" });
    try {
      await trivy.updateDb(bin, o.toolDir);
    } catch (e) {
      o.note("trivy", false, e);
      ready = false;
    }
  }
  const tool = bin ? await trivy.version(bin, o.toolDir) : { version: null, dbUpdated: null };
  let exploited: Set<string> | null = null;
  if (ready && wanted)
    try {
      exploited = await kev.load(o.toolDir, now);
      o.note("kev", true);
    } catch (e) {
      o.note("kev", false, e);
    }
  else if (ready) o.note("kev", true);

  // Support dates of every runtime Keelson recognises, read once: which images hold which isn't known before they are scanned.
  const lines = ready && wanted ? await eol.load(Object.values(RUNTIME_PRODUCT), o.toolDir, now).catch(() => ({}) as Awaited<ReturnType<typeof eol.load>>) : {};
  // Coverage is the scan's: what the backlog meets after it is over is that image's own, shown with the next scan.
  let note = o.note;
  const logins = new Map<ImageTarget["login"], { at: number; login: Promise<RegistryLogin | null> }>();
  const loginFor = (login: ImageTarget["login"]): Promise<RegistryLogin | null> | null => {
    if (!login) return null;
    const had = logins.get(login);
    if (had && Date.now() - had.at < LOGIN_MS) return had.login;
    const asked = login();
    logins.set(login, { at: Date.now(), login: asked });
    return asked;
  };

  // A registry host that couldn't be reached isn't tried again for its other images: each try is minutes of Trivy's
  // retries, and a registry behind an allowlist would otherwise take a scan's whole time and leave nothing read.
  const unreachable = new Map<string, string>();

  /** Pulls one image and reads it, and keeps Trivy's bill of materials for it. `skip`: what the reference names isn't an image. */
  const read = async (t: ImageTarget, key: string, at: number): Promise<{ scan?: ImageScan; skip?: boolean; error?: string }> => {
    const sbomKey = sbomCacheKey(key);
    const away = unreachable.get(t.registry);
    if (away) return { error: away };
    try {
      const auth = await loginFor(t.login);
      const ref = `${imageName(t)}${t.digest ? `@${t.digest}` : `:${t.tags[0] ?? "latest"}`}`;
      // Trivy asks for linux/amd64. An image built for other platforms only is asked for by one of its own.
      let platform = t.platforms?.length && !t.platforms.includes(DEFAULT_PLATFORM) ? (t.platforms.find((p) => p.startsWith("linux/")) ?? null) : null;
      let text: string;
      try {
        text = await trivy.image(bin!, ref, auth, o.toolDir, platform);
      } catch (e) {
        // The registry didn't say which platforms it has: arm64 is the other one images are built for.
        if (!(e as TrivyError).noPlatform || platform) throw e;
        platform = "linux/arm64";
        text = await trivy.image(bin!, ref, auth, o.toolDir, platform);
      }
      const doc = parseReport(text);
      const scan = reduceReport(doc, t, tool.version, at, platform, tool.dbUpdated);
      note("pull", true);
      note("network", true);
      // Trivy's own list of what it read, kept so later scans match it against a newer database without pulling.
      // Without one the image is read again next time, as before.
      try {
        o.cache.put(sbomKey, keptSbom(JSON.parse(await trivy.sbom(bin!, JSON.stringify(inventoryOf(doc)))), ref));
      } catch {
        o.cache.delete(sbomKey);
      }
      return { scan };
    } catch (e) {
      const te = e as TrivyError;
      if (te.notImage) {
        o.cache.put(key, { format: IMAGE_FORMAT, skip: "not an image" });
        return { skip: true };
      }
      if (te.unreachable) {
        const message = `${te.message}${t.reach ? ` ${t.reach}` : ""}`.slice(0, 480);
        unreachable.set(t.registry, message);
        note("network", false, new Error(message));
        return { error: message };
      }
      // A registry that refuses a login the account handed out is a missing permission. An image that's gone, or
      // one Trivy can't read, is that image's own: only a failure of the tool itself is a gap.
      if (t.login && (te.denied || !(e instanceof TrivyError))) note("pull", false, e);
      else if (e instanceof TrivyError && !te.image) note("trivy", false, e);
      // Its end: a Go error's cause is its last part.
      return { error: shortChain(String(te?.message || e), 480) };
    }
  };

  /** Applies what changes while an image stays the same; true when the result differs from what is stored. */
  const refresh = (scan: ImageScan, at: number): boolean => {
    let changed = false;
    // CISA's list changes between scans of the same image: it is applied on every scan, not kept from the last one.
    if (exploited)
      for (const v of scan.vulns)
        if (v.kev !== exploited.has(v.id)) {
          v.kev = !v.kev;
          changed = true;
        }
    // So do support dates: a release line that was supported at the last scan may have reached its end since.
    for (const r of scan.runtimes) {
      const support = supportOf(lines[RUNTIME_PRODUCT[r.name] ?? ""], r.version, at);
      if (support.eol !== r.eol || support.latest !== r.latest || support.until !== r.until) {
        Object.assign(r, support);
        changed = true;
      }
    }
    return changed;
  };

  const started = Date.now();
  const rest: ImageTarget[] = [];
  let pulled = 0;
  let checked = 0;
  let done = 0;
  let ran = false;
  for (const t of targets) {
    const { priority: _p, latest: _l, login: _login, reach: _reach, unreadable, ...entry } = t;
    const key = imageCacheKey(t);
    const cached = o.cache.get<ImageScan & { skip?: string }>(key);
    // What a reference named last time wasn't an image (a build attestation): it isn't asked for again, or listed.
    if (cached?.skip && cached.format === IMAGE_FORMAT) continue;
    const usable = cached && !cached.skip ? upgradeScan(cached) : null;
    let scan: ImageScan | null = usable;
    let error: string | null = unreadable ?? null;
    /** The stored result differs from this one: a new scan, or a vulnerability that joined or left CISA's list. */
    let stale = false;
    // What was read of an image named by its digest stays true: only what the database says of its packages changes.
    const known = usable && cached?.format === IMAGE_FORMAT && (t.digest != null || now - Date.parse(usable.scannedAt) < RESCAN_MS) ? usable : null;
    /** Its vulnerabilities are the current database's, without pulling it. */
    let current = false;
    if (bin && ready && !unreadable && known) {
      // The same database as last time has nothing new to say.
      if (known.dbUpdated && known.dbUpdated === tool.dbUpdated) current = true;
      else {
        const sbom = o.cache.get<Json>(sbomCacheKey(key));
        if (sbom && Array.isArray(sbom.components))
          try {
            o.onProgress({ phase: "Scanning images with Trivy", done, total: targets.length });
            // An image without a package has nothing to match.
            const doc = sbom.components.length ? parseMatch(await trivy.match(bin, JSON.stringify(sbom), o.toolDir)) : {};
            scan = rematched(known, doc, tool.dbUpdated);
            current = stale = ran = true;
          } catch {
            // The image is read again below, which also writes its bill of materials again.
          }
      }
    }
    if (current) checked++;
    if (bin && ready && !unreadable && !current) {
      // Only the images that can wait give way to the clock.
      if (!readInScan(t) && (Date.now() - started) / 1000 > trivyLimits.totalSeconds) rest.push(t);
      else {
        o.onProgress({ phase: "Scanning images with Trivy", done, total: targets.length });
        const r = await read(t, key, now);
        if (r.skip) {
          done++;
          continue;
        }
        if (r.scan) {
          scan = r.scan;
          stale = ran = true;
          pulled++;
        } else error = r.error ?? null;
      }
    }
    done++;
    if (scan) {
      if (refresh(scan, now)) stale = true;
      if (stale) o.cache.put(key, scan);
      scans.set(key, highlightsOf(scan));
      index.add(key, scan);
    }
    entries.push({ ...entry, key, digest: entry.digest ?? scan?.digest ?? null, summary: scan ? summarize(scan) : null, error: scan ? null : error });
  }
  if (ready && (ran || !wanted)) o.note("trivy", true);
  note = () => {};
  // Results of images that are gone, or no longer picked, go with them.
  const kept = new Set(targets.map(imageCacheKey));
  for (const key of o.cache.keys("img:")) if (!kept.has(key)) o.cache.delete(key);
  for (const key of o.cache.keys("imgsbom:")) if (!kept.has(`img:${key.slice(8)}`)) o.cache.delete(key);
  // What is in which image, for the lists that work across every image.
  o.cache.put(INDEX_KEY, index.done());

  let next = 0;
  let got = 0;
  const later: ImageBacklog | null = rest.length
    ? {
        total: rest.length,
        async run({ stop, onProgress, now: clock = Date.now }) {
          // Trivy refreshes its database as it goes: a result says which one its vulnerabilities are from.
          const fresh = await trivy.version(bin!, o.toolDir);
          if (fresh.dbUpdated) Object.assign(tool, fresh);
          while (next < rest.length && !stop()) {
            onProgress?.(next, rest.length);
            const t = rest[next];
            const key = imageCacheKey(t);
            const at = clock();
            const r = await read(t, key, at);
            if (r.scan) {
              refresh(r.scan, at);
              o.cache.put(key, r.scan);
              got++;
            }
            next++;
          }
          onProgress?.(next, rest.length);
          return { finished: next >= rest.length, read: got };
        },
      }
    : null;
  return {
    snapshot: { images: entries, repositories: o.repositories, waiting: rest.length, pulled, checked, trivy: tool.version, dbUpdated: tool.dbUpdated },
    scans,
    later,
  };
}

/**
 * The order images are scanned in (a new image takes half a minute to pull and read; one already read is only matched
 * against the database, in a fraction of a second). First what a scan reads itself, most exposed first: the images
 * workloads run, then each repository's latest, new ones before ones already read. Then the rest, which have what is
 * left of the scan's time: never read before read, and the ones read longest ago first. In the order they are listed, a
 * scan would reach the same first images every day and never the others.
 */
export function inScanOrder(targets: ImageTarget[], previous: ImagesSnapshot | null): ImageTarget[] {
  const scannedAt = new Map((previous?.images ?? []).filter((i) => i.summary).map((i) => [i.key, i.summary!.scannedAt]));
  const rank = (t: ImageTarget) => (readInScan(t) ? 0 : 2) + (scannedAt.has(imageCacheKey(t)) ? 1 : 0);
  return [...targets].sort(
    (a, b) =>
      rank(a) - rank(b) ||
      (rank(a) === 3 ? (scannedAt.get(imageCacheKey(a)) ?? "").localeCompare(scannedAt.get(imageCacheKey(b)) ?? "") : 0) ||
      b.priority - a.priority ||
      (b.pushedAt ?? "").localeCompare(a.pushedAt ?? ""),
  );
}

/** Trivy's JSON, checked for being an image report: anything else is the tool's failure, never an empty result. */
export function parseReport(text: string): Json {
  let doc: Json;
  try {
    doc = JSON.parse(text);
  } catch {
    doc = null;
  }
  if (!doc || typeof doc !== "object" || doc.ArtifactType !== "container_image" || typeof doc.Metadata !== "object")
    throw new TrivyError("Trivy's output wasn't the image report Keelson reads. Check that Trivy runs where Keelson runs.");
  return doc;
}

const SEVERITY: Record<string, VulnSeverity> = { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low" };
const arr = (x: unknown): Json[] => (Array.isArray(x) ? x : []);
const str = (x: unknown): string | null => (typeof x === "string" && x ? x : null);

/** Trivy's report reduced to what Keelson keeps. Files, layers, history, labels and variable values are dropped here. */
export function reduceReport(
  doc: Json,
  target: Pick<ImageEntry, "registry" | "repository" | "digest">,
  version: string | null,
  now: number,
  platform: string | null = null,
  dbUpdated: string | null = null,
): ImageScan {
  const meta = doc.Metadata ?? {};
  const config = meta.ImageConfig?.config ?? {};
  // Which layers the base image brought: every layer up to the base's own CMD line in the build history. A build adds its
  // layers after it, so a package in an earlier layer came with the base image.
  const history = arr(meta.ImageConfig?.history);
  const diffIds: string[] = arr(meta.ImageConfig?.rootfs?.diff_ids ?? meta.DiffIDs).map(String);
  const counted = baseLayerCount(history);
  const baseLayers = counted && counted < diffIds.length ? counted : null;
  const baseIds = new Set(baseLayers ? diffIds.slice(0, baseLayers).map(layerId) : []);
  const inBase = (x: Json) => (baseIds.has(layerId(x?.Layer?.DiffID)) ? { base: true } : {});
  const labels: Record<string, unknown> = config.Labels && typeof config.Labels === "object" ? config.Labels : {};
  const packages: ImagePackage[] = [];
  const secrets: ImageSecret[] = [];
  for (const r of arr(doc.Results)) {
    const layer = r.Class === "os-pkgs" ? "os" : "app";
    if (r.Class === "secret" || arr(r.Secrets).length) {
      // Only what kind of credential and where: the matched text and the lines around it are never read.
      for (const s of arr(r.Secrets)) {
        const kind = str(s.Title) ?? str(s.RuleID) ?? "a credential";
        if (!secrets.some((x) => x.kind === kind && x.where === String(r.Target))) secrets.push({ kind, where: String(r.Target ?? ""), likely: false });
      }
      if (r.Class === "secret") continue;
    }
    if (r.Class !== "os-pkgs" && r.Class !== "lang-pkgs") continue;
    const type = String(r.Type ?? "");
    const file = fileOf(r);
    for (const p of arr(r.Packages)) {
      if (packages.length >= MAX_PACKAGES) break;
      packages.push({
        name: String(p.Name ?? ""),
        version: String(p.Version ?? ""),
        type,
        layer,
        path: str(p.FilePath) ?? file,
        purl: str(p.Identifier?.PURL),
        licenses: arr(p.Licenses).map(String).filter(Boolean).slice(0, 5),
        ...inBase(p),
      });
    }
  }
  // The image's own environment variables, scanned in memory: only a variable's name and the kind found leave this function.
  const env = Object.fromEntries(
    arr(config.Env).map((line) => {
      const s = String(line);
      const eq = s.indexOf("=");
      return eq < 0 ? [s, ""] : [s.slice(0, eq), s.slice(eq + 1)];
    }),
  );
  const found = secretInVariables(env);
  if (found) secrets.push({ kind: found.kind, where: `environment variable ${found.where}`, likely: found.likely });
  // The build history records each Dockerfile step as written, build arguments included: scanned the same way, and dropped.
  const built = arr(meta.ImageConfig?.history)
    .map((h) => secretKindIn(String(h?.created_by ?? "")))
    .find(Boolean);
  if (built) secrets.push({ kind: built, where: "the image's build history", likely: false });
  const digest = target.digest ?? str(arr(meta.RepoDigests).map((d) => String(d).split("@")[1])[0]);
  const os = meta.OS && typeof meta.OS === "object" && meta.OS.Family ? meta.OS : null;
  const source = str(labels["org.opencontainers.image.source"]) ?? str(labels["org.label-schema.vcs-url"]);
  return {
    format: IMAGE_FORMAT,
    registry: target.registry,
    repository: target.repository,
    digest,
    os: os ? { family: String(os.Family), name: String(os.Name ?? ""), eol: os.EOSL === true } : null,
    architecture: str(meta.ImageConfig?.architecture),
    created: str(meta.ImageConfig?.created),
    size: Number.isFinite(Number(meta.Size)) && Number(meta.Size) > 0 ? Number(meta.Size) : null,
    // An image that names no user runs as root; Trivy leaves the field out then.
    user: typeof config.User === "string" ? config.User : meta.ImageConfig ? "" : null,
    // A source label is a URL that may carry a token (https://x-access-token:…@github.com/…): only its host and path are kept.
    source: source ? cleanSource(source) : null,
    revision: str(labels["org.opencontainers.image.revision"]) ?? str(labels["org.label-schema.vcs-ref"]),
    packages,
    vulns: vulnsOf(doc, baseIds),
    secrets,
    scannedAt: new Date(now).toISOString(),
    dbUpdated,
    trivy: version,
    platform,
    layers: diffIds.map(layerId),
    baseLayers,
    baseName: imageNameOf(labels["org.opencontainers.image.base.name"]),
    runtimes: runtimesIn(env),
  };
}

/** A layer's ID as Keelson keeps it: the start of its diff ID. */
const layerId = (x: unknown): string =>
  String(x ?? "")
    .replace(/^sha256:/, "")
    .slice(0, 16);
/** A lock file's packages are recorded in it; packages found one by one (node_modules, JAR files) name their own file. */
const fileOf = (r: Json): string | null => (r.Class !== "os-pkgs" && /[/.]/.test(String(r.Target ?? "")) ? String(r.Target) : null);

/** The vulnerabilities of a report, Trivy's for an image or for its bill of materials: one per ID, package, version and file. */
function vulnsOf(doc: Json, baseIds: Set<string>): ImageVuln[] {
  const vulns = new Map<string, ImageVuln>();
  for (const r of arr(doc.Results)) {
    if (r.Class !== "os-pkgs" && r.Class !== "lang-pkgs") continue;
    const type = String(r.Type ?? "");
    const layer = r.Class === "os-pkgs" ? "os" : "app";
    const file = fileOf(r);
    for (const v of arr(r.Vulnerabilities)) {
      const id = String(v.VulnerabilityID ?? "");
      if (!id) continue;
      const path = str(v.PkgPath) ?? file;
      const key = `${id}|${v.PkgName}|${v.InstalledVersion}|${path ?? ""}`;
      if (vulns.has(key) || vulns.size >= MAX_VULNS) continue;
      const scores = Object.values<Json>(v.CVSS ?? {})
        .flatMap((c) => [c?.V40Score, c?.V3Score])
        .map(Number)
        .filter((n) => Number.isFinite(n) && n > 0);
      vulns.set(key, {
        id,
        pkg: String(v.PkgName ?? ""),
        version: String(v.InstalledVersion ?? ""),
        type,
        layer,
        path,
        fixedIn: str(v.FixedVersion),
        status: String(v.Status ?? "unknown"),
        severity: SEVERITY[String(v.Severity ?? "").toUpperCase()] ?? "unknown",
        cvss: scores.length ? Math.max(...scores) : null,
        kev: false,
        title: String(v.Title || v.Description || "")
          .replace(/\s+/g, " ")
          .trim()
          .slice(0, 200),
        url: /^https:\/\//.test(String(v.PrimaryURL ?? "")) ? String(v.PrimaryURL) : null,
        ...(baseIds.has(layerId(v?.Layer?.DiffID)) ? { base: true } : {}),
      });
    }
  }
  return [...vulns.values()].sort(byUrgency);
}

/**
 * What Trivy is given to write its bill of materials from: the report's packages and the few facts that place them (the
 * operating system and the layers). The image's configuration stays out, so no label, variable or build step reaches
 * the bill of materials Keelson keeps.
 */
export function inventoryOf(doc: Json): Json {
  const meta = doc.Metadata ?? {};
  return {
    SchemaVersion: doc.SchemaVersion,
    ArtifactName: "image",
    ArtifactType: "container_image",
    Metadata: { OS: meta.OS, ImageID: meta.ImageID, DiffIDs: meta.DiffIDs, Size: meta.Size },
    Results: arr(doc.Results)
      .filter((r) => r.Class === "os-pkgs" || r.Class === "lang-pkgs")
      .map((r) => ({ Target: r.Target, Class: r.Class, Type: r.Type, Packages: r.Packages })),
  };
}

/**
 * Trivy's CycloneDX reduced to what matching needs: the components and how they depend on each other. The image is named
 * by Keelson, and Trivy's own description of it (where labels would be) and its list of vulnerabilities are dropped.
 */
export function keptSbom(cdx: Json, name: string): Json {
  if (!cdx || typeof cdx !== "object" || cdx.bomFormat !== "CycloneDX")
    throw new TrivyError("Trivy's bill of materials wasn't the CycloneDX document Keelson reads.");
  return {
    bomFormat: "CycloneDX",
    specVersion: String(cdx.specVersion ?? "1.6"),
    version: 1,
    metadata: { component: { "bom-ref": String(cdx.metadata?.component?.["bom-ref"] ?? name), type: "container", name } },
    components: arr(cdx.components),
    dependencies: arr(cdx.dependencies),
  };
}

/** Trivy's JSON for a bill of materials, checked for being that report: anything else is the tool's failure, never an empty result. */
export function parseMatch(text: string): Json {
  let doc: Json;
  try {
    doc = JSON.parse(text);
  } catch {
    doc = null;
  }
  if (!doc || typeof doc !== "object" || doc.ArtifactType !== "cyclonedx")
    throw new TrivyError("Trivy's output wasn't the report Keelson reads. Check that Trivy runs where Keelson runs.");
  return doc;
}

/**
 * A stored result with its vulnerabilities as the current database gives them for the same packages. Everything read
 * from the image itself stays as it was: the image hasn't changed.
 */
export function rematched(scan: ImageScan, doc: Json, dbUpdated: string | null): ImageScan {
  const os = doc.Metadata?.OS;
  // CISA's list is applied by the scan after this; what was on it stays marked when the list can't be read.
  const exploited = new Set(scan.vulns.filter((v) => v.kev).map((v) => v.id));
  const vulns = vulnsOf(doc, new Set(scan.baseLayers ? scan.layers.slice(0, scan.baseLayers) : [])).map((v) => (exploited.has(v.id) ? { ...v, kev: true } : v));
  return {
    ...scan,
    // An operating system release reaches its end of life while the image stays the same.
    os: scan.os && os && typeof os === "object" && String(os.Family) === scan.os.family ? { ...scan.os, eol: os.EOSL === true } : scan.os,
    vulns: vulns.sort(byUrgency),
    dbUpdated,
  };
}

const DEFAULT_PLATFORM = "linux/amd64";

/**
 * How many layers of an image are its base image's, from its build history. A base image ends with its own CMD line,
 * which adds no layer; the build's steps come after. So the last such line that still has a layer after it marks where
 * the base ends (the way Trivy tells base layers apart). Null when the history shows no such line.
 */
export function baseLayerCount(history: Json[]): number | null {
  let end = -1;
  let layerAfter = false;
  for (let i = history.length - 1; i >= 0; i--) {
    const h = history[i] ?? {};
    if (!layerAfter) {
      if (h.empty_layer) continue;
      layerAfter = true;
    }
    if (!h.empty_layer) continue;
    if (/^(\/bin\/sh -c #\(nop\)\s+)?CMD\b/.test(String(h.created_by ?? ""))) {
      end = i;
      break;
    }
  }
  if (end < 0) return null;
  const layers = history.slice(0, end + 1).filter((h) => !h?.empty_layer).length;
  return layers || null;
}

/** The variables official images record their runtime's version in, and the product each is on endoflife.date. */
const RUNTIMES: Record<string, [name: string, product: string]> = {
  NODE_VERSION: ["Node.js", "nodejs"],
  NGINX_VERSION: ["nginx", "nginx"],
  PYTHON_VERSION: ["Python", "python"],
  GOLANG_VERSION: ["Go", "go"],
  RUBY_VERSION: ["Ruby", "ruby"],
  PHP_VERSION: ["PHP", "php"],
  JAVA_VERSION: ["Java", "eclipse-temurin"],
  DOTNET_VERSION: [".NET", "dotnet"],
  REDIS_VERSION: ["Redis", "redis"],
  PG_VERSION: ["PostgreSQL", "postgresql"],
  MONGO_VERSION: ["MongoDB", "mongodb"],
  MYSQL_VERSION: ["MySQL", "mysql"],
  MARIADB_VERSION: ["MariaDB", "mariadb"],
  TOMCAT_VERSION: ["Tomcat", "tomcat"],
  HTTPD_VERSION: ["Apache HTTP Server", "apache-http-server"],
};
const RUNTIME_PRODUCT: Record<string, string> = Object.fromEntries(Object.values(RUNTIMES));

/**
 * The runtimes an image's own variables name. Only these variables are read for their value, and only a version number
 * is taken from it ("jdk-17.0.9+9" is 17.0.9): nothing else of a variable's value is ever kept.
 */
export function runtimesIn(env: Record<string, string>): ImageRuntime[] {
  const out: ImageRuntime[] = [];
  for (const [key, [name]] of Object.entries(RUNTIMES)) {
    const version = /(\d+(?:\.\d+){0,3})/.exec(String(env[key] ?? "").replace(/^\d+:/, ""))?.[1];
    if (version) out.push({ name, version, eol: null, until: null, latest: null });
  }
  return out;
}

/** An image name from a label, when it reads like one ("docker.io/library/node:20-alpine"). */
function imageNameOf(x: unknown): string | null {
  const s = typeof x === "string" ? x.trim() : "";
  return s && s.length <= 200 && parseImageRef(s) ? s : null;
}

/** A stored result in an older shape, with what it lacks filled in as unknown. Null for a shape Keelson can't show. */
export function upgradeScan(scan: ImageScan | null | undefined): ImageScan | null {
  if (!scan || !READABLE_FORMATS.includes(scan.format) || !Array.isArray(scan.packages)) return null;
  return {
    ...scan,
    platform: scan.platform ?? null,
    layers: scan.layers ?? [],
    baseLayers: scan.baseLayers ?? null,
    baseName: scan.baseName ?? null,
    runtimes: scan.runtimes ?? [],
    dbUpdated: scan.dbUpdated ?? null,
  };
}

const RANK: Record<VulnSeverity, number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
const byUrgency = (a: ImageVuln, b: ImageVuln) =>
  Number(b.kev) - Number(a.kev) || RANK[b.severity] - RANK[a.severity] || Number(!!b.fixedIn) - Number(!!a.fixedIn) || a.id.localeCompare(b.id);

function cleanSource(url: string): string | null {
  const m = /^(?:https?:\/\/|git@|ssh:\/\/git@)(?:[^@/\s]+@)?([\w.-]+)[/:]([\w./-]+?)(?:\.git)?\/?$/.exec(url.trim());
  return m ? `https://${m[1].toLowerCase()}/${m[2]}` : null;
}

/** The GitHub repository ("org/name", lowercase) an image's source label names, or null. */
export function githubRepoOf(source: string | null): string | null {
  const m = /^https:\/\/github\.com\/([\w.-]+\/[\w.-]+)$/.exec(source ?? "");
  return m ? m[1].toLowerCase() : null;
}

export function summarize(scan: ImageScan): ImageSummary {
  return {
    os: scan.os ? `${scan.os.family} ${scan.os.name}`.trim() : null,
    eol: scan.os?.eol === true,
    created: scan.created,
    size: scan.size,
    packages: scan.packages.length,
    vulns: countVulns(scan.vulns),
    fixable: countVulns(scan.vulns.filter((v) => v.fixedIn)),
    exploited: [...new Set(scan.vulns.filter((v) => v.kev).map((v) => v.id))],
    secrets: scan.secrets.length,
    source: scan.source,
    revision: scan.revision,
    scannedAt: scan.scannedAt,
    runtimes: scan.runtimes,
    baseName: scan.baseName,
    fromBase: scan.baseLayers ? { packages: scan.packages.filter((p) => p.base).length, vulns: scan.vulns.filter((v) => v.base).length } : null,
  };
}

/** A snapshot for a scan that looked at no image: the registry couldn't be listed, or has none. */
export const noImages = (repositories = 0): ImagesSnapshot => ({ images: [], repositories, waiting: 0, trivy: null, dbUpdated: null });

export { canonicalRegistry, NO_VULNS };
