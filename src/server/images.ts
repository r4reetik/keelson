// Container images across the accounts in view, for the Images page: each image
// with what Trivy found in it, the workloads that run it and how the internet
// reaches them, the repository that builds it, the base image it is built on, and
// where each vulnerability is fixed.
//
// An image is scanned by the account whose registry holds it; what runs it and
// what builds it are usually other accounts' knowledge (an AWS account's ECS
// services, a GitHub organization's repositories). Those are joined here inside
// the image's own entity and never across entities.
//
// Everything is built once per set of scans and kept until one of them changes,
// then served a page at a time: a real registry has hundreds of images and tens
// of thousands of packages, and sending or holding all of it made the page, and
// the machine Keelson runs on, slow. The lists across images (vulnerabilities,
// components) are read from each account's compact index (src/core/image-index.ts),
// never from every image's full result. Triage is joined on every request.

import type { Repo } from "../store/repo.ts";
import { displayName, type Account, type Scope } from "../store/repo.ts";
import { coverage, scanMeta, type AccountScan } from "./scope.ts";
import { buildersOf } from "../core/image-checks.ts";
import { IndexBuilder, INDEX_FORMAT, type ImageIndex } from "../core/image-index.ts";
import { INDEX_KEY, runningIn, upgradeScan, usageOf } from "../core/images.ts";
import { ecosystemOfType } from "../core/sbom/manifests.ts";
import type { Coverage, DnsHostRecord, ProviderLinks, ScanMeta } from "../shared/api.ts";
import type { RepoDependencies } from "../shared/dependencies.ts";
import {
  countVulns,
  imageName,
  moreInUse,
  NO_VULNS,
  parseImageRef,
  registryKind,
  runsImage,
  usageRank,
  type ComponentKind,
  type ComponentRow,
  type FixPlace,
  type ImageBase,
  type ImageBrief,
  type ImageBuildLink,
  type ImageBuildRef,
  type ImageDetailResponse,
  type ImageFindingRef,
  type ImageList,
  type ImageRow,
  type ImageScan,
  type ImagesSnapshot,
  type ImagesSummary,
  type ImageUse,
  type ImageVuln,
  type ImageVulnDetail,
  type ImageVulnRow,
  type ImageVulnStatus,
  type ImageWorkloadRef,
  type RegistryKind,
  type VulnCounts,
  type VulnSeverity,
  type WorkloadLink,
  type WorkloadRow,
} from "../shared/images.ts";

const RANK: Record<VulnSeverity, number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
const SEVERITIES: VulnSeverity[] = ["critical", "high", "medium", "low", "unknown"];
const DNS_LISTS = ["cloudflareDns", "route53Dns", "alidnsDns"] as const satisfies readonly (keyof ProviderLinks)[];
const WORKLOAD_LISTS = ["awsWorkloads", "alibabaWorkloads"] as const satisfies readonly (keyof ProviderLinks)[];
/** What a row of a list carries of a longer list; the row says how many there are in all. */
const SHOWN = 3;
/** Views and filtered lists kept: enough for the views someone flips between, and no more. */
const VIEWS_KEPT = 4;
const RESULTS_KEPT = 12;

/** One account's latest scan, as the joins need it. */
interface Scanned {
  account: Account;
  scanId: number;
  links: ProviderLinks;
  images: ImagesSnapshot | null;
  /** A GitHub organization's repositories as GitHub spells them, by "org/name" in lowercase. */
  repoNames?: Map<string, string>;
}

/** An account's index with each of its images resolved to the row shown for it (null for one the view doesn't list). */
interface Part {
  accountId: string;
  index: ImageIndex;
  rows: (ImageRow | null)[];
  /** Each package's vulnerabilities and the version that fixes them all, worked out the first time components are listed. */
  vulnsOf?: Map<number, { ids: Set<number>; fixedIn: string | null }>;
  /** Each package's name in lowercase and its key, made once: a search reads them for every package on every key typed. */
  names?: string[];
  pkgKeys?: string[];
}

/** The fields of a finding that don't change with triage. */
type FindingRef = Omit<ImageFindingRef, "status">;

interface View {
  signature: string;
  scan: ScanMeta | null;
  coverage: Coverage[];
  snapshots: ImagesSnapshot[];
  /** Every image in view, most exposed first, with every workload that runs it. Findings are joined when rows are served. */
  images: ImageRow[];
  byId: Map<string, ImageRow>;
  workloads: WorkloadRow[];
  findings: Map<string, FindingRef[]>;
  /** The indexes, read the first time a list across images is asked for. */
  parts: Part[] | null;
  /** Filtered lists by their filters, the one used last at the end. */
  results: Map<string, unknown[]>;
  /** Lists being made now, shared by every request that asks for one meanwhile. */
  pending: Map<string, Promise<unknown[]>>;
}

/** The sources image scanning depends on, on any platform: their gaps are shown on the page. */
const SOURCES = new Set(["ecr", "ecrImages", "ecs", "imagePull", "registryNetwork", "trivy", "kev", "packages", "registries", "containerGroups", "manifests"]);

const views = new Map<string, View>();
const host = (s: string) => s.toLowerCase().replace(/\.$/, "");

/** Hostnames in the entity's DNS that reach each load balancer name, directly or through other names of the entity (three hops). */
function hostsByTarget(records: DnsHostRecord[]): (target: string) => string[] {
  const pointing = new Map<string, Set<string>>();
  for (const r of records) {
    if (r.type !== "CNAME" && r.type !== "A" && r.type !== "AAAA") continue;
    const t = host(r.target).replace(/^dualstack\./, "");
    pointing.set(t, (pointing.get(t) ?? new Set()).add(host(r.host)));
  }
  return (target) => {
    const found = new Set<string>();
    let frontier = [host(target).replace(/^dualstack\./, "")];
    for (let hop = 0; hop < 3 && frontier.length; hop++) {
      const next: string[] = [];
      for (const t of frontier)
        for (const h of pointing.get(t) ?? [])
          if (!found.has(h)) {
            found.add(h);
            next.push(h);
          }
      frontier = next;
    }
    return [...found].sort();
  };
}

/** One entity's images and workloads, joined with each other and with the repositories that build the images. */
function joinEntity(scanned: Scanned[], now: number): { images: ImageRow[]; workloads: WorkloadRow[] } {
  const workloads = scanned.flatMap((s) => WORKLOAD_LISTS.flatMap((k) => (s.links[k] ?? []).map((w) => ({ ...w, accountId: s.account.id }))));
  const builds: ImageBuildLink[] = scanned.flatMap((s) => s.links.githubImageBuilds ?? []);
  const repos = scanned.flatMap((s) => [...(s.links.githubRepos ?? []), ...(s.links.gitlabProjects ?? [])].map((r) => r.repo));
  // The GitHub or GitLab account that holds each organization or group, to link a repository's name to its page.
  const orgAccount = new Map(
    scanned.flatMap((s) => [...(s.links.githubOrgs ?? []), ...(s.links.gitlabGroups ?? []).map((g) => g.group)].map((org) => [org, s.account.id] as const)),
  );
  const spelled = new Map(scanned.flatMap((s) => [...(s.repoNames ?? [])]));
  const hostsOf = hostsByTarget(scanned.flatMap((s) => DNS_LISTS.flatMap((k) => s.links[k] ?? [])));
  const reach = (w: WorkloadLink) => [...new Set(w.loadBalancers.flatMap(hostsOf))].slice(0, 10);

  const images: ImageRow[] = [];
  for (const s of scanned)
    for (const e of s.images?.images ?? []) {
      const uses = runningIn(e, workloads);
      const refs = uses
        .map(
          (u): ImageWorkloadRef => ({
            kind: u.workload.kind,
            name: u.workload.name,
            group: u.workload.group,
            account: u.workload.account,
            provider: u.workload.provider,
            region: u.workload.region,
            link: u.workload.link,
            container: u.container,
            image: u.image,
            byTag: !u.ref.digest,
            internet: u.workload.internet,
            via: u.workload.via,
            hosts: reach(u.workload),
          }),
        )
        .sort((a, b) => Number(b.internet === true) - Number(a.internet === true));
      images.push({
        ...e,
        id: `${s.account.id}~${e.key}`,
        accountId: s.account.id,
        account: displayName(s.account),
        provider: s.account.provider,
        kind: registryKind(e.registry),
        use: usageOf(e, uses, now),
        workloads: refs,
        workloadCount: refs.length,
        builtBy: buildersOf(e, e.summary, builds, repos).map(
          (b): ImageBuildRef => ({
            repo: b.repo,
            ...(spelled.has(b.repo) ? { name: spelled.get(b.repo) } : {}),
            accountId: orgAccount.get(b.repo.split("/")[0]) ?? null,
            how: b.how,
            workflow: b.workflow,
            revision: b.how === "label" ? (e.summary?.revision ?? null) : null,
          }),
        ),
        findings: [],
      });
    }

  const rows: WorkloadRow[] = workloads.map((w) => ({
    ...w,
    hosts: reach(w),
    containers: w.containers.map((c) => {
      const ref = parseImageRef(c.image);
      const image = ref ? images.find((i) => runsImage(ref, i)) : undefined;
      return {
        name: c.name,
        image: c.image,
        imageId: image?.summary ? image.id : null,
        unscanned: image?.summary
          ? null
          : image
            ? (image.error ?? "It waits for a later scan: one scan only spends so long on images.")
            : !ref
              ? "Keelson can't read this image reference."
              : "No connected account holds its registry, or its scan hasn't listed this image yet.",
        vulns: image?.summary?.vulns ?? null,
        exploited: image?.summary?.exploited.length ?? 0,
      };
    }),
  }));
  return { images, workloads: rows };
}

/** The image findings of a scan, by image name. What they say doesn't change until the next scan; their triage does. */
function findingRefs(repo: Repo, account: Account, scanId: number, into: Map<string, FindingRef[]>): void {
  for (const f of repo.findings.forScan(scanId, repo.settings.get().slaDays)) {
    if (!/^[A-Z]IM-\d{3}$/.test(f.checkId)) continue;
    const named = (f.evidence as { image?: { images?: { registry: string; repository: string }[] } } | null)?.image?.images ?? [];
    for (const key of new Set(named.map((i) => `${account.id}|${imageName(i)}`)))
      into.set(key, [...(into.get(key) ?? []), { fingerprint: f.fingerprint, checkId: f.checkId, severity: f.severity, title: f.title }]);
  }
}

/**
 * The images and workloads of a view, built when one of the scans behind it is new and kept until the next. Images come
 * from the accounts in view; the workloads, repositories and DNS records they are joined with come from every account
 * of their entity, so a view of one account still shows where its images run.
 */
export function imagesView(repo: Repo, scope: Scope, now = Date.now()): View {
  const inView = new Set(scope.accounts.map((a) => a.id));
  const entities = new Set(scope.accounts.map((a) => a.entityId));
  const accounts = repo.accounts.list().filter((a) => entities.has(a.entityId));
  // Scan IDs only, without their snapshots: reading every snapshot on every request is what a view is kept to avoid.
  const signature = `${[...inView].sort().join(",")}|${accounts.map((a) => `${a.id}:${repo.scans.latestSummary(a.id)?.id ?? 0}`).join(",")}`;
  const hit = views.get(signature);
  if (hit) return hit;

  const scanned: (Scanned & AccountScan)[] = [];
  const names = new Map(repo.entities.list().map((e) => [e.id, e]));
  for (const account of accounts) {
    const scan = repo.scans.latest(account.id);
    if (scan)
      scanned.push({
        account,
        entity: names.get(account.entityId) ?? null,
        scan,
        scanId: scan.id,
        links: scan.snap.links ?? {},
        images: scan.snap.images ?? null,
        // "owner/name" as registries and workflows spell it, to the name its account knows it by.
        repoNames: new Map((scan.snap.repos ?? []).map((r) => [`${r.owner ?? scan.snap.links?.githubOrgs?.[0] ?? ""}/${r.name}`.toLowerCase(), r.name])),
      });
  }
  const mine = scanned.filter((s) => inView.has(s.account.id));
  const images: ImageRow[] = [];
  const workloads: WorkloadRow[] = [];
  for (const entityId of entities) {
    const joined = joinEntity(
      scanned.filter((s) => s.account.entityId === entityId),
      now,
    );
    images.push(...joined.images.filter((i) => inView.has(i.accountId)));
    workloads.push(...joined.workloads.filter((w) => inView.has(w.accountId)));
  }
  const worst = (i: ImageRow) => (i.summary ? i.summary.exploited.length * 1000 + i.summary.fixable.critical * 100 + i.summary.fixable.high : -1);
  images.sort((a, b) => usageRank(b.use) - usageRank(a.use) || worst(b) - worst(a) || imageName(a).localeCompare(imageName(b)));
  workloads.sort((a, b) => Number(b.internet === true) - Number(a.internet === true) || a.name.localeCompare(b.name));
  const findings = new Map<string, FindingRef[]>();
  for (const s of mine) if (s.images?.images.length) findingRefs(repo, s.account, s.scanId, findings);

  const view: View = {
    signature,
    scan: scanMeta(mine),
    coverage: coverage(mine).filter((c) => SOURCES.has(c.key ?? "")),
    snapshots: mine.map((s) => s.images).filter((x): x is ImagesSnapshot => !!x),
    images,
    byId: new Map(images.map((i) => [i.id, i])),
    workloads,
    findings,
    parts: null,
    results: new Map(),
    pending: new Map(),
  };
  views.set(signature, view);
  while (views.size > VIEWS_KEPT) views.delete(views.keys().next().value!);
  return view;
}

/** Each account's index, with its images resolved to the view's rows. An account scanned before indexes were kept gets one made now, once. */
function partsOf(repo: Repo, view: View): Part[] {
  if (view.parts) return view.parts;
  const byAccount = new Map<string, ImageRow[]>();
  for (const i of view.images) if (i.summary) byAccount.set(i.accountId, [...(byAccount.get(i.accountId) ?? []), i]);
  const parts: Part[] = [];
  for (const [accountId, rows] of byAccount) {
    const byKey = new Map(rows.map((r) => [r.key, r]));
    let index = repo.cache.get<ImageIndex>(accountId, INDEX_KEY);
    if (index?.format !== INDEX_FORMAT || !rows.some((r) => index!.keys.includes(r.key))) {
      const builder = new IndexBuilder();
      for (const r of rows) {
        const scan = upgradeScan(repo.cache.get<ImageScan>(accountId, r.key));
        if (scan) builder.add(r.key, scan);
      }
      index = builder.done();
      repo.cache.put(accountId, INDEX_KEY, index);
    }
    parts.push({ accountId, index, rows: index.keys.map((k) => byKey.get(k) ?? null) });
  }
  view.parts = parts;
  return parts;
}

/**
 * A filtered list, computed once per filter and kept while its view is. The one used longest ago goes first: a search
 * is narrowed from the list without it, which every search uses and so stays.
 */
function kept<T>(view: View, key: string, make: () => T[]): T[] {
  return had<T>(view, key) ?? keep(view, key, make());
}

function had<T>(view: View, key: string): T[] | null {
  const hit = view.results.get(key);
  if (!hit) return null;
  view.results.delete(key);
  view.results.set(key, hit);
  return hit as T[];
}

function keep<T>(view: View, key: string, rows: T[]): T[] {
  view.results.set(key, rows);
  while (view.results.size > RESULTS_KEPT) view.results.delete(view.results.keys().next().value!);
  return rows;
}

/**
 * The same for a list that takes long enough to be made in slices. With `shared`, requests that arrive while it is
 * being made wait for that one piece of work instead of each starting their own.
 */
async function keptLater<T>(view: View, key: string, make: () => Promise<T[]>, shared = false): Promise<T[]> {
  const hit = had<T>(view, key);
  if (hit) return hit;
  if (!shared) return keep(view, key, await make());
  let work = view.pending.get(key) as Promise<T[]> | undefined;
  if (!work) {
    work = make()
      .then((rows) => keep(view, key, rows))
      .finally(() => view.pending.delete(key));
    view.pending.set(key, work);
  }
  return work;
}

/** Thrown when whoever asked stopped waiting: the browser drops a search as soon as the next one starts. */
export class Abandoned extends Error {}

/** How long a list is worked on before other requests get their turn. */
export const SLICE_MS = 10;

/**
 * For work that goes through every vulnerability of every image: returns a function to call now and then, which
 * steps aside for other requests every few milliseconds and stops the work once nobody waits for its answer. Without
 * it the server answered nothing else for up to a second, and worked through searches the browser had already dropped.
 */
export function inSlices(signal?: AbortSignal): () => Promise<void> | undefined {
  let until = performance.now() + SLICE_MS;
  return () => {
    if (performance.now() < until) return;
    return new Promise<void>((resolve, reject) =>
      setImmediate(() => {
        until = performance.now() + SLICE_MS;
        if (signal?.aborted) reject(new Abandoned());
        else resolve();
      }),
    );
  };
}

const brief = (row: ImageRow): ImageBrief => ({ id: row.id, name: imageName(row), tag: row.tags[0] ?? null, use: row.use });
const mostExposed = (rows: Iterable<ImageRow>): ImageBrief[] => [...rows].sort((a, b) => usageRank(b.use) - usageRank(a.use)).map(brief);
const page = <T>(rows: T[], offset: number, limit: number): ImageList<T> => ({ rows: rows.slice(offset, offset + limit), total: rows.length });
const newer = (a: string | null, b: string | null) => (!a ? b : !b ? a : a.localeCompare(b, undefined, { numeric: true }) >= 0 ? a : b);
const older = (a: string | null, b: string | null) => (!a ? b : !b ? a : a.localeCompare(b, undefined, { numeric: true }) <= 0 ? a : b);
const endOfLife = (i: ImageRow) => !!i.summary && (i.summary.eol || !!i.summary.runtimes?.some((r) => r.eol));

export interface ImageFilters {
  q?: string;
  /** At least this much in use ("stored": stored only). */
  use?: ImageUse;
  /** Images: what was found in them. Workloads: what they run. */
  has?: string;
  registry?: string;
  builder?: "known" | "unknown";
  reach?: "internet" | "private" | "unknown";
  severity?: string;
  status?: ImageVulnStatus;
  layer?: "os" | "app";
  /** From the base image, or added by the image's own build. */
  from?: "base" | "added";
  kind?: ComponentKind;
  type?: string;
  vulnerable?: boolean;
  eol?: boolean;
  /** One image, by its row's id. */
  image?: string;
  /** Only these rows, by their keys: a selection. */
  keys?: string[];
}

const usedEnough = (row: ImageRow, use: ImageUse | undefined) => !use || (use === "stored" ? row.use === "stored" : usageRank(row.use) >= usageRank(use));

function imageMatches(i: ImageRow, f: ImageFilters, open: (i: ImageRow) => boolean): boolean {
  const s = i.summary;
  if (f.q) {
    const text = `${imageName(i)} ${i.tags.join(" ")} ${i.account} ${i.builtBy.map((b) => b.repo).join(" ")} ${s?.os ?? ""} ${(s?.runtimes ?? []).map((r) => `${r.name} ${r.version}`).join(" ")} ${s?.baseName ?? ""}`;
    if (!text.toLowerCase().includes(f.q.toLowerCase())) return false;
  }
  if (!usedEnough(i, f.use) || (f.registry && i.kind !== f.registry)) return false;
  if (f.builder && (f.builder === "known") !== i.builtBy.length > 0) return false;
  switch (f.has) {
    case "exploited":
      return !!s?.exploited.length;
    case "fixable":
      return !!s && s.fixable.critical + s.fixable.high > 0;
    case "eol":
      return endOfLife(i);
    case "secrets":
      return !!s && s.secrets > 0;
    case "findings":
      return open(i);
    case "unscanned":
      return !s;
    default:
      return true;
  }
}

/** The images that match, a page of them, each with its findings as they are triaged now. */
export function imagePage(repo: Repo, view: View, f: ImageFilters, offset: number, limit: number, full = false): ImageList<ImageRow> {
  const refsOf = (i: ImageRow) => view.findings.get(`${i.accountId}|${imageName(i)}`) ?? [];
  let settled: Set<string> | null = null;
  const open = (i: ImageRow) => refsOf(i).some((r) => !(settled ??= repo.findings.settled()).has(r.fingerprint));
  const keys = f.keys?.length ? new Set(f.keys) : null;
  // Open findings change with triage, so that filter isn't kept; the others are.
  const { keys: _k, ...shape } = f;
  const all =
    f.has === "findings"
      ? view.images.filter((i) => imageMatches(i, f, open))
      : kept(view, `images|${JSON.stringify(shape)}`, () => view.images.filter((i) => imageMatches(i, f, open)));
  const rows = keys ? all.filter((i) => keys.has(i.id)) : all;
  const out = page(rows, offset, limit);
  return { total: out.total, rows: out.rows.map((i) => served(repo, view, i, full)) };
}

/** An image as a list sends it: its findings as they are triaged now, and every workload or the first few. */
function served(repo: Repo, view: View, i: ImageRow, full: boolean): ImageRow {
  return {
    ...i,
    workloads: full ? i.workloads : i.workloads.slice(0, SHOWN),
    findings: (view.findings.get(`${i.accountId}|${imageName(i)}`) ?? []).map((r) => ({
      ...r,
      status: repo.findings.triageOf(r.fingerprint)?.status ?? "open",
    })),
  };
}

/**
 * The images one vulnerability or one component is in, in full and most exposed first: what a row's "and 43 more"
 * opens. Under the list's own filters, so it is the same images the row counted.
 */
export async function imagesWithin(
  repo: Repo,
  view: View,
  list: "vulnerabilities" | "components",
  f: ImageFilters,
  key: string,
  offset: number,
  limit: number,
  signal?: AbortSignal,
): Promise<ImageList<ImageRow> | null> {
  const row =
    list === "vulnerabilities" ? (await vulnRows(repo, view, f, signal)).find((v) => v.id === key) : componentRows(repo, view, f).find((c) => c.key === key);
  if (!row) return null;
  const out = page(
    [...row.rows].sort((a, b) => usageRank(b.use) - usageRank(a.use) || imageName(a).localeCompare(imageName(b))),
    offset,
    limit,
  );
  return { total: out.total, rows: out.rows.map((i) => served(repo, view, i, true)) };
}

const workloadKey = (w: WorkloadRow) => `${w.accountId}|${w.region}|${w.kind}|${w.group ?? ""}|${w.name}`;

export function workloadPage(view: View, f: ImageFilters, offset: number, limit: number): ImageList<WorkloadRow & { key: string }> {
  const q = f.q?.toLowerCase();
  const keys = f.keys?.length ? new Set(f.keys) : null;
  const rows = view.workloads
    .filter(
      (w) =>
        (!q ||
          `${w.kind} ${w.name} ${w.group ?? ""} ${w.account} ${w.hosts.join(" ")} ${w.containers.map((c) => c.image).join(" ")}`.toLowerCase().includes(q)) &&
        (!f.reach || (f.reach === "internet" ? w.internet === true : f.reach === "private" ? w.internet === false : w.internet == null)) &&
        (f.has !== "exploited" || w.containers.some((c) => c.exploited > 0)) &&
        (f.has !== "unscanned" || w.containers.some((c) => !c.imageId)) &&
        (!keys || keys.has(workloadKey(w))),
    )
    .map((w) => ({ ...w, key: workloadKey(w) }));
  return page(rows, offset, limit);
}

/** A vulnerability with every package and image it is in, before a row is cut down to what a list shows. */
interface VulnAll extends Omit<ImageVulnRow, "packages" | "images"> {
  packages: Map<string, ImageVulnRow["packages"][number]>;
  rows: Set<ImageRow>;
  /** What a search reads of the vulnerability itself, in lowercase. */
  text: string;
}

const byUrgency = (a: VulnAll, b: VulnAll) =>
  Number(b.kev) - Number(a.kev) ||
  usageRank(b.use) - usageRank(a.use) ||
  RANK[b.severity] - RANK[a.severity] ||
  b.rows.size - a.rows.size ||
  a.id.localeCompare(b.id);

/** How many index entries are read between looks at the clock (a multiple of an entry's five numbers). */
const CHECK_EVERY = 5 * 4096;

/** Two sorted lists as one, without sorting again. */
function merged<T>(a: T[], b: T[], order: (x: T, y: T) => number): T[] {
  if (!a.length || !b.length) return a.length ? a : b;
  const out: T[] = [];
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) out.push(order(a[i], b[j]) <= 0 ? a[i++] : b[j++]);
  while (i < a.length) out.push(a[i++]);
  while (j < b.length) out.push(b[j++]);
  return out;
}

/**
 * The vulnerabilities the filters leave, each with the packages and images it is in. `only` narrows them further, by
 * vulnerability and package as an index numbers them.
 */
async function gatherVulns(
  repo: Repo,
  view: View,
  f: ImageFilters,
  only?: (part: Part) => ((vuln: number, pkg: number) => boolean) | null,
  signal?: AbortSignal,
): Promise<VulnAll[]> {
  const out = new Map<string, VulnAll>();
  const pause = inSlices(signal);
  const min = f.severity ? (RANK[f.severity as VulnSeverity] ?? 0) : 0;
  for (const part of partsOf(repo, view)) {
    const { index, rows } = part;
    const wanted = only?.(part);
    if (wanted === null) continue;
    // What the severity says about each vulnerability, and each package's key, worked out once for the index.
    const vulnOk = index.vulns.map((v) => RANK[v.severity] >= min && (f.status !== "exploited" || v.kev));
    const pkgKeys = (part.pkgKeys ??= index.packages.map((p) => `${p.type}|${p.name}|${p.version}`));
    const slot: (VulnAll | undefined)[] = new Array(index.vulns.length);
    const h = index.hits;
    for (let n = 0; n < h.length; n += 5) {
      if (n % CHECK_EVERY === 0) await pause();
      const vi = h[n + 2];
      const pi = h[n + 1];
      if (!vulnOk[vi] || (wanted && !wanted(vi, pi))) continue;
      const row = rows[h[n]];
      if (!row || !usedEnough(row, f.use) || (f.image && row.id !== f.image)) continue;
      const pkg = index.packages[pi];
      const fix = h[n + 3];
      const base = h[n + 4] === 1;
      if ((f.layer && pkg.layer !== f.layer) || (f.from && (f.from === "base") !== base)) continue;
      if (f.status === "fixable" ? !fix : f.status === "nofix" ? !!fix : false) continue;
      const v = index.vulns[vi];
      let r = slot[vi];
      if (!r) {
        r = out.get(v.id);
        if (!r)
          out.set(
            v.id,
            (r = {
              ...v,
              packages: new Map(),
              packageCount: 0,
              rows: new Set(),
              imageCount: 0,
              base: true,
              use: "stored",
              text: `${v.id} ${v.title}`.toLowerCase(),
            }),
          );
        slot[vi] = r;
      }
      if (RANK[v.severity] > RANK[r.severity]) r.severity = v.severity;
      r.cvss = Math.max(r.cvss ?? 0, v.cvss ?? 0) || null;
      r.kev ||= v.kev;
      r.base &&= base;
      const fixedIn = index.fixes[fix] || null;
      const p = r.packages.get(pkgKeys[pi]);
      if (p) p.fixedIn = older(p.fixedIn, fixedIn);
      else r.packages.set(pkgKeys[pi], { name: pkg.name, version: pkg.version, type: pkg.type, layer: pkg.layer, fixedIn });
      r.rows.add(row);
      r.use = moreInUse(r.use, row.use);
    }
  }
  return [...out.values()].sort(byUrgency);
}

/**
 * The vulnerabilities that match, most urgent first. A search doesn't go through every image again: a vulnerability
 * whose own ID or title matches is taken as the list without the search has it, and only the others are looked up
 * again, in the packages whose name matches. On a real registry that took a search from a second to a few milliseconds.
 */
async function vulnRows(repo: Repo, view: View, f: ImageFilters, signal?: AbortSignal): Promise<VulnAll[]> {
  const { keys: _k, q, ...shape } = f;
  // The list without the search is what every search starts from, so it is made once whoever asks, and never dropped
  // half made: a search typed while it is made waits for the same work.
  const all = await keptLater(view, `vulns|${JSON.stringify(shape)}`, () => gatherVulns(repo, view, shape), true);
  if (signal?.aborted) throw new Abandoned();
  const needle = q?.toLowerCase();
  if (!needle) return all;
  return keptLater(view, `vulns|${JSON.stringify(shape)}|${needle}`, async () => {
    const named = all.filter((r) => r.text.includes(needle));
    const ids = new Set(named.map((r) => r.id));
    const inPackages = await gatherVulns(
      repo,
      view,
      shape,
      (part) => {
        const names = (part.names ??= part.index.packages.map((p) => p.name.toLowerCase()));
        const hit = names.map((name) => name.includes(needle));
        if (!hit.includes(true)) return null;
        const taken = part.index.vulns.map((v) => ids.has(v.id));
        return (vuln, pkg) => hit[pkg] && !taken[vuln];
      },
      signal,
    );
    return merged(named, inPackages, byUrgency);
  });
}

export async function vulnPage(
  repo: Repo,
  view: View,
  f: ImageFilters,
  offset: number,
  limit: number,
  full = false,
  signal?: AbortSignal,
): Promise<ImageList<ImageVulnRow>> {
  const keys = f.keys?.length ? new Set(f.keys) : null;
  const all = await vulnRows(repo, view, f, signal);
  const out = page(keys ? all.filter((r) => keys.has(r.id)) : all, offset, limit);
  return {
    total: out.total,
    rows: out.rows.map(({ rows, packages, text: _text, ...r }) => {
      const images = mostExposed(rows);
      return {
        ...r,
        packages: full ? [...packages.values()] : [...packages.values()].slice(0, SHOWN),
        packageCount: packages.size,
        images: full ? images : images.slice(0, SHOWN),
        imageCount: images.length,
      };
    }),
  };
}

interface ComponentAll extends Omit<ComponentRow, "images" | "imageCount"> {
  rows: Set<ImageRow>;
  /** What a search reads of the component, in lowercase. */
  text: string;
}

/**
 * Every component in view at every version: packages from the indexes, operating systems and runtimes from each
 * image's summary. A search only picks rows from the list without it, which is made once: whether a component matches
 * depends on the component alone, not on the images it is in.
 */
function componentRows(repo: Repo, view: View, f: ImageFilters): ComponentAll[] {
  const { keys: _k, q, ...shape } = f;
  const all = componentsFor(repo, view, shape);
  const needle = q?.toLowerCase();
  return needle ? kept(view, `components|${JSON.stringify(shape)}|${needle}`, () => all.filter((c) => c.text.includes(needle))) : all;
}

function componentsFor(repo: Repo, view: View, f: ImageFilters): ComponentAll[] {
  return kept(view, `components|${JSON.stringify(f)}`, () => {
    const out = new Map<string, ComponentAll>();
    const wants = (kind: ComponentKind) => !f.kind || f.kind === kind;
    const inScope = (row: ImageRow) => usedEnough(row, f.use) && (!f.image || row.id === f.image);
    const add = (key: string, row: ImageRow, base: boolean, make: () => Omit<ComponentAll, "rows" | "use" | "base">) => {
      let c = out.get(key);
      if (!c) out.set(key, (c = { ...make(), rows: new Set(), use: "stored", base: true }));
      c.rows.add(row);
      c.base &&= base;
      c.use = moreInUse(c.use, row.use);
      return c;
    };
    for (const part of partsOf(repo, view)) {
      const { index, rows } = part;
      // Each package's vulnerabilities: the same wherever that version is found.
      if (!part.vulnsOf) {
        part.vulnsOf = new Map();
        const h = index.hits;
        for (let n = 0; n < h.length; n += 5) {
          const e = part.vulnsOf.get(h[n + 1]) ?? { ids: new Set<number>(), fixedIn: null };
          e.ids.add(h[n + 2]);
          e.fixedIn = newer(e.fixedIn, index.fixes[h[n + 3]] || null);
          part.vulnsOf.set(h[n + 1], e);
        }
      }
      const vulnsOf = part.vulnsOf;
      const hit = index.packages.map((p) => {
        const kind: ComponentKind = p.layer === "os" ? "os-package" : "app-package";
        return wants(kind) && (!f.type || p.type === f.type);
      });
      const has = index.has;
      for (let n = 0; n < has.length; n += 3) {
        const row = rows[has[n]];
        const pi = has[n + 1];
        if (!row || !hit[pi] || !inScope(row)) continue;
        const p = index.packages[pi];
        add(`${p.type}|${p.name}|${p.version}`, row, has[n + 2] === 1, () => {
          const mine = [...(vulnsOf.get(pi)?.ids ?? [])].map((i) => index.vulns[i]);
          return {
            key: `${p.type}|${p.name}|${p.version}`,
            kind: p.layer === "os" ? "os-package" : "app-package",
            name: p.name,
            version: p.version,
            type: p.type,
            licenses: p.licenses,
            vulns: countVulns(mine),
            worst: mine.reduce<VulnSeverity | null>((w, v) => (!w || RANK[v.severity] > RANK[w] ? v.severity : w), null),
            kev: mine.some((v) => v.kev),
            fixedIn: vulnsOf.get(pi)?.fixedIn ?? null,
            eol: null,
            text: `${p.name} ${p.type}`.toLowerCase(),
          };
        });
      }
    }
    // The operating system an image is built on and the runtime it is built around are components too, though no package list names them.
    const plain = { licenses: [], vulns: { ...NO_VULNS }, worst: null, kev: false };
    for (const row of view.images) {
      const s = row.summary;
      if (!s || !inScope(row)) continue;
      const [family, ...release] = (s.os ?? "").split(" ");
      if (family && wants("os") && (!f.type || f.type === family))
        add(`os|${s.os}`, row, true, () => ({
          ...plain,
          key: `os|${s.os}`,
          kind: "os",
          name: family,
          version: release.join(" "),
          type: family,
          fixedIn: null,
          eol: s.eol,
          text: s.os!.toLowerCase(),
        }));
      if (wants("runtime") && (!f.type || f.type === "runtime"))
        for (const r of s.runtimes ?? [])
          add(`runtime|${r.name}|${r.version}`, row, true, () => ({
            ...plain,
            key: `runtime|${r.name}|${r.version}`,
            kind: "runtime",
            name: r.name,
            version: r.version,
            type: "runtime",
            fixedIn: r.latest,
            eol: r.eol,
            text: `${r.name} ${r.version}`.toLowerCase(),
          }));
    }
    const risk = (c: ComponentAll) => (c.kev ? 100 : 0) + (c.eol ? 10 : 0) + (c.worst ? RANK[c.worst] : -1);
    return [...out.values()]
      .filter((c) => (!f.vulnerable || !!c.worst) && (!f.eol || c.eol === true))
      .sort(
        (a, b) =>
          risk(b) - risk(a) || b.rows.size - a.rows.size || a.name.localeCompare(b.name) || a.version.localeCompare(b.version, undefined, { numeric: true }),
      );
  });
}

export function componentPage(repo: Repo, view: View, f: ImageFilters, offset: number, limit: number, full = false): ImageList<ComponentRow> {
  const keys = f.keys?.length ? new Set(f.keys) : null;
  const all = componentRows(repo, view, f);
  const out = page(keys ? all.filter((r) => keys.has(r.key)) : all, offset, limit);
  return {
    total: out.total,
    rows: out.rows.map(({ rows, text: _text, ...c }) => {
      const images = mostExposed(rows);
      return { ...c, images: full ? images : images.slice(0, SHOWN), imageCount: images.length };
    }),
  };
}

/** The package types among the components in view, for the filter. */
export function componentTypes(repo: Repo, view: View): string[] {
  return kept(view, "types", () => [...new Set(partsOf(repo, view).flatMap((p) => p.index.packages.map((x) => x.type)))].sort());
}

export function imagesSummary(repo: Repo, view: View): ImagesSummary | null {
  const { images, workloads, snapshots } = view;
  if (!snapshots.length && !workloads.length) return null;
  const scanned = images.filter((i) => i.summary);
  const uses: Record<ImageUse, number> = { internet: 0, running: 0, pulled: 0, stored: 0 };
  for (const i of images) uses[i.use]++;
  const exploited = scanned.filter((i) => i.summary!.exploited.length);
  const components = componentRows(repo, view, {});
  return {
    images: images.length,
    scanned: scanned.length,
    repositories: snapshots.reduce((n, s) => n + s.repositories, 0),
    waiting: snapshots.reduce((n, s) => n + s.waiting, 0),
    uses,
    fixable: scanned.filter((i) => i.summary!.fixable.critical + i.summary!.fixable.high > 0).length,
    exploited: exploited.length,
    exploitedInternet: exploited.filter((i) => i.use === "internet").length,
    secrets: scanned.filter((i) => i.summary!.secrets > 0).length,
    eol: scanned.filter(endOfLife).length,
    components: components.length,
    componentsAtRisk: components.filter((c) => c.worst || c.eol).length,
    workloads: workloads.length,
    workloadsInternet: workloads.filter((w) => w.internet === true).length,
    workloadsUnscanned: workloads.filter((w) => w.containers.some((c) => !c.imageId)).length,
    pulled: snapshots.some((s) => s.pulled != null) ? snapshots.reduce((n, s) => n + (s.pulled ?? 0), 0) : null,
    checked: snapshots.some((s) => s.checked != null) ? snapshots.reduce((n, s) => n + (s.checked ?? 0), 0) : null,
    trivy: snapshots.map((s) => s.trivy).find(Boolean) ?? null,
    dbUpdated: snapshots.map((s) => s.dbUpdated).find(Boolean) ?? null,
  };
}

export const registriesIn = (view: View): RegistryKind[] => [...new Set(view.images.map((i) => i.kind))];

/** One line per vulnerability, package and image, for a spreadsheet. */
export function vulnCsv(repo: Repo, view: View, f: ImageFilters): unknown[][] {
  const out: unknown[][] = [
    [
      "vulnerability",
      "severity",
      "cvss",
      "known exploited",
      "package",
      "version",
      "fixed in",
      "from",
      "came with",
      "image",
      "tag",
      "in use",
      "runs in",
      "built by",
      "link",
    ],
  ];
  const q = f.q?.toLowerCase();
  const min = f.severity ? (RANK[f.severity as VulnSeverity] ?? 0) : 0;
  for (const { index, rows } of partsOf(repo, view)) {
    const h = index.hits;
    for (let n = 0; n < h.length; n += 5) {
      const row = rows[h[n]];
      const v = index.vulns[h[n + 2]];
      const p = index.packages[h[n + 1]];
      const fixedIn = index.fixes[h[n + 3]];
      const base = h[n + 4] === 1;
      if (!row || RANK[v.severity] < min || !usedEnough(row, f.use) || (f.image && row.id !== f.image)) continue;
      if ((f.layer && p.layer !== f.layer) || (f.from && (f.from === "base") !== base)) continue;
      if (f.status === "exploited" ? !v.kev : f.status === "fixable" ? !fixedIn : f.status === "nofix" ? !!fixedIn : false) continue;
      if (q && !`${v.id} ${p.name} ${v.title}`.toLowerCase().includes(q)) continue;
      out.push([
        v.id,
        v.severity,
        v.cvss ?? "",
        v.kev ? "yes" : "",
        p.name,
        p.version,
        fixedIn,
        p.layer === "os" ? "operating system" : "application",
        base ? "the base image" : "the image's own build",
        imageName(row),
        row.tags[0] ?? "",
        row.use,
        [...new Set(row.workloads.map((w) => `${w.kind} ${w.name}`))].join("; "),
        row.builtBy.map((b) => b.repo).join("; "),
        v.url ?? "",
      ]);
    }
  }
  return out;
}

/** The inventory: one line per component at each version, with how many images hold it. */
export function componentCsv(repo: Repo, view: View, f: ImageFilters): unknown[][] {
  return [
    [
      "component",
      "version",
      "kind",
      "type",
      "images",
      "most exposed",
      "critical",
      "high",
      "medium",
      "low",
      "known exploited",
      "past end of life",
      "upgrade to",
      "came with the base image",
      "licenses",
    ],
    ...componentRows(repo, view, f).map((c) => [
      c.name,
      c.version,
      c.kind,
      c.type,
      c.rows.size,
      c.use,
      c.vulns.critical,
      c.vulns.high,
      c.vulns.medium,
      c.vulns.low,
      c.kev ? "yes" : "",
      c.eol == null ? "" : c.eol ? "yes" : "no",
      c.fixedIn ?? "",
      c.base ? "yes" : "",
      c.licenses.join(" "),
    ]),
  ];
}

/** Trivy's package types by the ecosystem Keelson's dependency view names. */
const ECOSYSTEM: Record<string, string> = {
  npm: "npm",
  "node-pkg": "npm",
  yarn: "npm",
  pnpm: "npm",
  bun: "npm",
  pip: "PyPI",
  pipenv: "PyPI",
  poetry: "PyPI",
  uv: "PyPI",
  "python-pkg": "PyPI",
  gomod: "Go",
  gobinary: "Go",
  jar: "Maven",
  pom: "Maven",
  gradle: "Maven",
  sbt: "Maven",
  bundler: "RubyGems",
  gemspec: "RubyGems",
  cargo: "crates.io",
  rustbinary: "crates.io",
  composer: "Packagist",
  "composer-vendor": "Packagist",
  nuget: "NuGet",
  "dotnet-core": "NuGet",
  "packages-props": "NuGet",
  hex: "Hex",
  pub: "pub",
  swift: "Swift",
  cocoapods: "CocoaPods",
  conan: "Conan",
};

/** Go versions carry a "v" in lock files and not always in images; Python names differ in case and separators. */
const sameName = (a: string, b: string) => a.toLowerCase().replace(/[._]/g, "-") === b.toLowerCase().replace(/[._]/g, "-");
const bare = (v: string) => v.replace(/^v/i, "");

/**
 * Where each vulnerability of an image is fixed. A package in a layer the base image brought is the base image's: a
 * newer base fixes it. One the image's own build added is looked up in the dependencies of the repository that builds
 * the image: still vulnerable there means the code needs the upgrade, already fixed there means the image is behind
 * its code, and absent there (an operating system package the Dockerfile installs, a tool it downloads) means the build
 * step that adds it. `baseKnown` says the build history showed where the base image ends; when it didn't, an operating
 * system package is taken to be the base image's.
 */
export function fixPlaces(vulns: ImageVuln[], deps: RepoDependencies[], baseKnown = false): ImageVulnDetail[] {
  const packages = deps.flatMap((d) => d.packages ?? []);
  const read = deps.some((d) => d.packages);
  return vulns.map((v): ImageVulnDetail => {
    if (v.base || (v.layer === "os" && !baseKnown)) return { ...v, where: "base", inCode: null };
    if (v.layer === "os") return { ...v, where: "build", inCode: null };
    if (!read) return { ...v, where: "app", inCode: null };
    const eco = ECOSYSTEM[v.type];
    const mine = packages.filter((p) => sameName(p.name, v.pkg) && (!eco || (p.ecosystem || ecosystemOfType(p.type)) === eco));
    if (!mine.length) return { ...v, where: "build", inCode: null };
    const affected = mine.find((p) => bare(p.version) === bare(v.version) || p.vulns.some((x) => x.id === v.id || x.aliases.includes(v.id)));
    return affected ? { ...v, where: "code", inCode: affected.version } : { ...v, where: "rebuild", inCode: mine[0].version };
  });
}

/** An image's full result, as its account's cache holds it; null when it wasn't scanned or the result is gone. */
export function scanOf(repo: Repo, image: ImageRow): ImageScan | null {
  return image.summary ? upgradeScan(repo.cache.get<ImageScan>(image.accountId, image.key)) : null;
}

/** The dependencies of the repositories that build an image, from their GitHub account's latest scan, in the image's own entity. */
function builderDependencies(repo: Repo, image: ImageRow): RepoDependencies[] {
  const entity = repo.accounts.get(image.accountId)?.entityId;
  return image.builtBy.flatMap((b) => {
    const account = b.accountId ? repo.accounts.get(b.accountId) : null;
    if (!account || account.entityId !== entity) return [];
    // The cache names a repository as GitHub spells it; the link is lowercase.
    const stored = repo.cache.get<{ dependencies: RepoDependencies }>(account.id, `deps:${b.name ?? b.repo.split("/")[1]}`);
    return stored?.dependencies ? [stored.dependencies] : [];
  });
}

/** What an image is built on: what it says itself, what the Dockerfiles of its repository say, and another scanned image its layers start with. */
function baseOf(repo: Repo, view: View, image: ImageRow, scan: ImageScan, deps: RepoDependencies[]): ImageBase {
  const dockerfile = [...new Set(deps.flatMap((d) => d.parts.flatMap((p) => p.images ?? [])))];
  // An image built on another starts with every one of that image's layers, in order.
  let on: ImageRow | null = null;
  let depth = 0;
  if (scan.layers.length > 1)
    for (const { accountId, index, rows } of partsOf(repo, view)) {
      void accountId;
      for (let n = 0; n < index.keys.length; n++) {
        const other = rows[n];
        const layers = index.layers?.[n];
        if (!other || !layers?.length || other.id === image.id || imageName(other) === imageName(image)) continue;
        if (layers.length > depth && layers.length < scan.layers.length && layers.every((l, i) => l === scan.layers[i])) {
          on = other;
          depth = layers.length;
        }
      }
    }
  const fromBase = scan.vulns.filter((v) => v.base);
  return {
    names: scan.baseName ? [scan.baseName] : dockerfile,
    from: scan.baseName ? "label" : dockerfile.length ? "dockerfile" : null,
    image: on ? brief(on) : null,
    layers: scan.layers.length,
    baseLayers: scan.baseLayers ?? (depth || null),
    packages: scan.packages.filter((p) => p.base).length,
    vulns: countVulns(fromBase),
  };
}

/** One image with everything about it; null when no image in view has this id. */
export function imageDetail(repo: Repo, view: View, id: string): ImageDetailResponse | null {
  const row = view.byId.get(id);
  if (!row) return null;
  const image = imagePage(repo, view, { keys: [id] }, 0, 1, true).rows[0] ?? row;
  const scan = scanOf(repo, image);
  const deps = builderDependencies(repo, image);
  const vulns = scan ? fixPlaces(scan.vulns, deps, scan.baseLayers != null) : [];
  const places: Record<FixPlace, number> = { base: 0, code: 0, rebuild: 0, build: 0, app: 0 };
  for (const v of vulns) places[v.where]++;
  const { vulns: _v, format: _f, layers: _l, ...rest } = scan ?? ({} as ImageScan);
  return {
    image,
    scan: scan ? { ...rest, vulns } : null,
    places,
    base: scan ? baseOf(repo, view, image, scan, deps) : null,
    siblings: view.images
      .filter((i) => i.id !== id && i.accountId === image.accountId && imageName(i) === imageName(image))
      .sort((a, b) => (b.pushedAt ?? "").localeCompare(a.pushedAt ?? ""))
      .slice(0, 20)
      .map((i) => ({ id: i.id, tags: i.tags, digest: i.digest, pushedAt: i.pushedAt, vulns: i.summary?.vulns ?? null, use: i.use })),
  };
}

/** The images a repository builds, for its page: each with what was found in it and where it runs. */
export function imagesBuiltBy(view: View, repoFullName: string): ImageRow[] {
  const name = repoFullName.toLowerCase();
  return view.images.filter((i) => i.builtBy.some((b) => b.repo === name)).map((i) => ({ ...i, workloads: i.workloads.slice(0, SHOWN) }));
}

export type { VulnCounts };
export { SEVERITIES };
