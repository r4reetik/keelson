// Each repository's dependencies, from its manifest and lock files: a software
// bill of materials made by Anchore's Syft, the packages' known vulnerabilities
// matched by Grype, and their licenses sorted by Grant.
//
// Shared by every platform that hosts code (GitHub, Gitea): each gives a
// CodeHost, and writes no reading, matching or caching of its own.
//
// Keelson fetches only those files (manifests, lock files, Actions workflows
// and Dockerfiles, found in the default branch's file list), never the
// code. They are written to a temporary folder for Syft and deleted as soon as it
// has read them; only the SBOM is kept. An SBOM is made again only when one of
// those files changes, so most scans fetch nothing but each repository's file
// list. Grype runs on every scan, once over the unique packages of every
// repository, so a vulnerability published today is found in code that didn't
// change.

import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, posix } from "node:path";
import { AnchoreError, anchore } from "../anchore.ts";
import type { AccountCache } from "../../store/repo.ts";
import type { ProgressEvent } from "../types.ts";
import type { ActionUse, DepPackage, DepUsage, DepVuln, RepoDependencies } from "../../shared/dependencies.ts";
import { imageBuilds, type BuildRef } from "./builds.ts";
import { CI_FILE, ecosystemOfType, findParts, isWorkflowDir, MAX_FILE_BYTES, MAX_FILES, wanted, WORKFLOW_FILE, type Part } from "./manifests.ts";

/** A raw API or tool payload, read field by field. */
export type Json = any;

/**
 * What reading dependencies needs of a platform that hosts code. GitHub and Gitea name the three reads alike
 * (/repos/<org>/<repo>/git/trees/<branch>?recursive=1, …/git/blobs/<sha>, …/languages) and answer in the same
 * shapes, so each platform's client is one of these; a platform that differs wraps its client to answer this way.
 */
export interface CodeHost {
  /** The organization's name in addresses. */
  org: string;
  /** One GET under the platform's API. Rejects with an error that has a `status`. */
  raw(path: string): Promise<Json>;
  /** Records whether a source was readable, as the platform's client does for its own sources. */
  note(source: "manifests" | "syft" | "grype" | "grant", ok: boolean, err?: unknown): void;
  coverage: { get(key: "repos"): { ok: boolean } | undefined };
}

/** A repository whose dependencies are read. */
export interface CodeRepo {
  name: string;
  archived: boolean;
  empty: boolean;
  defaultBranch: string;
}

export interface DependencyInventory {
  repos: RepoDependencies[];
  /** Versions of the tools that ran; null for one that isn't installed. */
  tools: { syft: string | null; grype: string | null; grant: string | null };
  /** When Grype's vulnerability database was built. */
  dbBuilt: string | null;
}

type HostError = { status?: number };

/** Bump when what's cached per repository changes shape, so every SBOM is made again. */
const FORMAT = 2;
const REPO_CONCURRENCY = 6;
const BLOB_CONCURRENCY = 6;
const SYFT_CONCURRENCY = 3;
/** Packages per Grype run; more are split into several runs. */
const GRYPE_BATCH = 20_000;
/** A tree walked folder by folder (when GitHub cuts the full list short) stops after this many requests. */
const MAX_TREE_CALLS = 300;
/** Vulnerabilities kept per package in the view; the rest are counted. */
export const MAX_VULNS = 40;

/** What's cached per repository between scans: the SBOM and what Keelson read from the files, never the files. */
interface Cached {
  format: number;
  /** Hash of every fetched file's path and blob SHA, and the Syft version. */
  key: string;
  generatedAt: number;
  syft: string | null;
  /** Syft's document, trimmed to its packages and their relationships. */
  sbom: Json | null;
  parts: Part[];
  actions: ActionUse[];
  /** Container images the workflows build and push. Absent on entries cached before Keelson read them. */
  builds?: BuildRef[];
  /** npm packages the lock file marks as development only ("name@version"). */
  devPackages: string[];
  languages: Record<string, number> | null;
  partial: boolean;
  /** Why Syft failed on this repository, when it did. */
  error?: string;
}

interface TreeFile {
  path: string;
  sha: string;
  size: number;
}

/**
 * Reads, builds and matches every active repository's dependencies. Returns null when the App can't read
 * repository contents (the coverage entry says so) or there is nothing to read.
 */
export async function collectDependencies(
  client: CodeHost,
  repos: CodeRepo[],
  cache: AccountCache,
  toolDir: string | null,
  onProgress: (p: ProgressEvent) => void,
  /** Why the platform's credential can't read files at all (a permission nobody granted); null when it can. */
  refused: Error | null = null,
): Promise<DependencyInventory | null> {
  const targets = repos.filter((r) => !r.archived && !r.empty);
  if (refused) {
    // Public repositories would still answer, but a partial inventory would pass checks on what wasn't read.
    client.note("manifests", false, refused);
    return null;
  }

  const syftBin = anchore.path("syft");
  const grypeBin = anchore.path("grype");
  const grantBin = anchore.path("grant");
  const [syft, grype, grant] = await Promise.all([
    syftBin ? anchore.version("syft", syftBin) : null,
    grypeBin ? anchore.version("grype", grypeBin) : null,
    grantBin ? anchore.version("grant", grantBin) : null,
  ]);
  if (!syftBin) client.note("syft", false, new AnchoreError("Syft isn't installed where Keelson runs."));
  // Cached SBOMs count as read; a repository Syft fails on now marks it unreadable.
  else client.note("syft", true);
  if (!grypeBin) client.note("grype", false, new AnchoreError("Grype isn't installed where Keelson runs."));
  if (!grantBin) client.note("grant", false, new AnchoreError("Grant isn't installed where Keelson runs."));

  // 1. Each repository's file list, and its SBOM: the cached one when no manifest or lock file changed.
  const cached = new Map<string, Cached>();
  let done = 0;
  const syftQueue = new Limit(SYFT_CONCURRENCY);
  await pool(targets, REPO_CONCURRENCY, async (r) => {
    const c = await readRepo(client, r, cache, syftBin, syft, syftQueue);
    if (c) cached.set(r.name, c);
    onProgress({ phase: "Reading dependency manifests", done: ++done, total: targets.length });
  });
  // Repositories that are gone, archived or emptied take their SBOM with them, once the list is known to be complete.
  if (!client.coverage.get("repos") || client.coverage.get("repos")?.ok)
    for (const key of cache.keys("sbom:")) if (!cached.has(key.slice(5))) cache.delete(key);

  // 2. Every unique package, matched once.
  const unique = new Map<string, Json>();
  // A copy that states its license is kept over one that doesn't, so Grant sees every license.
  for (const c of cached.values())
    for (const a of artifactsOf(c)) {
      const prev = unique.get(identity(a));
      if (!prev || (!prev.licenses?.length && a.licenses?.length)) unique.set(identity(a), a);
    }
  let vulns = new Map<string, DepVuln[]>();
  let licenses = new Map<string, LicenseClass>();
  let dbBuilt: string | null = null;
  if (grypeBin && unique.size) {
    onProgress({ phase: "Matching vulnerabilities with Grype" });
    try {
      ({ vulns, dbBuilt } = await matchVulnerabilities(grypeBin, [...unique.values()], toolDir, sampleSchema(cached)));
      client.note("grype", true);
    } catch (e) {
      client.note("grype", false, e);
    }
  } else if (grypeBin) client.note("grype", true);
  if (grantBin && unique.size) {
    onProgress({ phase: "Checking licenses with Grant" });
    try {
      licenses = await licenseRisks(grantBin, [...unique.values()], sampleSchema(cached));
      client.note("grant", true);
    } catch (e) {
      client.note("grant", false, e);
    }
  } else if (grantBin) client.note("grant", true);

  // 3. Each repository's packages, with where they're used, their vulnerabilities and their licenses.
  const out: RepoDependencies[] = [];
  for (const r of targets) {
    const c = cached.get(r.name);
    if (!c) continue;
    out.push(dependenciesOf(r.name, c, vulns, licenses));
  }
  out.sort((a, b) => a.repo.localeCompare(b.repo));
  return { repos: out, tools: { syft, grype, grant }, dbBuilt };
}

/** One repository's file list, and its SBOM: cached, or made now. Null when its files couldn't be listed. */
async function readRepo(
  client: CodeHost,
  r: CodeRepo,
  cache: AccountCache,
  syftBin: string | null,
  syft: string | null,
  syftQueue: Limit,
): Promise<Cached | null> {
  const base = `/repos/${client.org}/${encodeURIComponent(r.name)}`;
  const listed = await listFiles(client, base, r.defaultBranch);
  if (!listed) return null;
  const { files, partial } = pick(listed.files);
  const key = createHash("sha256")
    .update(`${FORMAT}|${syft ?? "no-syft"}|${files.map((f) => `${f.path}:${f.sha}`).join("\n")}`)
    .digest("hex")
    .slice(0, 32);
  const prev = cache.get<Cached>(`sbom:${r.name}`);
  if (prev?.format === FORMAT && prev.key === key) {
    if (prev.builds) return prev;
    // Cached before Keelson read which images workflows push: only the workflows are fetched again, not the SBOM remade.
    const workflows = new Map<string, string>();
    let unread = false;
    await pool(
      files.filter((f) => WORKFLOW_FILE.test(f.path)),
      BLOB_CONCURRENCY,
      async (f) => {
        try {
          workflows.set(f.path, Buffer.from(String((await client.raw(`${base}/git/blobs/${f.sha}`))?.content ?? ""), "base64").toString("utf8"));
        } catch {
          unread = true;
        }
      },
    );
    if (unread) return prev;
    const filled = { ...prev, builds: imageBuilds(workflows, `${client.org}/${r.name}`) };
    cache.put(`sbom:${r.name}`, filled);
    return filled;
  }

  // Something changed: fetch the files, read them, and let Syft read them from a folder that's deleted right after.
  const contents = new Map<string, string>();
  let missed = false;
  await pool(files, BLOB_CONCURRENCY, async (f) => {
    try {
      const blob = await client.raw(`${base}/git/blobs/${f.sha}`);
      contents.set(f.path, Buffer.from(String(blob?.content ?? ""), "base64").toString("utf8"));
    } catch (e) {
      // A file the App isn't allowed to read means the permission is missing; any other failure is retried next scan.
      if ([401, 403].includes((e as HostError).status ?? 0)) client.note("manifests", false, e);
      missed = true;
    }
  });
  const parts = findParts(contents);
  const actions = actionUses(contents);
  const builds = imageBuilds(contents, `${client.org}/${r.name}`);
  const devPackages = npmDevPackages(contents);
  const languages = await client.raw(`${base}/languages`).catch(() => null);
  let sbom: Json | null = null;
  let error: string | undefined;
  // Nothing to read is an empty SBOM, not a missing one.
  if (syftBin && !contents.size && !missed)
    sbom = { artifacts: [], artifactRelationships: [], schema: null, descriptor: { name: "syft", version: syft ?? "" } };
  if (syftBin && contents.size) {
    const dir = await mkdtemp(join(tmpdir(), "keelson-sbom-"));
    try {
      for (const [path, text] of contents) {
        const file = join(dir, ...path.split("/"));
        // GitHub's paths never climb out, but a folder written from someone else's data is checked anyway.
        if (!file.startsWith(dir + "/")) continue;
        await mkdir(dirname(file), { recursive: true });
        await writeFile(file, text);
      }
      sbom = trim(report(await syftQueue.run(() => anchore.syft(syftBin, dir)), "Syft", "artifacts"));
      client.note("syft", true);
    } catch (e) {
      error = (e as Error).message;
      client.note("syft", false, e);
    } finally {
      await rm(dir, { recursive: true, force: true }).catch(() => {});
    }
  }
  const out: Cached = {
    format: FORMAT,
    key,
    generatedAt: Date.now(),
    syft,
    sbom,
    parts,
    actions,
    builds,
    devPackages,
    languages: languages && typeof languages === "object" ? languages : null,
    partial: partial || listed.partial || missed,
    ...(error ? { error } : {}),
  };
  // A failed read is tried again next scan rather than cached.
  if (!missed && !error) cache.put(`sbom:${r.name}`, out);
  return out;
}

/** The default branch's files, from GitHub's tree: in one request, or folder by folder when GitHub cuts the list short. */
async function listFiles(client: CodeHost, base: string, branch: string): Promise<{ files: TreeFile[]; partial: boolean } | null> {
  const toFiles = (tree: Json[], prefix = "") =>
    tree.filter((e) => e?.type === "blob").map((e) => ({ path: prefix + String(e.path), sha: String(e.sha), size: Number(e.size ?? 0) }));
  let body: Json;
  try {
    body = await client.raw(`${base}/git/trees/${encodeURIComponent(branch)}?recursive=1`);
    client.note("manifests", true);
  } catch (e) {
    // An empty repository has no tree (409); a branch that's gone, none either.
    if ([404, 409].includes((e as HostError).status ?? 0)) return null;
    client.note("manifests", false, e);
    return null;
  }
  if (!body?.truncated) return { files: toFiles(body?.tree ?? []), partial: false };

  // Too many files for one answer: walk the folders that can hold manifests, skipping installed packages and build output.
  const files: TreeFile[] = [];
  const queue: { sha: string; prefix: string }[] = [{ sha: String(body.sha), prefix: "" }];
  let calls = 0;
  while (queue.length && calls < MAX_TREE_CALLS) {
    const { sha, prefix } = queue.shift()!;
    calls++;
    const t = await client.raw(`${base}/git/trees/${sha}`).catch(() => null);
    for (const e of t?.tree ?? []) {
      const path = prefix + String(e.path);
      if (e.type === "blob") files.push({ path, sha: String(e.sha), size: Number(e.size ?? 0) });
      else if (e.type === "tree" && (wanted(`${path}/package.json`) || path === ".github" || path === ".gitea" || isWorkflowDir(path)))
        queue.push({ sha: String(e.sha), prefix: `${path}/` });
    }
  }
  return { files, partial: queue.length > 0 };
}

/** The files Keelson fetches: manifests and lock files within the size limit, lock files first when there are too many. */
function pick(all: TreeFile[]): { files: TreeFile[]; partial: boolean } {
  const want = all.filter((f) => wanted(f.path));
  const fits = want.filter((f) => f.size <= MAX_FILE_BYTES);
  const ranked = fits.sort((a, b) => depth(a.path) - depth(b.path) || a.path.localeCompare(b.path));
  return { files: ranked.slice(0, MAX_FILES).sort((a, b) => a.path.localeCompare(b.path)), partial: fits.length < want.length || ranked.length > MAX_FILES };
}
const depth = (path: string) => path.split("/").length;

/** Syft's document without what Keelson doesn't need: file listings, and the tool's own configuration. */
function trim(doc: Json): Json {
  return {
    artifacts: (doc?.artifacts ?? []).map((a: Json) => ({
      ...a,
      locations: (a.locations ?? []).map((l: Json) => ({ path: l.path, annotations: l.annotations })),
    })),
    artifactRelationships: (doc?.artifactRelationships ?? []).filter((r: Json) => r.type === "dependency-of"),
    schema: doc?.schema ?? null,
    descriptor: { name: "syft", version: doc?.descriptor?.version ?? "" },
  };
}

/** Packages of a repository's SBOM that are dependencies: not the repository's own projects (workspace entries). */
function artifactsOf(c: Cached): Json[] {
  const own = new Set(c.parts.map((p) => p.name).filter(Boolean));
  return (c.sbom?.artifacts ?? []).filter((a: Json) => !isOwn(a, own));
}
const isOwn = (a: Json, own: Set<string | null>) =>
  own.has(a.name) ||
  a.version === "UNKNOWN" ||
  (a.type === "npm" && typeof a.metadata?.resolved === "string" && /^(?!https?:)[^:]*\//.test(a.metadata.resolved) && !a.metadata.integrity);

/**
 * A tool's JSON document, checked for the list Keelson reads from it (a dotted path). Anything else (a count, a version line, an
 * error printed to standard output) is the tool's failure, a coverage gap, never an empty result.
 */
export function report(text: string, tool: string, list: string): Json {
  let doc: Json;
  try {
    doc = JSON.parse(text);
  } catch {
    doc = null;
  }
  const at = list.split(".").reduce((o: Json, k) => o?.[k], doc);
  if (!doc || typeof doc !== "object" || !Array.isArray(at))
    throw new AnchoreError(`${tool}'s output wasn't the report Keelson reads (no "${list}"). Check that ${tool} runs where Keelson runs.`);
  return doc;
}

/** One identity per package across repositories, so each is matched once. */
const identity = (a: Json) => `${a.type}|${a.purl || `${a.name}@${a.version}`}`;

const sampleSchema = (cached: Map<string, Cached>) => [...cached.values()].find((c) => c.sbom?.schema)?.sbom.schema ?? null;

/** A Syft document of packages only, for Grype or Grant. Each package's ID is its identity's hash. */
function combined(artifacts: Json[], schema: Json): Json {
  return {
    artifacts: artifacts.map((a) => ({ ...a, id: idOf(a) })),
    artifactRelationships: [],
    source: { id: "keelson", name: "keelson", version: "", type: "directory", metadata: { path: "/" } },
    distro: {},
    descriptor: { name: "syft", version: "" },
    schema: schema ?? { version: "16.0.0", url: "" },
  };
}
const idOf = (a: Json) => createHash("sha256").update(identity(a)).digest("hex").slice(0, 16);

async function withFile<T>(doc: Json, fn: (file: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), "keelson-sbom-"));
  try {
    const file = join(dir, "sbom.json");
    await writeFile(file, JSON.stringify(doc));
    return await fn(file);
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

const SEVERITIES = ["critical", "high", "medium", "low"] as const;
const severityOf = (s: unknown): DepVuln["severity"] => {
  const v = String(s ?? "").toLowerCase();
  return (SEVERITIES as readonly string[]).includes(v) ? (v as DepVuln["severity"]) : "unknown";
};
const RANK: Record<DepVuln["severity"], number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };

/** Grype's matches for every package, by identity: one entry per vulnerability, its aliases merged. */
async function matchVulnerabilities(
  bin: string,
  artifacts: Json[],
  toolDir: string | null,
  schema: Json,
): Promise<{ vulns: Map<string, DepVuln[]>; dbBuilt: string | null }> {
  const byId = new Map(artifacts.map((a) => [idOf(a), identity(a)]));
  const raw = new Map<string, DepVuln[]>();
  let dbBuilt: string | null = null;
  for (let i = 0; i < artifacts.length; i += GRYPE_BATCH) {
    const out = report(await withFile(combined(artifacts.slice(i, i + GRYPE_BATCH), schema), (f) => anchore.grype(bin, f, toolDir)), "Grype", "matches");
    dbBuilt ??= out.descriptor?.db?.status?.built ?? null;
    for (const m of out.matches) {
      const key = byId.get(String(m.artifact?.id));
      if (!key) continue;
      raw.set(key, [...(raw.get(key) ?? []), toVuln(m)]);
    }
  }
  const vulns = new Map<string, DepVuln[]>();
  for (const [key, list] of raw) vulns.set(key, mergeAliases(list));
  return { vulns, dbBuilt };
}

function toVuln(m: Json): DepVuln {
  const v = m.vulnerability ?? {};
  const related: Json[] = m.relatedVulnerabilities ?? [];
  const kev: Json[] = [...(v.knownExploited ?? []), ...related.flatMap((r) => r.knownExploited ?? [])];
  const epss: Json[] = [...(v.epss ?? []), ...related.flatMap((r) => r.epss ?? [])];
  const cvss = [...(v.cvss ?? []), ...related.flatMap((r) => r.cvss ?? [])].map((c: Json) => Number(c?.metrics?.baseScore)).filter((n) => Number.isFinite(n));
  const details: Json[] = m.matchDetails ?? [];
  const suggested = details.map((d) => d?.fix?.suggestedVersion).find((s) => typeof s === "string" && s) ?? null;
  const description = String(v.description || related.find((r) => r.description)?.description || "");
  return {
    id: String(v.id ?? ""),
    aliases: [...new Set(related.map((r) => String(r.id ?? "")).filter((id) => id && id !== v.id))],
    severity: severityOf(v.severity),
    cvss: cvss.length ? Math.max(...cvss) : null,
    epss: epss.length ? Math.max(...epss.map((e) => Number(e.epss) || 0)) : null,
    percentile: epss.length ? Math.max(...epss.map((e) => Number(e.percentile) || 0)) : null,
    kev: kev.length > 0,
    ransomware: kev.some((k) => String(k.knownRansomwareCampaignUse ?? "").toLowerCase() === "known"),
    fixedIn: suggested ?? (Array.isArray(v.fix?.versions) && v.fix.versions.length ? String(v.fix.versions[0]) : null),
    state: String(v.fix?.state ?? "unknown"),
    summary: description.replace(/\s+/g, " ").trim().slice(0, 400),
    url: typeof v.dataSource === "string" && /^https:\/\//.test(v.dataSource) ? v.dataSource : null,
    risk: Number(v.risk) || 0,
    cpeOnly: details.length > 0 && details.every((d) => String(d?.type ?? "").startsWith("cpe")),
  };
}

/** One entry per vulnerability: Grype can report the same one under its GitHub advisory and its CVE. */
export function mergeAliases(list: DepVuln[]): DepVuln[] {
  const groups: DepVuln[][] = [];
  const groupOf = new Map<string, DepVuln[]>();
  for (const v of list) {
    const ids = [v.id, ...v.aliases];
    let g = ids.map((id) => groupOf.get(id)).find(Boolean);
    if (!g) groups.push((g = []));
    g.push(v);
    for (const id of ids) groupOf.set(id, g);
  }
  const preferred = (id: string) =>
    id.startsWith("GHSA-") ? 0 : id.startsWith("GO-") || id.startsWith("PYSEC-") || id.startsWith("RUSTSEC-") ? 1 : id.startsWith("CVE-") ? 2 : 3;
  return groups
    .map((g) => {
      const ids = [...new Set(g.flatMap((v) => [v.id, ...v.aliases]))].sort((a, b) => preferred(a) - preferred(b) || a.localeCompare(b));
      const best = [...g].sort((a, b) => RANK[b.severity] - RANK[a.severity] || b.risk - a.risk)[0];
      const fixes = g.map((v) => v.fixedIn).filter((f): f is string => !!f);
      return {
        ...best,
        id: ids[0],
        aliases: ids.slice(1),
        cvss: maxOf(g.map((v) => v.cvss)),
        epss: maxOf(g.map((v) => v.epss)),
        percentile: maxOf(g.map((v) => v.percentile)),
        kev: g.some((v) => v.kev),
        ransomware: g.some((v) => v.ransomware),
        // The lowest version that fixes it: the smallest upgrade.
        fixedIn: fixes.sort(compareVersions)[0] ?? null,
        state: g.some((v) => v.state === "fixed") ? "fixed" : best.state,
        risk: Math.max(...g.map((v) => v.risk)),
        cpeOnly: g.every((v) => v.cpeOnly),
        summary: g.map((v) => v.summary).find(Boolean) ?? "",
        url: g.map((v) => v.url).find((u) => u?.includes("github.com/advisories")) ?? best.url,
      };
    })
    .sort((a, b) => Number(b.kev) - Number(a.kev) || b.risk - a.risk || RANK[b.severity] - RANK[a.severity] || a.id.localeCompare(b.id));
}

const maxOf = (ns: (number | null)[]) => {
  const xs = ns.filter((n): n is number => n != null);
  return xs.length ? Math.max(...xs) : null;
};

/** Orders versions like "1.10.0" after "1.9.2"; a leading "v" and pre-release words are tolerated. */
export function compareVersions(a: string, b: string): number {
  const parts = (v: string) => v.replace(/^v/i, "").split(/[.+-]/);
  const pa = parts(a);
  const pb = parts(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? "0";
    const y = pb[i] ?? "0";
    const nx = /^\d+$/.test(x) ? Number(x) : Number.NaN;
    const ny = /^\d+$/.test(y) ? Number(y) : Number.NaN;
    if (!Number.isNaN(nx) && !Number.isNaN(ny)) {
      if (nx !== ny) return nx - ny;
    } else if (x !== y) return x.localeCompare(y);
  }
  return 0;
}

/**
 * Grant's risk class for every license it saw, by its ID (lowercase). Each package is then judged by its own
 * license expression (`licenseRiskOf`): the same package version can state a license in one repository's lock file
 * and none in another's, and only one copy of it is given to Grant.
 */
async function licenseRisks(bin: string, artifacts: Json[], schema: Json): Promise<Map<string, LicenseClass>> {
  const doc = report(await withFile(combined(artifacts, schema), (f) => anchore.grant(bin, f)), "Grant", "run.targets");
  const out = new Map<string, LicenseClass>();
  // Grant 0.7 puts its report under run.targets.
  for (const t of doc.run.targets)
    for (const p of t?.evaluation?.findings?.packages ?? [])
      for (const l of p.licenses ?? []) for (const id of [l.id, l.name]) if (typeof id === "string" && id) out.set(id.toLowerCase(), riskOf(l.riskCategory));
  return out;
}

type LicenseClass = "permissive" | "weak" | "strong" | "other";
const ORDER: LicenseClass[] = ["permissive", "weak", "other", "strong"];

/**
 * A package's license risk from its expressions and Grant's classes: "MIT OR GPL-3.0" can be used under MIT, so a
 * choice takes its least restrictive license and anything else its most restrictive. A license Grant didn't classify
 * is "other"; no stated license is null.
 */
export function licenseRiskOf(expressions: string[], classes: Map<string, LicenseClass>): DepPackage["licenseRisk"] {
  if (!expressions.length || !classes.size) return null;
  const one = (expr: string): LicenseClass => {
    const whole = classes.get(
      expr
        .trim()
        .toLowerCase()
        .replace(/^\((.*)\)$/, "$1"),
    );
    if (whole) return whole;
    const ids = expr
      .replace(/[()]/g, " ")
      .split(/\s+(?:OR|AND|WITH)\s+/i)
      .map((x) => x.trim().toLowerCase())
      .filter(Boolean);
    const risks = ids.map((id) => classes.get(id) ?? "other").sort((x, y) => ORDER.indexOf(x) - ORDER.indexOf(y));
    const choice = / OR /i.test(expr) && !/ AND /i.test(expr);
    return (choice ? risks[0] : risks.at(-1)) ?? "other";
  };
  return expressions
    .map(one)
    .sort((x, y) => ORDER.indexOf(x) - ORDER.indexOf(y))
    .at(-1)!;
}

const riskOf = (category: unknown): "permissive" | "weak" | "strong" | "other" => {
  const c = String(category ?? "").toLowerCase();
  if (c.includes("strong")) return "strong";
  if (c.includes("weak")) return "weak";
  if (c.includes("permissive")) return "permissive";
  return "other";
};

/** A repository's packages, each with where it's used, its vulnerabilities and its license's risk. */
function dependenciesOf(repo: string, c: Cached, vulns: Map<string, DepVuln[]>, licenses: Map<string, LicenseClass>): RepoDependencies {
  const base = { repo, generatedAt: c.generatedAt, languages: c.languages, parts: c.parts, actions: c.actions, builds: c.builds ?? [], partial: c.partial };
  if (!c.sbom) return { ...base, packages: null };
  const artifacts: Json[] = c.sbom.artifacts ?? [];
  const byArtifact = new Map<string, Json>(artifacts.map((a) => [String(a.id), a]));
  // "A dependency-of B": A is one of B's dependencies.
  const depsOf = new Map<string, string[]>();
  for (const r of c.sbom.artifactRelationships ?? []) depsOf.set(String(r.child), [...(depsOf.get(String(r.child)) ?? []), String(r.parent)]);
  const own = new Set(c.parts.map((p) => p.name).filter(Boolean));
  const dev = new Set(c.devPackages);
  const usage = new Map<string, Map<string, DepUsage>>();
  const use = (id: string, part: string, direct: boolean, devUse: boolean) => {
    const m = usage.get(id) ?? new Map<string, DepUsage>();
    const prev = m.get(part);
    m.set(part, { part, direct: direct || !!prev?.direct, dev: prev ? prev.dev && devUse : devUse });
    usage.set(id, m);
  };
  const walk = (from: string[], part: string, devUse: boolean) => {
    const seen = new Set<string>();
    const queue = [...from];
    while (queue.length) {
      const id = queue.shift()!;
      for (const d of depsOf.get(id) ?? [])
        if (!seen.has(d)) {
          seen.add(d);
          use(d, part, false, devUse);
          queue.push(d);
        }
    }
  };
  const ecosystemMatches = (a: Json, eco: string) => ecosystemOfType(String(a.type)) === eco;
  for (const p of c.parts) {
    // The part's own entry in the lock file (a workspace) lists its direct dependencies too.
    const self = artifacts.filter((a) => p.name && a.name === p.name).map((a) => String(a.id));
    for (const id of self) for (const d of depsOf.get(id) ?? []) use(d, p.path, true, p.devOnly || !!p.direct[String(byArtifact.get(d)?.name ?? "")]?.dev);
    for (const a of artifacts) {
      const d = p.direct[a.name];
      if (!d || !ecosystemMatches(a, d.ecosystem)) continue;
      use(String(a.id), p.path, true, d.dev || p.devOnly);
      walk([String(a.id)], p.path, d.dev || p.devOnly);
    }
    walk(self, p.path, p.devOnly);
  }
  const parts = [...c.parts].sort((a, b) => b.path.length - a.path.length);
  const partAt = (location: string) => {
    const dir = posix.dirname(location.replace(/^\//, ""));
    const d = dir === "." ? "" : dir;
    if (isWorkflowDir(d)) return d;
    return parts.find((p) => !p.workflows && (p.path === "" || d === p.path || d.startsWith(`${p.path}/`)))?.path ?? "";
  };

  const packages: DepPackage[] = [];
  for (const a of artifacts) {
    if (isOwn(a, own)) continue;
    const id = String(a.id);
    const locations: string[] = [...new Set<string>((a.locations ?? []).map((l: Json) => String(l.path).replace(/^\//, "")))];
    // Packages nothing names (a lock file Keelson couldn't relate to a manifest) belong to the part holding their lock file.
    // A workflow names its actions itself.
    if (!usage.get(id)?.size)
      for (const l of locations) {
        const at = partAt(l);
        use(id, at, isWorkflowDir(at), c.parts.find((p) => p.path === at)?.devOnly ?? false);
      }
    const usedBy = [...(usage.get(id)?.values() ?? [])].sort((x, y) => Number(y.direct) - Number(x.direct) || x.part.localeCompare(y.part));
    const devOnly = dev.has(`${a.name}@${a.version}`) || (usedBy.length > 0 && usedBy.every((u) => u.dev));
    const key = identity(a);
    packages.push({
      name: String(a.name),
      version: String(a.version),
      type: String(a.type),
      ecosystem: ecosystemOfType(String(a.type)),
      purl: a.purl ? String(a.purl) : null,
      locations,
      licenses: (a.licenses ?? []).map((l: Json) => String(l.spdxExpression || l.value || "")).filter(Boolean),
      licenseRisk: licenseRiskOf((a.licenses ?? []).map((l: Json) => String(l.spdxExpression || l.value || "")).filter(Boolean), licenses),
      usedBy,
      devOnly,
      vulns: vulns.get(key) ?? [],
    });
  }
  // The same package from two lock files of one part is one package.
  const merged = new Map<string, DepPackage>();
  for (const p of packages) {
    const k = `${p.type}|${p.name}|${p.version}`;
    const prev = merged.get(k);
    if (!prev) merged.set(k, p);
    else {
      prev.locations = [...new Set([...prev.locations, ...p.locations])];
      for (const u of p.usedBy) if (!prev.usedBy.some((x) => x.part === u.part)) prev.usedBy.push(u);
      prev.devOnly &&= p.devOnly;
    }
  }
  return { ...base, packages: [...merged.values()].sort((a, b) => a.name.localeCompare(b.name) || compareVersions(a.version, b.version)) };
}

/** Steps that run another repository's action, from the workflows and composite actions. */
export function actionUses(files: Map<string, string>): ActionUse[] {
  const out: ActionUse[] = ciIncludes(files);
  for (const [path, text] of files) {
    if (!WORKFLOW_FILE.test(path) && !/(^|\/)action\.ya?ml$/.test(path)) continue;
    for (const m of text.matchAll(/^\s*(?:-\s*)?uses:\s*["']?([^\s"'#]+)["']?/gm)) {
      const uses = m[1];
      // Local actions (./…) and container images (docker://…) aren't another repository's action.
      if (uses.startsWith("./") || uses.startsWith("docker://")) continue;
      const at = uses.lastIndexOf("@");
      if (at < 1) continue;
      out.push({ action: uses.slice(0, at), ref: uses.slice(at + 1), workflow: path });
    }
  }
  return out;
}

/**
 * What a GitLab CI configuration includes from outside its own project: another project's files (`project:` with a
 * `ref:`), a CI/CD component (`component: host/group/name@version`) and a file at an address (`remote:`). Each is
 * code the pipeline runs with the project's CI variables, as an action is in a workflow, so they are kept in the same
 * shape: what is included, the ref it is included at, and the file that includes it. GitLab's own templates
 * (`template:`) and the project's own files (`local:`) aren't someone else's code. A reading of text, like the rest.
 */
export function ciIncludes(files: Map<string, string>): ActionUse[] {
  const out: ActionUse[] = [];
  const value = (v: string) => v.trim().replace(/^["']|["']$/g, "");
  for (const [path, text] of files) {
    if (!CI_FILE.test(path)) continue;
    const lines = text.split("\n").map((l) => l.replace(/\s+#.*$/, ""));
    for (let i = 0; i < lines.length; i++) {
      const m = /^(\s*)(?:-\s*)?(project|component|remote):\s*(\S.*)$/.exec(lines[i]);
      if (!m) continue;
      const what = value(m[3]);
      if (m[2] === "component") {
        // "$CI_SERVER_FQDN/group/name@1.2" or "gitlab.com/group/name@~latest": the host isn't part of whose it is.
        const at = what.lastIndexOf("@");
        const name = (at > 0 ? what.slice(0, at) : what).replace(/^[^/]+\//, "");
        out.push({ action: name, ref: at > 0 ? what.slice(at + 1) : "~latest", workflow: path });
      } else if (m[2] === "remote") {
        try {
          const u = new URL(what);
          // An address is pinned only when a commit is part of it.
          out.push({ action: `${u.host}${u.pathname}`, ref: /\b[0-9a-f]{40}\b/.exec(u.pathname)?.[0] ?? "an address that can change", workflow: path });
        } catch {
          /* a variable where the address goes: nothing to say about it */
        }
      } else {
        // The ref is a sibling key of `project:`, on one of the next lines of the same list item.
        let ref = "the default branch";
        for (let j = i + 1; j < Math.min(i + 6, lines.length); j++) {
          if (/^\s*-\s/.test(lines[j]) || /^\S/.test(lines[j])) break;
          const r = /^\s*ref:\s*(\S.*)$/.exec(lines[j]);
          if (r) ref = value(r[1]);
        }
        out.push({ action: what.replace(/^\//, ""), ref, workflow: path });
      }
    }
  }
  return out;
}

/** npm packages a package-lock.json marks as development only. */
function npmDevPackages(files: Map<string, string>): string[] {
  const out = new Set<string>();
  for (const [path, text] of files) {
    if (!/(^|\/)(package-lock|npm-shrinkwrap)\.json$/.test(path)) continue;
    let lock: Json;
    try {
      lock = JSON.parse(text);
    } catch {
      continue;
    }
    for (const [key, entry] of Object.entries<Json>(lock?.packages ?? {})) {
      if (!key || !entry?.dev || !entry.version) continue;
      const name = entry.name ?? key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length);
      out.add(`${name}@${entry.version}`);
    }
  }
  return [...out];
}

/** Runs at most `n` jobs at once. */
class Limit {
  readonly n: number;
  #active = 0;
  #queue: (() => void)[] = [];
  constructor(n: number) {
    this.n = n;
  }
  async run<T>(fn: () => Promise<T>): Promise<T> {
    while (this.#active >= this.n) await new Promise<void>((r) => this.#queue.push(r));
    this.#active++;
    try {
      return await fn();
    } finally {
      this.#active--;
      this.#queue.shift()?.();
    }
  }
}

async function pool<T>(items: T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (next < items.length) await fn(items[next++]);
    }),
  );
}

/**
 * Keeps each repository's dependencies as the Repositories and Dependencies pages read them (`deps:<repo>` in the
 * account's cache), replaced on every scan; a repository whose dependencies weren't read this time keeps its last
 * view only while its SBOM is cached.
 */
export function saveDependencyViews(deps: DependencyInventory | null, unreadable: string[], cache: AccountCache): void {
  if (!deps) return;
  const seen = new Set<string>();
  for (const d of deps.repos) {
    seen.add(d.repo);
    cache.put(`deps:${d.repo}`, { dependencies: d, tools: deps.tools, dbBuilt: deps.dbBuilt, unreadable });
  }
  const kept = new Set(cache.keys("sbom:").map((k) => k.slice(5)));
  for (const key of cache.keys("deps:")) if (!seen.has(key.slice(5)) && !kept.has(key.slice(5))) cache.delete(key);
}
