// Every repository's dependencies in one place, for the Dependencies page: each
// package at each version across the repositories in view, each vulnerability
// across the packages it affects, and each license as Grant classifies it (the
// Grant report). Built from the per-repository views a GitHub scan caches
// (`deps:<repo>`, src/providers/github/index.ts), once per account and scan, and
// filtered per request. Triage is joined on every request, so a finding triaged a
// moment ago shows its new status.

import type { Repo } from "../store/repo.ts";
import { displayName } from "../store/repo.ts";
import type { AccountScan } from "./scope.ts";
import type {
  DepPackage,
  DepVuln,
  LicenseRiskFilter,
  LicenseRow,
  PackageFinding,
  PackageRow,
  PackageStatus,
  RepoDependencies,
  SbomPage,
  SbomResponse,
  VulnRow,
} from "../shared/dependencies.ts";

interface StoredView {
  dependencies: RepoDependencies;
  tools: NonNullable<SbomResponse["summary"]>["tools"];
  dbBuilt: string | null;
}

/** One package in one repository. */
interface Use {
  accountId: string;
  account: string;
  repo: string;
  pkg: DepPackage;
  labels: Map<string, string>;
}

interface AccountIndex {
  uses: Use[];
  repos: string[];
  tools: StoredView["tools"];
  dbBuilt: string | null;
}

/** Indexes by account and scan: a new scan replaces its account's entry. */
const indexes = new Map<string, { scanId: number; index: AccountIndex }>();

function accountIndex(repo: Repo, { account, scan }: AccountScan): AccountIndex | null {
  const hit = indexes.get(account.id);
  if (hit?.scanId === scan.id) return hit.index;
  const keys = repo.cache.keys(account.id, "deps:");
  if (!keys.length) return null;
  const uses: Use[] = [];
  const repos: string[] = [];
  let tools: StoredView["tools"] = null;
  let dbBuilt: string | null = null;
  for (const key of keys) {
    const view = repo.cache.get<StoredView>(account.id, key);
    if (!view?.dependencies) continue;
    const d = view.dependencies;
    tools ??= view.tools;
    dbBuilt ??= view.dbBuilt;
    if (!d.packages) continue;
    repos.push(d.repo);
    const labels = new Map(d.parts.map((p) => [p.path, p.workflows ? "workflows" : p.path || "root"]));
    for (const pkg of d.packages) uses.push({ accountId: account.id, account: displayName(account), repo: d.repo, pkg, labels });
  }
  const index = { uses, repos: repos.sort(), tools, dbBuilt };
  indexes.set(account.id, { scanId: scan.id, index });
  return index;
}

/** The dependency findings of each package in each repository, with their triage now. */
function findingsOf(repo: Repo, scans: AccountScan[]): Map<string, PackageFinding> {
  const out = new Map<string, PackageFinding>();
  const sla = repo.settings.get().slaDays;
  for (const { account, scan } of scans)
    for (const f of repo.findings.forScan(scan.id, sla))
      if (f.checkId.startsWith("GDP-") && f.zone)
        out.set(`${account.id}|${f.zone}|${f.resource}`, { fingerprint: f.fingerprint, checkId: f.checkId, severity: f.severity, status: f.status });
  return out;
}

const RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
const isMalicious = (v: DepVuln) => [v.id, ...v.aliases].some((id) => id.startsWith("MAL-"));
const keyOf = (p: DepPackage) => `${p.ecosystem}|${p.name}|${p.version}`;

/** Orders versions numerically where they are numbers ("1.10" after "1.9"). */
function compareVersions(a: string, b: string): number {
  const parts = (v: string) => v.replace(/^v/i, "").split(/[.+-]/);
  const pa = parts(a);
  const pb = parts(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? "0";
    const y = pb[i] ?? "0";
    if (/^\d+$/.test(x) && /^\d+$/.test(y)) {
      if (Number(x) !== Number(y)) return Number(x) - Number(y);
    } else if (x !== y) return x.localeCompare(y);
  }
  return 0;
}

export interface SbomFilters {
  q?: string;
  ecosystem?: string;
  status?: PackageStatus;
  severity?: string;
  risk?: LicenseRiskFilter;
  license?: string;
  usage?: "direct" | "transitive";
  env?: "runtime" | "dev";
  repo?: string;
  triage?: string;
  vuln?: string;
}

/** Every use in view, each package's rows built from them, and the repositories with an SBOM. */
function gather(repo: Repo, scans: AccountScan[]) {
  const indexes = scans.map((s) => accountIndex(repo, s)).filter((i): i is AccountIndex => !!i);
  return {
    uses: indexes.flatMap((i) => i.uses),
    repoList: indexes.flatMap((i, n) => i.repos.map((r) => ({ accountId: scans[n].account.id, account: displayName(scans[n].account), repo: r }))),
    tools: indexes.find((i) => i.tools)?.tools ?? null,
    dbBuilt: indexes.map((i) => i.dbBuilt).find(Boolean) ?? null,
  };
}

/** Packages at each version, from their uses: one row per package, its repositories under it. */
function rowsOf(uses: Use[], findings: Map<string, PackageFinding>): PackageRow[] {
  const rows = new Map<string, PackageRow>();
  for (const u of uses) {
    const p = u.pkg;
    let row = rows.get(keyOf(p));
    if (!row) {
      const fixes = p.vulns.map((v) => v.fixedIn).filter((f): f is string => !!f);
      row = {
        name: p.name,
        version: p.version,
        ecosystem: p.ecosystem,
        type: p.type,
        purl: p.purl,
        licenses: p.licenses,
        licenseRisk: p.licenseRisk,
        direct: false,
        devOnly: true,
        worst: p.vulns.length ? p.vulns.reduce((w, v) => (RANK[v.severity] > RANK[w] ? v.severity : w), "unknown" as DepVuln["severity"]) : null,
        kev: p.vulns.some((v) => v.kev),
        malicious: p.vulns.some(isMalicious),
        epss: p.vulns.length ? Math.max(...p.vulns.map((v) => v.epss ?? 0)) : null,
        upgrade: fixes.sort(compareVersions).at(-1) ?? null,
        vulns: p.vulns,
        uses: [],
      };
      rows.set(keyOf(p), row);
    }
    const direct = p.usedBy.some((x) => x.direct);
    row.direct ||= direct;
    row.devOnly &&= p.devOnly;
    row.uses.push({
      accountId: u.accountId,
      account: u.account,
      repo: u.repo,
      parts: p.usedBy.map((x) => ({ label: u.labels.get(x.part) ?? (x.part || "root"), direct: x.direct, dev: x.dev })),
      direct,
      devOnly: p.devOnly,
      locations: p.locations,
      finding: findings.get(`${u.accountId}|${u.repo}|${p.name} (${p.ecosystem})`) ?? null,
    });
  }
  return [...rows.values()];
}

const riskOf = (r: PackageRow | DepPackage): LicenseRiskFilter => r.licenseRisk ?? (r.licenses.length ? "other" : "none");
const licenseOf = (r: { licenses: string[] }) => r.licenses.join(" AND ");

function statusMatches(r: PackageRow, s: PackageStatus): boolean {
  switch (s) {
    case "vulnerable":
      return r.vulns.length > 0;
    case "exploited":
      return r.kev;
    case "malicious":
      return r.malicious;
    case "fixable":
      return r.vulns.some((v) => v.fixedIn);
    case "nofix":
      return r.vulns.length > 0 && r.vulns.every((v) => !v.fixedIn);
    case "clean":
      return r.vulns.length === 0;
  }
}

/** The rows that match, each keeping only the repositories the repository and triage filters allow. */
function filterRows(rows: PackageRow[], f: SbomFilters): PackageRow[] {
  const q = f.q?.trim().toLowerCase();
  const min = f.severity ? (RANK[f.severity] ?? 0) : 0;
  const out: PackageRow[] = [];
  for (const r of rows) {
    if (q && !`${r.name} ${r.version} ${r.purl ?? ""}`.toLowerCase().includes(q)) continue;
    if (f.ecosystem && r.ecosystem !== f.ecosystem) continue;
    if (f.status && !statusMatches(r, f.status)) continue;
    if (min && (!r.worst || RANK[r.worst] < min)) continue;
    if (f.risk && riskOf(r) !== f.risk) continue;
    if (f.license != null && licenseOf(r) !== f.license) continue;
    if (f.vuln && !r.vulns.some((v) => v.id === f.vuln || v.aliases.includes(f.vuln!))) continue;
    let uses = r.uses;
    if (f.repo) uses = uses.filter((u) => `${u.accountId}/${u.repo}` === f.repo);
    if (f.usage) uses = uses.filter((u) => u.direct === (f.usage === "direct"));
    if (f.env) uses = uses.filter((u) => u.devOnly === (f.env === "dev"));
    if (f.triage) uses = uses.filter((u) => (f.triage === "none" ? !u.finding : u.finding?.status === f.triage));
    if (!uses.length) continue;
    out.push(uses === r.uses ? r : { ...r, uses, direct: uses.some((u) => u.direct), devOnly: uses.every((u) => u.devOnly) });
  }
  return out;
}

/** Most urgent first: exploited or malicious, then by severity and chance of exploitation, then by reach. */
const byRisk = (a: PackageRow, b: PackageRow) =>
  Number(b.malicious) - Number(a.malicious) ||
  Number(b.kev) - Number(a.kev) ||
  (RANK[b.worst ?? ""] ?? -1) - (RANK[a.worst ?? ""] ?? -1) ||
  (b.epss ?? 0) - (a.epss ?? 0) ||
  b.uses.length - a.uses.length ||
  a.name.localeCompare(b.name) ||
  compareVersions(a.version, b.version);

const page = <T>(rows: T[], offset: number, limit: number): SbomPage<T> => ({
  rows: rows.slice(offset, offset + limit),
  total: rows.length,
  offset,
});

export function sbomSummary(repo: Repo, scans: AccountScan[]): SbomResponse["summary"] {
  const { uses, repoList, tools, dbBuilt } = gather(repo, scans);
  if (!repoList.length) return null;
  const rows = rowsOf(uses, new Map());
  const vulns = vulnRows(rows);
  const eco = new Map<string, number>();
  for (const r of rows) eco.set(r.ecosystem, (eco.get(r.ecosystem) ?? 0) + 1);
  const licenseRisks: Record<LicenseRiskFilter, number> = { strong: 0, weak: 0, permissive: 0, other: 0, none: 0 };
  for (const r of rows) licenseRisks[riskOf(r)]++;
  const severities = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const v of vulns) severities[v.severity]++;
  const withSbom = new Set(repoList.map((r) => `${r.accountId}/${r.repo}`));
  const inView = scans.reduce((n, s) => n + (s.scan.snap.repos?.filter((r) => !r.archived).length ?? 0), 0);
  return {
    repos: withSbom.size,
    missing: Math.max(0, inView - withSbom.size),
    packages: rows.length,
    uses: uses.length,
    vulnerable: rows.filter((r) => r.vulns.length).length,
    exploited: rows.filter((r) => r.kev).length,
    malicious: rows.filter((r) => r.malicious).length,
    fixable: rows.filter((r) => r.vulns.some((v) => v.fixedIn)).length,
    copyleft: licenseRisks.strong,
    vulnerabilities: severities,
    ecosystems: [...eco].map(([name, packages]) => ({ name, packages })).sort((a, b) => b.packages - a.packages),
    licenseRisks,
    repoList: repoList.sort((a, b) => a.repo.localeCompare(b.repo)),
    tools,
    dbBuilt,
  };
}

export function packagePage(repo: Repo, scans: AccountScan[], f: SbomFilters, sort: string, offset: number, limit: number): SbomPage<PackageRow> {
  const { uses } = gather(repo, scans);
  const rows = filterRows(rowsOf(uses, findingsOf(repo, scans)), f);
  rows.sort(
    sort === "name"
      ? (a, b) => a.name.localeCompare(b.name) || compareVersions(a.version, b.version)
      : sort === "repos"
        ? (a, b) => b.uses.length - a.uses.length || byRisk(a, b)
        : byRisk,
  );
  return page(rows, offset, limit);
}

/** One row per vulnerability, with the packages (and versions) it affects. */
function vulnRows(rows: PackageRow[]): VulnRow[] {
  const by = new Map<string, VulnRow & { repoSet: Set<string> }>();
  for (const r of rows)
    for (const v of r.vulns) {
      let row = by.get(v.id);
      if (!row) {
        const { fixedIn: _f, cpeOnly: _c, ...rest } = v;
        row = { ...rest, packages: [], repos: 0, repoSet: new Set() };
        by.set(v.id, row);
      }
      row.packages.push({ name: r.name, version: r.version, ecosystem: r.ecosystem, fixedIn: v.fixedIn, repos: r.uses.length });
      for (const u of r.uses) row.repoSet.add(`${u.accountId}/${u.repo}`);
    }
  return [...by.values()].map(({ repoSet, ...v }) => ({ ...v, repos: repoSet.size }));
}

export function vulnPage(repo: Repo, scans: AccountScan[], f: SbomFilters, offset: number, limit: number): SbomPage<VulnRow> {
  const { uses } = gather(repo, scans);
  // Package filters narrow which packages count; the vulnerability's own filters apply after.
  const rows = filterRows(rowsOf(uses, new Map()), { ...f, q: undefined, status: undefined, severity: undefined, vuln: undefined });
  const q = f.q?.trim().toLowerCase();
  const min = f.severity ? (RANK[f.severity] ?? 0) : 0;
  const out = vulnRows(rows).filter(
    (v) =>
      (!q || `${v.id} ${v.aliases.join(" ")} ${v.summary} ${v.packages.map((p) => p.name).join(" ")}`.toLowerCase().includes(q)) &&
      (!min || RANK[v.severity] >= min) &&
      (f.status !== "exploited" || v.kev) &&
      (f.status !== "malicious" || [v.id, ...v.aliases].some((id) => id.startsWith("MAL-"))) &&
      (f.status !== "fixable" || v.packages.some((p) => p.fixedIn)) &&
      (f.status !== "nofix" || v.packages.every((p) => !p.fixedIn)),
  );
  out.sort((a, b) => Number(b.kev) - Number(a.kev) || b.risk - a.risk || RANK[b.severity] - RANK[a.severity] || b.repos - a.repos || a.id.localeCompare(b.id));
  return page(out, offset, limit);
}

/** The Grant report: one row per license expression, with its risk class and how many packages and repositories have it. */
export function licensePage(repo: Repo, scans: AccountScan[], f: SbomFilters, offset: number, limit: number): SbomPage<LicenseRow> {
  const { uses } = gather(repo, scans);
  const rows = filterRows(rowsOf(uses, new Map()), { ...f, q: undefined, license: undefined });
  const by = new Map<string, LicenseRow & { repoSet: Set<string>; eco: Set<string> }>();
  for (const r of rows) {
    const license = licenseOf(r);
    let row = by.get(license);
    if (!row) {
      row = { license, risk: riskOf(r), packages: 0, repos: 0, ecosystems: [], repoSet: new Set(), eco: new Set() };
      by.set(license, row);
    }
    row.packages++;
    row.eco.add(r.ecosystem);
    for (const u of r.uses) row.repoSet.add(`${u.accountId}/${u.repo}`);
  }
  const order: LicenseRiskFilter[] = ["strong", "weak", "other", "none", "permissive"];
  const q = f.q?.trim().toLowerCase();
  const out = [...by.values()]
    .map(({ repoSet, eco, ...l }) => ({ ...l, repos: repoSet.size, ecosystems: [...eco].sort() }))
    .filter((l) => !q || l.license.toLowerCase().includes(q))
    .sort((a, b) => order.indexOf(a.risk) - order.indexOf(b.risk) || b.packages - a.packages || a.license.localeCompare(b.license));
  return page(out, offset, limit);
}

/** Every matching package use as CSV rows, one per package and repository. */
export function packageCsv(repo: Repo, scans: AccountScan[], f: SbomFilters): string[][] {
  const { rows } = packagePage(repo, scans, f, "risk", 0, Number.MAX_SAFE_INTEGER);
  const out = [
    [
      "package",
      "version",
      "ecosystem",
      "purl",
      "license",
      "license_risk",
      "repository",
      "account",
      "used_by",
      "direct",
      "development_only",
      "worst_severity",
      "vulnerabilities",
      "exploited",
      "upgrade_to",
      "triage",
    ],
  ];
  for (const r of rows)
    for (const u of r.uses)
      out.push([
        r.name,
        r.version,
        r.ecosystem,
        r.purl ?? "",
        licenseOf(r),
        riskOf(r),
        u.repo,
        u.account,
        u.parts.map((p) => p.label).join("; "),
        String(u.direct),
        String(u.devOnly),
        r.worst ?? "",
        r.vulns.map((v) => v.id).join(" "),
        String(r.kev),
        r.upgrade ?? "",
        u.finding?.status ?? "",
      ]);
  return out;
}
