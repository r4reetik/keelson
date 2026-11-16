// Every package the GitHub repositories in view depend on, from each one's
// software bill of materials (Syft), with their known vulnerabilities (Grype) and
// licenses (Grant). Three tabs over one set of filters kept in the URL: packages
// (each at each version, with the repositories that use it and their findings'
// triage), vulnerabilities (each one with the packages it affects), and licenses
// (the Grant report: each license with its risk class).

import { useState, type ReactNode } from "react";
import { Badge, Banner, Button, Dialog, Input, Link, Pagination, Select, Table, Tabs } from "@cloudflare/kumo";
import { DownloadSimpleIcon, WarningIcon, XIcon } from "@phosphor-icons/react";
import {
  LICENSE_RISKS,
  PACKAGE_STATUSES,
  STATUS_LABEL,
  num,
  plural,
  setParams,
  useLocation,
  withScope,
  type LicenseRow,
  type PackageRow,
  type SbomPage,
  type SbomResponse,
  type Severity,
  type TriageStatus,
  type VulnRow,
} from "../lib.ts";
import { useScopedApi, useShell } from "../shell.tsx";
import { DialogHeader, ListCard, NoRows, Page, PageState, Row, SeverityBadge, Stat, unreadableText } from "../components/ui.tsx";
import { ExploitedBadges, UsedBy, VulnSeverity, VulnTable, epssText } from "../components/dependencies.tsx";

const TITLE = "Dependencies";
const DESCRIPTION =
  "Every package your GitHub repositories depend on, from each repository's software bill of materials: what it is, where it's used, its known vulnerabilities and its license.";
const PER_PAGE = 50;
const ALL = "all";
type Tab = "packages" | "vulnerabilities" | "licenses";

/** Filters each tab reads from the URL, so a filtered view can be linked and survives a reload. */
const TAB_FILTERS: Record<Tab, string[]> = {
  packages: ["q", "status", "severity", "ecosystem", "risk", "license", "usage", "env", "repo", "triage", "vuln", "sort"],
  vulnerabilities: ["q", "status", "severity", "ecosystem", "repo"],
  licenses: ["q", "risk", "ecosystem", "repo"],
};

const SEVERITY_FILTERS = { [ALL]: "Any severity", critical: "Critical", high: "High or worse", medium: "Medium or worse", low: "Low or worse" };
const LICENSE_VARIANT: Record<string, "red" | "warning" | "outline" | "neutral" | "secondary"> = {
  strong: "red",
  weak: "warning",
  other: "outline",
  none: "secondary",
  permissive: "neutral",
};

const riskOfRow = (r: { licenseRisk: string | null; licenses: string[] }) => r.licenseRisk ?? (r.licenses.length ? "other" : "none");

export function DependenciesPage() {
  const { view } = useShell();
  const { params } = useLocation();
  const tab = (["vulnerabilities", "licenses"].includes(params.get("tab") ?? "") ? params.get("tab") : "packages") as Tab;
  const page = Math.max(1, Number(params.get("page")) || 1);
  const { data, error, loading, reload } = useScopedApi<SbomResponse>("/api/sbom");

  const query = new URLSearchParams();
  for (const k of TAB_FILTERS[tab]) if (params.has(k)) query.set(k, params.get(k)!);
  query.set("offset", String((page - 1) * PER_PAGE));
  query.set("limit", String(PER_PAGE));
  const list = useScopedApi<SbomPage<PackageRow | VulnRow | LicenseRow>>(data?.summary ? `/api/sbom/${tab}?${query}` : null);
  const [open, setOpen] = useState<PackageRow | null>(null);

  const gaps = (data?.coverage ?? []).filter((c) => !c.ok && ["manifests", "syft", "grype", "grant"].includes(c.key ?? ""));
  const s = data?.summary;
  if (error || !data || !s) {
    return (
      <PageState
        title={TITLE}
        description={DESCRIPTION}
        error={error}
        loading={!data && loading}
        empty={!!data}
        retry={reload}
        emptyText={
          data?.scan ? (gaps.length ? unreadableText(gaps, gaps[0].key ?? "", "dependencies") : "No repository in this view has an SBOM yet.") : undefined
        }
      />
    );
  }

  /** Changes filters and goes back to the first page. */
  const filter = (next: Record<string, string | null>) => setParams({ ...next, page: null });
  const select = (key: string, label: string, items: Record<string, string>, className = "sm:w-44") => (
    <Select
      aria-label={label}
      className={`min-w-36 flex-1 sm:flex-none ${className}`}
      value={params.get(key) ?? ALL}
      onValueChange={(v) => filter({ [key]: v === ALL ? null : String(v) })}
      items={{ [ALL]: label, ...items }}
    />
  );
  const ecosystems = Object.fromEntries(s.ecosystems.map((e) => [e.name, `${e.name} (${num(e.packages)})`]));
  const repos = Object.fromEntries(s.repoList.map((r) => [`${r.accountId}/${r.repo}`, view.accounts.length > 1 ? `${r.repo} · ${r.account}` : r.repo]));
  const active = TAB_FILTERS[tab].filter((k) => k !== "sort" && params.has(k));
  const exportHref = withScope(`/api/sbom/packages.csv?${new URLSearchParams([...query].filter(([k]) => k !== "offset" && k !== "limit"))}`, view.key);

  const toolbar: Record<Tab, ReactNode> = {
    packages: (
      <>
        <Input
          className="w-full min-w-48 sm:w-60"
          aria-label="Search packages"
          placeholder="Search packages"
          value={params.get("q") || ""}
          onChange={(e) => filter({ q: e.target.value || null })}
        />
        {select("status", "Any status", PACKAGE_STATUSES)}
        {select("severity", "Any severity", Object.fromEntries(Object.entries(SEVERITY_FILTERS).slice(1)))}
        {select("ecosystem", "Every package manager", ecosystems, "sm:w-52")}
        {select("repo", "Every repository", repos, "sm:w-52")}
        {select("risk", "Any license", LICENSE_RISKS)}
        {select("usage", "Direct or not", { direct: "Direct dependencies", transitive: "Through other packages" })}
        {select("env", "Runtime or development", { runtime: "Runtime", dev: "Development only" }, "sm:w-52")}
        {select("triage", "Any triage", { ...STATUS_LABEL, none: "No finding" })}
        {select("sort", "Most urgent first", { name: "By name", repos: "Most used first" })}
      </>
    ),
    vulnerabilities: (
      <>
        <Input
          className="w-full min-w-48 sm:w-60"
          aria-label="Search vulnerabilities"
          placeholder="CVE, advisory or package"
          value={params.get("q") || ""}
          onChange={(e) => filter({ q: e.target.value || null })}
        />
        {select("status", "Any status", { exploited: "Exploited", fixable: "Has a fix", nofix: "No fix yet", malicious: "Malicious" })}
        {select("severity", "Any severity", Object.fromEntries(Object.entries(SEVERITY_FILTERS).slice(1)))}
        {select("ecosystem", "Every package manager", ecosystems, "sm:w-52")}
        {select("repo", "Every repository", repos, "sm:w-52")}
      </>
    ),
    licenses: (
      <>
        <Input
          className="w-full min-w-48 sm:w-60"
          aria-label="Search licenses"
          placeholder="Search licenses"
          value={params.get("q") || ""}
          onChange={(e) => filter({ q: e.target.value || null })}
        />
        {select("risk", "Any risk", LICENSE_RISKS)}
        {select("ecosystem", "Every package manager", ecosystems, "sm:w-52")}
        {select("repo", "Every repository", repos, "sm:w-52")}
      </>
    ),
  };

  const rows = list.data?.rows ?? [];
  const total = list.data?.total ?? 0;
  const goTo = (to: Tab, next: Record<string, string | null> = {}) => {
    const clear = Object.fromEntries(
      ["q", "status", "severity", "ecosystem", "risk", "license", "usage", "env", "repo", "triage", "vuln", "sort", "page"].map((k) => [k, null]),
    );
    setParams({ ...clear, tab: to === "packages" ? null : to, ...next });
  };

  return (
    <Page
      title={TITLE}
      description={DESCRIPTION}
      actions={
        <Button size="sm" icon={<DownloadSimpleIcon />} onClick={() => window.open(exportHref, "_self")}>
          Export packages
        </Button>
      }
    >
      {gaps.length > 0 && (
        <Banner
          variant="alert"
          icon={<WarningIcon weight="fill" />}
          title="Some dependency data isn't read"
          description={
            <ul className="list-disc space-y-1 pl-5">
              {gaps.map((c) => (
                <li key={c.key}>
                  {c.label}: {c.message ?? `needs ${c.permission}.`}
                </li>
              ))}
            </ul>
          }
        />
      )}
      <Row cols={4}>
        <Stat
          label="Packages"
          value={num(s.packages)}
          note={`In ${plural(s.repos, "repository", "repositories")}${s.missing ? `; ${num(s.missing)} without an SBOM` : ""}`}
          onClick={() => goTo("packages")}
        />
        <Stat
          label="Vulnerable packages"
          value={num(s.vulnerable)}
          note={`${num(s.fixable)} with a fix · ${plural(s.vulnerabilities.critical + s.vulnerabilities.high, "critical or high vulnerability", "critical or high vulnerabilities")}`}
          onClick={() => goTo("packages", { status: "vulnerable" })}
        />
        <Stat
          label="Exploited"
          value={num(s.exploited + s.malicious)}
          note={s.malicious ? `${num(s.malicious)} malicious packages` : "Packages with a vulnerability attackers use"}
          hint="In CISA's catalog of known exploited vulnerabilities, or known to be malicious"
          onClick={() => goTo("packages", { status: "exploited" })}
        />
        <Stat
          label="Strong copyleft"
          value={num(s.copyleft)}
          note={`${num(s.licenseRisks.none)} packages state no license`}
          hint="Grant's risk class for GPL, AGPL and similar licenses"
          onClick={() => goTo("licenses", { risk: "strong" })}
        />
      </Row>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <Tabs
          value={tab}
          onValueChange={(v) => goTo(v as Tab)}
          tabs={[
            { value: "packages", label: `Packages ${num(s.packages)}` },
            { value: "vulnerabilities", label: `Vulnerabilities ${num(Object.values(s.vulnerabilities).reduce((a, b) => a + b, 0))}` },
            { value: "licenses", label: "Licenses (Grant)" },
          ]}
        />
        <span className="text-sm text-kumo-subtle">
          {[
            s.tools?.syft && `Syft ${s.tools.syft}`,
            s.tools?.grype && `Grype ${s.tools.grype}`,
            s.tools?.grant && `Grant ${s.tools.grant}`,
            s.dbBuilt && `vulnerability data from ${new Date(s.dbBuilt).toLocaleDateString()}`,
          ]
            .filter(Boolean)
            .join(" · ")}
        </span>
      </div>

      <ListCard
        toolbar={
          <>
            {toolbar[tab]}
            {active.length > 0 && (
              <Button
                size="sm"
                variant="ghost"
                icon={<XIcon />}
                onClick={() => goTo(tab, Object.fromEntries(params.has("sort") ? [["sort", params.get("sort")]] : []))}
              >
                Clear filters
              </Button>
            )}
            {params.get("license") != null && <Badge variant="outline">License: {params.get("license") || "not stated"}</Badge>}
            {params.get("vuln") && <Badge variant="outline">Vulnerability: {params.get("vuln")}</Badge>}
          </>
        }
        footer={
          <>
            <span>
              {list.loading && !list.data
                ? "Loading…"
                : `${num(total)} ${tab === "packages" ? (total === 1 ? "package" : "packages") : tab === "vulnerabilities" ? (total === 1 ? "vulnerability" : "vulnerabilities") : total === 1 ? "license" : "licenses"}`}
              {tab === "licenses" && " · licenses come from the lock files; Keelson doesn't look them up online"}
            </span>
            {total > PER_PAGE && (
              <Pagination page={page} setPage={(p: number) => setParams({ page: p === 1 ? null : String(p) })} perPage={PER_PAGE} totalCount={total} />
            )}
          </>
        }
      >
        {list.error ? (
          <NoRows>{list.error.message}</NoRows>
        ) : !rows.length ? (
          <NoRows>{list.loading ? "Loading…" : "Nothing matches these filters."}</NoRows>
        ) : tab === "packages" ? (
          <Packages rows={rows as PackageRow[]} onOpen={setOpen} />
        ) : tab === "vulnerabilities" ? (
          <Vulnerabilities rows={rows as VulnRow[]} onPackages={(id) => goTo("packages", { vuln: id })} />
        ) : (
          <Licenses rows={rows as LicenseRow[]} onPackages={(license) => goTo("packages", { license })} />
        )}
      </ListCard>

      <PackageDialog row={open} onClose={() => setOpen(null)} />
    </Page>
  );
}

/** Triage of the package's findings across repositories: "2 open, 1 accepted". */
function triageText(r: PackageRow): string {
  const counts = new Map<string, number>();
  for (const u of r.uses) if (u.finding) counts.set(u.finding.status, (counts.get(u.finding.status) ?? 0) + 1);
  return [...counts].map(([s, n]) => `${num(n)} ${STATUS_LABEL[s as TriageStatus]?.toLowerCase() ?? s}`).join(", ");
}

function Packages({ rows, onOpen }: { rows: PackageRow[]; onOpen: (r: PackageRow) => void }) {
  return (
    <Table layout="auto">
      <Table.Header variant="compact">
        <Table.Row>
          <Table.Head sticky="left">Package</Table.Head>
          <Table.Head className="whitespace-nowrap">Version</Table.Head>
          <Table.Head className="whitespace-nowrap">Vulnerabilities</Table.Head>
          <Table.Head className="whitespace-nowrap">Upgrade to</Table.Head>
          <Table.Head className="whitespace-nowrap">Repositories</Table.Head>
          <Table.Head className="whitespace-nowrap">Findings</Table.Head>
          <Table.Head className="whitespace-nowrap">License</Table.Head>
        </Table.Row>
      </Table.Header>
      <Table.Body>
        {rows.map((r) => {
          const risk = riskOfRow(r);
          return (
            <Table.Row key={`${r.ecosystem}|${r.name}|${r.version}`}>
              <Table.Cell sticky="left" className="whitespace-nowrap">
                <span className="inline-flex items-center gap-2">
                  <Link variant="plain" render={<button type="button" onClick={() => onOpen(r)} />}>
                    {r.name}
                  </Link>
                  <span className="text-xs text-kumo-subtle">{r.ecosystem}</span>
                  {r.devOnly && <Badge variant="outline">Development</Badge>}
                  {!r.direct && <span className="text-xs text-kumo-subtle">transitive</span>}
                </span>
              </Table.Cell>
              <Table.Cell className="whitespace-nowrap font-mono text-xs">{r.version.length > 24 ? `${r.version.slice(0, 12)}…` : r.version}</Table.Cell>
              <Table.Cell className="whitespace-nowrap">
                {r.vulns.length ? (
                  <span className="inline-flex items-center gap-2">
                    <VulnSeverity severity={r.worst ?? "unknown"} />
                    <span className="tabular-nums text-kumo-subtle">{num(r.vulns.length)}</span>
                    <ExploitedBadges kev={r.kev} />
                    {r.malicious && <Badge variant="red">Malicious</Badge>}
                  </span>
                ) : (
                  <span className="text-kumo-subtle">None known</span>
                )}
              </Table.Cell>
              <Table.Cell className="whitespace-nowrap font-mono text-xs">
                {r.upgrade ?? (r.vulns.length ? <span className="font-sans text-kumo-subtle">No fix yet</span> : "")}
              </Table.Cell>
              <Table.Cell className="text-sm">
                <span className="tabular-nums">{num(r.uses.length)}</span>
                <span className="text-kumo-subtle">
                  {" "}
                  ·{" "}
                  {r.uses
                    .slice(0, 2)
                    .map((u) => u.repo)
                    .join(", ")}
                  {r.uses.length > 2 ? ` and ${num(r.uses.length - 2)} more` : ""}
                </span>
              </Table.Cell>
              <Table.Cell className="whitespace-nowrap text-sm text-kumo-subtle">{triageText(r) || "—"}</Table.Cell>
              <Table.Cell className="whitespace-nowrap">
                <span className="inline-flex items-center gap-2">
                  <span className="max-w-40 truncate text-sm">{r.licenses.join(", ") || <span className="text-kumo-subtle">Not stated</span>}</span>
                  {risk !== "permissive" && risk !== "none" && (
                    <Badge variant={LICENSE_VARIANT[risk]}>{LICENSE_RISKS[risk as keyof typeof LICENSE_RISKS]}</Badge>
                  )}
                </span>
              </Table.Cell>
            </Table.Row>
          );
        })}
      </Table.Body>
    </Table>
  );
}

function Vulnerabilities({ rows, onPackages }: { rows: VulnRow[]; onPackages: (id: string) => void }) {
  return (
    <Table layout="auto">
      <Table.Header variant="compact">
        <Table.Row>
          <Table.Head sticky="left">Vulnerability</Table.Head>
          <Table.Head className="whitespace-nowrap">Severity</Table.Head>
          <Table.Head className="whitespace-nowrap">Exploit chance</Table.Head>
          <Table.Head className="whitespace-nowrap">Packages affected</Table.Head>
          <Table.Head className="whitespace-nowrap">Repositories</Table.Head>
        </Table.Row>
      </Table.Header>
      <Table.Body>
        {rows.map((v) => (
          <Table.Row key={v.id}>
            <Table.Cell sticky="left" className="min-w-72 align-top">
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                {v.url ? (
                  <Link href={v.url} target="_blank" rel="noopener noreferrer" className="font-mono text-xs">
                    {v.id}
                  </Link>
                ) : (
                  <span className="font-mono text-xs">{v.id}</span>
                )}
                {v.aliases.slice(0, 2).map((a) => (
                  <span key={a} className="font-mono text-xs text-kumo-subtle">
                    {a}
                  </span>
                ))}
                <ExploitedBadges kev={v.kev} ransomware={v.ransomware} />
              </div>
              {v.summary && <p className="mt-1 line-clamp-2 max-w-xl text-xs text-kumo-subtle">{v.summary}</p>}
            </Table.Cell>
            <Table.Cell className="whitespace-nowrap align-top">
              <span className="inline-flex items-center gap-2">
                <VulnSeverity severity={v.severity} />
                {v.cvss != null && <span className="text-xs tabular-nums text-kumo-subtle">CVSS {v.cvss.toFixed(1)}</span>}
              </span>
            </Table.Cell>
            <Table.Cell className="whitespace-nowrap align-top tabular-nums">{epssText(v.epss)}</Table.Cell>
            <Table.Cell className="align-top text-sm">
              <ul className="flex flex-col gap-0.5">
                {v.packages.slice(0, 3).map((p) => (
                  <li key={`${p.name}@${p.version}`} className="whitespace-nowrap">
                    <span className="font-mono text-xs">
                      {p.name} {p.version}
                    </span>
                    <span className="text-xs text-kumo-subtle"> {p.fixedIn ? `→ ${p.fixedIn}` : "· no fix yet"}</span>
                  </li>
                ))}
                {v.packages.length > 3 && <li className="text-xs text-kumo-subtle">and {num(v.packages.length - 3)} more versions</li>}
              </ul>
            </Table.Cell>
            <Table.Cell className="whitespace-nowrap align-top">
              <Link variant="plain" render={<button type="button" onClick={() => onPackages(v.id)} />}>
                {plural(v.repos, "repository", "repositories")}
              </Link>
            </Table.Cell>
          </Table.Row>
        ))}
      </Table.Body>
    </Table>
  );
}

/** The Grant report: each license with Grant's risk class. */
function Licenses({ rows, onPackages }: { rows: LicenseRow[]; onPackages: (license: string) => void }) {
  return (
    <Table layout="auto">
      <Table.Header variant="compact">
        <Table.Row>
          <Table.Head sticky="left">License</Table.Head>
          <Table.Head className="whitespace-nowrap">Risk (Grant)</Table.Head>
          <Table.Head className="whitespace-nowrap">Packages</Table.Head>
          <Table.Head className="whitespace-nowrap">Repositories</Table.Head>
          <Table.Head className="whitespace-nowrap">Package managers</Table.Head>
        </Table.Row>
      </Table.Header>
      <Table.Body>
        {rows.map((l) => (
          <Table.Row key={l.license}>
            <Table.Cell sticky="left" className="max-w-md">
              {l.license ? <span className="break-words">{l.license}</span> : <span className="text-kumo-subtle">Not stated in the lock file</span>}
            </Table.Cell>
            <Table.Cell className="whitespace-nowrap">
              <Badge variant={LICENSE_VARIANT[l.risk]}>{LICENSE_RISKS[l.risk]}</Badge>
            </Table.Cell>
            <Table.Cell className="whitespace-nowrap">
              <Link variant="plain" render={<button type="button" onClick={() => onPackages(l.license)} />}>
                {plural(l.packages, "package", "packages")}
              </Link>
            </Table.Cell>
            <Table.Cell className="whitespace-nowrap tabular-nums">{num(l.repos)}</Table.Cell>
            <Table.Cell className="text-sm text-kumo-subtle">{l.ecosystems.join(", ")}</Table.Cell>
          </Table.Row>
        ))}
      </Table.Body>
    </Table>
  );
}

/** A package at one version: its vulnerabilities, and each repository that uses it with how, and its finding. */
function PackageDialog({ row, onClose }: { row: PackageRow | null; onClose: () => void }) {
  return (
    <Dialog.Root open={!!row} onOpenChange={(o: boolean) => !o && onClose()}>
      <Dialog size="xl" className="max-h-[calc(100vh-6rem)] overflow-y-auto p-6 sm:w-[75vw]">
        {row && (
          <>
            <DialogHeader
              title={`${row.name} ${row.version}`}
              description={[
                row.ecosystem,
                row.licenses.join(", ") || "license not stated",
                row.upgrade ? `upgrade to ${row.upgrade} to fix every vulnerability that has a fix` : null,
                row.purl,
              ]
                .filter(Boolean)
                .join(" · ")}
            />
            <div className="flex flex-col gap-5 text-sm">
              {row.vulns.length > 0 && <VulnTable vulns={row.vulns} />}
              <div>
                <div className="mb-2 text-xs font-medium uppercase tracking-wide text-kumo-subtle">
                  Used in {plural(row.uses.length, "repository", "repositories")}
                </div>
                <div className="overflow-x-auto rounded-md ring ring-kumo-line">
                  <Table layout="auto">
                    <Table.Header variant="compact">
                      <Table.Row>
                        <Table.Head>Repository</Table.Head>
                        <Table.Head>Where</Table.Head>
                        <Table.Head className="whitespace-nowrap">Finding</Table.Head>
                      </Table.Row>
                    </Table.Header>
                    <Table.Body>
                      {row.uses.map((u) => (
                        <Table.Row key={`${u.accountId}/${u.repo}`}>
                          <Table.Cell className="whitespace-nowrap align-top">
                            <Link variant="plain" href={`/repositories/${encodeURIComponent(u.accountId)}/${encodeURIComponent(u.repo)}`}>
                              {u.repo}
                            </Link>
                          </Table.Cell>
                          <Table.Cell className="align-top">
                            <UsedBy usages={u.parts} />
                            <p className="mt-1 text-xs text-kumo-subtle">Recorded in {u.locations.join(", ")}</p>
                          </Table.Cell>
                          <Table.Cell className="whitespace-nowrap align-top">
                            {u.finding ? (
                              <span className="inline-flex items-center gap-2">
                                <SeverityBadge severity={u.finding.severity as Severity} />
                                <Link variant="plain" href={`/findings/${u.finding.fingerprint}`}>
                                  {STATUS_LABEL[u.finding.status as TriageStatus] ?? u.finding.status}
                                </Link>
                              </span>
                            ) : (
                              <span className="text-kumo-subtle">—</span>
                            )}
                          </Table.Cell>
                        </Table.Row>
                      ))}
                    </Table.Body>
                  </Table>
                </div>
              </div>
              <p className="text-xs text-kumo-subtle">
                Highest chance of exploitation in the next 30 days: {epssText(row.epss)}. Findings are raised for exploited, malicious, critical and high
                vulnerabilities, and for others likely to be exploited.
              </p>
            </div>
          </>
        )}
      </Dialog>
    </Dialog.Root>
  );
}
