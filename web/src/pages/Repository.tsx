// One GitHub repository's dependencies, from its software bill of materials: its
// projects (each part of a monorepo, with its ecosystems, lock file and base
// images), every package with where it's used, its known vulnerabilities and its
// license, and the SBOM itself to download as CycloneDX, SPDX or Syft JSON.

import { useMemo, useState } from "react";
import { Badge, Button, Dialog, DropdownMenu, Input, Link, Select, Switch, Table, Tooltip } from "@cloudflare/kumo";
import { ArrowLeftIcon, ArrowSquareOutIcon, DownloadSimpleIcon, WarningIcon, XIcon } from "@phosphor-icons/react";
import {
  HttpError,
  dateTime,
  navigate,
  num,
  plural,
  setParams,
  useApi,
  useLocation,
  type DepPackage,
  type DependenciesResponse,
  type Part,
  type Severity,
} from "../lib.ts";
import { useShell } from "../shell.tsx";
import { Card, DialogHeader, KeyValue, ListCard, NoRows, Page, PageState, Row, SeverityBadge, Stat } from "../components/ui.tsx";
import { ExploitedBadges, UsedBy, VulnTable, epssText } from "../components/dependencies.tsx";

const RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
const worst = (p: DepPackage) => p.vulns.reduce((w, v) => Math.max(w, RANK[v.severity] ?? 0), 0);
const SEVERITY_OF = ["info", "low", "medium", "high", "critical"] as const;
const ALL = "all";
const PAGE = 200;

/** The smallest version that fixes every known vulnerability of a package that has a fix. */
function upgradeOf(p: DepPackage): string | null {
  const fixes = p.vulns.map((v) => v.fixedIn).filter((f): f is string => !!f);
  if (!fixes.length) return null;
  const parts = (v: string) =>
    v
      .replace(/^v/i, "")
      .split(/[.+-]/)
      .map((x) => (/^\d+$/.test(x) ? Number(x) : x));
  return fixes.sort((a, b) => {
    const pa = parts(a);
    const pb = parts(b);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const x = pa[i] ?? 0;
      const y = pb[i] ?? 0;
      if (x !== y) return typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y));
    }
    return 0;
  })[fixes.length - 1];
}

const partLabel = (parts: Part[], path: string) => {
  const p = parts.find((x) => x.path === path);
  return p?.workflows ? "workflows" : path || "root";
};

const LICENSE_RISK: Record<string, { label: string; variant: "red" | "warning" | "outline" | "neutral" }> = {
  strong: { label: "Strong copyleft", variant: "red" },
  weak: { label: "Weak copyleft", variant: "warning" },
  other: { label: "Not a known license", variant: "outline" },
};

export function RepositoryPage({ params }: { params: Record<string, string> }) {
  const { dataVersion } = useShell();
  const { params: query } = useLocation();
  const path = `/api/dependencies?account=${encodeURIComponent(params.account)}&repo=${encodeURIComponent(params.repo)}`;
  const { data, error, loading, reload } = useApi<DependenciesResponse>(path, dataVersion);
  const [open, setOpen] = useState<DepPackage | null>(null);
  const [shown, setShown] = useState(PAGE);
  const back = (
    <Button variant="ghost" size="sm" icon={<ArrowLeftIcon />} onClick={() => navigate("/repositories")}>
      Repositories
    </Button>
  );

  const d = data?.dependencies;
  const q = (query.get("q") || "").toLowerCase();
  const part = query.get("part");
  const vulnerableOnly = query.get("vulnerable") === "1";
  const ecosystem = query.get("ecosystem") || ALL;
  const license = query.get("license");

  const packages = useMemo(() => {
    const all = d?.packages ?? [];
    return all
      .filter(
        (p) =>
          (!q || `${p.name} ${p.version}`.toLowerCase().includes(q)) &&
          (part == null || p.usedBy.some((u) => u.part === part)) &&
          (!vulnerableOnly || p.vulns.length > 0) &&
          (ecosystem === ALL || p.ecosystem === ecosystem) &&
          (license == null || p.licenses.join(" AND ") === license),
      )
      .sort((a, b) => worst(b) - worst(a) || Number(b.vulns.some((v) => v.kev)) - Number(a.vulns.some((v) => v.kev)) || a.name.localeCompare(b.name));
  }, [d, q, part, vulnerableOnly, ecosystem, license]);

  if (error || !data || !d) {
    const missing = error instanceof HttpError && error.status === 404;
    return (
      <PageState
        title={params.repo}
        actions={back}
        error={missing ? null : error}
        loading={loading}
        empty={missing || (!!data && !d)}
        emptyText={missing ? error.message : "Keelson hasn't read this repository's dependencies yet."}
        retry={reload}
      />
    );
  }

  const pkgs = d.packages;
  const findingOf = new Map(data.findings.map((f) => [f.resource, f]));
  const ecosystems = [...new Set([...d.parts.flatMap((p) => p.ecosystems), ...(pkgs ?? []).map((p) => p.ecosystem)])].sort();
  const vulnerable = (pkgs ?? []).filter((p) => p.vulns.length);
  const exploited = vulnerable.filter((p) => p.vulns.some((v) => v.kev));
  const copyleft = (pkgs ?? []).filter((p) => p.licenseRisk === "strong");
  const projects = d.parts.filter((p) => !p.workflows);
  const totalBytes = Object.values(d.languages ?? {}).reduce((a, b) => a + b, 0);
  const languages = Object.entries(d.languages ?? {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([name, bytes]) => {
      const share = totalBytes ? (100 * bytes) / totalBytes : 0;
      return `${name} ${share < 1 ? "<1" : Math.round(share)}%`;
    });
  const sbom = (format: string) =>
    `/api/dependencies/sbom?account=${encodeURIComponent(data.accountId)}&repo=${encodeURIComponent(data.repo)}&format=${format}`;
  const usesOf = (p: Part) => (pkgs ?? []).filter((x) => x.usedBy.some((u) => u.part === p.path));

  return (
    <Page
      title={data.repo}
      description={
        <>
          Dependencies from the repository's software bill of materials, made by Syft from its manifest and lock files on {data.defaultBranch}. Keelson reads
          those files only, never the code.
        </>
      }
      actions={
        <>
          {back}
          <Link href={data.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-sm">
            Open on GitHub <ArrowSquareOutIcon />
          </Link>
          <Link variant="plain" href={`/dependencies?repo=${encodeURIComponent(`${data.accountId}/${data.repo}`)}`} className="text-sm">
            Across every repository
          </Link>
          {pkgs && (
            <DropdownMenu>
              <DropdownMenu.Trigger
                render={
                  <Button size="sm" icon={<DownloadSimpleIcon />}>
                    Download SBOM
                  </Button>
                }
              />
              <DropdownMenu.Content align="end">
                <DropdownMenu.Group>
                  <DropdownMenu.Label>Format</DropdownMenu.Label>
                  <DropdownMenu.Item onClick={() => window.open(sbom("cyclonedx"), "_self")}>CycloneDX JSON</DropdownMenu.Item>
                  <DropdownMenu.Item onClick={() => window.open(sbom("spdx"), "_self")}>SPDX JSON</DropdownMenu.Item>
                  <DropdownMenu.Item onClick={() => window.open(sbom("syft"), "_self")}>Syft JSON</DropdownMenu.Item>
                </DropdownMenu.Group>
              </DropdownMenu.Content>
            </DropdownMenu>
          )}
        </>
      }
    >
      <Row cols={4}>
        <Stat
          label="Packages"
          value={pkgs ? num(pkgs.length) : "—"}
          note={pkgs ? plural(ecosystems.length, "ecosystem", "ecosystems") : "Syft isn't installed"}
        />
        <Stat
          label="Vulnerable packages"
          value={pkgs && data.tools?.grype ? num(vulnerable.length) : "—"}
          note={
            exploited.length
              ? `${exploited.length} with a vulnerability attackers exploit`
              : data.tools?.grype
                ? "None known to be exploited"
                : "Grype isn't installed"
          }
          onClick={vulnerable.length ? () => setParams({ vulnerable: "1", part: null }) : undefined}
        />
        <Stat
          label="Projects"
          value={num(projects.length)}
          note={projects.length > 1 ? "A monorepo: each is listed below" : projects[0]?.ecosystems.join(", ") || "No package manifests"}
        />
        <Stat
          label="Strong copyleft"
          value={pkgs && data.tools?.grant ? num(copyleft.length) : "—"}
          note={data.tools?.grant ? "Packages under GPL, AGPL and similar" : "Grant isn't installed"}
        />
      </Row>

      <Card title="About">
        <KeyValue
          items={[
            ["Languages", languages.length ? languages.join(" · ") : "—"],
            ["Ecosystems", ecosystems.length ? ecosystems.join(", ") : "—"],
            ["SBOM made", `${dateTime(new Date(d.generatedAt).toISOString())}. Made again when a manifest or lock file changes`],
            [
              "Tools",
              [
                data.tools?.syft && `Syft ${data.tools.syft}`,
                data.tools?.grype && `Grype ${data.tools.grype}${data.dbBuilt ? ` (vulnerability data from ${dateTime(data.dbBuilt)})` : ""}`,
                data.tools?.grant && `Grant ${data.tools.grant}`,
              ]
                .filter(Boolean)
                .join(" · ") || "None installed",
            ],
            ...(d.partial
              ? ([
                  [
                    "Coverage",
                    <span key="p" className="inline-flex items-center gap-1.5">
                      <WarningIcon className="text-kumo-warning" /> Some files were too large or too many to read, so a few packages may be missing.
                    </span>,
                  ],
                ] as [string, React.ReactNode][])
              : []),
          ]}
        />
      </Card>

      <ListCard title={projects.length > 1 ? "Projects in this monorepo" : "Project"}>
        {!d.parts.length ? (
          <NoRows>No package manifests, lock files or workflows in this repository.</NoRows>
        ) : (
          <Table layout="auto">
            <Table.Header variant="compact">
              <Table.Row>
                <Table.Head sticky="left">Project</Table.Head>
                <Table.Head className="whitespace-nowrap">Ecosystems</Table.Head>
                <Table.Head className="whitespace-nowrap">Lock file</Table.Head>
                <Table.Head className="whitespace-nowrap">Packages</Table.Head>
                <Table.Head className="whitespace-nowrap">Vulnerable</Table.Head>
                <Table.Head className="whitespace-nowrap">Base images</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {d.parts.map((p) => {
                const used = usesOf(p);
                const bad = used.filter((x) => x.vulns.length);
                const sev = bad.reduce((w, x) => Math.max(w, worst(x)), 0);
                return (
                  <Table.Row key={p.path}>
                    <Table.Cell sticky="left" className="whitespace-nowrap">
                      <Link variant="plain" render={<button type="button" onClick={() => setParams({ part: p.path, vulnerable: null })} />}>
                        <span className="font-mono text-sm">{p.workflows ? ".github/workflows" : p.path || "/"}</span>
                      </Link>
                      {p.name && !p.workflows && <div className="max-w-80 truncate text-sm text-kumo-subtle">{p.name}</div>}
                      {p.devOnly && <Badge variant="outline">Examples or tests</Badge>}
                    </Table.Cell>
                    <Table.Cell className="whitespace-nowrap text-kumo-subtle">{p.ecosystems.join(", ") || "—"}</Table.Cell>
                    <Table.Cell>
                      {p.workflows ? (
                        <span className="text-kumo-subtle">n/a</span>
                      ) : p.unpinned.length ? (
                        <Tooltip content={`Installed without a pinned version: ${p.unpinned.join(", ")}`}>
                          <Badge variant="warning">None for {plural(p.unpinned.length, "package", "packages")}</Badge>
                        </Tooltip>
                      ) : p.lockfile ? (
                        <span className="whitespace-nowrap font-mono text-xs text-kumo-subtle">{p.lockfile}</span>
                      ) : (
                        <span className="text-kumo-subtle">None needed</span>
                      )}
                    </Table.Cell>
                    <Table.Cell className="tabular-nums">{pkgs ? num(used.length) : "—"}</Table.Cell>
                    <Table.Cell className="whitespace-nowrap">
                      {bad.length ? (
                        <span className="inline-flex items-center gap-2">
                          <SeverityBadge severity={SEVERITY_OF[sev] as Severity} />
                          <span className="tabular-nums text-kumo-subtle">{num(bad.length)}</span>
                        </span>
                      ) : (
                        <span className="text-kumo-subtle">{pkgs && data.tools?.grype ? "None" : "—"}</span>
                      )}
                    </Table.Cell>
                    <Table.Cell className="text-kumo-subtle">
                      {p.images.length ? <span className="font-mono text-xs">{p.images.join(", ")}</span> : "—"}
                    </Table.Cell>
                  </Table.Row>
                );
              })}
            </Table.Body>
          </Table>
        )}
      </ListCard>

      {pkgs && data.tools?.grant && <LicenseSummary packages={pkgs} onPick={(l) => setParams({ license: l, part: null })} />}

      {pkgs && (
        <ListCard
          title="Packages"
          toolbar={
            <>
              <Input
                className="w-full min-w-48 sm:w-64"
                aria-label="Search packages"
                placeholder="Search packages"
                value={query.get("q") || ""}
                onChange={(e) => setParams({ q: e.target.value || null })}
              />
              {d.parts.length > 1 && (
                <Select
                  aria-label="Project"
                  className="min-w-36 flex-1 sm:w-48 sm:flex-none"
                  value={part ?? ALL}
                  onValueChange={(v) => setParams({ part: v === ALL ? null : String(v) })}
                  items={{ [ALL]: "Every project", ...Object.fromEntries(d.parts.map((p) => [p.path, partLabel(d.parts, p.path)])) }}
                />
              )}
              {ecosystems.length > 1 && (
                <Select
                  aria-label="Ecosystem"
                  className="min-w-36 flex-1 sm:w-44 sm:flex-none"
                  value={ecosystem}
                  onValueChange={(v) => setParams({ ecosystem: v === ALL ? null : String(v) })}
                  items={{ [ALL]: "Every ecosystem", ...Object.fromEntries(ecosystems.map((e) => [e, e])) }}
                />
              )}
              <span className="inline-flex items-center gap-2 text-sm text-kumo-subtle">
                <Switch
                  aria-label="Only vulnerable packages"
                  checked={vulnerableOnly}
                  onCheckedChange={(v: boolean) => setParams({ vulnerable: v ? "1" : null })}
                />
                <span aria-hidden>Only vulnerable packages</span>
              </span>
              {license != null && (
                <Button size="sm" variant="ghost" icon={<XIcon />} onClick={() => setParams({ license: null })}>
                  License: {license || "not stated"}
                </Button>
              )}
            </>
          }
          footer={
            <>
              <span>
                {packages.length === pkgs.length
                  ? plural(pkgs.length, "package", "packages")
                  : `${num(packages.length)} of ${plural(pkgs.length, "package", "packages")}`}{" "}
                · most severe first
              </span>
              {packages.length > shown && (
                <Button size="sm" variant="secondary" onClick={() => setShown(shown + PAGE)}>
                  Show {num(Math.min(PAGE, packages.length - shown))} more
                </Button>
              )}
            </>
          }
        >
          {!packages.length ? (
            <NoRows>No packages match.</NoRows>
          ) : (
            <Table layout="auto">
              <Table.Header variant="compact">
                <Table.Row>
                  <Table.Head sticky="left">Package</Table.Head>
                  <Table.Head className="whitespace-nowrap">Version</Table.Head>
                  <Table.Head className="whitespace-nowrap">Vulnerabilities</Table.Head>
                  <Table.Head className="whitespace-nowrap">Upgrade to</Table.Head>
                  <Table.Head className="whitespace-nowrap">Used by</Table.Head>
                  <Table.Head className="whitespace-nowrap">License</Table.Head>
                </Table.Row>
              </Table.Header>
              <Table.Body>
                {packages.slice(0, shown).map((p) => {
                  const sev = worst(p);
                  const kev = p.vulns.some((v) => v.kev);
                  const finding = findingOf.get(`${p.name} (${p.ecosystem})`);
                  const direct = p.usedBy.filter((u) => u.direct).map((u) => partLabel(d.parts, u.part));
                  const through = p.usedBy.filter((u) => !u.direct).map((u) => partLabel(d.parts, u.part));
                  const risk = p.licenseRisk ? LICENSE_RISK[p.licenseRisk] : null;
                  return (
                    <Table.Row key={`${p.type}:${p.name}@${p.version}`}>
                      <Table.Cell sticky="left" className="whitespace-nowrap">
                        <span className="inline-flex items-center gap-2">
                          {p.vulns.length ? (
                            <Link variant="plain" render={<button type="button" onClick={() => setOpen(p)} />}>
                              {p.name}
                            </Link>
                          ) : (
                            <span>{p.name}</span>
                          )}
                          <span className="text-xs text-kumo-subtle">{p.ecosystem}</span>
                          {p.devOnly && <Badge variant="outline">Development</Badge>}
                        </span>
                      </Table.Cell>
                      <Table.Cell className="whitespace-nowrap font-mono text-xs">
                        <Version v={p.version} />
                      </Table.Cell>
                      <Table.Cell className="whitespace-nowrap">
                        {p.vulns.length ? (
                          <span className="inline-flex items-center gap-2">
                            <SeverityBadge severity={SEVERITY_OF[sev] as Severity} />
                            <Link variant="plain" render={<button type="button" onClick={() => setOpen(p)} />}>
                              {plural(p.vulns.length, "vulnerability", "vulnerabilities")}
                            </Link>
                            <ExploitedBadges kev={kev} />
                            {finding && (
                              <Link variant="plain" href={`/findings/${finding.fingerprint}`}>
                                Finding
                              </Link>
                            )}
                          </span>
                        ) : (
                          <span className="text-kumo-subtle">{data.tools?.grype ? "None known" : "—"}</span>
                        )}
                      </Table.Cell>
                      <Table.Cell className="whitespace-nowrap font-mono text-xs">
                        {upgradeOf(p) ?? (p.vulns.length ? <span className="font-sans text-kumo-subtle">No fix yet</span> : "")}
                      </Table.Cell>
                      <Table.Cell className="text-sm">
                        {direct.length > 0 && <div>{direct.join(", ")}</div>}
                        {through.length > 0 && <div className="text-kumo-subtle">through others in {through.join(", ")}</div>}
                        {!p.usedBy.length && <span className="text-kumo-subtle">—</span>}
                      </Table.Cell>
                      <Table.Cell className="whitespace-nowrap">
                        <span className="inline-flex items-center gap-2">
                          <span className="max-w-48 truncate text-sm">{p.licenses.join(", ") || <span className="text-kumo-subtle">Not stated</span>}</span>
                          {risk && <Badge variant={risk.variant}>{risk.label}</Badge>}
                        </span>
                      </Table.Cell>
                    </Table.Row>
                  );
                })}
              </Table.Body>
            </Table>
          )}
        </ListCard>
      )}

      <Dialog.Root open={!!open} onOpenChange={(o: boolean) => !o && setOpen(null)}>
        <Dialog size="xl" className="max-h-[calc(100vh-6rem)] overflow-y-auto p-6 sm:w-[75vw]">
          {open && (
            <>
              <DialogHeader
                title={`${open.name} ${open.version}`}
                description={`${open.ecosystem} · ${plural(open.vulns.length, "known vulnerability", "known vulnerabilities")}${upgradeOf(open) ? ` · upgrade to ${upgradeOf(open)} to fix every one that has a fix` : ""}`}
              />
              <div className="flex flex-col gap-4 text-sm">
                <div>
                  <div className="mb-1 text-xs font-medium uppercase tracking-wide text-kumo-subtle">Where it's used</div>
                  <UsedBy usages={open.usedBy.map((u) => ({ ...u, label: partLabel(d.parts, u.part) }))} />
                  <p className="mt-1 text-xs text-kumo-subtle">Recorded in {open.locations.join(", ")}</p>
                </div>
                <VulnTable vulns={open.vulns} />
                <p className="text-xs text-kumo-subtle">
                  Highest chance of exploitation in the next 30 days: {epssText(Math.max(0, ...open.vulns.map((v) => v.epss ?? 0)))}.
                </p>
              </div>
            </>
          )}
        </Dialog>
      </Dialog.Root>
    </Page>
  );
}

/** A version; a commit SHA (an action pinned to a commit) is shortened, with the whole SHA on hover. */
function Version({ v }: { v: string }) {
  if (!/^[0-9a-f]{40}$/i.test(v)) return <>{v}</>;
  return (
    <Tooltip content={v}>
      <span>{v.slice(0, 12)}…</span>
    </Tooltip>
  );
}

const LICENSE_ORDER = ["strong", "weak", "other", "none", "permissive"];

/** This repository's Grant report: each license with its risk class and how many packages have it. */
function LicenseSummary({ packages, onPick }: { packages: DepPackage[]; onPick: (license: string) => void }) {
  const by = new Map<string, { risk: string; count: number }>();
  for (const p of packages) {
    const license = p.licenses.join(" AND ");
    const risk = p.licenseRisk ?? (p.licenses.length ? "other" : "none");
    const row = by.get(license) ?? { risk, count: 0 };
    row.count++;
    by.set(license, row);
  }
  const rows = [...by].sort((a, b) => LICENSE_ORDER.indexOf(a[1].risk) - LICENSE_ORDER.indexOf(b[1].risk) || b[1].count - a[1].count);
  const label: Record<string, string> = {
    strong: "Strong copyleft",
    weak: "Weak copyleft",
    other: "Not a known license",
    none: "Not stated",
    permissive: "Permissive",
  };
  const variant: Record<string, "red" | "warning" | "outline" | "secondary" | "neutral"> = {
    strong: "red",
    weak: "warning",
    other: "outline",
    none: "secondary",
    permissive: "neutral",
  };
  return (
    <ListCard title="Licenses (Grant)" footer={<span>From the lock files; Keelson doesn't look licenses up online. Pick one to list its packages.</span>}>
      <Table layout="auto">
        <Table.Header variant="compact">
          <Table.Row>
            <Table.Head sticky="left">License</Table.Head>
            <Table.Head className="whitespace-nowrap">Risk (Grant)</Table.Head>
            <Table.Head className="whitespace-nowrap">Packages</Table.Head>
          </Table.Row>
        </Table.Header>
        <Table.Body>
          {rows.slice(0, 12).map(([license, r]) => (
            <Table.Row key={license}>
              <Table.Cell sticky="left">{license || <span className="text-kumo-subtle">Not stated in the lock file</span>}</Table.Cell>
              <Table.Cell className="whitespace-nowrap">
                <Badge variant={variant[r.risk]}>{label[r.risk]}</Badge>
              </Table.Cell>
              <Table.Cell className="whitespace-nowrap">
                <Link variant="plain" render={<button type="button" onClick={() => onPick(license)} />}>
                  {plural(r.count, "package", "packages")}
                </Link>
              </Table.Cell>
            </Table.Row>
          ))}
        </Table.Body>
      </Table>
    </ListCard>
  );
}
