// Repositories on GitHub and Gitea: how each default branch is protected, whether secret
// scanning and push protection are on, open security alerts, the Pages site, and
// open findings. The GitHub counterpart of Zones, Projects and Regions. Filter by
// language or visibility, and pick repositories to copy or download them.

import { Badge, Banner, Input, Select, Switch, Table, Link, Tooltip } from "@cloudflare/kumo";
import { FireIcon, WarningIcon } from "@phosphor-icons/react";
import { useScopedApi, useShell } from "../shell.tsx";
import { coverageNeed, isScannerTool, num, plural, SCORED_SEVERITIES, setParams, totalScored, useLocation, type RepoRow, type ReposResponse } from "../lib.ts";
import { Flag, ListCard, NoRows, Page, PageState, SeverityBadge, unreadableText } from "../components/ui.tsx";
import { MoreNames } from "../components/full-list.tsx";
import { CopyMenu, DownloadCsvButton, SelectPage, SelectRow, SelectionBar, downloadCsv, useSelection } from "../components/selection.tsx";

const TITLE = "Repositories";
const DESCRIPTION =
  "Every repository Keelson can read: how its default branch is protected and its open findings, and on GitHub also secret scanning, open security alerts and what it depends on.";

/** Open alerts by kind; Dependabot and code scanning count critical and high only. */
const ALERTS: [keyof RepoRow["alerts"], string][] = [
  ["secrets", "Leaked secrets"],
  ["dependabot", "Dependabot"],
  ["codeScanning", "Code scanning"],
];

const ALL = "all";
const VISIBILITY = { public: "Public", private: "Private", internal: "Internal", archived: "Archived" };
const keyOf = (r: RepoRow) => `${r.accountId ?? ""}/${r.name}`;
/** "owner/repo", or the bare name when the scan didn't record the organization's login. */
const fullName = (r: RepoRow) => (r.owner ? `${r.owner}/${r.name}` : r.name);
/** Where the repository is opened: the address its scan recorded (a platform people host themselves), else GitHub's. */
const linkTo = (r: RepoRow) => r.url ?? (r.owner ? `https://github.com/${r.owner}/${r.name}` : r.name);
const languagesOf = (r: RepoRow) => r.dependencies?.languages.map((l) => l.name) ?? [];

export function RepositoriesPage() {
  const { multi, session } = useShell();
  const { params } = useLocation();
  const { data, error, loading, reload } = useScopedApi<ReposResponse>("/api/repos");
  const selection = useSelection(["q", "issues", "language", "visibility"].map((k) => params.get(k)));
  if (error || !data?.scan || !data.repos) {
    return (
      <PageState
        title={TITLE}
        description={DESCRIPTION}
        error={error}
        loading={!data && loading}
        empty={!!data}
        retry={reload}
        emptyText={data?.scan ? unreadableText(data.coverage, "repos", "repositories") : undefined}
      />
    );
  }
  // Secret scanning, security alerts and Pages are read on GitHub only: a view without any shows the rest.
  const scanners = data.repos.some((r) => r.secretScanning != null || !!r.pages || Object.values(r.alerts).some((n) => n != null));
  const q = (params.get("q") || "").toLowerCase();
  const issuesOnly = params.get("issues") === "1";
  const language = params.get("language");
  const visibility = params.get("visibility");
  // Languages by how many repositories have them, from GitHub's own count of each repository's code.
  const languageCounts = new Map<string, number>();
  for (const r of data.repos) for (const l of languagesOf(r)) languageCounts.set(l, (languageCounts.get(l) ?? 0) + 1);
  const languages = Object.fromEntries([...languageCounts].sort((a, b) => b[1] - a[1]).map(([l, n]) => [l, `${l} (${num(n)})`]));
  const repos = data.repos
    .filter(
      (r) =>
        (!q || `${r.name} ${r.account || ""} ${languagesOf(r).join(" ")}`.toLowerCase().includes(q)) &&
        (!issuesOnly || totalScored(r.findings) > 0) &&
        (!language || languagesOf(r).includes(language)) &&
        (!visibility || (visibility === "archived" ? r.archived : r.visibility === visibility && !r.archived)),
    )
    .sort((a, b) => Number(a.archived) - Number(b.archived) || totalScored(b.findings) - totalScored(a.findings) || a.name.localeCompare(b.name));

  const picked = repos.filter((r) => selection.has(keyOf(r)));

  // Dependencies need the App's Contents permission and Anchore's tools: say which is missing, once, instead of in every row.
  const sbomGaps = data.coverage.filter((c) => !c.ok && ["manifests", "syft", "grype", "grant"].includes(c.key ?? ""));

  return (
    <Page
      title={TITLE}
      description={DESCRIPTION}
      actions={
        repos.some((r) => r.dependencies?.packages != null) && (
          <Link variant="plain" href="/dependencies" className="text-sm">
            Every dependency, vulnerability and license
          </Link>
        )
      }
    >
      {sbomGaps.length > 0 && (
        <Banner
          variant="alert"
          icon={<WarningIcon weight="fill" />}
          title={sbomGaps.some((c) => c.key === "manifests") ? "Dependencies aren't read yet" : "Some dependency data isn't read"}
          description={
            <ul className="list-disc space-y-1 pl-5">
              {sbomGaps.map((c) => (
                <li key={c.key}>
                  {c.label}: {c.message ?? `needs ${coverageNeed(c, session.install)}.`}
                  {c.message && isScannerTool(c.key) && <span className="text-kumo-subtle"> Needs: {coverageNeed(c, session.install)}.</span>}
                </li>
              ))}
            </ul>
          }
        />
      )}
      <ListCard
        toolbar={
          selection.keys.size > 0 ? (
            <SelectionBar selection={selection} noun={["repository", "repositories"]} total={repos.length} pageKeys={repos.map(keyOf)}>
              <CopyMenu
                items={[
                  { label: "Repositories (owner/repo)", run: () => ({ lines: picked.map(fullName), what: ["repository", "repositories"] }) },
                  {
                    label: "Repository links",
                    run: () => ({
                      lines: picked.map(linkTo),
                      what: ["repository link", "repository links"],
                    }),
                  },
                ]}
              />
              <DownloadCsvButton
                onClick={() =>
                  downloadCsv("keelson-repositories", [
                    [
                      "repository",
                      "account",
                      "visibility",
                      "archived",
                      "default branch",
                      "protection",
                      "secret scanning",
                      "push protection",
                      "languages",
                      "packages",
                      "vulnerable packages",
                      "exploited",
                      "critical findings",
                      "high findings",
                      "medium findings",
                      "low findings",
                    ],
                    ...picked.map((r) => [
                      fullName(r),
                      r.account ?? "",
                      r.visibility,
                      r.archived,
                      r.defaultBranch,
                      r.protection ?? "",
                      r.secretScanning ?? "",
                      r.pushProtection ?? "",
                      languagesOf(r).join(" "),
                      r.dependencies?.packages ?? "",
                      r.dependencies?.vulnerable ?? "",
                      r.dependencies?.exploited ?? "",
                      r.findings.critical,
                      r.findings.high,
                      r.findings.medium,
                      r.findings.low,
                    ]),
                  ])
                }
              />
            </SelectionBar>
          ) : (
            <>
              <Input
                className="w-full min-w-48 sm:w-72"
                aria-label="Search repositories"
                placeholder="Repository or language"
                value={params.get("q") || ""}
                onChange={(e) => setParams({ q: e.target.value || null })}
              />
              <Select
                aria-label="Language"
                className="min-w-36 flex-1 sm:w-52 sm:flex-none"
                value={language ?? ALL}
                onValueChange={(v) => setParams({ language: v === ALL ? null : String(v) })}
                items={{ [ALL]: "Every language", ...languages }}
              />
              <Select
                aria-label="Visibility"
                className="min-w-36 flex-1 sm:w-40 sm:flex-none"
                value={visibility ?? ALL}
                onValueChange={(v) => setParams({ visibility: v === ALL ? null : String(v) })}
                items={{ [ALL]: "Any visibility", ...VISIBILITY }}
              />
              <span className="inline-flex items-center gap-2 text-sm text-kumo-subtle">
                <Switch
                  aria-label="Only repositories with open findings"
                  checked={issuesOnly}
                  onCheckedChange={(v: boolean) => setParams({ issues: v ? "1" : null })}
                />
                <span aria-hidden>Only repositories with open findings</span>
              </span>
            </>
          )
        }
        footer={
          <span>
            {repos.length === data.repos.length
              ? plural(data.repos.length, "repository", "repositories")
              : `${num(repos.length)} of ${plural(data.repos.length, "repository", "repositories")}`}{" "}
            · most findings first, archived last
          </span>
        }
      >
        {!repos.length ? (
          <NoRows>No repositories match.</NoRows>
        ) : (
          <Table layout="auto">
            <Table.Header variant="compact">
              <Table.Row>
                <Table.Head className="w-10">
                  <SelectPage selection={selection} keys={repos.map(keyOf)} label="Select every repository shown" />
                </Table.Head>
                <Table.Head sticky="left">Repository</Table.Head>
                <Table.Head className="whitespace-nowrap">Default branch</Table.Head>
                {scanners && (
                  <>
                    <Table.Head className="whitespace-nowrap">Secret scanning</Table.Head>
                    <Table.Head className="whitespace-nowrap">Push protection</Table.Head>
                    <Table.Head className="whitespace-nowrap">Open alerts</Table.Head>
                  </>
                )}
                <Table.Head className="whitespace-nowrap">Dependencies</Table.Head>
                {scanners && <Table.Head className="whitespace-nowrap">Pages</Table.Head>}
                <Table.Head className="whitespace-nowrap">Open findings</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {repos.map((r) => {
                // Findings record the repository as their zone; the account is part of the link, as organizations can share repository names.
                const href = `/findings?zone=${encodeURIComponent(r.name)}${r.accountId ? `&account=${r.accountId}` : ""}&status=all`;
                const page = r.dependencies && r.accountId ? `/repositories/${encodeURIComponent(r.accountId)}/${encodeURIComponent(r.name)}` : null;
                const alerts = ALERTS.filter(([k]) => r.alerts[k]);
                return (
                  <Table.Row key={`${r.accountId}/${r.name}`}>
                    <Table.Cell>
                      <SelectRow selection={selection} id={keyOf(r)} label={`Select ${r.name}`} />
                    </Table.Cell>
                    <Table.Cell sticky="left" className="whitespace-nowrap">
                      <span className="inline-flex items-center gap-2">
                        <Link variant="plain" href={page ?? href}>
                          {r.name}
                        </Link>
                        {r.visibility !== "private" && <Badge variant="outline">{r.visibility === "public" ? "Public" : "Internal"}</Badge>}
                        {r.archived && <Badge variant="neutral">Archived</Badge>}
                      </span>
                      {multi && <div className="max-w-80 truncate text-sm text-kumo-subtle">{r.account}</div>}
                    </Table.Cell>
                    <Table.Cell className="whitespace-nowrap">
                      <span className="font-mono text-xs text-kumo-subtle">{r.defaultBranch}</span>{" "}
                      {r.protection == null ? (
                        <span className="text-kumo-subtle">n/a</span>
                      ) : r.protection === "None" ? (
                        <Badge variant="warning">Unprotected</Badge>
                      ) : (
                        <span className="text-kumo-default">{r.protection}</span>
                      )}
                    </Table.Cell>
                    {scanners && (
                      <>
                        <Table.Cell className="whitespace-nowrap">
                          {/* Free on public repositories; on private ones it needs GitHub Secret Protection, so off there is a softer warning. */}
                          <Flag value={r.archived ? null : r.secretScanning} warn={r.visibility === "private"} />
                        </Table.Cell>
                        <Table.Cell className="whitespace-nowrap">
                          <Flag value={r.archived || !r.secretScanning ? null : r.pushProtection} />
                        </Table.Cell>
                        <Table.Cell>
                          {alerts.length ? (
                            <span className="flex max-w-md flex-wrap gap-x-4 gap-y-1">
                              {alerts.map(([k, label]) => (
                                <span key={k} className="whitespace-nowrap text-kumo-subtle">
                                  {label} <span className="tabular-nums text-kumo-default">{num(r.alerts[k] ?? 0)}</span>
                                </span>
                              ))}
                            </span>
                          ) : (
                            <span className="text-kumo-subtle">None</span>
                          )}
                        </Table.Cell>
                      </>
                    )}
                    <Table.Cell className="whitespace-nowrap">
                      <Dependencies r={r} href={page} />
                    </Table.Cell>
                    {scanners && <Table.Cell className="whitespace-nowrap text-kumo-subtle">{r.pages ?? "None"}</Table.Cell>}
                    <Table.Cell>
                      <Link variant="plain" href={href} className="flex items-center gap-3 whitespace-nowrap">
                        {SCORED_SEVERITIES.filter((s) => r.findings[s]).map((s) => (
                          <span key={s} className="inline-flex items-center gap-1.5">
                            <SeverityBadge severity={s} />
                            <span className="tabular-nums text-kumo-subtle">{r.findings[s]}</span>
                          </span>
                        ))}
                        {!SCORED_SEVERITIES.some((s) => r.findings[s]) && <span className="text-kumo-subtle">None</span>}
                      </Link>
                    </Table.Cell>
                  </Table.Row>
                );
              })}
            </Table.Body>
          </Table>
        )}
      </ListCard>
    </Page>
  );
}

/** What a repository depends on, in a cell: packages and projects, then its worst known vulnerabilities. */
function Dependencies({ r, href }: { r: RepoRow; href: string | null }) {
  const d = r.dependencies;
  if (!d) return <span className="text-kumo-subtle">{r.archived ? "n/a" : "Not read"}</span>;
  const v = d.vulns;
  const serious = v ? (["critical", "high"] as const).filter((s) => v[s]) : [];
  return (
    <div className="flex flex-col gap-1">
      <span className="text-kumo-default">
        {d.packages == null ? "Projects only" : plural(d.packages, "package", "packages")}
        {d.parts > 1 && <span className="text-kumo-subtle"> · {num(d.parts)} projects</span>}
      </span>
      <span className="inline-flex items-center gap-2 text-sm text-kumo-subtle">
        <span>
          {d.ecosystems.slice(0, 3).join(", ") || "No manifests"}
          <MoreNames names={d.ecosystems} shown={3} title={`Package managers in ${r.name}`} noun={["package manager", "package managers"]} />
        </span>
        {(d.exploited ?? 0) > 0 && (
          <Tooltip content="Vulnerabilities attackers are known to exploit (CISA KEV)">
            <Badge variant="red" icon={<FireIcon weight="fill" />}>
              {num(d.exploited ?? 0)} exploited
            </Badge>
          </Tooltip>
        )}
        {d.unlocked > 0 && (
          <Tooltip content="Projects that install dependencies without a lock file or pinned versions">
            <Badge variant="warning">{d.unlocked === 1 ? "No lock file" : `${num(d.unlocked)} without a lock file`}</Badge>
          </Tooltip>
        )}
        {serious.map((s) => (
          <span key={s} className="inline-flex items-center gap-1.5">
            <SeverityBadge severity={s} />
            <span className="tabular-nums">{num(v![s])}</span>
          </span>
        ))}
        {href && d.packages != null && (
          <Link variant="plain" href={href}>
            Details
          </Link>
        )}
      </span>
    </div>
  );
}
