// GitHub repositories: how each default branch is protected, whether secret
// scanning and push protection are on, open security alerts, the Pages site, and
// open findings. The GitHub counterpart of Zones, Projects and Regions.

import { Badge, Input, Switch, Table } from "@cloudflare/kumo";
import { useScopedApi, useShell } from "../shell.tsx";
import { link, num, plural, SCORED_SEVERITIES, setParams, totalScored, useLocation, type RepoRow, type ReposResponse } from "../lib.ts";
import { Flag, ListCard, NoRows, Page, PageState, SeverityBadge, unreadableText } from "../components/ui.tsx";

const TITLE = "Repositories";
const DESCRIPTION = "Every repository the GitHub App can read: how its default branch is protected, secret scanning, open security alerts and open findings.";

/** Open alerts by kind; Dependabot and code scanning count critical and high only. */
const ALERTS: [keyof RepoRow["alerts"], string][] = [
  ["secrets", "Leaked secrets"],
  ["dependabot", "Dependabot"],
  ["codeScanning", "Code scanning"],
];

export function RepositoriesPage() {
  const { multi } = useShell();
  const { params } = useLocation();
  const { data, error, loading, reload } = useScopedApi<ReposResponse>("/api/repos");
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
  const q = (params.get("q") || "").toLowerCase();
  const issuesOnly = params.get("issues") === "1";
  const repos = data.repos
    .filter((r) => (!q || `${r.name} ${r.account || ""}`.toLowerCase().includes(q)) && (!issuesOnly || totalScored(r.findings) > 0))
    .sort((a, b) => Number(a.archived) - Number(b.archived) || totalScored(b.findings) - totalScored(a.findings) || a.name.localeCompare(b.name));

  return (
    <Page title={TITLE} description={DESCRIPTION}>
      <ListCard
        toolbar={
          <>
            <Input
              className="w-full min-w-48 sm:w-72"
              aria-label="Search repositories"
              placeholder="Search repositories"
              value={params.get("q") || ""}
              onChange={(e) => setParams({ q: e.target.value || null })}
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
                <Table.Head sticky="left">Repository</Table.Head>
                <Table.Head className="whitespace-nowrap">Default branch</Table.Head>
                <Table.Head className="whitespace-nowrap">Secret scanning</Table.Head>
                <Table.Head className="whitespace-nowrap">Push protection</Table.Head>
                <Table.Head className="whitespace-nowrap">Open alerts</Table.Head>
                <Table.Head className="whitespace-nowrap">Pages</Table.Head>
                <Table.Head className="whitespace-nowrap">Open findings</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {repos.map((r) => {
                // Findings record the repository as their zone; the account is part of the link, as organizations can share repository names.
                const href = `/findings?zone=${encodeURIComponent(r.name)}${r.accountId ? `&account=${r.accountId}` : ""}&status=all`;
                const alerts = ALERTS.filter(([k]) => r.alerts[k]);
                return (
                  <Table.Row key={`${r.accountId}/${r.name}`}>
                    <Table.Cell sticky="left" className="whitespace-nowrap">
                      <span className="inline-flex items-center gap-2">
                        <a className="text-kumo-link hover:underline" {...link(href)}>
                          {r.name}
                        </a>
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
                    <Table.Cell className="whitespace-nowrap text-kumo-subtle">{r.pages ?? "None"}</Table.Cell>
                    <Table.Cell>
                      <div className="flex items-center gap-3 whitespace-nowrap">
                        {SCORED_SEVERITIES.filter((s) => r.findings[s]).map((s) => (
                          <span key={s} className="inline-flex items-center gap-1.5">
                            <SeverityBadge severity={s} />
                            <span className="tabular-nums text-kumo-subtle">{r.findings[s]}</span>
                          </span>
                        ))}
                        {!SCORED_SEVERITIES.some((s) => r.findings[s]) && <span className="text-kumo-subtle">None</span>}
                      </div>
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
