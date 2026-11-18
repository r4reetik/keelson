// A cloud's resources, in its own words: Alibaba Cloud's ECS instances, CLBs, ALBs
// and NLBs, OSS buckets, RDS, Tair and MongoDB, functions, RAM users and roles.
// Each row says where it is, how the internet reaches it, and its open findings,
// so the question "what of ours is public, and what's wrong with it" has one
// answer. Regions are a filter, not the page's rows: in a cloud with thirty regions
// most of them are empty, and the ones in use are listed with their names.

import { Input, Link, Select, Switch, Table } from "@cloudflare/kumo";
import { GlobeIcon } from "@phosphor-icons/react";
import { useScopedApi, useShell } from "../shell.tsx";
import { num, plural, RESOURCE_GROUPS, SCORED_SEVERITIES, setParams, totalScored, useLocation, type ResourceRow, type ResourcesResponse } from "../lib.ts";
import { ListCard, NoRows, Page, PageState, SeverityBadge, unreadableText } from "../components/ui.tsx";
import { CopyMenu, DownloadCsvButton, downloadCsv } from "../components/selection.tsx";

/** IPv4 addresses in an exposure line ("Public address 203.0.113.7"). */
const IPV4 = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g;

const TITLE = "Resources";
const DESCRIPTION =
  "Every cloud resource Keelson checks, in the cloud's own words: where it is, how the internet reaches it, and its open findings. Regions with nothing in them are left out.";
const ALL = "all";

/** "Singapore (ap-southeast-1)", or the ID alone when the cloud gave no name. */
const regionText = (name: string, label: string | null | undefined) => (label ? `${label} (${name})` : name);

export function ResourcesPage() {
  const { multi } = useShell();
  const { params } = useLocation();
  const { data, error, loading, reload } = useScopedApi<ResourcesResponse>("/api/resources");
  if (error || !data?.scan || !data.resources) {
    return (
      <PageState
        title={TITLE}
        description={DESCRIPTION}
        error={error}
        loading={!data && loading}
        empty={!!data}
        retry={reload}
        emptyText={data?.scan ? unreadableText(data.coverage, "regions", "resources") : undefined}
      />
    );
  }
  const view = data.resources;
  const labels = new Map(view.regions.map((r) => [r.name, r.label]));
  const q = (params.get("q") || "").toLowerCase();
  const group = params.get("group") ?? ALL;
  const region = params.get("region") ?? ALL;
  const publicOnly = params.get("public") === "1";
  const issuesOnly = params.get("issues") === "1";
  const rows = view.rows
    .filter(
      (r) =>
        (group === ALL || r.group === group) &&
        (region === ALL || r.region === region) &&
        (!publicOnly || r.exposure) &&
        (!issuesOnly || totalScored(r.findings) > 0) &&
        (!q || `${r.name} ${r.id} ${r.kind} ${r.exposure ?? ""} ${r.facts.join(" ")} ${r.account ?? ""}`.toLowerCase().includes(q)),
    )
    .sort(
      (a, b) =>
        totalScored(b.findings) - totalScored(a.findings) ||
        Number(!!b.exposure) - Number(!!a.exposure) ||
        a.group.localeCompare(b.group) ||
        a.kind.localeCompare(b.kind) ||
        a.name.localeCompare(b.name),
    );
  const groups = RESOURCE_GROUPS.filter((g) => view.rows.some((r) => r.group === g));
  const regionNames = [...new Set(view.rows.map((r) => r.region))].sort((a, b) => (a === "Global" ? -1 : b === "Global" ? 1 : a.localeCompare(b)));
  const exposed = view.rows.filter((r) => r.exposure).length;
  const pick = (key: string, value: string | null) => setParams({ [key]: value });

  return (
    <Page title={TITLE} description={DESCRIPTION}>
      <ListCard title="Regions in use">
        <div className="flex flex-col gap-2 p-3 text-sm">
          {view.regions.length ? (
            <div className="flex flex-wrap gap-x-6 gap-y-2">
              {view.regions.map((r) => (
                <Link
                  key={`${r.accountId}/${r.name}`}
                  variant="plain"
                  render={<button type="button" onClick={() => pick("region", region === r.name ? null : r.name)} />}
                >
                  <span className={region === r.name ? "font-medium text-kumo-default" : undefined}>{regionText(r.name, r.label)}</span>{" "}
                  <span className="tabular-nums text-kumo-subtle">{num(r.resources)}</span>
                </Link>
              ))}
            </div>
          ) : (
            <span className="text-kumo-subtle">Nothing runs in any region yet: only account-wide resources were found.</span>
          )}
          {(view.emptyRegions > 0 || view.skippedRegions.length > 0) && (
            <span className="text-kumo-subtle">
              {[
                view.emptyRegions ? `${plural(view.emptyRegions, "other enabled region")} ${view.emptyRegions === 1 ? "is" : "are"} empty` : "",
                view.skippedRegions.length ? `${view.skippedRegions.join(", ")} refused the credential, so nothing there was read` : "",
              ]
                .filter(Boolean)
                .join(". ")}
              .
            </span>
          )}
        </div>
      </ListCard>

      <ListCard
        toolbar={
          <>
            <Input
              className="w-full min-w-48 sm:w-64"
              aria-label="Search resources"
              placeholder="Search resources"
              value={params.get("q") || ""}
              onChange={(e) => pick("q", e.target.value || null)}
            />
            <Select
              aria-label="Kind"
              className="min-w-36 flex-1 sm:w-44 sm:flex-none"
              value={group}
              onValueChange={(v) => pick("group", v === ALL ? null : String(v))}
              items={{ [ALL]: "Every kind", ...Object.fromEntries(groups.map((g) => [g, g])) }}
            />
            <Select
              aria-label="Region"
              className="min-w-36 flex-1 sm:w-60 sm:flex-none"
              value={region}
              onValueChange={(v) => pick("region", v === ALL ? null : String(v))}
              items={{
                [ALL]: "Every region",
                ...Object.fromEntries(regionNames.map((n) => [n, n === "Global" ? "Global (account-wide)" : regionText(n, labels.get(n))])),
              }}
            />
            <span className="inline-flex items-center gap-2 text-sm text-kumo-subtle">
              <Switch aria-label="Only resources the internet reaches" checked={publicOnly} onCheckedChange={(v: boolean) => pick("public", v ? "1" : null)} />
              <span aria-hidden>Reachable from the internet</span>
            </span>
            <span className="inline-flex items-center gap-2 text-sm text-kumo-subtle">
              <Switch aria-label="Only resources with open findings" checked={issuesOnly} onCheckedChange={(v: boolean) => pick("issues", v ? "1" : null)} />
              <span aria-hidden>With open findings</span>
            </span>
            <CopyMenu
              label="Copy shown"
              items={[
                { label: "Resource IDs", run: () => ({ lines: rows.map((r) => r.id), what: ["resource ID", "resource IDs"] }) },
                { label: "Names", run: () => ({ lines: rows.map((r) => r.name), what: ["name", "names"] }) },
                {
                  label: "Public addresses",
                  run: () => ({ lines: rows.flatMap((r) => r.exposure?.match(IPV4) ?? []), what: ["public address", "public addresses"] }),
                },
              ]}
            />
            <DownloadCsvButton
              label="Download shown"
              onClick={() =>
                downloadCsv("keelson-resources", [
                  ["kind", "id", "name", "region", "account", "reachable from the internet", "facts", "critical", "high", "medium", "low"],
                  ...rows.map((r) => [
                    r.kind,
                    r.id,
                    r.name,
                    r.region,
                    r.account ?? "",
                    r.exposure ?? "",
                    r.facts.join("; "),
                    r.findings.critical,
                    r.findings.high,
                    r.findings.medium,
                    r.findings.low,
                  ]),
                ])
              }
            />
          </>
        }
        footer={
          <span>
            {rows.length === view.rows.length ? plural(view.rows.length, "resource") : `${num(rows.length)} of ${plural(view.rows.length, "resource")}`} ·{" "}
            {num(exposed)} reachable from the internet · most findings first
          </span>
        }
      >
        {!rows.length ? (
          <NoRows>No resources match.</NoRows>
        ) : (
          <Table layout="auto">
            <Table.Header variant="compact">
              <Table.Row>
                <Table.Head sticky="left">Resource</Table.Head>
                <Table.Head>Region</Table.Head>
                <Table.Head className="whitespace-nowrap">From the internet</Table.Head>
                <Table.Head>Details</Table.Head>
                <Table.Head className="whitespace-nowrap">Open findings</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {rows.map((r) => (
                <ResourceLine key={`${r.accountId}/${r.region}/${r.kind}/${r.id}`} r={r} label={labels.get(r.region)} multi={multi} />
              ))}
            </Table.Body>
          </Table>
        )}
      </ListCard>
    </Page>
  );
}

function ResourceLine({ r, label, multi }: { r: ResourceRow; label: string | null | undefined; multi: boolean }) {
  // Findings record the region as their zone and name the resource; the account is part of the link, as accounts share names.
  const findings = `/findings?zone=${encodeURIComponent(r.region)}&q=${encodeURIComponent(r.id)}${r.accountId ? `&account=${r.accountId}` : ""}`;
  return (
    <Table.Row>
      <Table.Cell sticky="left" className="max-w-96">
        {r.link ? (
          <Link variant="plain" href={r.link} target="_blank" rel="noreferrer" className="break-words">
            {r.name}
          </Link>
        ) : (
          <span className="break-words">{r.name}</span>
        )}
        <div className="truncate text-sm text-kumo-subtle">
          {r.kind}
          {r.id !== r.name ? ` · ${r.id}` : ""}
          {multi && r.account ? ` · ${r.account}` : ""}
        </div>
      </Table.Cell>
      <Table.Cell className="whitespace-nowrap text-kumo-subtle">{r.region === "Global" ? "Global" : (label ?? r.region)}</Table.Cell>
      <Table.Cell className="min-w-44 max-w-72">
        {r.exposure ? (
          <span className="inline-flex items-start gap-1.5 text-sm">
            <GlobeIcon className="mt-0.5 h-4 w-4 shrink-0 text-kumo-warning" aria-label="Reachable from the internet" />
            <span className="break-words">{r.exposure}</span>
          </span>
        ) : (
          <span className="text-sm text-kumo-subtle">Not reachable</span>
        )}
      </Table.Cell>
      <Table.Cell className="min-w-44 max-w-72 text-sm text-kumo-subtle">{r.facts.join(" · ") || "None"}</Table.Cell>
      <Table.Cell>
        {totalScored(r.findings) ? (
          <Link variant="plain" href={findings} className="inline-flex items-center gap-3 whitespace-nowrap">
            {SCORED_SEVERITIES.filter((s) => r.findings[s]).map((s) => (
              <span key={s} className="inline-flex items-center gap-1.5">
                <SeverityBadge severity={s} />
                <span className="tabular-nums text-kumo-subtle">{r.findings[s]}</span>
              </span>
            ))}
          </Link>
        ) : (
          <span className="text-kumo-subtle">None</span>
        )}
      </Table.Cell>
    </Table.Row>
  );
}
