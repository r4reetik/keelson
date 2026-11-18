// Sonar: each entity's external attack surface. Its hostnames (from the entity's DNS,
// certificate logs, Shodan, load balancer rules and Amass) and what serves them, each
// followed into AWS or Alibaba Cloud (load balancer, matching rules, targets); the load balancers; the
// public addresses with what Shodan has seen open there and what security groups let
// anyone reach; and its domains with where their DNS lives and who issues their
// certificates. The internet's counterpart of Zones and Regions. Rows can be
// picked to copy their names, addresses or open ports, or download them.

import { useState } from "react";
import { Badge, Button, Dialog, Input, Switch, Table, Tabs, Link } from "@cloudflare/kumo";
import { BroadcastIcon } from "@phosphor-icons/react";
import { useScopedApi, useShell } from "../shell.tsx";
import {
  dateTime,
  navigate,
  num,
  plural,
  PROVIDER_INFO,
  SCORED_SEVERITIES,
  setParams,
  totalScored,
  useLocation,
  type SeverityCounts,
  type SurfaceHostRoute,
  type SurfaceListener,
  type SurfaceLoadBalancerRow,
  type SurfaceResponse,
} from "../lib.ts";
import { Card, DialogHeader, ListCard, NoRows, Page, PageState, SeverityBadge, unreadableText } from "../components/ui.tsx";
import { CopyMenu, DownloadCsvButton, SelectPage, SelectRow, SelectionBar, downloadCsv, useSelection, type CopyItem } from "../components/selection.tsx";

const TITLE = "Attack surface";
const DESCRIPTION =
  "Sonar: what each entity exposes to the internet. Hostnames from its DNS, certificate logs, Shodan, load balancer rules and Amass, followed to the load balancers and servers behind them, the addresses they point at with what is open there, and its domains.";

const VIEWS = ["hosts", "balancers", "addresses", "domains"] as const;
type View = (typeof VIEWS)[number];

function Findings({ counts }: { counts: SeverityCounts }) {
  const any = SCORED_SEVERITIES.some((s) => counts[s]);
  return (
    <div className="flex items-center gap-3 whitespace-nowrap">
      {SCORED_SEVERITIES.filter((s) => counts[s]).map((s) => (
        <span key={s} className="inline-flex items-center gap-1.5">
          <SeverityBadge severity={s} />
          <span className="tabular-nums text-kumo-subtle">{counts[s]}</span>
        </span>
      ))}
      {!any && <span className="text-kumo-subtle">None</span>}
    </div>
  );
}

const SCHEME = (internetFacing: boolean) => (internetFacing ? <Badge variant="neutral">Internet-facing</Badge> : <Badge variant="outline">Internal</Badge>);

const TYPE: Record<string, string> = { application: "Application", network: "Network", gateway: "Gateway", classic: "Classic" };
/** Each cloud's names for its kinds of load balancer; rows stored before Alibaba Cloud have no cloud and are AWS's. */
const LB_TYPE: Record<"aws" | "alibaba", Record<string, string>> = { aws: TYPE, alibaba: { application: "ALB", network: "NLB", classic: "CLB" } };
const typeOf = (lb: { provider?: "aws" | "alibaba"; type: string }) => LB_TYPE[lb.provider ?? "aws"][lb.type] ?? lb.type;

/** Open findings by severity, as CSV columns. */
const counts = (c: SeverityCounts) => [c.critical, c.high, c.medium, c.low];

const WEB: Record<string, string> = { open: "Anyone on 80/443", cloudflare: "Only Cloudflare", other: "Some public ranges" };

/** A listener's routes: what each matches, what it does, and the targets behind it. */
function Routes({ listeners }: { listeners: SurfaceListener[] }) {
  if (!listeners.length) return <p className="text-sm text-kumo-subtle">No listeners.</p>;
  return (
    <div className="flex flex-col gap-5">
      {listeners.map((l) => (
        <div key={`${l.port}/${l.protocol}`}>
          <div className="mb-2 text-sm font-semibold text-kumo-default">
            Port {l.port ?? "?"} · {l.protocol}
          </div>
          {!l.routes ? (
            <p className="text-sm text-kumo-subtle">Its rules couldn't be read.</p>
          ) : (
            <Table layout="auto">
              <Table.Header variant="compact">
                <Table.Row>
                  <Table.Head className="whitespace-nowrap">Rule</Table.Head>
                  <Table.Head className="whitespace-nowrap">Matches</Table.Head>
                  <Table.Head className="whitespace-nowrap">Action</Table.Head>
                  <Table.Head className="whitespace-nowrap">Targets</Table.Head>
                </Table.Row>
              </Table.Header>
              <Table.Body>
                {l.routes.map((r) => (
                  <Table.Row key={r.rule}>
                    <Table.Cell className="whitespace-nowrap tabular-nums text-kumo-subtle">{r.rule === "default" ? "Default" : r.rule}</Table.Cell>
                    <Table.Cell className="min-w-56 max-w-80 font-mono text-xs [overflow-wrap:anywhere]">{r.match}</Table.Cell>
                    <Table.Cell className="text-kumo-default">{r.action}</Table.Cell>
                    <Table.Cell>
                      {!r.targets ? (
                        <span className="text-kumo-subtle">Couldn't be read</span>
                      ) : !r.targets.length ? (
                        <span className="text-kumo-subtle">None</span>
                      ) : (
                        <ul className="flex flex-col gap-1">
                          {r.targets.map((t) => (
                            <li key={`${t.label}/${t.port}`} className="text-sm">
                              <span className="text-kumo-default">{t.label}</span>
                              <span className="text-kumo-subtle">
                                {t.port != null && ` :${t.port}`}
                                {t.health && ` · ${t.health}`}
                                {t.publicIp && ` · public ${t.publicIp}`}
                              </span>{" "}
                              {t.direct && <Badge variant="error">Reachable without the load balancer</Badge>}
                            </li>
                          ))}
                        </ul>
                      )}
                    </Table.Cell>
                  </Table.Row>
                ))}
              </Table.Body>
            </Table>
          )}
        </div>
      ))}
    </div>
  );
}

/** A hostname's or load balancer's path into the cloud that serves it, in a dialog. */
function RouteDialog({
  title,
  points,
  via,
  lb,
  listeners,
  address,
  onClose,
}: {
  title: string;
  /** The hostname's DNS answer, when the dialog is for a hostname. */
  points?: string;
  /** Load balancers in front of `lb` that the hostname reaches first. */
  via?: string[];
  lb: SurfaceLoadBalancerRow | null;
  listeners: SurfaceListener[];
  address?: { ip: string; resource: string; open: string[] | null } | null;
  onClose: () => void;
}) {
  return (
    <Dialog.Root open onOpenChange={(o: boolean) => !o && onClose()}>
      <Dialog size="xl" className="max-h-[calc(100vh-6rem)] overflow-y-auto p-6 sm:w-[75vw]">
        <DialogHeader
          title={title}
          description={
            lb
              ? `${typeOf(lb)} load balancer ${lb.name} in ${lb.awsAccount}, ${lb.region}. Rules are listed in the order the load balancer tries them.`
              : "Where requests for this hostname go in the cloud account that serves it."
          }
        />
        {lb && (
          <dl className="mb-5 grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1.5 text-sm">
            {points && (
              <>
                <dt className="text-kumo-subtle">DNS</dt>
                <dd className="font-mono text-xs [overflow-wrap:anywhere]">{points}</dd>
              </>
            )}
            {via && via.length > 0 && (
              <>
                <dt className="text-kumo-subtle">Through</dt>
                <dd>
                  {via.join(" → ")}, which forwards to {lb.name}
                </dd>
              </>
            )}
            <dt className="text-kumo-subtle">Scheme</dt>
            <dd>{SCHEME(lb.internetFacing)}</dd>
            <dt className="text-kumo-subtle">Its security groups admit</dt>
            <dd>{lb.web ? WEB[lb.web] : "Not known (no groups of its own, or a prefix list that couldn't be read)"}</dd>
            <dt className="text-kumo-subtle">WAF web ACL</dt>
            <dd>{lb.waf == null ? "Not known" : lb.waf ? "Yes" : "None"}</dd>
            <dt className="text-kumo-subtle">Hostnames that point at it</dt>
            <dd className="break-words">{lb.hosts.length ? lb.hosts.join(", ") : "None of the entity's"}</dd>
            {lb.unpointed.length > 0 && (
              <>
                <dt className="text-kumo-subtle">Routed, but DNS doesn't point here</dt>
                <dd className="break-words">{lb.unpointed.join(", ")}</dd>
              </>
            )}
          </dl>
        )}
        {address && (
          <dl className="mb-5 grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1.5 text-sm">
            {points && !lb && (
              <>
                <dt className="text-kumo-subtle">DNS</dt>
                <dd className="font-mono text-xs [overflow-wrap:anywhere]">{points}</dd>
              </>
            )}
            <dt className="text-kumo-subtle">Address</dt>
            <dd className="font-mono">{address.ip}</dd>
            <dt className="text-kumo-subtle">Held by</dt>
            <dd>{address.resource}</dd>
            <dt className="text-kumo-subtle">Open to anyone</dt>
            <dd>{address.open == null ? "Not known" : address.open.length ? address.open.join(", ") : "Nothing"}</dd>
          </dl>
        )}
        {lb && <Routes listeners={listeners} />}
      </Dialog>
    </Dialog.Root>
  );
}

/** Findings on one hostname, address or domain: they record it as their resource. */
const findingsHref = (resource: string, accountId?: string) =>
  `/findings?q=${encodeURIComponent(resource)}${accountId ? `&account=${accountId}` : ""}&status=all`;

export function SurfacePage() {
  const { multi, view: shellView, can } = useShell();
  const { params } = useLocation();
  const { data, error, loading, reload } = useScopedApi<SurfaceResponse>("/api/surface");
  const [open, setOpen] = useState<{ host?: string; lb?: string; accountId?: string } | null>(null);
  const selection = useSelection(["view", "q", "issues"].map((k) => params.get(k)));
  // Before Sonar watches any entity in view, this page is where it's offered.
  const watched = shellView.accounts.some((a) => PROVIDER_INFO[a.provider].perEntity);
  if (!watched) {
    const entity = shellView.accounts.length ? shellView.accounts[0].entityId : null;
    const one = new Set(shellView.accounts.map((a) => a.entityId)).size === 1;
    return (
      <Page title={TITLE} description={DESCRIPTION}>
        <Card
          title="Sonar isn't watching this view yet"
          description="Sonar starts from the domains, DNS records and addresses your connected accounts already have. It finds more hostnames in certificate transparency logs and Shodan, and asks Shodan what it has seen open on your addresses. It sends nothing to your hosts. A Shodan API key is optional: it adds products, versions and subdomains."
        >
          {can("accounts") ? (
            <Button
              variant="primary"
              icon={<BroadcastIcon />}
              onClick={() => navigate(`/accounts/add/internet${one && entity != null ? `?entity=${entity}` : ""}`)}
            >
              Watch from the internet
            </Button>
          ) : (
            <p className="text-sm text-kumo-subtle">Someone with the Manager or Admin role can turn it on, under Accounts.</p>
          )}
        </Card>
      </Page>
    );
  }
  if (error || !data?.scan || !data.surface) {
    return (
      <PageState
        title={TITLE}
        description={DESCRIPTION}
        error={error}
        loading={!data && loading}
        empty={!!data}
        retry={reload}
        emptyText={data?.scan ? unreadableText(data.coverage, "related", "attack surface") : undefined}
      />
    );
  }
  const s = data.surface;
  const view: View = (VIEWS as readonly string[]).includes(params.get("view") || "") ? (params.get("view") as View) : "hosts";
  const q = (params.get("q") || "").toLowerCase();
  const issuesOnly = params.get("issues") === "1";
  const keep = (text: string, counts: SeverityCounts) => (!q || text.toLowerCase().includes(q)) && (!issuesOnly || totalScored(counts) > 0);
  const byFindings = <T extends { findings: SeverityCounts }>(a: T, b: T) => totalScored(b.findings) - totalScored(a.findings);

  const hosts = s.hosts
    .filter((h) => keep(`${h.name} ${h.points} ${h.servedBy} ${h.account || ""}`, h.findings))
    .sort((a, b) => byFindings(a, b) || a.name.localeCompare(b.name));
  const addresses = s.addresses
    .filter((a) => keep(`${a.ip} ${a.hosts.join(" ")} ${a.shodan?.products.join(" ") ?? ""} ${a.account || ""}`, a.findings))
    .sort(
      (a, b) => byFindings(a, b) || (b.shodan?.ports.length ?? 0) - (a.shodan?.ports.length ?? 0) || a.ip.localeCompare(b.ip, undefined, { numeric: true }),
    );
  const domains = s.domains.filter((d) => keep(`${d.name} ${d.account || ""}`, d.findings)).sort((a, b) => byFindings(a, b) || a.name.localeCompare(b.name));
  const allBalancers = s.loadBalancers ?? [];
  const balancers = allBalancers
    .filter((b) => keep(`${b.name} ${b.region} ${b.hosts.join(" ")} ${b.awsAccount} ${b.account ?? ""}`, b.findings))
    .sort((a, b) => byFindings(a, b) || b.hosts.length - a.hosts.length || a.name.localeCompare(b.name));
  const shown = {
    hosts: [hosts.length, s.hosts.length],
    balancers: [balancers.length, allBalancers.length],
    addresses: [addresses.length, s.addresses.length],
    domains: [domains.length, s.domains.length],
  }[view];
  const word = {
    hosts: ["hostname", "hostnames"],
    balancers: ["load balancer", "load balancers"],
    addresses: ["address", "addresses"],
    domains: ["domain", "domains"],
  }[view];
  const lbNamed = (name: string | null, accountId?: string) => allBalancers.find((b) => b.name === name && b.accountId === accountId) ?? null;
  const openHost = open?.host ? s.hosts.find((h) => h.name === open.host && h.accountId === open.accountId) : undefined;
  const openLb = open?.lb ? lbNamed(open.lb, open.accountId) : openHost?.route ? lbNamed(openHost.route.loadBalancer, openHost.accountId) : null;
  const account = (a?: string) => multi && a && <div className="max-w-80 truncate text-sm text-kumo-subtle">{a}</div>;

  // Picking rows: each view names its rows by account and name (or address), since entities can share a hostname.
  const hostKey = (h: { accountId?: string; name: string }) => `${h.accountId}/${h.name}`;
  const lbKey = (b: SurfaceLoadBalancerRow) => `${b.accountId}/${b.region}/${b.name}`;
  const ipKey = (a: { accountId?: string; ip: string }) => `${a.accountId}/${a.ip}`;
  const shownKeys = { hosts: hosts.map(hostKey), balancers: balancers.map(lbKey), addresses: addresses.map(ipKey), domains: domains.map(hostKey) }[view];
  const pickedHosts = hosts.filter((h) => selection.has(hostKey(h)));
  const pickedLbs = balancers.filter((b) => selection.has(lbKey(b)));
  const pickedIps = addresses.filter((a) => selection.has(ipKey(a)));
  const pickedDomains = domains.filter((d) => selection.has(hostKey(d)));
  const copyItems: CopyItem[] = {
    hosts: [
      { label: "Hostnames", run: () => ({ lines: pickedHosts.map((h) => h.name), what: ["hostname", "hostnames"] as [string, string] }) },
      { label: "Links (https://…)", run: () => ({ lines: pickedHosts.map((h) => `https://${h.name}`), what: ["link", "links"] as [string, string] }) },
    ],
    balancers: [
      { label: "Load balancer names", run: () => ({ lines: pickedLbs.map((b) => b.name), what: ["load balancer", "load balancers"] as [string, string] }) },
      { label: "Hostnames that reach them", run: () => ({ lines: pickedLbs.flatMap((b) => b.hosts), what: ["hostname", "hostnames"] as [string, string] }) },
    ],
    addresses: [
      { label: "Addresses", run: () => ({ lines: pickedIps.map((a) => a.ip), what: ["address", "addresses"] as [string, string] }) },
      {
        label: "Open ports (address:port)",
        run: () => ({
          lines: pickedIps.flatMap((a) => (a.shodan?.ports ?? []).map((p) => `${a.ip}:${p}`)),
          what: ["open port", "open ports"] as [string, string],
        }),
      },
      { label: "Hostnames on them", run: () => ({ lines: pickedIps.flatMap((a) => a.hosts), what: ["hostname", "hostnames"] as [string, string] }) },
    ],
    domains: [{ label: "Domains", run: () => ({ lines: pickedDomains.map((d) => d.name), what: ["domain", "domains"] as [string, string] }) }],
  }[view];
  const downloadPicked = () =>
    ({
      hosts: () =>
        downloadCsv("keelson-hostnames", [
          ["hostname", "domain", "entity", "served by", "points at", "found in", "critical", "high", "medium", "low"],
          ...pickedHosts.map((h) => [h.name, h.domain, h.account ?? "", h.servedBy, h.points, h.found.join(" "), ...counts(h.findings)]),
        ]),
      balancers: () =>
        downloadCsv("keelson-load-balancers", [
          ["load balancer", "cloud account", "region", "type", "internet-facing", "hostnames", "critical", "high", "medium", "low"],
          ...pickedLbs.map((b) => [b.name, b.awsAccount, b.region, typeOf(b), b.internetFacing, b.hosts.join(" "), ...counts(b.findings)]),
        ]),
      addresses: () =>
        downloadCsv("keelson-addresses", [
          [
            "address",
            "entity",
            "held by",
            "resource",
            "hostnames",
            "open ports (Shodan)",
            "open to anyone",
            "known vulnerabilities",
            "critical",
            "high",
            "medium",
            "low",
          ],
          ...pickedIps.map((a) => [
            a.ip,
            a.account ?? "",
            a.heldBy ?? "",
            a.resource ?? "",
            a.hosts.join(" "),
            a.shodan?.ports.join(" ") ?? "",
            a.open?.join("; ") ?? "",
            a.shodan?.vulns ?? "",
            ...counts(a.findings),
          ]),
        ]),
      domains: () =>
        downloadCsv("keelson-domains", [
          ["domain", "entity", "dns", "critical", "high", "medium", "low"],
          ...pickedDomains.map((d) => [d.name, d.account ?? "", d.dns ?? "", ...counts(d.findings)]),
        ]),
    })[view]();

  return (
    <Page title={TITLE} description={DESCRIPTION}>
      <div>
        <Tabs
          value={view}
          onValueChange={(v) => setParams({ view: v === "hosts" ? null : String(v) })}
          tabs={[
            { value: "hosts", label: `Hostnames ${num(s.hosts.length)}` },
            ...(allBalancers.length ? [{ value: "balancers", label: `Load balancers ${num(allBalancers.length)}` }] : []),
            { value: "addresses", label: `Addresses ${num(s.addresses.length)}` },
            { value: "domains", label: `Domains ${num(s.domains.length)}` },
          ]}
        />
      </div>
      <ListCard
        toolbar={
          selection.keys.size > 0 ? (
            <SelectionBar selection={selection} noun={word as [string, string]} total={shown[0]} pageKeys={shownKeys}>
              <CopyMenu items={copyItems} />
              <DownloadCsvButton onClick={downloadPicked} />
            </SelectionBar>
          ) : (
            <>
              <Input
                className="w-full min-w-48 sm:w-72"
                aria-label={`Search ${word[1]}`}
                placeholder={`Search ${word[1]}`}
                value={params.get("q") || ""}
                onChange={(e) => setParams({ q: e.target.value || null })}
              />
              <span className="inline-flex items-center gap-2 text-sm text-kumo-subtle">
                <Switch aria-label="Only with open findings" checked={issuesOnly} onCheckedChange={(v: boolean) => setParams({ issues: v ? "1" : null })} />
                <span aria-hidden>Only with open findings</span>
              </span>
            </>
          )
        }
        footer={
          <span>
            {shown[0] === shown[1] ? plural(shown[1], word[0], word[1]) : `${num(shown[0])} of ${plural(shown[1], word[0], word[1])}`} · most findings first
            {view === "hosts" && s.unresolved > 0 && ` · ${plural(s.unresolved, "name")} found elsewhere don't resolve`}
            {view === "hosts" && s.amass && ` · Amass added ${plural(s.amass.added, "hostname")} in ${plural(s.amass.minutes, "minute")}`}
          </span>
        }
      >
        {view === "hosts" &&
          (!hosts.length ? (
            <NoRows>No hostnames match.</NoRows>
          ) : (
            <Table layout="auto">
              <Table.Header variant="compact">
                <Table.Row>
                  <Table.Head className="w-10">
                    <SelectPage selection={selection} keys={shownKeys} label="Select every hostname shown" />
                  </Table.Head>
                  <Table.Head sticky="left">Hostname</Table.Head>
                  <Table.Head className="whitespace-nowrap">Served by</Table.Head>
                  <Table.Head className="whitespace-nowrap">Path in the cloud</Table.Head>
                  <Table.Head className="whitespace-nowrap">Points at</Table.Head>
                  <Table.Head className="whitespace-nowrap">Found in</Table.Head>
                  <Table.Head className="whitespace-nowrap">Open findings</Table.Head>
                </Table.Row>
              </Table.Header>
              <Table.Body>
                {hosts.map((h) => (
                  <Table.Row key={`${h.accountId}/${h.name}`}>
                    <Table.Cell>
                      <SelectRow selection={selection} id={hostKey(h)} label={`Select ${h.name}`} />
                    </Table.Cell>
                    <Table.Cell sticky="left" className="whitespace-nowrap">
                      <Link variant="plain" href={findingsHref(h.name, h.accountId)}>
                        {h.name}
                      </Link>
                      {account(h.account)}
                    </Table.Cell>
                    <Table.Cell className="whitespace-nowrap">
                      {h.servedBy === "Outside connected accounts" || h.servedBy.includes("isn't connected") ? (
                        <Badge variant="outline">{h.servedBy}</Badge>
                      ) : (
                        <span className="text-kumo-default">{h.servedBy}</span>
                      )}
                    </Table.Cell>
                    <Table.Cell className="whitespace-nowrap">
                      {!h.route ? (
                        <span className="text-kumo-subtle">None</span>
                      ) : (
                        <span className="inline-flex items-center gap-2">
                          <Link variant="plain" render={<button type="button" onClick={() => setOpen({ host: h.name, accountId: h.accountId })} />}>
                            {pathSummary(h.route)}
                          </Link>
                          {bypassable(h.route) && <Badge variant="error">Bypassable</Badge>}
                        </span>
                      )}
                    </Table.Cell>
                    <Table.Cell className="max-w-96 truncate font-mono text-xs text-kumo-subtle" title={h.points}>
                      {h.points}
                    </Table.Cell>
                    <Table.Cell className="whitespace-nowrap text-kumo-subtle">{h.found.join(", ")}</Table.Cell>
                    <Table.Cell>
                      <Findings counts={h.findings} />
                    </Table.Cell>
                  </Table.Row>
                ))}
              </Table.Body>
            </Table>
          ))}
        {view === "balancers" &&
          (!balancers.length ? (
            <NoRows>No load balancers match.</NoRows>
          ) : (
            <Table layout="auto">
              <Table.Header variant="compact">
                <Table.Row>
                  <Table.Head className="w-10">
                    <SelectPage selection={selection} keys={shownKeys} label="Select every load balancer shown" />
                  </Table.Head>
                  <Table.Head sticky="left">Load balancer</Table.Head>
                  <Table.Head className="whitespace-nowrap">Scheme</Table.Head>
                  <Table.Head className="whitespace-nowrap">Hostnames</Table.Head>
                  <Table.Head className="whitespace-nowrap">Rules</Table.Head>
                  <Table.Head className="whitespace-nowrap">Targets</Table.Head>
                  <Table.Head className="whitespace-nowrap">Open findings</Table.Head>
                </Table.Row>
              </Table.Header>
              <Table.Body>
                {balancers.map((b) => {
                  const routes = b.listeners.flatMap((l) => l.routes ?? []);
                  const targets = new Map(routes.flatMap((r) => r.targets ?? []).map((t) => [t.label, t]));
                  const direct = [...targets.values()].filter((t) => t.direct).length;
                  return (
                    <Table.Row key={`${b.accountId}/${b.region}/${b.name}`}>
                      <Table.Cell>
                        <SelectRow selection={selection} id={lbKey(b)} label={`Select ${b.name}`} />
                      </Table.Cell>
                      <Table.Cell sticky="left" className="whitespace-nowrap">
                        <Link variant="plain" render={<button type="button" onClick={() => setOpen({ lb: b.name, accountId: b.accountId })} />}>
                          {b.name}
                        </Link>
                        <div className="text-xs text-kumo-subtle">
                          {typeOf(b)} · {b.awsAccount} · {b.region}
                        </div>
                      </Table.Cell>
                      <Table.Cell className="whitespace-nowrap">{SCHEME(b.internetFacing)}</Table.Cell>
                      <Table.Cell className="max-w-72 truncate text-kumo-subtle" title={b.hosts.join(", ")}>
                        {b.hosts.length ? b.hosts.join(", ") : "None of the entity's"}
                        {b.unpointed.length > 0 && <div className="text-xs">{plural(b.unpointed.length, "routed hostname")} without DNS</div>}
                      </Table.Cell>
                      <Table.Cell className="whitespace-nowrap tabular-nums">
                        {b.listeners.some((l) => !l.routes) ? <span className="text-kumo-subtle">Couldn't read</span> : num(routes.length)}
                      </Table.Cell>
                      <Table.Cell className="whitespace-nowrap">
                        <span className="tabular-nums">{num(targets.size)}</span>
                        {direct > 0 && (
                          <>
                            {" "}
                            <Badge variant="error">{num(direct)} reachable directly</Badge>
                          </>
                        )}
                      </Table.Cell>
                      <Table.Cell>
                        <Findings counts={b.findings} />
                      </Table.Cell>
                    </Table.Row>
                  );
                })}
              </Table.Body>
            </Table>
          ))}
        {view === "addresses" &&
          (!addresses.length ? (
            <NoRows>{s.addresses.length ? "No addresses match." : unreadableText(data.coverage, "shodan", "addresses")}</NoRows>
          ) : (
            <Table layout="auto">
              <Table.Header variant="compact">
                <Table.Row>
                  <Table.Head className="w-10">
                    <SelectPage selection={selection} keys={shownKeys} label="Select every address shown" />
                  </Table.Head>
                  <Table.Head sticky="left">Address</Table.Head>
                  <Table.Head className="whitespace-nowrap">Held by</Table.Head>
                  <Table.Head className="whitespace-nowrap">Hostnames</Table.Head>
                  <Table.Head className="whitespace-nowrap">Open ports (Shodan)</Table.Head>
                  <Table.Head className="whitespace-nowrap">Security groups admit anyone to</Table.Head>
                  <Table.Head className="whitespace-nowrap">Known vulnerabilities</Table.Head>
                  <Table.Head className="whitespace-nowrap">Open findings</Table.Head>
                </Table.Row>
              </Table.Header>
              <Table.Body>
                {addresses.map((a) => (
                  <Table.Row key={`${a.accountId}/${a.ip}`}>
                    <Table.Cell>
                      <SelectRow selection={selection} id={ipKey(a)} label={`Select ${a.ip}`} />
                    </Table.Cell>
                    <Table.Cell sticky="left" className="whitespace-nowrap">
                      <span className="inline-flex items-center gap-2">
                        <Link variant="plain" href={findingsHref(a.ip, a.accountId)} className="font-mono">
                          {a.ip}
                        </Link>
                        {a.origin && <Badge variant="neutral">Origin</Badge>}
                      </span>
                      {account(a.account)}
                    </Table.Cell>
                    <Table.Cell className="whitespace-nowrap">
                      {a.heldBy ?? <span className="text-kumo-subtle">Not a connected account</span>}
                      {a.resource && <div className="max-w-64 truncate text-xs text-kumo-subtle">{a.resource}</div>}
                    </Table.Cell>
                    <Table.Cell className="max-w-72 truncate text-kumo-subtle" title={a.hosts.join(", ")}>
                      {a.hosts.length ? a.hosts.join(", ") : "None"}
                    </Table.Cell>
                    <Table.Cell>
                      {!a.shodan ? (
                        <span className="text-kumo-subtle">Couldn't ask</span>
                      ) : !a.shodan.seen ? (
                        <span className="text-kumo-subtle">Nothing seen</span>
                      ) : (
                        <div className="max-w-80">
                          <div className="font-mono text-xs text-kumo-default">{a.shodan.ports.join(", ") || "None"}</div>
                          {(a.shodan.products.length > 0 || a.shodan.lastSeen) && (
                            <div className="truncate text-xs text-kumo-subtle">
                              {[a.shodan.products.slice(0, 3).join(", "), a.shodan.lastSeen && `seen ${dateTime(a.shodan.lastSeen)}`]
                                .filter(Boolean)
                                .join(" · ")}
                            </div>
                          )}
                        </div>
                      )}
                    </Table.Cell>
                    <Table.Cell className="max-w-64 font-mono text-xs">
                      {a.open == null ? (
                        <span className="font-sans text-kumo-subtle">n/a</span>
                      ) : a.open.length ? (
                        a.open.join(", ")
                      ) : (
                        <span className="font-sans text-kumo-subtle">Nothing</span>
                      )}
                    </Table.Cell>
                    <Table.Cell className="whitespace-nowrap tabular-nums">
                      {a.shodan?.seen ? (
                        a.shodan.vulns ? (
                          num(a.shodan.vulns)
                        ) : (
                          <span className="text-kumo-subtle">None</span>
                        )
                      ) : (
                        <span className="text-kumo-subtle">n/a</span>
                      )}
                    </Table.Cell>
                    <Table.Cell>
                      <Findings counts={a.findings} />
                    </Table.Cell>
                  </Table.Row>
                ))}
              </Table.Body>
            </Table>
          ))}
        {view === "domains" &&
          (!domains.length ? (
            <NoRows>No domains match.</NoRows>
          ) : (
            <Table layout="auto">
              <Table.Header variant="compact">
                <Table.Row>
                  <Table.Head className="w-10">
                    <SelectPage selection={selection} keys={shownKeys} label="Select every domain shown" />
                  </Table.Head>
                  <Table.Head sticky="left">Domain</Table.Head>
                  <Table.Head className="whitespace-nowrap">DNS</Table.Head>
                  <Table.Head className="whitespace-nowrap">Valid certificates</Table.Head>
                  <Table.Head className="whitespace-nowrap">CAA allows</Table.Head>
                  <Table.Head className="whitespace-nowrap">Open findings</Table.Head>
                </Table.Row>
              </Table.Header>
              <Table.Body>
                {domains.map((d) => (
                  <Table.Row key={`${d.accountId}/${d.name}`}>
                    <Table.Cell>
                      <SelectRow selection={selection} id={hostKey(d)} label={`Select ${d.name}`} />
                    </Table.Cell>
                    <Table.Cell sticky="left" className="whitespace-nowrap">
                      <Link variant="plain" href={findingsHref(d.name, d.accountId)}>
                        {d.name}
                      </Link>
                      {account(d.account)}
                    </Table.Cell>
                    <Table.Cell className="whitespace-nowrap">
                      {d.dns ? (
                        PROVIDER_INFO[d.dns].label
                      ) : (
                        <span>
                          <Badge variant="outline">Not in a connected account</Badge>
                          {d.nameservers?.length ? <div className="text-xs text-kumo-subtle">{d.nameservers.slice(0, 2).join(", ")}</div> : null}
                        </span>
                      )}
                    </Table.Cell>
                    <Table.Cell>
                      {d.certificates == null ? (
                        <span className="text-kumo-subtle">Couldn't read the logs</span>
                      ) : (
                        <div className="max-w-80">
                          <div className="tabular-nums">{num(d.certificates)}</div>
                          {d.issuers.length > 0 && <div className="truncate text-xs text-kumo-subtle">{d.issuers.slice(0, 3).join(", ")}</div>}
                        </div>
                      )}
                    </Table.Cell>
                    <Table.Cell className="whitespace-nowrap text-kumo-subtle">
                      {d.caa == null ? "Couldn't look up" : d.caa.length ? d.caa.join(", ") : "Any authority (no CAA)"}
                    </Table.Cell>
                    <Table.Cell>
                      <Findings counts={d.findings} />
                    </Table.Cell>
                  </Table.Row>
                ))}
              </Table.Body>
            </Table>
          ))}
      </ListCard>
      {open && (openHost || openLb) && (
        <RouteDialog
          title={openHost ? openHost.name : openLb!.name}
          points={openHost?.points}
          via={openHost?.route?.via}
          lb={openLb}
          listeners={openHost?.route ? openHost.route.listeners : (openLb?.listeners ?? [])}
          address={openHost?.route?.address}
          onClose={() => setOpen(null)}
        />
      )}
    </Page>
  );
}

type HostRoute = SurfaceHostRoute;

/** "web-alb · 3 rules", "instance web-1 (i-…)". */
function pathSummary(r: HostRoute): string {
  if (r.loadBalancer)
    return `${[...(r.via ?? []), r.loadBalancer].join(" → ")} · ${plural(
      r.listeners.reduce((sum, l) => sum + (l.routes?.length ?? 0), 0),
      "rule",
    )}`;
  return r.address ? r.address.resource : "Cloud account";
}

/** A target behind the hostname's load balancer can be reached without it. */
const bypassable = (r: HostRoute) => r.listeners.some((l) => l.routes?.some((x) => x.targets?.some((t) => t.direct)));
