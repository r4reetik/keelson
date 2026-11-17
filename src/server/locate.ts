// Where a finding's addresses and hostnames are in the entity's infrastructure. A
// finding from one platform often names something another platform holds: Cloudflare's
// Security Center reports an RDP server at an address, and that address is an ECS
// instance's EIP in the entity's Alibaba Cloud account, with a security group that
// lets anyone reach port 3389. This follows each address and hostname in a finding
// through what the entity's latest scans published for checks that span platforms
// (DNS records, load balancers, the addresses clouds hold and their open inbound
// rules, released addresses, Vercel and GitHub Pages domains, Sonar's hosts) and says
// what holds it, or that none of the entity's accounts does. It reads only the
// finding's own entity: entities never see each other's infrastructure.

import { PROVIDER_INFO, providerList, type ProviderId } from "../shared/providers.ts";
import {
  LINK_PROVIDER,
  type AwsExposureLink,
  type AwsLoadBalancerLink,
  type DnsHostRecord,
  type LinkKey,
  type LocatedItem,
  type LocatedResponse,
  type ProviderLinks,
  type ScanSnapshot,
} from "../shared/api.ts";
import { alibabaEndpointOf, awsEndpointOf } from "../core/links.ts";
import { inCloudflare, isInternal } from "../core/cloudflare-ranges.ts";
import { DATABASE_PORTS } from "../core/ports.ts";

/** One account's latest scan in the entity. */
export interface EntityScan {
  provider: ProviderId;
  accountId: string;
  account: string;
  snap: Partial<ScanSnapshot>;
}

/** What a finding says, from which addresses, hostnames and ports are read. */
export interface LocateInput {
  accountId: string;
  /** The finding's zone: a finding about a whole zone isn't about its apex hostname. */
  zone: string | null;
  title: string;
  checkId: string;
  resource: string;
  detail: string;
  evidence: unknown;
}

type Rules = AwsExposureLink["open"];

interface Holder {
  provider: ProviderId;
  accountId: string;
  account: string;
  /** "ECS instance web-1 (i-…)", "load balancer web-alb". */
  what: string;
  region: string | null;
  link: string | null;
  /** Inbound rules open to anyone; null when unknown or not applicable. */
  open: Rules;
  /** A load balancer's listener ports. */
  listeners?: number[];
}

interface DnsRecord {
  provider: ProviderId;
  /** "Route 53", "Cloudflare DNS". */
  service: string;
  accountId: string;
  record: DnsHostRecord;
}

/** The lists each kind of thing is published in. A new cloud adds its keys here. */
const ADDRESS_LISTS: LinkKey[] = ["awsAddresses", "alibabaAddresses"];
const EXPOSURE: LinkKey[] = ["awsExposure", "alibabaExposure"];
const RELEASED: LinkKey[] = ["awsReleased", "alibabaReleased"];
const LOAD_BALANCERS: LinkKey[] = ["awsLoadBalancers", "alibabaLoadBalancers"];
const ENDPOINTS: LinkKey[] = ["awsEndpoints", "alibabaEndpoints"];
/** DNS records by the service that serves them, named as people know it. */
const DNS: Partial<Record<LinkKey, string>> = { cloudflareDns: "Cloudflare DNS", route53Dns: "Route 53", alidnsDns: "Alibaba Cloud DNS" };

/** Services a finding can be about, by what its title or detail calls them, and their usual port. */
const SERVICES: [RegExp, number, string][] = [
  [/\brdp\b|remote desktop/i, 3389, "RDP"],
  [/\bssh\b/i, 22, "SSH"],
  [/\btelnet\b/i, 23, "Telnet"],
  [/\bftp\b/i, 21, "FTP"],
  [/\bsmb\b/i, 445, "SMB"],
  [/\bvnc\b/i, 5900, "VNC"],
  [/\bdocker\b/i, 2375, "Docker"],
  [/\bkubelet\b/i, 10250, "Kubelet"],
  ...Object.entries(DATABASE_PORTS).map(([port, name]): [RegExp, number, string] => [
    new RegExp(`\\b${name.replace(/\s+/g, "[ _]?")}\\b`, "i"),
    Number(port),
    name,
  ]),
];

const IPV4 = /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g;
const HOSTNAME = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi;
const MAX_VALUES = 8;
/** Endpoint kinds (src/core/links.ts) in words. */
const ENDPOINT_WORD: { [kind: string]: string } = {
  cloudfront: "CloudFront distribution",
  s3: "S3 bucket",
  elb: "load balancer",
  oss: "OSS bucket",
  slb: "load balancer",
  cdn: "CDN domain",
};
const MAX_HOPS = 5;

/** Addresses on the internet: not 0.0.0.0 (as in 0.0.0.0/0), private, shared (100.64.0.0/10), link-local or multicast. */
function isPublic(ip: string): boolean {
  const [a, b] = ip.split(".").map(Number);
  if (a === 0 || a >= 224 || (a === 100 && b >= 64 && b < 128) || (a === 169 && b === 254)) return false;
  return !isInternal(`${ip}/32`);
}

const list = <T>(links: ProviderLinks, key: LinkKey) => links[key] as T[] | undefined;
const host = (s: string) => s.toLowerCase().replace(/\.$/, "");

/** Everything the entity's scans published about addresses and names, indexed for lookups. */
function indexOf(scans: EntityScan[]) {
  const holders = new Map<string, Holder[]>();
  const released = new Map<string, { provider: ProviderId; account: string; at: string }[]>();
  const records = new Map<string, DnsRecord[]>();
  const balancers = new Map<string, Holder>();
  const served = new Map<string, Holder[]>();
  const endpoints = new Set<string>();
  const sonar = new Map<string, string>();
  const regionNames = new Map<string, string>();
  const add = <T>(m: Map<string, T[]>, k: string, v: T) => m.set(k, [...(m.get(k) ?? []), v]);
  // Which clouds list every address their accounts hold: only then is "not one of ours" a conclusion.
  const complete = new Map<ProviderId, boolean>();

  for (const s of scans) {
    const links = s.snap.links ?? {};
    const base = { provider: s.provider, accountId: s.accountId, account: s.account };
    for (const r of s.snap.resources?.regions ?? []) if (r.label) regionNames.set(r.name, r.label);
    for (const key of ADDRESS_LISTS) {
      if (LINK_PROVIDER[key] !== s.provider) continue;
      const ips = list<string>(links, key);
      complete.set(s.provider, (complete.get(s.provider) ?? true) && !!ips);
      for (const ip of ips ?? []) if (!holders.has(ip)) holders.set(ip, []);
    }
    // The resource view names what holds an address in the cloud's own words, with a console link.
    for (const row of s.snap.resources?.rows ?? []) {
      const ip = row.exposure?.match(/(?:Public address|Internet-facing at) (\d+\.\d+\.\d+\.\d+)/)?.[1];
      if (ip)
        add(holders, ip, {
          ...base,
          what: `${row.kind} ${row.name}${row.id !== row.name ? ` (${row.id})` : ""}`,
          region: row.region,
          link: row.link,
          open: null,
        });
    }
    for (const key of EXPOSURE)
      for (const e of list<AwsExposureLink>(links, key) ?? []) {
        const known = (holders.get(e.ip) ?? []).find((h) => h.accountId === s.accountId);
        if (known) known.open = e.open;
        else add(holders, e.ip, { ...base, what: e.resource, region: e.region, link: null, open: e.open });
      }
    for (const key of RELEASED) for (const r of list<{ ip: string; at: string }>(links, key) ?? []) add(released, r.ip, { ...base, at: r.at });
    for (const key of LOAD_BALANCERS)
      for (const lb of list<AwsLoadBalancerLink>(links, key) ?? []) {
        const h: Holder = {
          ...base,
          what: `${lb.type} load balancer ${lb.name}`,
          region: lb.region,
          link: null,
          open: null,
          listeners: lb.listeners.flatMap((l) => (l.port == null ? [] : [l.port])),
        };
        balancers.set(host(lb.dnsName), h);
        // A CLB is named by its address, and its targets with public addresses are held too.
        if (/^\d+\.\d+\.\d+\.\d+$/.test(lb.dnsName)) add(holders, lb.dnsName, h);
        for (const l of lb.listeners)
          for (const r of l.routes ?? [])
            for (const t of r.targets ?? [])
              if (t.publicIp && !(holders.get(t.publicIp) ?? []).some((x) => x.accountId === s.accountId))
                add(holders, t.publicIp, { ...base, what: `${t.kind} ${t.name ?? t.id}, a target of ${lb.name}`, region: lb.region, link: null, open: null });
      }
    for (const key of ENDPOINTS) for (const e of list<{ kind: string; name: string }>(links, key) ?? []) endpoints.add(`${e.kind}:${e.name.toLowerCase()}`);
    for (const [key, service] of Object.entries(DNS) as [LinkKey, string][])
      for (const r of list<DnsHostRecord>(links, key) ?? []) add(records, host(r.host), { provider: s.provider, service, accountId: s.accountId, record: r });
    for (const d of links.vercelDomains ?? []) add(served, host(d.host), { ...base, what: `project ${d.project}`, region: null, link: null, open: null });
    for (const p of links.githubPages ?? []) add(served, host(p.host), { ...base, what: `Pages site of ${p.repo}`, region: null, link: null, open: null });
    for (const h of s.snap.surface?.hosts ?? []) sonar.set(host(h.name), h.points);
  }
  return { holders, released, records, balancers, served, endpoints, sonar, regionNames, complete };
}

type Index = ReturnType<typeof indexOf>;

/** The ports a finding is about: services its title or detail names, and ports it states. */
export function portsOf(f: Pick<LocateInput, "title" | "checkId" | "detail">): { port: number; service: string }[] {
  const text = `${f.checkId} ${f.title} ${f.detail}`.replace(/_/g, " ");
  const out = new Map<number, string>();
  for (const [re, port, service] of SERVICES) if (re.test(text)) out.set(port, service);
  for (const m of text.matchAll(/\b(?:port|tcp|udp)\s+(\d{1,5})\b/gi)) {
    const port = Number(m[1]);
    if (port > 0 && port < 65536 && !out.has(port)) out.set(port, `port ${port}`);
  }
  return [...out].map(([port, service]) => ({ port, service }));
}

const covers = (rules: NonNullable<Rules>, port: number) =>
  rules.filter(
    (r) => r.protocol === "all" || r.protocol === "-1" || (r.protocol === "tcp" && r.from != null && r.to != null && r.from <= port && port <= r.to),
  );

/** Whether a holder lets anyone reach a port: its open inbound rules, or a load balancer's listeners. */
function judgePort(h: Holder, port: number, service: string): LocatedItem["ports"][number] {
  if (h.listeners)
    return h.listeners.includes(port)
      ? { port, service, open: true, detail: `${h.what} listens on ${port}` }
      : { port, service, open: false, detail: `${h.what} has no listener on ${port}` };
  if (!h.open) return { port, service, open: null, detail: `Keelson can't tell whether ${h.what} lets anyone reach ${port}` };
  const rules = covers(h.open, port);
  return rules.length
    ? {
        port,
        service,
        open: true,
        detail: `Its security group${rules.flatMap((r) => r.groups).length === 1 ? "" : "s"} ${[...new Set(rules.flatMap((r) => r.groups))].join(", ")} let anyone reach tcp ${port}: this confirms the finding`,
      }
    : { port, service, open: false, detail: `None of its security groups lets anyone reach tcp ${port}: it was closed since, or is reached another way` };
}

interface Trail {
  status: LocatedItem["status"];
  steps: LocatedItem["steps"];
  holders: Holder[];
}

const label = (p: ProviderId) => PROVIDER_INFO[p].label;

function where(idx: Index, h: Holder) {
  const region = h.region && h.region !== "Global" ? ` in ${idx.regionNames.get(h.region) ?? h.region}` : "";
  return `${h.what}${region}`;
}

/** Follows an address to what holds it. */
function followAddress(idx: Index, ip: string): Trail {
  const held: Holder[] = [];
  // Several lists can name the same thing (the resource view, the exposure list, a load balancer): one per account,
  // named by the first, with what the others know.
  for (const h of idx.holders.get(ip) ?? []) {
    const same = held.find((x) => x.accountId === h.accountId);
    if (!same) held.push({ ...h });
    else {
      same.open ??= h.open;
      same.listeners ??= h.listeners;
      same.link ??= h.link;
    }
  }
  if (held.length)
    return {
      status: "found",
      holders: held,
      steps: held.map((h) => ({ label: `${label(h.provider)} · ${h.account}`, value: `${where(idx, h)} holds ${ip}`, provider: h.provider, link: h.link })),
    };
  if (idx.holders.has(ip)) return { status: "found", holders: [], steps: [{ label: "Held in the entity", value: `An account in the entity holds ${ip}` }] };
  const gone = idx.released.get(ip);
  if (gone?.length)
    return {
      status: "released",
      holders: [],
      steps: gone.map((g) => ({
        label: `${label(g.provider)} · ${g.account}`,
        value: `Held ${ip} until it was released, around ${g.at.slice(0, 10)}`,
        provider: g.provider,
      })),
    };
  if (inCloudflare(`${ip}/32`))
    return { status: "unknown", holders: [], steps: [{ label: "Cloudflare", value: `${ip} is one of Cloudflare's addresses: the origin is behind it` }] };
  const searched = [...idx.complete].filter(([, ok]) => ok).map(([p]) => p);
  return searched.length
    ? {
        status: "outside",
        holders: [],
        steps: [
          {
            label: "Not in the entity",
            value: `None of the entity's ${providerList(searched)} accounts holds ${ip}: it is another company's, a platform's, or in an account that isn't connected`,
          },
        ],
      }
    : { status: "unknown", holders: [], steps: [] };
}

/** Follows a hostname through DNS records, CNAMEs and load balancers to what serves it. */
function followHost(idx: Index, name: string, hops = 0): Trail {
  const served = idx.served.get(name);
  if (served?.length)
    return {
      status: "found",
      holders: served,
      steps: served.map((h) => ({ label: `${label(h.provider)} · ${h.account}`, value: `${h.what} serves ${name}`, provider: h.provider, link: h.link })),
    };
  const lb = idx.balancers.get(name);
  if (lb)
    return {
      status: "found",
      holders: [lb],
      steps: [{ label: `${label(lb.provider)} · ${lb.account}`, value: `${where(idx, lb)} is ${name}`, provider: lb.provider }],
    };
  const endpoint = awsEndpointOf(name) ?? alibabaEndpointOf(name);
  if (endpoint) {
    const what = `${ENDPOINT_WORD[endpoint.kind] ?? endpoint.kind}${endpoint.name === name ? "" : ` ${endpoint.name}`}`;
    return idx.endpoints.has(`${endpoint.kind}:${endpoint.name}`)
      ? { status: "found", holders: [], steps: [{ label: "Held in the entity", value: `${name} is a ${what} that an account in the entity has` }] }
      : { status: "outside", holders: [], steps: [{ label: "Not in the entity", value: `${name} is a ${what} that no account in the entity has` }] };
  }
  // IPv6 records aren't matched to holders (clouds list IPv4), and Cloudflare's 100:: only stands for "proxied".
  const recs = (idx.records.get(name) ?? []).filter((r) => r.record.type !== "AAAA");
  if (!recs.length) {
    const ips = idx.sonar.get(name)?.match(IPV4) ?? [];
    if (!ips.length) return { status: "unknown", holders: [], steps: [] };
    return merge(ips.map((ip) => prefix({ label: "Public DNS (Sonar)", value: `${name} resolves to ${ip}` }, followAddress(idx, ip))));
  }
  // The same record in several DNS services (a zone in both Cloudflare and Route 53) is one step, followed once.
  const byTarget = new Map<string, DnsRecord[]>();
  for (const r of recs) {
    const key = `${r.record.type} ${host(r.record.target)}`;
    byTarget.set(key, [...(byTarget.get(key) ?? []), r]);
  }
  return merge(
    [...byTarget.values()].map((same) => {
      const r = same[0];
      const step = {
        label: [...new Set(same.map((x) => x.service))].join(" and "),
        value: `${name} ${r.record.type} ${r.record.target}${same.some((x) => x.record.proxied) ? ", proxied by Cloudflare" : ""} (zone ${r.record.zone})`,
        provider: r.provider,
      };
      const target = host(r.record.target);
      if (/^\d+\.\d+\.\d+\.\d+$/.test(target)) return prefix(step, followAddress(idx, target));
      if (hops >= MAX_HOPS || r.record.type === "AAAA") return { status: "unknown" as const, holders: [], steps: [step] };
      const next = followHost(idx, target, hops + 1);
      // A CNAME to a name nothing in the entity knows points outside it: another company's service.
      return next.status === "unknown" && !next.steps.length
        ? {
            status: "outside" as const,
            holders: [],
            steps: [step, { label: "Not in the entity", value: `${target} isn't served by any of the entity's connected accounts` }],
          }
        : prefix(step, next);
    }),
  );
}

const prefix = (step: LocatedItem["steps"][number], t: Trail): Trail => ({ ...t, steps: [step, ...t.steps] });

/** Several paths (several records): the best status wins, and every step is kept. */
function merge(trails: Trail[]): Trail {
  const rank: LocatedItem["status"][] = ["found", "released", "outside", "unknown"];
  const status = rank.find((s) => trails.some((t) => t.status === s)) ?? "unknown";
  const steps = trails.flatMap((t) => t.steps).filter((s, i, all) => all.findIndex((x) => x.label === s.label && x.value === s.value) === i);
  const holders = trails.flatMap((t) => t.holders).filter((h, i, all) => all.findIndex((x) => x.accountId === h.accountId && x.what === h.what) === i);
  return { status, holders, steps };
}

function summary(idx: Index, t: Trail, value: string): string {
  if (t.status === "found" && t.holders.length) {
    const h = t.holders[0];
    return `${label(h.provider)}: ${where(idx, h)}${t.holders.length > 1 ? ` and ${t.holders.length - 1} more` : ""}`;
  }
  if (t.status === "found") return "Held by an account in the entity";
  if (t.status === "released") {
    const p = t.steps.findLast((x) => x.provider)?.provider;
    return `Released by the entity's ${p ? `${label(p)} ` : ""}account: anything that still points at it reaches whoever holds it now`;
  }
  if (t.status === "outside") return t.steps[t.steps.length - 1]?.value ?? `None of the entity's accounts holds ${value}`;
  return `Nothing the entity's accounts publish names ${value}`;
}

/** Every public address and every known hostname a finding names, followed into the entity's infrastructure. */
export function locate(f: LocateInput, scans: EntityScan[]): LocatedResponse {
  const idx = indexOf(scans);
  // Email addresses name a person's domain, not a host.
  const text = [f.resource, f.detail, f.evidence ? JSON.stringify(f.evidence) : ""].join(" ").replace(/[^\s"'<>()]+@[^\s"'<>(),]+/g, " ");
  const ips = [...new Set(text.match(IPV4) ?? [])].filter(isPublic);
  const known = (h: string) =>
    idx.records.has(h) || idx.served.has(h) || idx.balancers.has(h) || idx.sonar.has(h) || !!(awsEndpointOf(h) ?? alibabaEndpointOf(h));
  const zone = f.zone ? host(f.zone) : null;
  const names = [...new Set((text.match(HOSTNAME) ?? []).map(host))].filter((h) => !/^\d+(\.\d+)+$/.test(h) && h !== zone && known(h));
  const ports = portsOf(f);
  const items: LocatedItem[] = [];
  const hostTrails = names.map((n) => ({ value: n, kind: "hostname" as const, trail: followHost(idx, n) }));
  // An address a hostname already led to is shown once, under the hostname.
  const reached = new Set(hostTrails.flatMap((t) => t.trail.steps.flatMap((s) => s.value.match(IPV4) ?? [])));
  const addressTrails = ips.filter((ip) => !reached.has(ip)).map((ip) => ({ value: ip, kind: "address" as const, trail: followAddress(idx, ip) }));
  for (const { value, kind, trail } of [...hostTrails, ...addressTrails].slice(0, MAX_VALUES)) {
    // What the finding's own account holds, the finding already says.
    if (trail.status === "found" && trail.holders.length && trail.holders.every((h) => h.accountId === f.accountId)) continue;
    if (trail.status === "unknown" && !trail.steps.length) continue;
    const holders = trail.holders.filter((h) => h.accountId !== f.accountId);
    const line = summary(idx, { ...trail, holders: holders.length ? holders : trail.holders }, value);
    items.push({
      value,
      kind,
      status: trail.status,
      summary: line,
      // The conclusion is the summary; the steps are how it was reached.
      steps: trail.steps.filter((x) => x.value !== line),
      ports: holders.length ? ports.flatMap(({ port, service }) => holders.map((h) => judgePort(h, port, service))) : [],
    });
  }
  return { items, searched: [...new Set(scans.map((s) => s.provider))] };
}
