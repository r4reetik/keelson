// Builds an entity's outside view (Sonar, passive). It starts from what the entity's
// accounts already know (domains, DNS records, the addresses AWS holds), finds more
// hostnames under those domains in certificate transparency logs and Shodan, looks
// them up in public DNS, and asks Shodan what it has seen on the addresses. Nothing
// here connects to the entity's hosts.
//
// Which addresses Shodan is asked about, and so which can produce findings: the ones an
// AWS account in the entity holds, and the ones the entity's DNS points at directly (or
// through a CNAME that stays under its domains). Left out: private addresses, Cloudflare's,
// Vercel's and GitHub Pages' shared addresses, addresses AWS was seen to release (someone
// else's now), and AWS addresses no AWS account in the entity holds (most are vendors').

import { doh, pool, type DohAnswer } from "../../core/cloudflare.ts";
import { inCloudflare, isInternal } from "../../core/cloudflare-ranges.ts";
import { inPrefixes, ipToInt, type Prefixes } from "../../core/aws-ranges.ts";
import { awsEndpointOf, pointsAtGithubPages, pointsAtVercel } from "../../core/links.ts";
import { InternetError, type CrtEntry, type InternetClient } from "./client.ts";
import { AmassError, amass as amassRunner } from "./amass.ts";
import { LINK_PROVIDER, type DnsHostRecord, type LinkKey } from "../../shared/api.ts";
import { PROVIDER_INFO, type ProviderId } from "../../shared/providers.ts";
import type { ProgressEvent } from "../../core/types.ts";
import type { Address, Caa, CtCertificate, Domain, Host, HostSource, InternetInventory, Related } from "./types.ts";

const MAX_DOMAINS = 50;
const MAX_LOOKUPS = 1000;
const MAX_HOSTS = 2000;
const MAX_ADDRESSES = 200;
const MAX_CERTS = 20_000;

const TYPE_A = 1,
  TYPE_NS = 2,
  TYPE_CNAME = 5,
  TYPE_CAA = 257;

/** The AWS lists that let a hostname be followed to its load balancer and targets; while one is missing, that part is a gap. */
export const ROUTING_INPUTS: LinkKey[] = ["awsLoadBalancers", "awsExposure"];

/** The lists this view is built from; while one is missing for an account in the entity, the view isn't complete. */
export const INPUTS: LinkKey[] = [
  "cloudflareZones",
  "cloudflareDns",
  "route53Zones",
  "route53Dns",
  "awsAddresses",
  "awsReleased",
  "vercelDomains",
  "githubPages",
];

export interface DiscoverInput {
  accountId: string;
  /** The entity's own domains and the ones its other accounts own (EngineOptions.orgDomains). */
  orgDomains: string[];
  related: Related;
  /** AWS's EC2 ranges, when the entity has AWS accounts and the file could be read. */
  ec2: Prefixes | null;
  /** The Amass binary, or null when it isn't installed. */
  amass: string | null;
  onProgress: (p: ProgressEvent) => void;
}

export async function discover(client: InternetClient, input: DiscoverInput): Promise<InternetInventory> {
  const { related, onProgress } = input;
  const missing = INPUTS.filter((k) => related.unknown.includes(k));
  if (missing.length) {
    const who = [...new Set(missing.map((k) => PROVIDER_INFO[LINK_PROVIDER[k]].label))].join(" and ");
    client.note(
      "related",
      false,
      new InternetError(0, `A ${who} account in this entity hasn't been scanned since Sonar was added. Scan it, then scan this again.`),
    );
  } else client.note("related", true);
  if (ROUTING_INPUTS.some((k) => related.unknown.includes(k)))
    client.note(
      "routing",
      false,
      new InternetError(0, "An AWS account in this entity hasn't been scanned since load balancer routing was added. Scan it, then scan this again."),
    );
  else client.note("routing", true);
  const loadBalancers = related.awsLoadBalancers ?? [];
  const lbByName = new Map(loadBalancers.map((lb) => [lb.dnsName, lb]));

  const records = [...(related.cloudflareDns ?? []), ...(related.route53Dns ?? [])];
  const zones = new Map<string, ProviderId>([
    ...(related.cloudflareZones ?? []).map((z) => [lower(z), "cloudflare"] as const),
    ...(related.route53Zones ?? []).map((z) => [lower(z), "aws"] as const),
  ]);

  // Domains: the zones as they are, everything else by its registrable name; a domain under another is dropped.
  const names = new Set<string>([
    ...zones.keys(),
    ...[...input.orgDomains, ...(related.vercelDomains ?? []).map((d) => d.host), ...(related.githubPages ?? []).map((p) => p.host)]
      .map(lower)
      .filter((n) => validName(n) && !sharedPlatformName(n))
      .map((n) => (zones.has(n) ? n : registrable(n))),
  ]);
  const domainNames = [...names]
    .filter((n) => ![...names].some((o) => o !== n && n.endsWith(`.${o}`)))
    .sort()
    .slice(0, MAX_DOMAINS);
  const domainOf = (host: string) => domainNames.find((d) => host === d || host.endsWith(`.${d}`)) ?? null;

  onProgress({ phase: "Looking up domains", done: 0, total: domainNames.length });
  let looked = 0;
  const domains: Domain[] = await pool(domainNames, 4, async (name) => {
    const dnsAt = zones.get(name) ?? null;
    const [caa, ns] = await Promise.all([doh(name, "CAA"), dnsAt ? Promise.resolve(null) : doh(name, "NS")]);
    onProgress({ phase: "Looking up domains", done: ++looked, total: domainNames.length });
    return {
      name,
      dnsAt,
      nameservers: ns && ns.status === 0 ? ns.answers.filter((a) => a.type === TYPE_NS).map((a) => lower(a.data)) : null,
      unregistered: ns?.status === 3,
      caa: caa.status === 0 || caa.status === 3 ? parseCaa(caa) : null,
      certificates: null,
    };
  });
  client.note("dns", domains.some((d) => d.caa) || !domains.length);

  // Certificate logs, one domain at a time: crt.sh is slow and shared.
  const found = new Map<string, Set<HostSource>>();
  const add = (host: string, src: HostSource) => {
    if (!validName(host) || !domainOf(host) || serviceName(host)) return;
    (found.get(host) ?? found.set(host, new Set()).get(host)!).add(src);
  };
  // A domain the logs couldn't answer for stays unread on its own (null); the source is a gap only when none could be read.
  let certsRead = 0,
    certsFailed: unknown = null;
  const readLogs = async (d: Domain) => {
    try {
      d.certificates = certificatesOf(await client.certificates(d.name), d.name);
      certsRead++;
      for (const c of d.certificates) for (const n of c.names) add(n.replace(/^\*\./, ""), "certificates");
    } catch (e) {
      certsFailed = e;
    }
  };
  for (const [i, d] of domains.entries()) {
    onProgress({ phase: "Reading certificate logs", done: i, total: domains.length });
    if (!d.unregistered) await readLogs(d);
  }
  // crt.sh often answers a domain it refused once it has had a few minutes: one more try for each, at the end.
  for (const d of domains) if (!d.unregistered && !d.certificates) await readLogs(d);
  client.note("certificates", !!certsRead || !certsFailed, certsFailed);

  if (client.hasKey) {
    onProgress({ phase: "Asking Shodan for subdomains" });
    for (const d of domains) {
      if (d.unregistered) continue;
      try {
        for (const h of await client.subdomains(d.name)) add(h, "shodan");
        client.note("shodanDns", true);
      } catch (e) {
        client.note("shodanDns", false, e);
        // A refused key or a plan without credits refuses every domain alike.
        if ([401, 402, 403].includes((e as InternetError).status)) break;
      }
    }
  } else client.note("shodanDns", false, new InternetError(0, "No Shodan API key: subdomains come from the certificate logs only."));

  // Hostnames a load balancer routes by name are the entity's, whether or not DNS still points at them.
  for (const lb of loadBalancers)
    for (const l of lb.listeners) for (const r of l.routes ?? []) for (const h of r.hosts) if (!/[*?]/.test(h)) add(lower(h), "loadBalancer");

  // Hosts in the connected DNS are known; the rest are looked up in public DNS.
  const byHost = new Map<string, DnsHostRecord[]>();
  for (const r of records) {
    const host = lower(r.host);
    if (host.startsWith("*.") || !domainOf(host) || serviceName(host)) continue;
    (byHost.get(host) ?? byHost.set(host, []).get(host)!).push(r);
    add(host, "dns");
  }

  // Amass, on the entity's domains, finds more under them. (Seeding it with the names already known crashes Amass 5.1's
  // engine; those names are only used to tell which of Amass's are new.)
  let amass: InternetInventory["amass"] = null;
  const amassIps = new Map<string, string[]>();
  const live = domains.filter((d) => !d.unregistered).map((d) => d.name);
  if (!input.amass) client.note("amass", false, new AmassError("Amass isn't installed where Keelson runs."));
  else if (live.length) {
    const started = Date.now();
    onProgress({ phase: "Running Amass" });
    try {
      const before = new Set(found.keys());
      const names = await amassRunner.run(input.amass, { domains: live, onProgress: (m) => onProgress({ phase: `Running Amass (${m} min)` }) });
      for (const [name, ips] of names) {
        // Amass returns the names it was given too; only the ones it adds are marked as its finds.
        if (!found.has(name)) add(name, "amass");
        if (ips.length) amassIps.set(name, ips);
      }
      amass = {
        names: [...names.keys()].filter((n) => found.has(n)).length,
        added: [...found.keys()].filter((n) => !before.has(n)).length,
        minutes: Math.round((Date.now() - started) / 60_000),
      };
      client.note("amass", true);
    } catch (e) {
      client.note("amass", false, e);
    }
  }

  const toResolve = [...found.keys()].filter((h) => !byHost.has(h)).slice(0, MAX_LOOKUPS);
  onProgress({ phase: "Looking up hostnames", done: 0, total: toResolve.length });
  let resolvedCount = 0;
  const resolved = new Map<string, { addresses: string[]; cnames: string[] } | null>(
    await pool(toResolve, 8, async (h) => {
      const a = await doh(h, "A");
      onProgress({ phase: "Looking up hostnames", done: ++resolvedCount, total: toResolve.length });
      const addresses = a.answers.filter((x) => x.type === TYPE_A).map((x) => x.data);
      return [h, addresses.length ? { addresses, cnames: a.answers.filter((x) => x.type === TYPE_CNAME).map((x) => lower(x.data)) } : null] as const;
    }),
  );

  const held = new Set(related.awsAddresses ?? []);
  // Only with AWS accounts in the entity: then an AWS address none of them holds is someone else's.
  const ec2 = related.awsAddresses ? input.ec2 : null;
  const released = new Set((related.awsReleased ?? []).map((r) => r.ip));
  const hosts: Host[] = [];
  // Names that don't resolve, or that weren't looked up past the limit.
  let unresolved = 0;
  for (const [name, srcs] of [...found.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const recs = byHost.get(name) ?? [];
    // Past the lookup limit, the addresses Amass resolved stand in for a lookup of our own.
    const viaAmass = amassIps.get(name);
    const res = recs.length ? null : (resolved.get(name) ?? (viaAmass && !resolved.has(name) ? { addresses: viaAmass, cnames: [] } : null));
    if (!recs.length && !res) {
      unresolved++;
      continue;
    }
    const lb = [...recs.filter((r) => r.type === "CNAME" || r.type === "ALIAS").map((r) => r.target), ...(res?.cnames ?? [])]
      .map((t) => awsEndpointOf(t))
      .find((e) => e?.kind === "elb" && lbByName.has(e.name));
    const direct = [...recs.filter((r) => r.type === "A").map((r) => r.target), ...(res?.cnames.every((c) => !!domainOf(c)) ? res.addresses : [])].find((ip) =>
      held.has(ip),
    );
    hosts.push({
      name,
      domain: domainOf(name)!,
      found: [...srcs].sort(),
      records: recs,
      resolved: res,
      // A proxied hostname is answered by Cloudflare; its load balancer is the origin, shown as its path.
      servedBy: lb && !recs.some((r) => r.proxied) ? "AWS load balancer" : servedBy(recs, res, held, ec2),
      loadBalancer: lb?.name ?? null,
      awsAddress: direct ?? null,
    });
  }
  followChains(hosts);

  // Addresses: held ones first, then origins of proxied hostnames, then the rest the entity's DNS points at.
  const ownName = (n: string) => !!domainOf(n);
  const addrs = new Map<string, Address>();
  const touch = (ip: string, host?: { name: string; proxied: boolean }) => {
    const a = addrs.get(ip) ?? addrs.set(ip, { ip, heldBy: held.has(ip) ? "aws" : null, hosts: [], shodan: null }).get(ip)!;
    if (host && !a.hosts.some((h) => h.name === host.name)) a.hosts.push(host);
  };
  for (const ip of held) touch(ip);
  for (const h of hosts) {
    for (const r of h.records) if (r.type === "A") touch(r.target, { name: h.name, proxied: r.proxied });
    // Through a CNAME outside the entity's domains, the address belongs to whoever runs that name.
    if (h.resolved?.cnames.every(ownName)) for (const ip of h.resolved.addresses) touch(ip, { name: h.name, proxied: false });
  }
  const addresses = [...addrs.values()]
    .filter((a) => ipToInt(a.ip) != null && !isInternal(`${a.ip}/32`) && !inCloudflare(`${a.ip}/32`) && !released.has(a.ip))
    .filter((a) => !pointsAtVercel("A", a.ip) && !pointsAtGithubPages("A", a.ip))
    .filter((a) => a.heldBy || !ec2 || !inPrefixes(a.ip, ec2))
    .sort((a, b) => rank(a) - rank(b) || a.ip.localeCompare(b.ip, undefined, { numeric: true }))
    .slice(0, MAX_ADDRESSES);

  onProgress({ phase: "Asking Shodan about addresses", done: 0, total: addresses.length });
  // An address Shodan couldn't answer for stays null on its own; a refused key, or no answer at all, is a gap.
  let asked = 0,
    answered = 0,
    refused: unknown = null,
    failed: unknown = null;
  await pool(addresses, 4, async (a) => {
    if (refused) return;
    try {
      const view = await client.host(a.ip);
      a.shodan = view.seen ? { ...view, hostnames: view.hostnames.filter(ownName) } : view;
      answered++;
    } catch (e) {
      if ([401, 403].includes((e as InternetError).status)) refused = e;
      failed = e;
    }
    onProgress({ phase: "Asking Shodan about addresses", done: ++asked, total: addresses.length });
  });
  client.note("shodan", !refused && (!!answered || !failed), refused ?? failed);

  return {
    accountId: input.accountId,
    now: new Date().toISOString(),
    unreadable: [],
    domains,
    hosts: hosts.slice(0, MAX_HOSTS),
    unresolved,
    addresses,
    loadBalancers,
    exposure: related.awsExposure ?? [],
    amass,
  };
}

/**
 * A hostname that CNAMEs to another of the entity's hostnames reaches whatever that one reaches: a proxied
 * `app.example.com` → `app-origin.example.com` → load balancer is common. Followed a few hops, never in a loop.
 */
export function followChains(hosts: Host[]): void {
  const byName = new Map(hosts.map((h) => [h.name, h]));
  const next = (h: Host) =>
    [...h.records.filter((r) => r.type === "CNAME" || r.type === "ALIAS").map((r) => r.target), ...(h.resolved?.cnames ?? [])]
      .map(lower)
      .map((t) => byName.get(t))
      .find((x) => x && x !== h);
  for (const h of hosts) {
    if (h.loadBalancer || h.awsAddress) continue;
    let at = next(h);
    for (let hop = 0; at && hop < 5; hop++, at = next(at)) {
      if (!at.loadBalancer && !at.awsAddress) continue;
      h.loadBalancer = at.loadBalancer;
      h.awsAddress = at.awsAddress;
      if (h.servedBy.startsWith("CNAME to") || h.servedBy === "Outside connected accounts") h.servedBy = at.servedBy;
      break;
    }
  }
}

const rank = (a: Address) => (a.heldBy ? 0 : a.hosts.some((h) => h.proxied) ? 1 : 2);

/** What answers for a hostname, in words, from its records or its public DNS answer. */
function servedBy(recs: DnsHostRecord[], res: { addresses: string[]; cnames: string[] } | null, held: Set<string>, ec2: Prefixes | null): string {
  if (recs.some((r) => r.proxied)) return "Cloudflare (proxied)";
  const pairs: [string, string][] = recs.length
    ? recs.map((r) => [r.type === "ALIAS" ? "CNAME" : r.type, r.target])
    : [...(res?.cnames ?? []).map((c): [string, string] => ["CNAME", c]), ...(res?.addresses ?? []).map((ip): [string, string] => ["A", ip])];
  for (const [type, target] of pairs) {
    if (pointsAtVercel(type, target)) return "Vercel";
    if (pointsAtGithubPages(type, target)) return "GitHub Pages";
    if (type === "CNAME" && awsEndpointOf(target)) return "AWS";
    if (type === "A" && held.has(target)) return "AWS";
  }
  const ip = pairs.find(([t]) => t === "A")?.[1];
  if (ip && isInternal(`${ip}/32`)) return "Private address";
  if (ip && inCloudflare(`${ip}/32`)) return "Cloudflare";
  // Common on real entities: an AWS account that isn't connected, or a vendor that runs on AWS.
  if (ip && ec2 && inPrefixes(ip, ec2)) return "AWS (an account that isn't connected)";
  const cname = pairs.find(([t]) => t === "CNAME")?.[1];
  return cname ? `CNAME to ${registrable(cname)}` : "Outside connected accounts";
}

/** Certificates still valid, one per serial, with only the names under the domain. */
export function certificatesOf(entries: CrtEntry[], domain: string): CtCertificate[] {
  const seen = new Map<string, CtCertificate>();
  for (const e of entries.slice(0, MAX_CERTS)) {
    const key = `${e.issuer_name}|${e.serial_number ?? e.id}`;
    const names = String(e.name_value ?? "")
      .split(/\n/)
      .map(lower)
      .filter((n) => n === domain || n.endsWith(`.${domain}`));
    if (!names.length) continue;
    const prev = seen.get(key);
    if (prev) {
      prev.names = [...new Set([...prev.names, ...names])];
      continue;
    }
    const issuer = issuerName(e.issuer_name);
    seen.set(key, {
      id: Number(e.id),
      names: [...new Set(names)],
      issuer,
      caa: caaOfIssuer(issuer),
      notBefore: utc(e.not_before),
      notAfter: utc(e.not_after),
      logged: utc(e.entry_timestamp),
    });
  }
  return [...seen.values()];
}

/** crt.sh's times have no zone; they are UTC. */
const utc = (s: string) => (s && !/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? `${s}Z` : s);

/** "C=US, O=Let's Encrypt, CN=R11" → "Let's Encrypt". */
export function issuerName(dn: string): string {
  const part = (k: string) => new RegExp(`(?:^|,\\s*)${k}=("[^"]*"|[^,]*)`).exec(dn)?.[1]?.replace(/^"|"$/g, "").trim();
  return part("O") || part("CN") || dn;
}

/** The CAA identifiers that let each certificate authority issue, by the organisation in its certificates. */
const ISSUERS: [RegExp, string[]][] = [
  [/let'?s encrypt/i, ["letsencrypt.org"]],
  [/google trust services/i, ["pki.goog"]],
  // Cloudflare's and older brands' certificates are issued by DigiCert.
  [/digicert|cloudflare|geotrust|rapidssl|thawte|symantec/i, ["digicert.com", "symantec.com", "geotrust.com", "rapidssl.com", "thawte.com"]],
  [/sectigo|comodo|zerossl|usertrust/i, ["sectigo.com", "comodoca.com", "comodo.com", "usertrust.com", "trust-provider.com", "zerossl.com"]],
  [/amazon/i, ["amazon.com", "amazontrust.com", "awstrust.com", "amazonaws.com"]],
  [/ssl\.com|ssl corporation/i, ["ssl.com"]],
  [/globalsign/i, ["globalsign.com"]],
  [/godaddy|starfield/i, ["godaddy.com", "starfieldtech.com"]],
  [/entrust/i, ["entrust.net"]],
  [/buypass/i, ["buypass.com", "buypass.no"]],
];

export const caaOfIssuer = (issuer: string): string[] | null => ISSUERS.find(([re]) => re.test(issuer))?.[1] ?? null;

/** CAA from a DNS-over-HTTPS answer, in presentation form (`0 issue "ca.example"`) or RFC 3597's (`\# 22 00 05 …`). */
export function parseCaa(answer: DohAnswer): Caa {
  const out: Caa = { issue: [], issuewild: [] };
  for (const a of answer.answers) {
    if (a.type !== TYPE_CAA) continue;
    const r = caaRecord(a.data);
    if (r && (r.tag === "issue" || r.tag === "issuewild")) out[r.tag].push(r.value.split(";")[0].trim().toLowerCase());
  }
  return out;
}

function caaRecord(data: string): { tag: string; value: string } | null {
  const text = /^\s*\d+\s+(\w+)\s+"?(.*?)"?\s*$/.exec(data);
  if (text && !data.trim().startsWith("\\#")) return { tag: text[1].toLowerCase(), value: text[2] };
  const hex = /^\s*\\#\s+\d+\s+([0-9a-f\s]+)$/i.exec(data);
  if (!hex) return null;
  const bytes =
    hex[1]
      .replace(/\s+/g, "")
      .match(/../g)
      ?.map((b) => Number.parseInt(b, 16)) ?? [];
  const len = bytes[1] ?? 0;
  const ascii = (b: number[]) => String.fromCharCode(...b);
  return { tag: ascii(bytes.slice(2, 2 + len)).toLowerCase(), value: ascii(bytes.slice(2 + len)) };
}

/**
 * Domains platforms share between their customers (a Vercel deployment's *.vercel.app, a GitHub Pages site's
 * *.github.io). A name under one belongs to the platform, so it is never one of the entity's domains: asking the
 * logs about it would list every other customer's names.
 */
const SHARED = [
  "vercel.app",
  "now.sh",
  "github.io",
  "githubusercontent.com",
  "pages.dev",
  "workers.dev",
  "cloudfront.net",
  "amazonaws.com",
  "awsapprunner.com",
  "amplifyapp.com",
  "herokuapp.com",
  "netlify.app",
  "azurewebsites.net",
  "azureedge.net",
  "web.app",
  "firebaseapp.com",
  "appspot.com",
  "run.app",
  "fly.dev",
  "onrender.com",
  "railway.app",
  "myshopify.com",
];
export const sharedPlatformName = (host: string) => SHARED.some((d) => host === d || host.endsWith(`.${d}`));

/**
 * A record name that isn't a host: a label starting with an underscore marks certificate and domain validation
 * (ACM, DigiCert, Google), DKIM keys and SRV services, and nothing answers HTTP there.
 */
export const serviceName = (host: string) => host.split(".").some((l) => l.startsWith("_"));

const lower = (s: string) => String(s).toLowerCase().trim().replace(/\.$/, "");
const validName = (s: string) => /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/.test(s);

/** Second-level labels under which country domains register names ("example.co.uk"). */
const SECOND_LEVEL = new Set(["co", "com", "net", "org", "gov", "ac", "edu", "ltd", "plc", "me", "or", "ne", "go", "gob", "nic", "mil"]);

/** The name someone registers, without a public suffix list: the last two labels, or three under a country's "co", "com" and the like. */
export function registrable(host: string): string {
  const labels = lower(host).split(".");
  if (labels.length <= 2) return labels.join(".");
  const [sld, tld] = labels.slice(-2);
  return tld.length === 2 && SECOND_LEVEL.has(sld) ? labels.slice(-3).join(".") : labels.slice(-2).join(".");
}
