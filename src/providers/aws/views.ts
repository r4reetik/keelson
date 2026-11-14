// What an AWS scan stores for the dashboard: one row per region (and one for the
// account's global resources) for the Regions page, the endpoints, addresses and
// origins other providers' checks compare against, and the domains the account owns.

import { countBySeverity } from "../../shared/severity.ts";
import type { AddressHistory, AwsOrigin, ProviderLinks, RegionRow } from "../../shared/api.ts";
import type { Result } from "../../core/types.ts";
import { opensWeb } from "./checks/define.ts";
import { GLOBAL, type AwsInventory, type AwsSecurityGroup } from "./types.ts";

const counted = (pairs: [string, unknown[] | null | undefined][]): RegionRow["resources"] =>
  pairs.flatMap(([label, list]) => (list ? [{ label, count: list.length }] : []));

export function regionRows(inv: AwsInventory, failures: Result[]): RegionRow[] {
  const findings = (zone: string) => countBySeverity(failures.filter((f) => f.zone === zone));
  return [
    {
      name: GLOBAL,
      resources: counted([
        ["IAM users", inv.users],
        ["IAM roles", inv.roles?.filter((r) => !r.serviceLinked)],
        ["S3 buckets", inv.buckets],
        ["CloudFront distributions", inv.distributions],
        ["Hosted zones", inv.hostedZones],
      ]),
      guardDuty: null,
      skipped: false,
      findings: findings(GLOBAL),
    },
    ...inv.regions.map((r) => ({
      name: r.name,
      resources: counted([
        ["Instances", r.instances],
        ["Security groups", r.securityGroups],
        ["Databases", r.databases],
        ["Load balancers", r.loadBalancers],
        ["Functions", r.functions],
        ["Elastic IPs", r.addresses],
        ["VPCs", r.vpcs],
      ]),
      guardDuty: r.guardDuty,
      skipped: false,
      findings: findings(r.name),
    })),
    ...inv.skippedRegions.map((name) => ({ name, resources: [], guardDuty: null, skipped: true, findings: findings(name) })),
  ];
}

/**
 * The endpoints this account has that a DNS record can name: CloudFront domain names (its own distributions, and the
 * ones AWS runs for its API Gateway custom domains), load balancer DNS names and S3 buckets. Null when any of them
 * couldn't be read, so a missing one is never mistaken for a deleted one.
 */
export function ownEndpoints(inv: AwsInventory): NonNullable<ProviderLinks["awsEndpoints"]> | null {
  if (!inv.distributions || !inv.buckets || inv.regions.some((r) => !r.loadBalancers || !r.apiDomains)) return null;
  return [
    ...inv.distributions.map((x) => ({ kind: "cloudfront" as const, name: x.domainName })),
    ...inv.regions.flatMap((r) => r.apiDomains!.map((name) => ({ kind: "cloudfront" as const, name }))),
    ...inv.regions.flatMap((r) => r.loadBalancers!.map((lb) => ({ kind: "elb" as const, name: lb.dnsName }))),
    ...inv.buckets.map((b) => ({ kind: "s3" as const, name: b.name })),
  ];
}

/** Every public IPv4 address the account holds: Elastic IPs, attached or not, and the addresses of its network interfaces. Null when a region couldn't be read. */
export function ownAddresses(inv: AwsInventory): string[] | null {
  if (inv.regions.some((r) => !r.interfaces || !r.addresses)) return null;
  return [...new Set(inv.regions.flatMap((r) => [...r.addresses!, ...r.interfaces!.flatMap((i) => i.publicIp ?? [])]))];
}

/** Who a set of security groups lets reach ports 80 and 443, or null when Keelson can't tell (see AwsOrigin). */
export function webAccess(groups: AwsSecurityGroup[]): Pick<AwsOrigin, "web" | "groups"> | null {
  const named = (gs: AwsSecurityGroup[]) => gs.map((g) => ({ id: g.id, name: g.name }));
  const open = groups.filter(opensWeb);
  if (open.length) return { web: "open", groups: named(open) };
  if (!groups.length || groups.some((g) => !g.webFrom || g.webFrom.prefixLists.length)) return null;
  if (groups.some((g) => g.webFrom!.other)) return { web: "other", groups: named(groups) };
  // No rule for the web ports at all: Cloudflare can't reach it there either, so it's served some other way.
  if (groups.some((g) => g.webFrom!.cloudflare)) return { web: "cloudflare", groups: named(groups) };
  return null;
}

/**
 * Who can reach the account's web origins: its load balancers by DNS name, and every network interface with a public
 * address. Null when a region's security groups, load balancers or interfaces couldn't be read.
 */
export function ownOrigins(inv: AwsInventory): AwsOrigin[] | null {
  if (inv.regions.some((r) => !r.securityGroups || !r.loadBalancers || !r.interfaces)) return null;
  const out: AwsOrigin[] = [];
  for (const r of inv.regions) {
    const groupsOf = (ids: string[]) => r.securityGroups!.filter((g) => ids.includes(g.id));
    // A load balancer without groups of its own (a network load balancer) is judged through its targets' addresses.
    for (const lb of r.loadBalancers!) {
      const access = lb.securityGroups.length ? webAccess(groupsOf(lb.securityGroups)) : null;
      if (access) out.push({ kind: "elb", name: lb.dnsName, region: r.name, resource: `load balancer ${lb.name}`, ...access });
    }
    for (const i of r.interfaces!) {
      const access = i.publicIp ? webAccess(groupsOf(i.securityGroups)) : null;
      if (!access) continue;
      const inst = i.kind === "instance" ? r.instances?.find((x) => x.id === i.owner) : undefined;
      const resource = inst ? `instance ${inst.name ? `${inst.name} (${inst.id})` : inst.id}` : `${i.kind} ${i.id}`;
      out.push({ kind: "ip", name: i.publicIp!, region: r.name, resource, ...access });
    }
  }
  return out;
}

const KEEP_RELEASED_DAYS = 180;
const MAX_RELEASED = 2000;

/**
 * Carries the account's address history one scan forward: an address held at the last complete scan and missing
 * now was released. A released address is forgotten when the account holds it again, or after six months. When
 * this scan couldn't read every region (`current` null) the history is kept as it was.
 */
export function addressHistory(previous: AddressHistory | null | undefined, current: string[] | null, now: number): AddressHistory {
  if (!current) return previous ?? { held: [], released: [] };
  const have = new Set(current);
  const cutoff = now - KEEP_RELEASED_DAYS * 86_400_000;
  const released = (previous?.released ?? []).filter((r) => !have.has(r.ip) && Date.parse(r.at) >= cutoff);
  const known = new Set(released.map((r) => r.ip));
  const at = new Date(now).toISOString();
  for (const ip of previous?.held ?? []) if (!have.has(ip) && !known.has(ip)) released.push({ ip, at });
  return { held: current, released: released.slice(-MAX_RELEASED) };
}

/**
 * What other accounts in the same entity need. A region that refused the scan makes the endpoint and address lists
 * incomplete, so they aren't shared; the account's own ID always is.
 */
export function awsLinks(inv: AwsInventory): ProviderLinks {
  const complete = !inv.skippedRegions.length;
  const endpoints = complete ? ownEndpoints(inv) : null;
  const addresses = complete ? ownAddresses(inv) : null;
  const origins = complete ? ownOrigins(inv) : null;
  return {
    awsAccounts: [inv.accountId],
    awsReleased: inv.released,
    ...(endpoints ? { awsEndpoints: endpoints } : {}),
    ...(addresses ? { awsAddresses: addresses } : {}),
    ...(origins ? { awsOrigins: origins } : {}),
  };
}

/** Public hosted zones: their names count as the entity's own email domains. */
export const hostedDomains = (inv: AwsInventory): string[] => (inv.hostedZones ?? []).filter((z) => !z.private).map((z) => z.name);
