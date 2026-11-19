// What an AWS scan stores for the dashboard: one row per region (and one for the
// account's global resources) for the Regions page, the endpoints, addresses and
// origins other providers' checks compare against, and the domains the account owns.

import { countBySeverity } from "../../shared/severity.ts";
import type { AwsExposureLink, AwsLoadBalancerLink, AwsOrigin, AwsTargetLink, ProviderLinks, RegionRow } from "../../shared/api.ts";
import type { Result } from "../../core/types.ts";
import type { WorkloadLink } from "../../shared/images.ts";
import type { RegistryImage } from "../../core/images.ts";
import { opens, opensWeb, ruleText } from "./checks/define.ts";
import { GLOBAL, type AwsInventory, type AwsRegion, type AwsSecurityGroup } from "./types.ts";

export { addressHistory } from "../../core/addresses.ts";

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

/** What an interface or instance is, as AWS's checks name it. */
function resourceOf(r: AwsRegion, kind: string, owner: string | null, id: string): string {
  const inst = kind === "instance" ? r.instances?.find((x) => x.id === owner) : undefined;
  if (inst) return `instance ${inst.name ? `${inst.name} (${inst.id})` : inst.id}`;
  // "ELB app/web-alb/0001" names the load balancer an interface belongs to.
  const lb = kind === "load balancer" ? (/^ELB (?:app|net|gwy)\/([^/]+)\//.exec(owner ?? "")?.[1] ?? /^ELB (\S+)$/.exec(owner ?? "")?.[1]) : undefined;
  return lb ? `load balancer ${lb}` : `${kind} ${id}`;
}

/**
 * Every load balancer with its listeners and where each route sends requests, down to the targets and whether each
 * can be reached without the load balancer. Null when a region's load balancers couldn't be read.
 */
export function loadBalancerLinks(inv: AwsInventory): AwsLoadBalancerLink[] | null {
  if (inv.regions.some((r) => !r.loadBalancers)) return null;
  const account = inv.accountName ?? inv.accountId;
  const fronted = new Set((inv.distributions ?? []).filter((x) => x.waf).flatMap((x) => x.origins.map((o) => o.domain.replace(/^dualstack\./, ""))));
  return inv.regions.flatMap((r) => {
    const groupsOf = (ids: string[]) => (r.securityGroups ?? []).filter((g) => ids.includes(g.id));
    const openOn = (ids: string[], port: number | null): boolean | null =>
      !r.securityGroups || port == null ? null : groupsOf(ids).some((g) => opens(g, port));
    const protectedArns = r.webAcls ? new Set(r.webAcls.flatMap((a) => a.loadBalancers)) : null;
    const target = (kind: string, id: string, port: number | null, health: string | null, group: string): AwsTargetLink => {
      if (kind === "instance") {
        const inst = r.instances?.find((i) => i.id === id);
        return {
          kind,
          id,
          name: inst?.name ?? null,
          group,
          port,
          health,
          publicIp: inst?.publicIp ?? null,
          openOnPort: inst ? openOn(inst.securityGroups, port) : null,
        };
      }
      if (kind === "ip") {
        const eni = r.interfaces?.find((i) => i.privateIp === id);
        const owner = eni ? resourceOf(r, eni.kind, eni.owner, eni.id) : null;
        return { kind, id, name: owner, group, port, health, publicIp: eni?.publicIp ?? null, openOnPort: eni ? openOn(eni.securityGroups, port) : null };
      }
      // A Lambda function or another load balancer, named by the end of its ARN.
      const name = kind === "lambda" ? (id.split(":").pop() ?? id) : (id.split("/")[2] ?? id);
      return { kind, id: name, name: null, group, port, health, publicIp: null, openOnPort: null };
    };
    return r.loadBalancers!.map((lb): AwsLoadBalancerLink => {
      const access = lb.securityGroups.length && r.securityGroups ? webAccess(groupsOf(lb.securityGroups)) : null;
      const targetsOf = (groupArns: string[], instancePort: number | null | undefined): AwsTargetLink[] | null => {
        if (groupArns.includes("classic")) return (lb.instances ?? []).map((id) => target("instance", id, instancePort ?? null, null, ""));
        const out: AwsTargetLink[] = [];
        for (const arn of groupArns) {
          const g = r.targetGroups?.find((x) => x.arn === arn);
          if (!g?.targets) return null;
          for (const t of g.targets) out.push(target(g.type, t.id, t.port ?? g.port, t.health, g.name));
        }
        return out;
      };
      return {
        name: lb.name,
        dnsName: lb.dnsName,
        account,
        region: r.name,
        type: lb.type,
        internetFacing: lb.internetFacing,
        web: access?.web ?? null,
        waf:
          lb.type !== "application"
            ? null
            : fronted.has(lb.dnsName) || (lb.arn && protectedArns?.has(lb.arn))
              ? true
              : protectedArns && inv.distributions
                ? false
                : null,
        listeners: (lb.listeners ?? []).map((l) => ({
          port: l.port,
          protocol: l.protocol,
          routes: l.rules
            ? l.rules.map((rule) => ({
                rule: rule.priority,
                hosts: rule.hosts,
                paths: rule.paths,
                conditions: rule.conditions,
                action: rule.action,
                authenticates: rule.authenticates,
                detail: rule.detail,
                targets: rule.action === "forward" ? targetsOf(rule.targetGroups, l.instancePort) : [],
              }))
            : null,
        })),
      };
    });
  });
}

/** Every public address the account holds, with what its security groups let anyone reach. Null when a region's interfaces couldn't be read. */
export function exposureLinks(inv: AwsInventory): AwsExposureLink[] | null {
  if (inv.regions.some((r) => !r.interfaces)) return null;
  const account = inv.accountName ?? inv.accountId;
  return inv.regions.flatMap((r) =>
    r.interfaces!.flatMap((i): AwsExposureLink[] => {
      if (!i.publicIp) return [];
      const open = r.securityGroups
        ? r.securityGroups
            .filter((g) => i.securityGroups.includes(g.id))
            .flatMap((g) => g.open.map((rule) => ({ protocol: rule.protocol, from: rule.from, to: rule.to, groups: [g.name || g.id] })))
        : null;
      // The same rule in two groups is one way in.
      const merged = open?.reduce<NonNullable<AwsExposureLink["open"]>>((acc, o) => {
        const same = acc.find((a) => a.protocol === o.protocol && a.from === o.from && a.to === o.to);
        if (same) same.groups.push(...o.groups.filter((g) => !same.groups.includes(g)));
        else acc.push(o);
        return acc;
      }, []);
      return [{ ip: i.publicIp, account, region: r.name, resource: resourceOf(r, i.kind, i.owner, i.id), open: merged ?? null }];
    }),
  );
}

/**
 * The account's workloads that run container images: its ECS services, each with its containers' images and how the
 * internet reaches it (an internet-facing load balancer in front of it, or a public address with a port its security
 * groups open to anyone). Null when a region's services couldn't be read.
 */
export function workloadLinks(inv: AwsInventory): WorkloadLink[] | null {
  if (inv.regions.some((r) => r.services === null || r.taskDefinitions === null)) return null;
  const account = inv.accountName ?? inv.accountId;
  return inv.regions.flatMap((r) =>
    (r.services ?? []).map((s): WorkloadLink => {
      const lbs = r.loadBalancers ?? [];
      const forwardsTo = (arn: string) => lbs.filter((lb) => lb.listeners?.some((l) => l.rules?.some((rule) => rule.targetGroups.includes(arn))));
      const front = new Set([...s.targetGroups.flatMap(forwardsTo), ...lbs.filter((lb) => s.classicLoadBalancers.includes(lb.name))]);
      // A network load balancer can pass requests on to an application load balancer: what reaches it reaches the service.
      for (const lb of [...front])
        for (const g of r.targetGroups ?? [])
          if (g.type === "alb" && lb.arn && g.targets?.some((t) => t.id === lb.arn)) for (const outer of forwardsTo(g.arn)) front.add(outer);
      const via = [...front].filter((lb) => lb.internetFacing).map((lb) => `load balancer ${lb.name}`);
      if (s.publicIp) {
        const open = (r.securityGroups ?? []).filter((g) => s.securityGroups.includes(g.id) && g.open.length);
        for (const g of open) via.push(`a public address, with ${ruleText(g.open[0])} in ${g.name || g.id}`);
      }
      const unknown =
        // Tasks on their instance's network are as exposed as the instance, which the service doesn't name.
        s.publicIp === null ||
        (s.publicIp && (!r.securityGroups || !s.securityGroups.length)) ||
        (!r.loadBalancers && s.targetGroups.length + s.classicLoadBalancers.length > 0);
      return {
        provider: "aws",
        kind: "ECS service",
        name: s.name,
        group: s.cluster,
        account,
        region: r.name,
        link: `https://${r.name}.console.aws.amazon.com/ecs/v2/clusters/${encodeURIComponent(s.cluster)}/services/${encodeURIComponent(s.name)}?region=${r.name}`,
        containers: r.taskDefinitions?.find((t) => t.name === s.taskDefinition)?.containers ?? [],
        running: s.running,
        internet: via.length ? true : unknown ? null : false,
        via,
        loadBalancers: [...front].map((lb) => lb.dnsName),
      };
    }),
  );
}

/** Every image the account's ECR repositories list, in the shape image scanning picks from. */
export function registryImages(inv: AwsInventory): RegistryImage[] {
  return inv.regions.flatMap((r) =>
    (r.repositories ?? []).flatMap((repo) =>
      (repo.images ?? []).map((i) => ({
        registry: `${inv.accountId}.dkr.ecr.${r.name}.amazonaws.com`,
        repository: repo.name,
        region: r.name,
        digest: i.digest,
        tags: i.tags,
        pushedAt: i.pushedAt,
        pulledAt: i.pulledAt,
        public: repo.publicPolicy,
        ...(i.platforms ? { platforms: i.platforms } : {}),
      })),
    ),
  );
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
  const dns = route53Dns(inv);
  const loadBalancers = complete ? loadBalancerLinks(inv) : null;
  const exposure = complete ? exposureLinks(inv) : null;
  const workloads = complete ? workloadLinks(inv) : null;
  return {
    awsAccounts: [inv.accountId],
    awsReleased: inv.released,
    ...(endpoints ? { awsEndpoints: endpoints } : {}),
    ...(addresses ? { awsAddresses: addresses } : {}),
    ...(origins ? { awsOrigins: origins } : {}),
    ...(loadBalancers ? { awsLoadBalancers: loadBalancers } : {}),
    ...(exposure ? { awsExposure: exposure } : {}),
    ...(workloads ? { awsWorkloads: workloads } : {}),
    ...(dns ? { route53Zones: hostedDomains(inv), route53Dns: dns } : {}),
  };
}

/** Host records in public hosted zones, an alias as type ALIAS with its target; null unless every public zone's records were read. */
function route53Dns(inv: AwsInventory): NonNullable<ProviderLinks["route53Dns"]> | null {
  const zones = (inv.hostedZones ?? []).filter((z) => !z.private);
  if (!inv.hostedZones || zones.some((z) => !z.records)) return null;
  return zones.flatMap((z) =>
    z.records!.flatMap((r) => r.targets.map((target) => ({ host: r.name, zone: z.name, type: r.alias ? "ALIAS" : r.type, target, proxied: false }))),
  );
}

/** Public hosted zones: their names count as the entity's own email domains. */
export const hostedDomains = (inv: AwsInventory): string[] => (inv.hostedZones ?? []).filter((z) => !z.private).map((z) => z.name);
