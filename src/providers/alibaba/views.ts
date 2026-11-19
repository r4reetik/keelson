// What an Alibaba Cloud scan stores for the dashboard: one row per resource for the
// Resources page, with the regions that hold them, and the endpoints,
// addresses, origins, load balancers and DNS records other providers' checks and
// Sonar compare against. The shapes are AWS's, so the code that reads them works for
// both clouds.

import { workloadLinks } from "./images.ts";
import { countBySeverity } from "../../shared/severity.ts";
import type { AwsExposureLink, AwsLoadBalancerLink, AwsOrigin, AwsTargetLink, ProviderLinks, ResourceRow, ResourcesView } from "../../shared/api.ts";
import type { Result } from "../../core/types.ts";
import { dash, isServer, opens, opensWeb, usedBy } from "./checks/define.ts";
import { publicThrough, serviceBucket } from "./checks/storage.ts";
import { GLOBAL, type AlibabaInventory, type AlibabaLoadBalancer, type AlibabaRegion, type AlibabaSecurityGroup } from "./types.ts";

export { addressHistory } from "../../core/addresses.ts";

/** Severity counts of the open findings on one resource: its zone, and its name, ID or "name (ID)" in the finding's resource. */
function findingsOn(failures: Result[]) {
  const byZone = new Map<string, Result[]>();
  for (const f of failures) byZone.set(f.zone ?? GLOBAL, [...(byZone.get(f.zone ?? GLOBAL) ?? []), f]);
  return (zone: string, id: string, name: string) =>
    countBySeverity(
      (byZone.get(zone) ?? []).filter((f) => {
        const r = f.resource ?? "";
        return r === id || r === name || r.includes(`(${id})`) || r.startsWith(`${name} (`);
      }),
    );
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/**
 * Every resource the checks read, for the Resources page: Alibaba Cloud's products in its own words, where each one
 * is, how the internet reaches it, and its open findings. Kinds that couldn't be read are left out, and so are
 * service-linked roles, which Alibaba Cloud manages.
 */
export function resourceView(inv: AlibabaInventory, failures: Result[]): ResourcesView {
  const on = findingsOn(failures);
  const rows: ResourceRow[] = [];
  const add = (r: Omit<ResourceRow, "findings">) => rows.push({ ...r, findings: on(r.region, r.id, r.name) });
  const block = inv.ossBlock;
  const admins = new Set((inv.admins ?? []).map((a) => `${a.kind}:${a.name}`));

  for (const u of inv.users ?? []) {
    const keys = (u.keys ?? []).filter((k) => k.active).length;
    add({
      kind: "RAM user",
      group: "Identity",
      id: u.name,
      name: u.name,
      region: GLOBAL,
      exposure: null,
      facts: [
        u.console ? (u.mfa === false ? "Console, no MFA" : "Console") : "",
        keys ? plural(keys, "AccessKey") : "",
        admins.has(`user:${u.name}`) ? "Administrator" : "",
      ].filter(Boolean),
      link: dash.user(u.name),
    });
  }
  for (const r of inv.roles ?? []) {
    if (r.serviceLinked) continue;
    const trusts = [
      ...new Set(r.trust.map((t) => (t.github ? "GitHub Actions" : t.kind === "service" ? t.principal.replace(/\.aliyuncs\.com$/, "") : t.kind))),
    ];
    add({
      kind: "RAM role",
      group: "Identity",
      id: r.name,
      name: r.name,
      region: GLOBAL,
      exposure: null,
      facts: [trusts.length ? `Trusts ${trusts.join(", ")}` : "", r.admin ? "Administrator" : ""].filter(Boolean),
      link: dash.role(r.name),
    });
  }
  for (const b of inv.buckets ?? []) {
    const through = b.acl === undefined || b.blockPublicAccess === undefined ? [] : publicThrough(b, block ?? null);
    add({
      kind: "OSS bucket",
      group: "Storage",
      id: b.name,
      name: b.name,
      region: b.region,
      exposure: through.length ? `Public through ${through.join(" and ")}` : null,
      facts: [
        b.acl ? `ACL ${b.acl}` : "",
        b.blockPublicAccess ? "Blocks public access" : "",
        serviceBucket(b.name) ? "Managed by Container Registry" : "",
      ].filter(Boolean),
      link: dash.bucket(b.name, b.region),
    });
  }
  for (const c of inv.cdnDomains ?? [])
    add({
      kind: "CDN domain",
      group: "Edge",
      id: c.name,
      name: c.name,
      region: GLOBAL,
      exposure: c.online ? `Serves ${c.https ? "HTTPS" : "plain HTTP only"}` : null,
      facts: [c.online ? "" : "Offline", ...c.origins.slice(0, 2).map((o) => `From ${o}`)].filter(Boolean),
      link: dash.cdnDomain(c.name),
    });
  for (const dom of inv.domains ?? [])
    add({
      kind: "DNS domain",
      group: "Edge",
      id: dom.name,
      name: dom.name,
      region: GLOBAL,
      exposure: null,
      facts: dom.records ? [plural(dom.records.length, "record")] : [],
      link: dash.dnsDomain(dom.name),
    });

  for (const r of inv.regions) {
    const zone = r.name;
    for (const i of r.instances ?? []) {
      const nics = (r.interfaces ?? []).filter((n) => n.owner === i.id);
      const address = i.publicIp ?? nics.find((n) => n.publicIp)?.publicIp ?? null;
      add({
        kind: "ECS instance",
        group: "Compute",
        id: i.id,
        name: i.name ?? i.id,
        region: zone,
        exposure: address ? `Public address ${address}` : null,
        facts: [
          i.running ? "" : "Stopped",
          i.os ? (i.os === "linux" ? (i.keyPair ? "Linux, key pair" : "Linux, password") : "Windows") : "",
          i.role ? `Runs as ${i.role}` : "",
          i.metadataTokens === false ? "Metadata without a token" : "",
          i.network === "classic" ? "Classic network" : "",
        ].filter(Boolean),
        link: dash.instance(zone, i.id),
      });
    }
    for (const lb of r.loadBalancers ?? []) {
      const ports = (lb.listeners ?? []).map((l) => `${l.protocol} ${l.port ?? ""}`.trim());
      add({
        kind: lb.type.toUpperCase(),
        group: "Networking",
        id: lb.id,
        name: lb.name,
        region: zone,
        exposure: lb.internetFacing ? `Internet-facing at ${lb.address ?? lb.dnsName ?? "a public address"}` : null,
        facts: [ports.length ? `Listens on ${ports.slice(0, 4).join(", ")}${ports.length > 4 ? ` and ${ports.length - 4} more` : ""}` : "No listeners"],
        link: dash.loadBalancer(zone, lb.type, lb.id),
      });
    }
    for (const g of r.securityGroups ?? []) {
      const attached = usedBy(r, g.id).filter(isServer);
      const reachable = attached.filter((n) => n.publicIp).length;
      const open = g.open.map((x) => (x.protocol === "all" ? "all traffic" : `${x.protocol} ${x.from === x.to ? x.from : `${x.from}-${x.to}`}`));
      add({
        kind: "Security group",
        group: "Networking",
        id: g.id,
        name: g.name,
        region: zone,
        exposure:
          open.length && reachable
            ? `Open to anyone on ${[...new Set(open)].slice(0, 4).join(", ")}, on ${plural(reachable, "public address", "public addresses")}`
            : null,
        facts: [
          r.interfaces
            ? attached.length
              ? `Attached to ${plural(attached.length, "server")}`
              : usedBy(r, g.id).length
                ? "Used by load balancers or Alibaba Cloud services"
                : "Not attached"
            : "",
          open.length && !reachable ? `Open to anyone on ${[...new Set(open)].slice(0, 3).join(", ")}` : "",
        ].filter(Boolean),
        link: dash.securityGroup(zone, g.id),
      });
    }
    for (const db of r.databases ?? []) {
      const kind = db.service === "redis" ? "Tair (Redis)" : db.service === "mongodb" ? "MongoDB" : "RDS";
      add({
        kind,
        group: "Databases",
        id: db.id,
        name: db.name ?? db.id,
        region: zone,
        exposure: db.publicEndpoint ? `Public endpoint${db.openWhitelist.length ? `, whitelist ${db.openWhitelist.join(", ")}` : ""}` : null,
        facts: [
          db.engine,
          !db.publicEndpoint && db.openWhitelist.length ? `Whitelist ${db.openWhitelist.join(", ")}` : "",
          db.passwordFree ? "No password in the VPC" : "",
          db.ssl === false ? "No TLS" : "",
        ].filter(Boolean),
        link: dash.database(zone, db.id, db.service),
      });
    }
    for (const f of r.functions ?? [])
      add({
        kind: "Function",
        group: "Compute",
        id: f.name,
        name: f.name,
        region: zone,
        exposure: f.anonymousTriggers?.length ? `Anyone can call ${f.anonymousTriggers.join(", ")}` : null,
        facts: [f.runtime ?? "", f.role ? `Runs as ${f.role}` : ""].filter(Boolean),
        link: dash.function(zone, f.name),
      });
    for (const c of r.clusters ?? [])
      add({
        kind: "ACK cluster",
        group: "Compute",
        id: c.id,
        name: c.name,
        region: zone,
        exposure: c.publicEndpoint ? "API server on the internet" : null,
        facts: c.version ? [`Kubernetes ${c.version}`] : [],
        link: dash.cluster(zone, c.id),
      });
    for (const v of r.vpcs ?? [])
      add({
        kind: "VPC",
        group: "Networking",
        id: v.id,
        name: v.id,
        region: zone,
        exposure: null,
        facts: [v.flowLogs === false ? "No flow logs" : v.flowLogs ? "Flow logs" : ""].filter(Boolean),
        link: dash.vpc(zone, v.id),
      });
  }

  const count = new Map<string, number>();
  for (const row of rows) if (row.region !== GLOBAL) count.set(row.region, (count.get(row.region) ?? 0) + 1);
  return {
    rows,
    regions: [...count]
      .map(([name, resources]) => ({ name, label: inv.regionNames[name] ?? null, resources }))
      .sort((a, b) => b.resources - a.resources || a.name.localeCompare(b.name)),
    emptyRegions: inv.regions.filter((r) => !count.has(r.name)).length,
    skippedRegions: inv.skippedRegions,
  };
}

/**
 * The endpoints this account has that a DNS record can name: OSS buckets, ALB and NLB DNS names and CDN domains'
 * CNAMEs. Null when any of them couldn't be read, so a missing one is never mistaken for a deleted one.
 */
export function ownEndpoints(inv: AlibabaInventory): NonNullable<ProviderLinks["alibabaEndpoints"]> | null {
  if (!inv.buckets || !inv.cdnDomains || inv.regions.some((r) => !r.loadBalancers)) return null;
  return [
    ...inv.buckets.map((b) => ({ kind: "oss" as const, name: b.name })),
    ...inv.regions.flatMap((r) => r.loadBalancers!.flatMap((lb) => (lb.dnsName ? [{ kind: "slb" as const, name: lb.dnsName.toLowerCase() }] : []))),
    ...inv.cdnDomains.map((c) => ({ kind: "cdn" as const, name: c.cname.toLowerCase() })),
  ];
}

/** Every public IPv4 address the account holds: EIPs, instances' and interfaces' public addresses, and CLBs' addresses. Null when a region couldn't be read. */
export function ownAddresses(inv: AlibabaInventory): string[] | null {
  if (inv.regions.some((r) => !r.interfaces || !r.addresses || !r.instances || !r.loadBalancers)) return null;
  return [
    ...new Set(
      inv.regions.flatMap((r) => [
        ...r.addresses!,
        ...r.interfaces!.flatMap((i) => i.publicIp ?? []),
        ...r.instances!.flatMap((i) => i.publicIp ?? []),
        ...r.loadBalancers!.flatMap((lb) => (lb.internetFacing && lb.address ? [lb.address] : [])),
      ]),
    ),
  ];
}

/** Who a set of security groups lets reach ports 80 and 443, or null when Keelson can't tell (see AwsOrigin). */
function webAccess(groups: AlibabaSecurityGroup[]): Pick<AwsOrigin, "web" | "groups"> | null {
  const named = (gs: AlibabaSecurityGroup[]) => gs.map((g) => ({ id: g.id, name: g.name }));
  const open = groups.filter(opensWeb);
  if (open.length) return { web: "open", groups: named(open) };
  if (!groups.length || groups.some((g) => !g.webFrom || g.webFrom.prefixLists.length)) return null;
  if (groups.some((g) => g.webFrom!.other)) return { web: "other", groups: named(groups) };
  // No rule for the web ports at all: Cloudflare can't reach it there either, so it's served some other way.
  if (groups.some((g) => g.webFrom!.cloudflare)) return { web: "cloudflare", groups: named(groups) };
  return null;
}

/** What an interface is, as the checks name it. */
function resourceOf(r: AlibabaRegion, kind: string, owner: string | null, id: string): string {
  const inst = kind === "instance" ? r.instances?.find((x) => x.id === owner) : undefined;
  if (inst) return `instance ${inst.name ? `${inst.name} (${inst.id})` : inst.id}`;
  return owner ? `${kind} ${owner}` : `${kind} ${id}`;
}

/**
 * Who can reach the account's web origins: ALBs and NLBs with security groups by DNS name, and every interface with
 * a public address. Null when a region's security groups, load balancers or interfaces couldn't be read.
 */
export function ownOrigins(inv: AlibabaInventory): AwsOrigin[] | null {
  if (inv.regions.some((r) => !r.securityGroups || !r.loadBalancers || !r.interfaces)) return null;
  const out: AwsOrigin[] = [];
  for (const r of inv.regions) {
    const groupsOf = (ids: string[]) => r.securityGroups!.filter((g) => ids.includes(g.id));
    for (const lb of r.loadBalancers!) {
      const access = lb.securityGroups.length ? webAccess(groupsOf(lb.securityGroups)) : null;
      if (access && lb.dnsName) out.push({ kind: "elb", name: lb.dnsName.toLowerCase(), region: r.name, resource: `load balancer ${lb.name}`, ...access });
    }
    for (const i of r.interfaces!) {
      const access = i.publicIp ? webAccess(groupsOf(i.securityGroups)) : null;
      if (access) out.push({ kind: "ip", name: i.publicIp!, region: r.name, resource: resourceOf(r, i.kind, i.owner, i.id), ...access });
    }
  }
  return out;
}

const AWS_TYPE: Record<AlibabaLoadBalancer["type"], string> = { alb: "application", nlb: "network", clb: "classic" };

/**
 * Every load balancer with its listeners and where each route sends requests, down to the backend servers and
 * whether each can be reached without the load balancer. In AWS's shape: an ALB is "application", an NLB "network",
 * a CLB "classic". Null when a region's load balancers couldn't be read.
 */
export function loadBalancerLinks(inv: AlibabaInventory): AwsLoadBalancerLink[] | null {
  if (inv.regions.some((r) => !r.loadBalancers)) return null;
  const account = inv.accountName ?? inv.accountId;
  return inv.regions.flatMap((r) => {
    const groupsOf = (ids: string[]) => (r.securityGroups ?? []).filter((g) => ids.includes(g.id));
    const openOn = (ids: string[], port: number | null): boolean | null =>
      !r.securityGroups || port == null ? null : groupsOf(ids).some((g) => opens(g, port));
    const server = (s: { id: string; ip: string | null; port: number | null; type: string }, group: string): AwsTargetLink => {
      const inst = r.instances?.find((i) => i.id === s.id);
      if (inst)
        return {
          kind: "instance",
          id: inst.id,
          name: inst.name,
          group,
          port: s.port,
          health: null,
          publicIp: inst.publicIp,
          openOnPort: openOn(inst.securityGroups, s.port),
        };
      const eni = r.interfaces?.find((i) => i.id === s.id || (s.ip && i.privateIp === s.ip));
      return {
        kind: s.type.toLowerCase() === "fc" ? "lambda" : "ip",
        id: s.ip ?? s.id,
        name: eni ? resourceOf(r, eni.kind, eni.owner, eni.id) : null,
        group,
        port: s.port,
        health: null,
        publicIp: eni?.publicIp ?? null,
        openOnPort: eni ? openOn(eni.securityGroups, s.port) : null,
      };
    };
    const targetsOf = (lb: AlibabaLoadBalancer, groups: string[], port: number | null): AwsTargetLink[] | null => {
      // A CLB's default backends are instances on the listener's backend port.
      if (lb.type === "clb" && !groups.length) return (lb.backends ?? []).map((id) => server({ id, ip: null, port, type: "Ecs" }, ""));
      const out: AwsTargetLink[] = [];
      for (const id of groups) {
        const g = r.serverGroups?.find((x) => x.id === id);
        if (!g?.servers) return null;
        for (const s of g.servers) out.push(server(s, g.name));
      }
      return out;
    };
    return r.loadBalancers!.map(
      (lb): AwsLoadBalancerLink => ({
        provider: "alibaba",
        name: lb.name,
        dnsName: (lb.dnsName ?? lb.address ?? lb.id).toLowerCase(),
        account,
        region: r.name,
        type: AWS_TYPE[lb.type],
        internetFacing: lb.internetFacing,
        web: lb.securityGroups.length && r.securityGroups ? (webAccess(groupsOf(lb.securityGroups))?.web ?? null) : null,
        waf: null,
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
                authenticates: false,
                detail: rule.detail,
                targets: rule.action === "forward" ? targetsOf(lb, rule.serverGroups, l.port) : [],
              }))
            : null,
        })),
      }),
    );
  });
}

/** Every public address the account holds, with what its security groups let anyone reach. Null when a region's interfaces couldn't be read. */
export function exposureLinks(inv: AlibabaInventory): AwsExposureLink[] | null {
  if (inv.regions.some((r) => !r.interfaces)) return null;
  const account = inv.accountName ?? inv.accountId;
  return inv.regions.flatMap((r) =>
    r.interfaces!.flatMap((i): AwsExposureLink[] => {
      if (!i.publicIp) return [];
      const open = r.securityGroups
        ? r.securityGroups
            .filter((g) => i.securityGroups.includes(g.id))
            .flatMap((g) =>
              g.open.map((rule) => ({ protocol: rule.protocol === "all" ? "-1" : rule.protocol, from: rule.from, to: rule.to, groups: [g.name || g.id] })),
            )
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

/** Enabled host records in Alibaba Cloud DNS; null unless every domain's records were read. */
function alidnsRecords(inv: AlibabaInventory): NonNullable<ProviderLinks["alidnsDns"]> | null {
  if (!inv.domains || inv.domains.some((z) => !z.records)) return null;
  return inv.domains.flatMap((z) =>
    z
      .records!.filter((r) => ["A", "AAAA", "CNAME"].includes(r.type))
      .map((r) => ({ host: r.name, zone: z.name, type: r.type, target: r.value.toLowerCase(), proxied: false })),
  );
}

/** Alibaba Cloud DNS's domains: they count as the entity's own email domains. */
export const hostedDomains = (inv: AlibabaInventory): string[] => (inv.domains ?? []).map((z) => z.name);

/**
 * What other accounts in the same entity need. A region that refused the scan makes the endpoint and address lists
 * incomplete, so they aren't shared; the account's own ID always is.
 */
export function alibabaLinks(inv: AlibabaInventory): ProviderLinks {
  const complete = !inv.skippedRegions.length;
  const endpoints = complete ? ownEndpoints(inv) : null;
  const addresses = complete ? ownAddresses(inv) : null;
  const origins = complete ? ownOrigins(inv) : null;
  const dns = alidnsRecords(inv);
  const loadBalancers = complete ? loadBalancerLinks(inv) : null;
  const exposure = complete ? exposureLinks(inv) : null;
  const workloads = complete ? workloadLinks(inv) : null;
  return {
    alibabaAccounts: [inv.accountId],
    alibabaReleased: inv.released,
    ...(endpoints ? { alibabaEndpoints: endpoints } : {}),
    ...(addresses ? { alibabaAddresses: addresses } : {}),
    ...(origins ? { alibabaOrigins: origins } : {}),
    ...(loadBalancers ? { alibabaLoadBalancers: loadBalancers } : {}),
    ...(exposure ? { alibabaExposure: exposure } : {}),
    ...(workloads ? { alibabaWorkloads: workloads } : {}),
    ...(dns ? { alidnsZones: hostedDomains(inv), alidnsDns: dns } : {}),
  };
}
