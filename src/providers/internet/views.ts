// What an internet scan (Sonar) stores for the Attack surface page: one row per
// domain, hostname and address, each with the findings on it.

import { countBySeverity } from "../../shared/severity.ts";
import { PROVIDER_INFO } from "../../shared/providers.ts";
import type { Result } from "../../core/types.ts";
import type { AwsExposureLink, AwsListenerLink, AwsRouteLink, SurfaceListener, SurfaceRouteRow, SurfaceView } from "../../shared/api.ts";
import type { InternetInventory } from "./types.ts";
import { actionText, chainOf, hostsByLoadBalancer, routesFor, targetLabel } from "./checks/routing.ts";

/** "tcp 443", "tcp 8000-8100", "all traffic". */
const portText = (o: NonNullable<AwsExposureLink["open"]>[number]) =>
  o.protocol === "-1"
    ? "all traffic"
    : `${o.protocol === "6" ? "tcp" : o.protocol === "17" ? "udp" : o.protocol} ${o.from === o.to ? o.from : `${o.from}-${o.to}`}`;

function routeRow(r: AwsRouteLink): SurfaceRouteRow {
  const match = [r.hosts.join(", "), r.paths.join(", "), r.conditions.length ? `(${r.conditions.join(", ")})` : ""].filter(Boolean).join(" ");
  return {
    rule: r.rule,
    match: match || "Any request",
    action: actionText(r),
    targets: r.targets
      ? r.targets.map((t) => ({ label: targetLabel(t), port: t.port, health: t.health, publicIp: t.publicIp, direct: !!t.publicIp && t.openOnPort === true }))
      : null,
  };
}

const listenerRow = (l: AwsListenerLink, routes: AwsRouteLink[] | null): SurfaceListener => ({
  port: l.port,
  protocol: l.protocol,
  routes: routes ? routes.map(routeRow) : null,
});

const DOMAIN_CHECKS = new Set(["NDS-001", "NCT-001"]);
const FOUND = { dns: "DNS", certificates: "Certificate logs", shodan: "Shodan", loadBalancer: "Load balancer rules", amass: "Amass" } as const;

export function surfaceView(inv: InternetInventory, failures: Result[]): SurfaceView {
  const on = (match: (f: Result) => boolean) => countBySeverity(failures.filter(match));
  const ipOf = (resource: string) => resource.replace(/:\d+$/, "");
  const lbs = new Map(inv.loadBalancers.map((lb) => [lb.dnsName, lb]));
  const exposure = new Map(inv.exposure.map((e) => [e.ip, e]));
  const reached = hostsByLoadBalancer(inv);
  // A target's direct-reach finding is about its address; the hostnames and load balancer it sits behind show it too.
  const targetsOf = (dnsName: string, host?: string) =>
    new Set(
      (lbs.get(dnsName)?.listeners ?? []).flatMap((l) =>
        (host ? routesFor(l, host) : (l.routes ?? [])).flatMap((r) => (r.targets ?? []).flatMap((t) => t.publicIp ?? [])),
      ),
    );
  return {
    domains: inv.domains.map((d) => {
      const issuers = new Map<string, number>();
      for (const c of d.certificates ?? []) issuers.set(c.issuer, (issuers.get(c.issuer) ?? 0) + 1);
      return {
        name: d.name,
        dns: d.dnsAt,
        nameservers: d.nameservers,
        certificates: d.certificates ? d.certificates.length : null,
        issuers: [...issuers.entries()].sort((a, b) => b[1] - a[1]).map(([n]) => n),
        caa: d.caa ? [...new Set([...d.caa.issue, ...d.caa.issuewild].map((x) => x || ";"))] : null,
        // The domain's own checks: where its DNS is, and the certificates issued under it.
        findings: on((f) => f.zone === d.name && DOMAIN_CHECKS.has(f.checkId)),
      };
    }),
    hosts: inv.hosts.map((h) => ({
      name: h.name,
      domain: h.domain,
      found: h.found.map((s) => FOUND[s]),
      points: h.records.length
        ? h.records.map((r) => `${r.type} ${r.target}${r.proxied ? " (proxied)" : ""}`).join(", ")
        : [...(h.resolved?.cnames ?? []).map((c) => `CNAME ${c}`), ...(h.resolved?.addresses ?? []).map((a) => `A ${a}`)].join(", "),
      servedBy: h.servedBy,
      route: routeOf(h),
      findings: on((f) => {
        if (f.resource === h.name) return true;
        if (h.loadBalancer && f.checkId === "XP-013") return chainOf(inv, h.loadBalancer).some((lb) => targetsOf(lb.dnsName, h.name).has(f.resource));
        return false;
      }),
    })),
    addresses: inv.addresses.map((a) => ({
      ip: a.ip,
      heldBy: a.heldBy ? PROVIDER_INFO[a.heldBy].label : null,
      hosts: a.hosts.map((h) => h.name),
      origin: a.hosts.some((h) => h.proxied),
      shodan: !a.shodan
        ? null
        : a.shodan.seen
          ? {
              seen: true,
              ports: a.shodan.ports,
              products: [...new Set(a.shodan.services.flatMap((s) => (s.product ? [[s.product, s.version].filter(Boolean).join(" ")] : [])))],
              vulns: a.shodan.vulns.length,
              lastSeen: a.shodan.lastSeen,
            }
          : { seen: false, ports: [], products: [], vulns: 0, lastSeen: null },
      resource: exposure.get(a.ip)?.resource ?? null,
      open: exposure.get(a.ip)?.open?.map(portText) ?? null,
      findings: on((f) => ipOf(f.resource) === a.ip),
    })),
    loadBalancers: inv.loadBalancers
      .filter((lb) => reached.has(lb.dnsName) || lb.internetFacing)
      .map((lb) => {
        const hosts = (reached.get(lb.dnsName) ?? []).map((h) => h.name);
        const targets = targetsOf(lb.dnsName);
        const named = [...new Set(lb.listeners.flatMap((l) => (l.routes ?? []).flatMap((r) => r.hosts.filter((x) => !/[*?]/.test(x)))))];
        return {
          provider: lb.provider ?? "aws",
          name: lb.name,
          awsAccount: lb.account,
          region: lb.region,
          type: lb.type,
          internetFacing: lb.internetFacing,
          web: lb.web,
          waf: lb.waf,
          hosts,
          unpointed: named.filter((n) => !hosts.includes(n)),
          listeners: lb.listeners.map((l) => listenerRow(l, l.routes)),
          findings: on(
            (f) =>
              (["XP-013", "XP-025"].includes(f.checkId) && targets.has(f.resource)) ||
              (["XP-014", "XP-015", "XP-026", "XP-027"].includes(f.checkId) && (hosts.includes(f.resource) || named.includes(f.resource))),
          ),
        };
      })
      .sort((a, b) => b.hosts.length - a.hosts.length || a.name.localeCompare(b.name)),
    unresolved: inv.unresolved,
    amass: inv.amass,
  };

  function routeOf(h: InternetInventory["hosts"][number]): SurfaceView["hosts"][number]["route"] {
    // Through a network load balancer in front of an application one, the application one's rules decide.
    const chain = h.loadBalancer ? chainOf(inv, h.loadBalancer) : [];
    const lb = chain.at(-1);
    const held = h.cloudAddress ? exposure.get(h.cloudAddress) : undefined;
    if (!lb && !held) return null;
    return {
      loadBalancer: lb?.name ?? null,
      via: chain.slice(0, -1).map((x) => x.name),
      listeners: lb ? lb.listeners.map((l) => listenerRow(l, l.routes ? routesFor(l, h.name) : null)) : [],
      address: held ? { ip: held.ip, resource: held.resource, open: held.open?.map(portText) ?? null } : null,
    };
  }
}
