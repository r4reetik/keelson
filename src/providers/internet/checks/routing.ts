// Follows each of the entity's hostnames to what serves it in AWS or Alibaba Cloud: the
// load balancer its DNS names, the listener rules that match it, the target (server)
// groups they forward to, and the instances or addresses registered there. Each cloud's
// findings have their own check IDs (XP-013–015 for AWS, XP-025–027 for Alibaba Cloud),
// so they carry the right platform and docs. What neither side shows alone:
//  - a target with a public address whose security groups let anyone in, so the load
//    balancer, and the WAF, sign-in and TLS on it, can be skipped by going straight there;
//  - a public hostname that points at a load balancer only reachable inside its VPC;
//  - a rule that still routes a hostname DNS no longer points at, reachable by anyone who
//    sends that Host header to the load balancer.

import { defineChecks } from "./define.ts";
import { alibabaEndpointOf, awsEndpointOf } from "../../../core/links.ts";
import { PROVIDER_INFO } from "../../../shared/providers.ts";
import type { AwsListenerLink, AwsLoadBalancerLink, AwsRouteLink, AwsTargetLink } from "../../../shared/api.ts";
import type { Host, InternetInventory } from "../types.ts";

/** Whether a host header condition value (with * and ? wildcards, any case) matches a hostname. */
export function hostMatches(pattern: string, host: string): boolean {
  const re = pattern
    .toLowerCase()
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp(`^${re}$`).test(host.toLowerCase());
}

/**
 * The routes of a listener a request for `host` can take, in the order the load balancer tries them: those with no
 * host condition or one that matches, up to the first that catches every remaining request for it.
 */
export function routesFor(l: AwsListenerLink, host: string): AwsRouteLink[] {
  const out: AwsRouteLink[] = [];
  for (const r of l.routes ?? []) {
    if (r.hosts.length && !r.hosts.some((p) => hostMatches(p, host))) continue;
    out.push(r);
    if (!r.paths.length && !r.conditions.length) break;
  }
  return out;
}

/** "web-1 (i-0abc…)", "10.0.1.20", "function thumbnailer". */
export const targetLabel = (t: AwsTargetLink): string =>
  t.kind === "instance"
    ? t.name
      ? `${t.name} (${t.id})`
      : t.id
    : t.kind === "ip"
      ? t.name
        ? `${t.name} at ${t.id}`
        : t.id
      : t.kind === "lambda"
        ? `function ${t.id}`
        : `load balancer ${t.id}`;

const kindOf = (lb: AwsLoadBalancerLink) =>
  `${lb.internetFacing ? "internet-facing" : "internal"} ${lb.type === "classic" ? "classic" : lb.type} load balancer`;

/** "443 HTTPS, rule 10 (api.example.com /admin/*)". */
export function routeText(l: AwsListenerLink, r: AwsRouteLink): string {
  const match = [r.hosts.join(", "), r.paths.join(", "), r.conditions.length ? `(${r.conditions.join(", ")})` : ""].filter(Boolean).join(" ");
  return `${l.port ?? "?"} ${l.protocol}, ${r.rule === "default" ? "default rule" : `rule ${r.rule}`}${match ? ` (${match})` : ""}`;
}

/** What a route does, in words. */
export function actionText(r: AwsRouteLink): string {
  const groups = [...new Set((r.targets ?? []).map((t) => t.group).filter(Boolean))];
  const to = groups.length ? ` to ${groups.join(", ")}` : "";
  if (r.action === "forward") return `${r.authenticates ? "Signs visitors in, then forwards" : "Forwards"}${to}`;
  if (r.action === "redirect") return `Redirects to ${r.detail ?? "another address"}`;
  if (r.action === "fixed-response") return `Answers ${r.detail ?? "a fixed response"}`;
  return "Other action";
}

/**
 * The load balancers a request reaches from the one a DNS name names: that one, then the application load balancer
 * it forwards to, when a network load balancer sits in front of one (an `alb` target). Same account and region only.
 */
export function chainOf(inv: InternetInventory, dnsName: string): AwsLoadBalancerLink[] {
  const out: AwsLoadBalancerLink[] = [];
  let lb = inv.loadBalancers.find((x) => x.dnsName === dnsName);
  while (lb && !out.includes(lb) && out.length < 3) {
    out.push(lb);
    const from: AwsLoadBalancerLink = lb;
    const next = from.listeners.flatMap((l) => (l.routes ?? []).flatMap((r) => (r.targets ?? []).filter((t) => t.kind === "alb").map((t) => t.id)))[0];
    lb = next
      ? inv.loadBalancers.find((x) => x.name === next && x.type === "application" && x.region === from.region && x.account === from.account)
      : undefined;
  }
  return out;
}

/** The hostnames whose DNS reaches each load balancer, directly or through one in front of it, by its DNS name. */
export function hostsByLoadBalancer(inv: InternetInventory): Map<string, Host[]> {
  const out = new Map<string, Host[]>();
  for (const h of inv.hosts)
    if (h.loadBalancer) for (const lb of chainOf(inv, h.loadBalancer)) (out.get(lb.dnsName) ?? out.set(lb.dnsName, []).get(lb.dnsName)!).push(h);
  return out;
}

/** Each cloud's check IDs: a target reached directly, a public name on an internal load balancer, a rule DNS no longer uses. */
const IDS = {
  aws: { direct: "XP-013", internal: "XP-014", stale: "XP-015", group: "target group" },
  alibaba: { direct: "XP-025", internal: "XP-026", stale: "XP-027", group: "server group" },
} as const;
const cloudOf = (lb: AwsLoadBalancerLink) => lb.provider ?? "aws";

/** CDNs that forward the visitor's Host header to their origin: a hostname on one may reach the load balancer through it. */
const viaCdn = (t: string) => awsEndpointOf(t)?.kind === "cloudfront" || alibabaEndpointOf(t)?.kind === "cdn";

const domainOf = (inv: InternetInventory, host: string) => inv.domains.find((d) => host === d.name || host.endsWith(`.${d.name}`))?.name ?? null;

export default defineChecks(
  {
    "XP-013": {
      spans: ["aws"],
      category: "Attack surface",
      severity: "high",
      docs: "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-update-security-groups.html",
      requires: ["routing"],
      attackPath: true,
      title: "Load balancer's target can be reached without the load balancer",
      why: "The entity's hostname goes through a load balancer, but a target behind it has its own public address and security groups that let anyone reach the port it serves on. Anyone who finds that address (Shodan, certificate logs, an old DNS record) skips the load balancer and everything on it: the WAF, rate limits, TLS settings, and any sign-in the rule requires. Critical when the rule signs visitors in first: the application is reachable without signing in.",
      fix: "1. Let only the load balancer reach its targets: in the target's security group, replace the rule that admits 0.0.0.0/0 or ::/0 on the target port with one that admits the load balancer's security group. 2. Move targets to private subnets without public addresses, so they can't be reached from the internet at all. 3. If the application checks who is signed in from the load balancer's headers, make it verify the header's signature, since a direct request can forge it.",
    },
    "XP-014": {
      spans: ["aws"],
      category: "DNS",
      severity: "low",
      docs: "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#load-balancer-scheme",
      requires: ["routing"],
      title: "Public hostname points at an internal load balancer",
      why: "The hostname is in public DNS but its load balancer is internal: it answers only inside its VPC, and its public name resolves to private addresses. Anyone can read the internal load balancer's name and the private addresses behind it, which maps the internal network, and the hostname doesn't work for anyone outside.",
      fix: "Move the record to a private hosted zone (Route 53) that only the VPC resolves, or point it at an internet-facing load balancer if it is meant to be public. Delete it if nothing uses it.",
    },
    "XP-015": {
      spans: ["aws"],
      category: "Attack surface",
      severity: "low",
      docs: "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/rule-condition-types.html#host-conditions",
      requires: ["routing", "related"],
      title: "Load balancer still routes a hostname that DNS doesn't point at it",
      why: "An internet-facing load balancer has a rule for this hostname, but no DNS record sends it there any more. The application behind the rule is still reachable by anyone who sends that Host header to the load balancer, and old or staging applications left this way are rarely patched or watched.",
      fix: "If the application is retired, delete the rule and its target group. If it is still needed, give it a DNS record and the same protection as the entity's other hostnames, or limit the rule to the addresses that use it (a source IP condition).",
    },
    "XP-025": {
      spans: ["alibaba"],
      category: "Attack surface",
      severity: "high",
      docs: "https://www.alibabacloud.com/help/en/slb/application-load-balancer/user-guide/add-an-alb-instance-to-a-security-group",
      requires: ["routing"],
      attackPath: true,
      title: "Alibaba Cloud load balancer's backend server can be reached without the load balancer",
      why: "The entity's hostname goes through an Alibaba Cloud load balancer, but a backend server behind it has its own public address and security groups that let anyone reach the port it serves on. Anyone who finds that address (Shodan, certificate logs, an old DNS record) skips the load balancer and everything on it: WAF, access control lists and TLS settings.",
      fix: "1. Let only the load balancer reach its backends: in the server's security group, replace the rule that admits 0.0.0.0/0 on the backend port with one that admits the load balancer's vSwitch range or security group. 2. Release the server's public address or EIP, so it can only be reached through the load balancer.",
    },
    "XP-026": {
      spans: ["alibaba"],
      category: "DNS",
      severity: "low",
      docs: "https://www.alibabacloud.com/help/en/slb/application-load-balancer/user-guide/create-an-alb-instance",
      requires: ["routing"],
      title: "Public hostname points at an internal Alibaba Cloud load balancer",
      why: "The hostname is in public DNS but its load balancer is internal (intranet): it answers only inside its VPC. Anyone can read the internal load balancer's name and the private addresses behind it, which maps the internal network, and the hostname doesn't work for anyone outside.",
      fix: "Move the record to Alibaba Cloud DNS PrivateZone, which only the VPC resolves, or point it at an internet-facing load balancer if it is meant to be public. Delete it if nothing uses it.",
    },
    "XP-027": {
      spans: ["alibaba"],
      category: "Attack surface",
      severity: "low",
      docs: "https://www.alibabacloud.com/help/en/slb/application-load-balancer/user-guide/manage-forwarding-rules-for-a-listener",
      requires: ["routing", "related"],
      title: "Alibaba Cloud load balancer still routes a hostname that DNS doesn't point at it",
      why: "An internet-facing ALB has a forwarding rule for this hostname, but no DNS record sends it there any more. The application behind the rule is still reachable by anyone who sends that Host header to the load balancer, and old or staging applications left this way are rarely patched or watched.",
      fix: "If the application is retired, delete the forwarding rule and its server group. If it is still needed, give it a DNS record and the same protection as the entity's other hostnames, or limit the rule to the addresses that use it (a source IP condition).",
    },
  },
  ({ inv }, report) => {
    const reached = hostsByLoadBalancer(inv);

    // XP-013: each public target behind a load balancer that one of the entity's hostnames reaches.
    const direct = new Map<
      string,
      { cloud: "aws" | "alibaba"; target: AwsTargetLink; steps: string[]; hosts: Set<string>; lbs: Set<string>; signsIn: boolean; open: boolean | null }
    >();
    for (const lb of inv.loadBalancers) {
      const hosts = reached.get(lb.dnsName) ?? [];
      // Only an internet-facing layer-7 load balancer adds something a direct request skips.
      if (!hosts.length || !lb.internetFacing || !["application", "classic"].includes(lb.type)) continue;
      for (const l of lb.listeners)
        for (const h of hosts)
          for (const r of routesFor(l, h.name)) {
            if (r.action !== "forward") continue;
            for (const t of r.targets ?? []) {
              if (!t.publicIp) continue;
              const e =
                direct.get(t.publicIp) ??
                direct
                  .set(t.publicIp, { cloud: cloudOf(lb), target: t, steps: [], hosts: new Set(), lbs: new Set(), signsIn: false, open: null })
                  .get(t.publicIp)!;
              e.hosts.add(h.name);
              e.lbs.add(lb.name);
              e.signsIn ||= r.authenticates && t.openOnPort === true;
              e.open = e.open === true || t.openOnPort === true ? true : (t.openOnPort ?? e.open);
              const step = `${h.name} → ${lb.name} (${kindOf(lb)}, ${lb.region}), ${routeText(l, r)}: ${actionText(r)}`;
              if (e.steps.length < 3 && !e.steps.includes(step)) e.steps.push(step);
            }
          }
    }
    for (const [ip, e] of direct) {
      if (e.open == null) continue;
      const hosts = [...e.hosts];
      const exposure = inv.exposure.find((x) => x.ip === ip);
      const groups = exposure?.open?.flatMap((o) => o.groups) ?? [];
      report(IDS[e.cloud].direct, {
        zone: domainOf(inv, hosts[0]),
        resource: ip,
        pass: !e.open,
        severity: e.open && e.signsIn ? "critical" : undefined,
        detail: e.open
          ? `${targetLabel(e.target)} answers on port ${e.target.port} to anyone, behind ${[...e.lbs].join(", ")}; reached by ${hosts.slice(0, 3).join(", ")}${hosts.length > 3 ? ` and ${hosts.length - 3} more` : ""}`
          : "",
        evidence: e.open
          ? {
              chain: [
                ...e.steps.map((value) => ({ label: "DNS and load balancer", value })),
                {
                  label: "Target",
                  value: `${targetLabel(e.target)} in ${IDS[e.cloud].group} ${e.target.group || "of the classic load balancer"}, port ${e.target.port}, public address ${ip}`,
                },
                {
                  label: "Security groups",
                  value: `${groups.length ? [...new Set(groups)].join(", ") : "Its groups"} let anyone reach port ${e.target.port}${e.signsIn ? ": a direct request skips the sign-in the rule requires" : ""}`,
                },
              ],
            }
          : null,
      });
    }

    // XP-014: every hostname that reaches a load balancer, by its scheme.
    const byName = new Map(inv.loadBalancers.map((lb) => [lb.dnsName, lb]));
    for (const h of inv.hosts) {
      const lb = h.loadBalancer ? byName.get(h.loadBalancer) : undefined;
      if (!lb) continue;
      report(IDS[cloudOf(lb)].internal, {
        zone: h.domain,
        resource: h.name,
        pass: lb.internetFacing,
        detail: lb.internetFacing ? "" : `Points at ${lb.name}, an ${kindOf(lb)} in ${lb.region}`,
        evidence: lb.internetFacing
          ? null
          : {
              chain: [
                { label: "DNS", value: `${h.name} → ${lb.dnsName}` },
                { label: PROVIDER_INFO[cloudOf(lb)].label, value: `${lb.name} is internal (${lb.account})` },
              ],
            },
      });
    }

    // XP-015: every exact hostname an internet-facing application load balancer routes without other conditions.
    for (const lb of inv.loadBalancers) {
      if (!lb.internetFacing || lb.type !== "application") continue;
      const routed = new Map<string, string>();
      for (const l of lb.listeners)
        for (const r of l.routes ?? [])
          if (r.action === "forward" && !r.conditions.length)
            for (const host of r.hosts) if (!/[*?]/.test(host) && !routed.has(host)) routed.set(host, `${routeText(l, r)}: ${actionText(r)}`);
      for (const [host, rule] of routed) {
        const zone = domainOf(inv, host);
        if (!zone) continue;
        const h = inv.hosts.find((x) => x.name === host);
        // CloudFront and Alibaba Cloud CDN forward the visitor's Host header to their origin, so a hostname on one may
        // well reach this load balancer through it: not judged.
        if (h && [...h.records.map((r) => r.target), ...(h.resolved?.cnames ?? [])].some(viaCdn)) continue;
        const pointed = !!h?.loadBalancer && chainOf(inv, h.loadBalancer).some((x) => x.dnsName === lb.dnsName);
        const elsewhere = h?.loadBalancer ? byName.get(h.loadBalancer) : undefined;
        report(IDS[cloudOf(lb)].stale, {
          zone,
          resource: host,
          pass: pointed,
          detail: pointed
            ? ""
            : `${lb.name} routes it, but ${!h ? "it doesn't resolve" : elsewhere ? `its DNS points at another load balancer, ${elsewhere.name}` : `its DNS points at ${h.servedBy}`}`,
          confidence: pointed ? undefined : "likely",
          evidence: pointed
            ? null
            : {
                chain: [
                  { label: "Load balancer", value: `${lb.name} (${kindOf(lb)}, ${lb.region}), ${rule}` },
                  {
                    label: "DNS",
                    value: !h
                      ? `${host} has no DNS answer`
                      : elsewhere
                        ? `${host} points at ${elsewhere.name} (${elsewhere.region})`
                        : `${host} points at ${h.servedBy}`,
                  },
                ],
              },
        });
      }
    }
  },
);
