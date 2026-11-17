// Security groups that let the whole internet in: on every port, on SSH and RDP,
// or on database ports, and instances still in the classic network. Then a path
// security groups don't show: a classic load balancer (CLB) has no security group
// of its own, and its backends must admit its addresses (100.64.0.0/10), so a
// listener on an admin or database port with no access control list exposes that
// port to the internet whatever the backends' groups say about 0.0.0.0/0. As with AWS,
// what matters is what a group is attached to: a group on something with a public
// address is a way in today, one on private interfaces needs another mistake
// first, and one attached to nothing is waiting for its first use.

import { defineChecks, isServer, opens, ruleText, usedBy } from "./define.ts";
import type { AlibabaInterface, AlibabaRegion, AlibabaSecurityGroup, AlibabaSecurityRule } from "../types.ts";
import type { Severity } from "../../../core/types.ts";
import { DATABASE_PORTS } from "../../../core/ports.ts";

const ADMIN_PORTS: Record<number, string> = { 22: "SSH", 3389: "RDP" };

const isAll = (r: AlibabaSecurityRule) => r.protocol === "all";
const covers = (r: AlibabaSecurityRule, port: number) => r.protocol === "tcp" && r.from != null && r.to != null && r.from <= port && port <= r.to;
/** The open rules of a group that reach any of the ports, with the service each one exposes. All-traffic rules have their own check. */
const exposed = (g: AlibabaSecurityGroup, ports: Record<number, string>) =>
  g.open.filter((r) => !isAll(r)).flatMap((r) => Object.entries(ports).flatMap(([p, name]) => (covers(r, Number(p)) ? [{ rule: r, name }] : [])));

/** "web-1 (i-…)" or "load balancer lb-…": what an interface belongs to. */
export function ownerText(region: AlibabaRegion, i: AlibabaInterface): string {
  if (i.kind !== "instance") return i.owner ? `${i.kind} ${i.owner}`.slice(0, 80) : i.kind;
  const inst = region.instances?.find((x) => x.id === i.owner);
  return inst?.name ? `${inst.name} (${inst.id})` : (i.owner ?? "instance");
}

const ONE_LOWER: Record<string, Severity> = { critical: "high", high: "medium", medium: "low", low: "low" };

export default defineChecks(
  {
    "LNW-001": {
      category: "Attack surface",
      severity: "high",
      docs: "https://www.alibabacloud.com/help/en/ecs/user-guide/security-group-rules",
      requires: ["securityGroups", "networkInterfaces"],
      attackPath: true,
      title: "Security group opens SSH or RDP to the internet",
      why: "Remote administration ports are scanned and brute-forced around the clock. An exposed SSH or RDP port turns one weak password or unpatched service into a foothold.",
      fix: "1. Edit the group's inbound rules and replace 0.0.0.0/0 with your office or VPN range. 2. Better: remove the rule and connect with Session Manager (Workbench) or Cloud Assistant, which need no inbound port. 3. If nothing uses the group, delete it.",
    },
    "LNW-002": {
      category: "Attack surface",
      severity: "high",
      docs: "https://www.alibabacloud.com/help/en/ecs/user-guide/security-group-rules",
      requires: ["securityGroups", "networkInterfaces"],
      title: "Security group opens a database port to the internet",
      why: "A database reachable from the internet is protected by its password alone, and exposed to every bug in its network protocol.",
      fix: "Edit the group's inbound rules so the database port is allowed only from the security group of the application that uses it, not from 0.0.0.0/0. If nothing uses the group, delete it.",
    },
    "LNW-003": {
      category: "Attack surface",
      severity: "critical",
      docs: "https://www.alibabacloud.com/help/en/ecs/user-guide/security-group-rules",
      requires: ["securityGroups", "networkInterfaces"],
      attackPath: true,
      title: "Security group allows all traffic from the internet",
      why: "Every port of everything that uses this group is reachable by anyone: admin interfaces, databases, debug ports and services nobody remembers are listening.",
      fix: "Edit the group's inbound rules: delete the rule that allows all traffic from 0.0.0.0/0 or ::/0, and add rules for the specific ports the service needs. If nothing uses the group, delete it.",
    },
    "LNW-005": {
      category: "Attack surface",
      severity: "high",
      docs: "https://www.alibabacloud.com/help/en/slb/classic-load-balancer/user-guide/access-control",
      requires: ["loadBalancers"],
      attackPath: true,
      title: "Internet-facing load balancer forwards an admin or database port to anyone",
      why: "The load balancer passes connections from the whole internet to SSH, RDP or a database behind it. The servers' security groups don't stop it: they must let the load balancer's own addresses in, and the load balancer lets everyone through. This exposure doesn't show in the security groups' rules.",
      fix: "1. Remove the listener if nothing outside needs the port; reach servers through Workbench or a VPN instead. 2. Otherwise turn on access control for the listener (CLB → the instance → Listener → Access Control) with a whitelist of the addresses that need it, or, for an NLB, attach a security group that allows only those addresses.",
    },
    "LNW-004": {
      category: "Attack surface",
      severity: "medium",
      docs: "https://www.alibabacloud.com/help/en/ecs/user-guide/migrate-ecs-instances-from-the-classic-network-to-a-vpc",
      requires: ["instances"],
      title: "Instance runs in the classic network",
      why: "The classic network is shared between Alibaba Cloud customers. Instances on it aren't isolated in a VPC of your own, so other tenants' instances sit on the same network and only security groups stand between them.",
      fix: "Migrate the instance to a VPC (ECS console → the instance → Migrate to VPC), then check its security groups.",
    },
  },
  ({ inv, d }, report) => {
    const SENSITIVE: Record<number, string> = { ...ADMIN_PORTS, ...DATABASE_PORTS };
    for (const region of inv.regions)
      for (const lb of region.loadBalancers ?? []) {
        // An ALB speaks only HTTP and HTTPS; a listener whose access control couldn't be read is left out.
        if (!lb.internetFacing || lb.type === "alb" || !lb.listeners) continue;
        const groups = (region.securityGroups ?? []).filter((g) => lb.securityGroups.includes(g.id));
        // An NLB with security groups is judged by them; one without any, like every CLB, lets everyone in.
        if (lb.type === "nlb" && lb.securityGroups.length && !region.securityGroups) continue;
        const exposed = lb.listeners.flatMap((l) => {
          if (lb.type === "clb" && l.access === undefined) return [];
          const port = [l.port, l.backendPort].find((p) => p != null && SENSITIVE[p]);
          if (port == null) return [];
          const open = lb.type === "clb" ? l.access !== "allow" : !lb.securityGroups.length || groups.some((g) => opens(g, l.port ?? port));
          return open ? [`${SENSITIVE[port]} (${l.protocol} ${l.port}${l.backendPort && l.backendPort !== l.port ? ` to ${l.backendPort}` : ""})`] : [];
        });
        if (lb.type === "clb" && lb.listeners.some((l) => l.access === undefined) && !exposed.length) continue;
        report("LNW-005", {
          zone: region.name,
          resource: `${lb.name} (${lb.id})`,
          pass: !exposed.length,
          detail: exposed.length
            ? `${exposed.join(", ")} on ${lb.address ?? lb.dnsName ?? "its public address"}, ${lb.type === "clb" ? "with no access control whitelist" : "with no security group limiting who connects"}`
            : "",
          evidence: exposed.length
            ? {
                chain: [
                  { label: "Internet-facing load balancer", value: `${lb.type.toUpperCase()} ${lb.name} at ${lb.address ?? lb.dnsName ?? "a public address"}` },
                  ...exposed.map((e) => ({ label: "Listener", value: e })),
                  { label: "Who can connect", value: lb.type === "clb" ? "Anyone: the listener has no whitelist" : "Anyone: no security group narrows it" },
                ],
              }
            : null,
          link: d.loadBalancer(region.name, lb.type, lb.id),
        });
      }
    for (const region of inv.regions) {
      for (const i of region.instances ?? [])
        report("LNW-004", {
          zone: region.name,
          resource: i.name ? `${i.name} (${i.id})` : i.id,
          pass: i.network !== "classic",
          detail: i.network === "classic" ? "In the classic network, not a VPC" : "",
          link: d.instance(region.name, i.id),
        });
      if (!region.securityGroups || !region.interfaces) continue;
      for (const g of region.securityGroups) {
        const users = usedBy(region, g.id);
        // A group only load balancers and Alibaba Cloud's own services use exposes their listeners, judged elsewhere.
        if (users.length && !users.some(isServer)) {
          for (const id of ["LNW-001", "LNW-002", "LNW-003"] as const)
            report(id, { zone: region.name, resource: `${g.name} (${g.id})`, pass: true, link: d.securityGroup(region.name, g.id) });
          continue;
        }
        const attached = users.filter(isServer);
        const reachable = attached.filter((i) => i.publicIp);
        const where = reachable.length
          ? `, reachable on ${reachable.length} public address${reachable.length === 1 ? "" : "es"}: ${reachable
              .slice(0, 3)
              .map((i) => ownerText(region, i))
              .join(", ")}${reachable.length > 3 ? " and more" : ""}`
          : attached.length
            ? `, attached to ${attached.length} network interface${attached.length === 1 ? "" : "s"}, none with a public address`
            : ", not attached to anything";
        // The check's own severity when something public uses the group, one step down when only private things do, low when nothing does.
        const severity = (own: Severity): Severity | undefined => (reachable.length ? undefined : attached.length ? ONE_LOWER[own] : "low");
        const base = { zone: region.name, resource: `${g.name} (${g.id})`, link: d.securityGroup(region.name, g.id) };
        const chain = (rules: AlibabaSecurityRule[]) =>
          reachable.length
            ? {
                chain: [
                  ...rules.map((r) => ({ label: "Inbound rule", value: ruleText(r) })),
                  ...reachable.slice(0, 5).map((i) => ({ label: "Reachable from the internet", value: `${ownerText(region, i)} at ${i.publicIp}` })),
                ],
              }
            : null;

        const all = g.open.filter(isAll);
        report("LNW-003", {
          ...base,
          pass: !all.length,
          severity: all.length ? severity("critical") : undefined,
          detail: all.length ? `${all.map(ruleText).join("; ")}${where}` : "",
          evidence: all.length ? chain(all) : null,
        });

        const admin = exposed(g, ADMIN_PORTS);
        report("LNW-001", {
          ...base,
          pass: !admin.length,
          severity: admin.length ? severity("high") : undefined,
          detail: admin.length
            ? `${[...new Set(admin.map((a) => a.name))].join(" and ")}: ${[...new Set(admin.map((a) => ruleText(a.rule)))].join("; ")}${where}`
            : "",
          evidence: admin.length ? chain(admin.map((a) => a.rule)) : null,
        });

        const db = exposed(g, DATABASE_PORTS);
        report("LNW-002", {
          ...base,
          pass: !db.length,
          severity: db.length ? severity("high") : undefined,
          detail: db.length ? `${[...new Set(db.map((a) => a.name))].join(", ")}: ${[...new Set(db.map((a) => ruleText(a.rule)))].join("; ")}${where}` : "",
          evidence: db.length ? chain(db.map((a) => a.rule)) : null,
        });
      }
    }
  },
);
