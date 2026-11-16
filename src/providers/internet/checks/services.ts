// What Shodan has seen answering on the entity's addresses: databases and caches,
// remote administration, and software with known vulnerabilities. Shodan scans the
// whole internet on its own schedule, so these are "likely": the port was open when
// Shodan last looked. AWS security group checks say the same from the inside.

import { defineChecks, ownerOf, seenWhen, shodanLink, zoneOf } from "./define.ts";
import type { Severity } from "../../../core/types.ts";
import type { AwsExposureLink } from "../../../shared/api.ts";
import type { Address, InternetInventory, ShodanView } from "../types.ts";

const LOWER: Record<Severity, Severity> = { critical: "high", high: "medium", medium: "low", low: "low", info: "info" };

/**
 * What the AWS account that holds an address says about a port Shodan saw: the groups that let anyone reach it, or
 * that none does now (then Shodan's view is older than the change, or the port is open only to ranges Shodan scans
 * from). Undefined when no AWS account in the entity holds the address or its groups couldn't be read.
 */
function groupsOn(inv: InternetInventory, ip: string, port: number): { open: string[] } | { open: null; resource: string } | undefined {
  const e: AwsExposureLink | undefined = inv.exposure.find((x) => x.ip === ip);
  if (!e?.open) return undefined;
  const rules = e.open.filter(
    (o) => o.protocol === "-1" || ((o.protocol === "tcp" || o.protocol === "6") && o.from != null && o.to != null && o.from <= port && port <= o.to),
  );
  return rules.length ? { open: [...new Set(rules.flatMap((r) => r.groups))] } : { open: null, resource: e.resource };
}

/** Data stores, with the ones that answer without a password by default rated critical. */
export const DATA_PORTS: Record<number, [string, Severity]> = {
  1433: ["Microsoft SQL Server", "high"],
  1521: ["Oracle Database", "high"],
  2181: ["ZooKeeper", "high"],
  2379: ["etcd", "critical"],
  3306: ["MySQL", "high"],
  5432: ["PostgreSQL", "high"],
  5672: ["RabbitMQ", "high"],
  5984: ["CouchDB", "critical"],
  6379: ["Redis", "critical"],
  7474: ["Neo4j", "high"],
  8086: ["InfluxDB", "high"],
  9042: ["Cassandra", "high"],
  9092: ["Kafka", "high"],
  9200: ["Elasticsearch", "critical"],
  9300: ["Elasticsearch", "critical"],
  11211: ["Memcached", "critical"],
  15672: ["RabbitMQ management", "high"],
  27017: ["MongoDB", "critical"],
};

/** Ways to log in to or control a machine. */
export const ADMIN_PORTS: Record<number, [string, Severity]> = {
  22: ["SSH", "medium"],
  23: ["Telnet", "high"],
  445: ["SMB", "high"],
  2049: ["NFS", "high"],
  2375: ["Docker API without TLS", "critical"],
  3389: ["Remote Desktop", "high"],
  5900: ["VNC", "high"],
  5985: ["WinRM", "high"],
  5986: ["WinRM", "high"],
  6443: ["Kubernetes API", "medium"],
  10250: ["Kubelet", "high"],
};

/** "CVE-2024-12345" → 2024012345, to sort by year and then number. */
const cveOrder = (id: string) => {
  const m = /^CVE-(\d{4})-(\d+)$/.exec(id);
  return m ? Number(m[1]) * 1e7 + Number(m[2]) : 0;
};

const seen = (a: Address): (ShodanView & { seen: true }) | null => (a.shodan?.seen ? a.shodan : null);
const product = (v: ShodanView, port: number) => {
  const s = v.services.find((x) => x.port === port && x.product);
  return s ? ` (${[s.product, s.version].filter(Boolean).join(" ")})` : "";
};

export default defineChecks(
  {
    "NSV-001": {
      category: "Attack surface",
      severity: "high",
      docs: "https://help.shodan.io/the-basics/what-is-shodan",
      requires: ["shodan"],
      attackPath: true,
      title: "Database or cache open to the internet",
      why: "Shodan reached a database, cache or message broker on this address from the internet. Anyone can try passwords against it, use any vulnerability in it, or, for stores that need no password by default (Redis, MongoDB, Elasticsearch, Memcached, etcd, CouchDB), read and change the data directly.",
      fix: "1. Close the port to the internet: in AWS, remove the security group rule that admits 0.0.0.0/0 or ::/0 on it; elsewhere, the host's firewall. 2. Reach the service from inside the network, or through a VPN, bastion or Cloudflare Tunnel. 3. Check the service's logs for connections you don't recognise.",
    },
    "NSV-002": {
      category: "Attack surface",
      severity: "high",
      docs: "https://help.shodan.io/the-basics/what-is-shodan",
      requires: ["shodan"],
      attackPath: true,
      title: "Remote administration open to the internet",
      why: "Shodan reached a way to log in to or control this machine (SSH, Remote Desktop, VNC, SMB, a Docker or Kubernetes API) from the internet. These are tried with stolen and guessed passwords around the clock, and an unauthenticated Docker API or Kubelet is a way to run code at once.",
      fix: "1. Close the port to the internet, or limit it to the addresses you work from. 2. Use AWS Systems Manager Session Manager, a VPN, a bastion or Cloudflare Access for remote access instead. 3. Never expose the Docker API without TLS.",
    },
    "NSV-003": {
      category: "Attack surface",
      severity: "medium",
      docs: "https://help.shodan.io/the-basics/what-is-shodan",
      requires: ["shodan"],
      title: "Software with known vulnerabilities on an address the entity uses",
      why: "Shodan matched the software it saw on this address to published vulnerabilities (CVEs). Shodan judges by the version the software announces, so a patched build can be listed by mistake, but attackers search Shodan the same way to find targets.",
      fix: "1. Open the address on Shodan to see which service and version each vulnerability is for. 2. Update that software, or confirm the fix is backported and mark the finding a false positive. 3. If the service doesn't need to be on the internet, close it.",
    },
  },
  ({ inv }, report) => {
    const exposed = (table: Record<number, [string, Severity]>, id: "NSV-001" | "NSV-002") => {
      for (const a of inv.addresses) {
        if (!a.shodan) continue;
        const v = seen(a);
        const zone = zoneOf(inv, a);
        const open = (v?.ports ?? []).filter((p) => table[p]);
        if (!open.length) report(id, { zone, resource: a.ip, pass: true });
        for (const port of open) {
          const [name, severity] = table[port];
          const aws = groupsOn(inv, a.ip, port);
          report(id, {
            zone,
            resource: `${a.ip}:${port}`,
            pass: false,
            severity: aws && !aws.open ? LOWER[severity] : severity,
            detail: `${name}${product(v!, port)} open on port ${port}${aws && !aws.open ? "; its security groups no longer let anyone reach it" : ""}`,
            confidence: "likely",
            evidence: {
              chain: [
                { label: "Shodan", value: `Port ${port} answered as ${name}${seenWhen(a)}` },
                { label: "Address", value: ownerOf(a) },
                ...(aws
                  ? [
                      {
                        label: "AWS security groups",
                        value: aws.open
                          ? `${aws.open.join(", ")} let anyone reach port ${port}`
                          : `No group on ${aws.resource} lets anyone reach port ${port} now: it was closed after Shodan looked, or is open only to some ranges`,
                      },
                    ]
                  : []),
              ],
            },
            link: shodanLink(a.ip),
          });
        }
      }
    };
    exposed(DATA_PORTS, "NSV-001");
    exposed(ADMIN_PORTS, "NSV-002");
    for (const a of inv.addresses) {
      if (!a.shodan) continue;
      const view = seen(a);
      // Highest score first; without scores (InternetDB), newest first, since old CVEs are the ones distributions backport.
      const vulns = (view?.vulns ?? []).slice().sort((x, y) => (y.cvss ?? 0) - (x.cvss ?? 0) || cveOrder(y.id) - cveOrder(x.id));
      const worst = Math.max(...vulns.map((v) => v.cvss ?? 0), 0);
      report("NSV-003", {
        zone: zoneOf(inv, a),
        resource: a.ip,
        pass: !vulns.length,
        severity: worst >= 9 ? "high" : undefined,
        detail: vulns.length
          ? `${vulns
              .slice(0, 5)
              .map((v) => v.id)
              .join(", ")}${vulns.length > 5 ? ` and ${vulns.length - 5} more` : ""}`
          : "",
        confidence: vulns.length ? "likely" : undefined,
        evidence: vulns.length
          ? {
              chain: [
                {
                  label: "Shodan",
                  value: `${vulns.length} known vulnerabilit${vulns.length === 1 ? "y" : "ies"}${worst ? `, highest CVSS ${worst}` : ""}${seenWhen(a)}`,
                },
                ...(view?.via === "internetdb"
                  ? [
                      {
                        label: "Scores",
                        value: "Shodan's free InternetDB doesn't score vulnerabilities. With a Shodan API key, one rated CVSS 9 or more makes this high.",
                      },
                    ]
                  : []),
                { label: "Address", value: ownerOf(a) },
              ],
            }
          : null,
        link: vulns.length ? shodanLink(a.ip) : null,
      });
    }
  },
);
