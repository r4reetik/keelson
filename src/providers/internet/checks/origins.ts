// Cloudflare hides an origin's address only while nobody can find it another way.
// Shodan indexes every address it scans with the hostnames in its certificates and
// replies, so an origin that answers with the proxied hostname's certificate can be
// found by searching Shodan for that hostname. Cloudflare's ATS-001 judges how the
// address leaks from the entity's own DNS; this judges how it leaks from outside.

import { defineChecks, seenWhen, shodanLink, zoneOf } from "./define.ts";

export default defineChecks(
  {
    "XP-012": {
      spans: ["cloudflare"],
      category: "Attack surface",
      severity: "medium",
      docs: "https://developers.cloudflare.com/fundamentals/security/protect-your-origin-server/",
      requires: ["shodan", "related"],
      attackPath: true,
      title: "Origin of a proxied hostname can be found on Shodan",
      why: "The hostname is proxied through Cloudflare to hide its origin, but Shodan lists the origin's address with the entity's hostnames, usually from the certificate the origin answers with. Anyone can search Shodan for the hostname, find the origin and send traffic straight to it, past the WAF, rate limits and Access.",
      fix: "1. Let only Cloudflare reach the origin: in AWS or Alibaba Cloud, a security group that admits only Cloudflare's ranges (a prefix list keeps it current); elsewhere, the firewall. 2. Better, use a Cloudflare Tunnel so the origin has no open port. 3. Use Authenticated Origin Pulls, so the origin refuses connections without Cloudflare's client certificate. 4. Move the origin to a new address once it is locked, since the old one is known.",
    },
  },
  ({ inv, related }, report) => {
    if (!related.cloudflareDns) return;
    const open = new Set(
      [...(related.awsOrigins ?? []), ...(related.alibabaOrigins ?? [])].filter((o) => o.kind === "ip" && o.web === "open").map((o) => o.name),
    );
    for (const a of inv.addresses) {
      const proxied = a.hosts.filter((h) => h.proxied);
      if (!proxied.length || !a.shodan) continue;
      const names = a.shodan.seen ? a.shodan.hostnames : [];
      for (const h of proxied)
        report("XP-012", {
          zone: zoneOf(inv, a),
          resource: h.name,
          pass: !names.length,
          severity: names.length && open.has(a.ip) ? "high" : undefined,
          detail: names.length ? `Origin ${a.ip} is listed with ${names.slice(0, 3).join(", ")}` : "",
          confidence: names.length ? "likely" : undefined,
          evidence: names.length
            ? {
                chain: [
                  { label: "Cloudflare DNS", value: `${h.name} is proxied to the origin ${a.ip}` },
                  { label: "Shodan", value: `${a.ip} is listed with ${names.slice(0, 5).join(", ")}${seenWhen(a)}` },
                  ...(open.has(a.ip) ? [{ label: "Security groups", value: `${a.ip} admits anyone on ports 80 and 443` }] : []),
                ],
              }
            : null,
          link: names.length ? shodanLink(a.ip) : null,
        });
    }
  },
);
