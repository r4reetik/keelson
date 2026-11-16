// The entity's domains as seen from outside: one whose DNS no connected account
// serves is a domain Keelson can't check for dangling records or exposed origins.

import { defineChecks } from "./define.ts";

export default defineChecks(
  {
    "NDS-001": {
      category: "DNS",
      severity: "low",
      docs: "https://developers.cloudflare.com/dns/zone-setups/full-setup/",
      requires: ["related"],
      title: "Domain whose DNS isn't in any connected account",
      why: "Keelson can only check the records of DNS it reads. Records on this domain that point at deleted servers, buckets or sites, or that publish an origin's address, go unnoticed, and the domain is often forgotten until someone takes over one of its names.",
      fix: "1. Find where the domain's DNS is hosted from its nameservers. 2. If it is on a platform Keelson reads (Cloudflare or Route 53), add that account to this entity. 3. Otherwise consider moving its DNS to one, or remove the domain from the entity's domains if it isn't yours.",
    },
  },
  ({ inv }, report) => {
    for (const d of inv.domains) {
      if (d.unregistered) continue;
      report("NDS-001", {
        zone: d.name,
        resource: d.name,
        pass: !!d.dnsAt,
        detail: d.dnsAt ? "" : d.nameservers?.length ? `Nameservers: ${d.nameservers.slice(0, 4).join(", ")}` : "Nameservers couldn't be looked up",
        confidence: d.dnsAt ? undefined : "likely",
      });
    }
  },
);
