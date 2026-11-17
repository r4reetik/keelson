// Checks that need Alibaba Cloud: Cloudflare DNS records that name an Alibaba
// Cloud endpoint (an OSS bucket, an ALB or NLB, a CDN domain) or point at an
// address the entity's Alibaba Cloud accounts released. They compare them with
// what those accounts have, from their latest scans, and are skipped when the
// entity has no Alibaba Cloud account, or one whose endpoints or addresses couldn't
// all be read. AWS's counterparts are XP-004 and XP-007.

import { defineChecks } from "./define.ts";
import { ALIBABA_DANGLING, alibabaEndpointOf } from "../links.ts";

export default defineChecks(
  {
    "XP-016": {
      spans: ["alibaba"],
      category: "DNS",
      severity: "medium",
      docs: "https://www.alibabacloud.com/help/en/oss/user-guide/map-custom-domain-names-5",
      requires: ["dnsRecords"],
      title: "DNS record points at an Alibaba Cloud resource that no Alibaba Cloud account in the entity has",
      why: "The record names an OSS bucket, load balancer or CDN domain that none of the entity's Alibaba Cloud accounts has. A deleted bucket's name can be registered by anyone, and links to its own address then load their files. A missing load balancer or CDN domain can't be claimed, so that record is dead, or points into an Alibaba Cloud account Keelson doesn't see.",
      fix: "1. If the site moved or was retired, delete the DNS record in Cloudflare. 2. If it should be live, recreate the resource or point the record at the current one. 3. If the resource belongs to an Alibaba Cloud account that isn't in Keelson, add that account to this entity, or mark the finding as a false positive.",
    },
    "XP-017": {
      spans: ["alibaba"],
      category: "DNS",
      severity: "high",
      docs: "https://www.alibabacloud.com/help/en/eip/user-guide/release-an-eip",
      requires: ["dnsRecords"],
      attackPath: true,
      title: "DNS record points at an Alibaba Cloud address the entity released",
      why: "Keelson saw this address in one of the entity's Alibaba Cloud accounts on an earlier scan, and it is gone now: the instance was released or the EIP was given back. Alibaba Cloud hands released addresses to other customers, and whoever gets this one receives your hostname's traffic, through Cloudflare's proxy too, and can obtain a certificate for it.",
      fix: "1. If the server is gone, delete the DNS record in Cloudflare. 2. If it moved, point the record at its current address, and give the server an EIP so the address can't change again. 3. If the address moved to an Alibaba Cloud account that isn't in Keelson, add that account to this entity.",
    },
  },
  ({ inv, opts, d }, report) => {
    const addresses = opts.related?.alibabaAddresses;
    if (addresses) {
      const held = new Set(addresses);
      const released = new Map((opts.related?.alibabaReleased ?? []).map((r) => [r.ip, r.at]));
      for (const z of inv.zones) {
        if (!z.dnsReadable) continue;
        for (const r of z.dns) {
          if (r.type !== "A") continue;
          const found = held.has(r.content);
          const gone = released.get(r.content);
          // Only what is known is reported: an address the entity holds passes, one it was seen to release fails.
          if (!found && !gone) continue;
          const host = r.name.toLowerCase();
          report("XP-017", {
            zone: z.name,
            resource: host,
            pass: found,
            detail: found ? "" : `A ${r.content}${r.proxied ? " (proxied)" : ""}, which left this entity's Alibaba Cloud accounts on ${gone!.slice(0, 10)}`,
            evidence: found
              ? null
              : {
                  chain: [
                    { label: "Cloudflare DNS", value: `${host} A ${r.content}${r.proxied ? ", proxied" : ""}` },
                    { label: "Last held", value: `Keelson saw ${r.content} in the entity's Alibaba Cloud accounts until ${gone!.slice(0, 10)}` },
                    { label: "Now", value: `${held.size} addresses checked, none is ${r.content}` },
                  ],
                },
            link: d.zone(z.name, "dns/records"),
          });
        }
      }
    }

    const endpoints = opts.related?.alibabaEndpoints;
    if (!endpoints) return;
    const have = new Set(endpoints.map((e) => `${e.kind}:${e.name}`));
    for (const z of inv.zones) {
      if (!z.dnsReadable) continue;
      for (const r of z.dns) {
        const ali = r.type === "CNAME" ? alibabaEndpointOf(r.content) : null;
        if (!ali) continue;
        const host = r.name.toLowerCase();
        const found = have.has(`${ali.kind}:${ali.name}`);
        const kind = ALIBABA_DANGLING[ali.kind];
        report("XP-016", {
          zone: z.name,
          resource: host,
          pass: found,
          severity: found ? undefined : kind.severity,
          detail: found ? "" : `CNAME ${r.content}, ${kind.a} that isn't in this entity's Alibaba Cloud accounts. ${kind.risk}`,
          confidence: found ? undefined : "likely",
          evidence: found
            ? null
            : {
                chain: [
                  { label: "Cloudflare DNS", value: `${host} CNAME ${r.content}` },
                  { label: `${kind.what[0].toUpperCase()}${kind.what.slice(1)}s in this entity's Alibaba Cloud accounts`, value: `None is ${ali.name}` },
                ],
              },
          link: d.zone(z.name, "dns/records"),
        });
      }
    }
  },
);
