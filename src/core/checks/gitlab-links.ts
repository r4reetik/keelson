// Checks that need GitLab: Cloudflare DNS records that send traffic to GitLab
// Pages on gitlab.com. XP-028 compares them with the custom domains of the Pages
// sites of the entity's GitLab groups (from their latest scans) and is skipped
// when the entity has no GitLab group, or one whose sites couldn't all be read.

import { defineChecks } from "./define.ts";
import { pointsAtGitlabPages } from "../links.ts";

export default defineChecks(
  {
    "XP-028": {
      spans: ["gitlab"],
      category: "DNS",
      severity: "high",
      docs: "https://docs.gitlab.com/user/project/pages/custom_domains_ssl_tls_certification/",
      requires: ["dnsRecords"],
      attackPath: true,
      title: "DNS record points at GitLab Pages, but no Pages site in the entity uses it",
      why: "The record sends visitors to GitLab Pages, yet none of the entity's GitLab groups has a Pages site with this hostname. GitLab asks for a verification record before it serves a custom domain, so a stranger needs that record too; but a record left from a site that was deleted, with its verification record still in DNS, lets whoever recreates the site's address serve content under your name.",
      fix: "1. If the site moved or was retired, delete the DNS record in Cloudflare, and the _gitlab-pages-verification-code TXT record beside it. 2. If it should be live, add the hostname under the project's Deploy → Pages → Domains and verify it.",
    },
  },
  ({ inv, opts, d }, report) => {
    const sites = opts.related?.gitlabPages;
    if (!sites) return;
    const known = new Map(sites.map((s) => [s.host.toLowerCase(), s] as const));
    for (const z of inv.zones) {
      if (!z.dnsReadable) continue;
      for (const r of z.dns) {
        if (!pointsAtGitlabPages(r.type, r.content)) continue;
        const host = r.name.toLowerCase();
        const match = known.get(host);
        report("XP-028", {
          zone: z.name,
          resource: host,
          pass: !!match,
          detail: match ? `Served by the Pages site of ${match.repo}` : `${r.type} ${r.content}, not on any Pages site in this entity`,
          confidence: match ? undefined : "likely",
          evidence: match
            ? null
            : {
                chain: [
                  { label: "Cloudflare DNS", value: `${host} ${r.type} ${r.content}` },
                  { label: "GitLab Pages sites in this entity", value: `${sites.length} checked, none has ${host}` },
                ],
              },
          link: d.zone(z.name, "dns/records"),
        });
      }
    }
  },
);
