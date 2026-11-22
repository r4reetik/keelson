// Route 53 records that send traffic to GitLab Pages on gitlab.com. XP-034
// compares them with the custom domains of the Pages sites of the entity's
// GitLab groups (from their latest scans) and is skipped when the entity has no
// GitLab group, or one whose sites couldn't all be read.

import { defineChecks } from "./define.ts";
import { pointsAtGitlabPages } from "../../../core/links.ts";
import { GLOBAL } from "../types.ts";

export default defineChecks(
  {
    "XP-034": {
      spans: ["gitlab"],
      category: "DNS",
      severity: "high",
      docs: "https://docs.gitlab.com/user/project/pages/custom_domains_ssl_tls_certification/",
      requires: ["route53"],
      attackPath: true,
      title: "Route 53 record points at GitLab Pages, but no Pages site in the entity uses it",
      why: "The record sends visitors to GitLab Pages, yet none of the entity's GitLab groups has a Pages site with this hostname. GitLab asks for a verification record before it serves a custom domain; a record left from a deleted site, with its verification record still in DNS, lets whoever recreates the site's address serve content under your name.",
      fix: "1. If the site moved or was retired, delete the record in Route 53, and the _gitlab-pages-verification-code TXT record beside it. 2. If it should be live, add the hostname under the project's Deploy → Pages → Domains and verify it.",
    },
  },
  ({ inv, d, related }, report) => {
    const sites = related.gitlabPages ? new Map(related.gitlabPages.map((p) => [p.host.toLowerCase(), p] as const)) : null;
    if (!sites) return;
    for (const z of inv.hostedZones ?? [])
      for (const r of z.records ?? []) {
        if (r.alias || !r.targets.some((t) => pointsAtGitlabPages(r.type, t))) continue;
        const match = sites.get(r.name.toLowerCase());
        report("XP-034", {
          zone: GLOBAL,
          resource: r.name,
          link: d.hostedZone(z.id),
          pass: !!match,
          detail: match ? `Served by the Pages site of ${match.repo}` : `${r.type} ${r.targets.join(", ")}, not on any Pages site in this entity`,
          confidence: match ? undefined : "likely",
        });
      }
  },
);
