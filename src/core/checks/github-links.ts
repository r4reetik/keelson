// Checks that need GitHub: Cloudflare DNS records that send traffic to GitHub
// Pages. XP-009 compares them with the custom domains of the entity's GitHub
// organizations' Pages sites (from their latest scans) and is skipped when the
// entity has no GitHub organization, or one whose sites couldn't all be read.

import { defineChecks } from "./define.ts";
import { pointsAtGithubPages } from "../links.ts";

/** GitHub serves a site's custom domain and redirects its www or apex twin, so either name counts as claimed. */
const twins = (host: string) => [host, host.startsWith("www.") ? host.slice(4) : `www.${host}`];

export default defineChecks(
  {
    "XP-009": {
      spans: ["github"],
      category: "DNS",
      severity: "high",
      docs: "https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages",
      requires: ["dnsRecords"],
      attackPath: true,
      title: "DNS record points at GitHub Pages, but no Pages site in the entity uses it",
      why: "The record sends visitors to GitHub Pages, yet none of the entity's GitHub organizations has a Pages site with this hostname. Anyone can create a Pages site in their own account with this hostname as its custom domain and serve content under it, unless the domain is verified for your organization.",
      fix: "1. If the site moved or was retired, delete the DNS record in Cloudflare. 2. If it should be live, set the hostname as the custom domain in the repository's Settings → Pages. 3. Verify the domain under the organization's Settings → Pages, so nobody else can use it. 4. If the site is in a GitHub organization that isn't in Keelson, add it to this entity.",
    },
  },
  ({ inv, opts, d }, report) => {
    const sites = opts.related?.githubPages;
    if (!sites) return;
    const known = new Map(sites.flatMap((s) => twins(s.host).map((h) => [h, s] as const)));
    for (const z of inv.zones) {
      if (!z.dnsReadable) continue;
      for (const r of z.dns) {
        if (!pointsAtGithubPages(r.type, r.content)) continue;
        const host = r.name.toLowerCase();
        const match = known.get(host);
        report("XP-009", {
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
                  { label: "GitHub Pages sites in this entity", value: `${sites.length} checked, none has ${host}` },
                ],
              },
          link: d.zone(z.name, "dns/records"),
        });
      }
    }
  },
);
