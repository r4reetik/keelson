// GitHub Pages sites: a custom domain served without HTTPS enforced.
// Whether a DNS record points at a Pages site nobody in the entity owns is
// Cloudflare's check (XP-009), from the custom domains a GitHub scan shares.

import { active, defineChecks } from "./define.ts";

export default defineChecks(
  {
    "GPG-001": {
      category: "TLS & HTTPS",
      severity: "low",
      docs: "https://docs.github.com/en/pages/getting-started-with-github-pages/securing-your-github-pages-site-with-https",
      requires: ["pages"],
      title: "GitHub Pages site doesn't enforce HTTPS",
      why: "Visitors who type the address or follow an old http:// link get the site unencrypted, where anyone on the network can change it.",
      fix: "In the repository's Settings → Pages, tick Enforce HTTPS. GitHub offers it once the custom domain's certificate is issued.",
    },
  },
  ({ inv, d }, report) => {
    for (const r of active(inv)) {
      const p = r.pages;
      if (!p || p.httpsEnforced == null) continue;
      report("GPG-001", {
        zone: r.name,
        resource: p.cname ?? r.name,
        pass: p.httpsEnforced,
        detail: p.httpsEnforced ? "" : "Enforce HTTPS is off",
        link: d.repo(r.name, "settings/pages"),
      });
    }
  },
);
