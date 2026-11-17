// Alibaba Cloud DNS records that point at something the entity doesn't have: an
// Alibaba Cloud endpoint (an OSS bucket, a load balancer, a CDN domain) or address,
// an AWS endpoint or address, a Vercel hostname no project serves, or a GitHub
// Pages site none of its organizations publishes. Each compares the records with the
// latest scans of the entity's accounts on that platform, and is skipped when one of
// them hasn't shared its list.
//
// Not every such record can be taken over, and the findings say which: an address
// Keelson saw leave the entity goes to another customer, a deleted OSS bucket's name
// can be registered again (though OSS asks for proof of the domain before serving it),
// but a load balancer's name can't be reused.

import { defineChecks } from "./define.ts";
import { ALIBABA_DANGLING, alibabaEndpointOf, awsEndpointOf, DANGLING, pointsAtGithubPages, pointsAtVercel } from "../../../core/links.ts";
import { ownAddresses, ownEndpoints } from "../views.ts";
import { GLOBAL } from "../types.ts";

const cap = (s: string) => `${s[0].toUpperCase()}${s.slice(1)}`;

export default defineChecks(
  {
    "LDN-001": {
      category: "DNS",
      severity: "medium",
      docs: "https://www.alibabacloud.com/help/en/dns/add-a-dns-record",
      requires: ["dns", "ossBuckets", "loadBalancers", "cdn"],
      attackPath: true,
      title: "Alibaba Cloud DNS record points at an Alibaba Cloud resource the entity doesn't have",
      why: "The record names an OSS bucket, load balancer or CDN domain that none of the entity's Alibaba Cloud accounts has. A deleted bucket's name can be registered by anyone; OSS won't serve your hostname from it without proof that they own the domain, but links to the bucket's own address would load their files. A missing load balancer or CDN domain can't be claimed that way, so that record is dead, or points into an account Keelson doesn't see.",
      fix: "1. If the site was retired, delete the record in Alibaba Cloud DNS. 2. If it should be live, recreate the resource or point the record at the current one. 3. If the resource belongs to an Alibaba Cloud account that isn't in Keelson, add that account to this entity, or mark the finding as a false positive.",
    },
    "LDN-002": {
      category: "DNS",
      severity: "high",
      docs: "https://www.alibabacloud.com/help/en/dns/add-a-dns-record",
      requires: ["dns", "networkInterfaces"],
      attackPath: true,
      title: "Alibaba Cloud DNS record points at an address the entity released",
      why: "Keelson saw this address in one of the entity's Alibaba Cloud accounts on an earlier scan, and it is gone now: the instance was released or the EIP was given back. Alibaba Cloud hands released addresses to other customers, and whoever gets this one receives your hostname's traffic and can obtain a certificate for it.",
      fix: "1. If the server is gone, delete the record in Alibaba Cloud DNS. 2. If it moved, point the record at its current address, and use an EIP or a load balancer so the address can't change again. 3. If the address moved to an account that isn't in Keelson, add that account to this entity.",
    },
    "XP-019": {
      spans: ["vercel"],
      category: "DNS",
      severity: "high",
      docs: "https://vercel.com/docs/domains/working-with-domains/add-a-domain",
      requires: ["dns"],
      attackPath: true,
      title: "Alibaba Cloud DNS record points at Vercel, but no Vercel project in the entity serves it",
      why: "The record sends visitors to Vercel, yet none of the entity's Vercel projects has this hostname. Whoever adds it to their own Vercel project first serves your traffic under your domain.",
      fix: "1. If the site moved or was retired, delete the record in Alibaba Cloud DNS. 2. If it should be live, add the hostname to the right Vercel project under Settings → Domains. 3. If it belongs to a Vercel team that isn't in Keelson, add that team to this entity, or mark the finding as a false positive.",
    },
    "XP-020": {
      spans: ["aws"],
      category: "DNS",
      severity: "high",
      docs: "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/protection-from-dangling-dns.html",
      requires: ["dns"],
      attackPath: true,
      title: "Alibaba Cloud DNS record points at an AWS resource or address the entity doesn't have",
      why: "The record names a CloudFront distribution, load balancer or S3 bucket that none of the entity's AWS accounts has, or an address Keelson saw leave them. A missing bucket or CloudFront alias can be claimed by anyone, and a released address is handed to another AWS customer; either way someone else can serve your hostname.",
      fix: "1. If the site moved or was retired, delete the record in Alibaba Cloud DNS. 2. If it should be live, recreate the resource or point the record at the current one. 3. If the resource belongs to an AWS account that isn't in Keelson, add that account to this entity.",
    },
    "XP-024": {
      spans: ["github"],
      category: "DNS",
      severity: "high",
      docs: "https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages",
      requires: ["dns"],
      attackPath: true,
      title: "Alibaba Cloud DNS record points at GitHub Pages, but no repository in the entity publishes it",
      why: "The record sends visitors to GitHub Pages, yet none of the entity's GitHub organizations has a Pages site with this custom domain. Anyone can add the hostname to a Pages site of their own and serve content under your domain, unless the domain is verified in GitHub.",
      fix: "1. If the site was retired, delete the record in Alibaba Cloud DNS. 2. If it should be live, set the custom domain on the right repository's Pages settings. 3. Verify the domain in your GitHub organization's settings so no one else can use it. 4. If the site belongs to an organization that isn't in Keelson, add it to this entity.",
    },
  },
  ({ inv, d, related }, report) => {
    if (!inv.domains) return;
    // Another Alibaba Cloud account in the entity that hasn't shared its list could be the owner: then nothing is judged.
    const own = related.unknown.includes("alibabaEndpoints") ? null : ownEndpoints(inv);
    const have = own ? new Set([...own, ...(related.alibabaEndpoints ?? [])].map((e) => `${e.kind}:${e.name}`)) : null;
    const ownIps = related.unknown.includes("alibabaAddresses") || inv.skippedRegions.length ? null : ownAddresses(inv);
    const held = ownIps ? new Set([...ownIps, ...(related.alibabaAddresses ?? [])]) : null;
    const released = new Map([...inv.released, ...(related.alibabaReleased ?? [])].map((r) => [r.ip, r.at]));
    const served = related.vercelDomains ? new Map(related.vercelDomains.map((x) => [x.host, x])) : null;
    const awsHave = related.awsEndpoints ? new Set(related.awsEndpoints.map((e) => `${e.kind}:${e.name}`)) : null;
    const awsHeld = related.awsAddresses ? new Set(related.awsAddresses) : null;
    const awsGone = new Map((related.awsReleased ?? []).map((r) => [r.ip, r.at]));
    // GitHub serves a site's custom domain and redirects its www or apex twin, so either name counts as claimed.
    const pages = related.githubPages
      ? new Set(related.githubPages.flatMap((p) => [p.host, p.host.startsWith("www.") ? p.host.slice(4) : `www.${p.host}`]))
      : null;

    for (const z of inv.domains)
      for (const r of z.records ?? []) {
        const link = d.dnsDomain(z.name);
        const base = { zone: GLOBAL, resource: r.name, link };
        const rec = `${r.name} ${r.type} ${r.value} (domain ${z.name})`;

        const ali = r.type === "CNAME" ? alibabaEndpointOf(r.value) : null;
        if (ali && have) {
          const found = have.has(`${ali.kind}:${ali.name}`);
          const kind = ALIBABA_DANGLING[ali.kind];
          report("LDN-001", {
            ...base,
            pass: found,
            severity: found ? undefined : kind.severity,
            detail: found ? "" : `CNAME ${r.value}, ${kind.a} that isn't in this entity's Alibaba Cloud accounts. ${kind.risk}`,
            confidence: found ? undefined : "likely",
            evidence: found
              ? null
              : {
                  chain: [
                    { label: "Alibaba Cloud DNS", value: rec },
                    { label: `${cap(kind.what)}s in this entity`, value: `None is ${ali.name}` },
                  ],
                },
          });
        }

        if (held && r.type === "A") {
          const found = held.has(r.value);
          const gone = released.get(r.value);
          // Only what is known is reported: an address the entity holds passes, one it was seen to release fails.
          if (found || gone)
            report("LDN-002", {
              ...base,
              pass: found,
              detail: found ? "" : `A ${r.value}, which left this entity's Alibaba Cloud accounts on ${gone!.slice(0, 10)}`,
              evidence: found
                ? null
                : {
                    chain: [
                      { label: "Alibaba Cloud DNS", value: rec },
                      { label: "Last held", value: `Keelson saw ${r.value} in the entity's Alibaba Cloud accounts until ${gone!.slice(0, 10)}` },
                      { label: "Now", value: `${held.size} addresses checked, none is ${r.value}` },
                    ],
                  },
            });
        }

        if (served && pointsAtVercel(r.type, r.value)) {
          const match = served.get(r.name) ?? served.get(`*.${r.name.split(".").slice(1).join(".")}`);
          report("XP-019", {
            ...base,
            pass: !!match,
            detail: match ? `Served by Vercel project ${match.project}` : `${r.type} ${r.value}, not on any Vercel project in this entity`,
            confidence: match ? undefined : "likely",
            evidence: match
              ? null
              : {
                  chain: [
                    { label: "Alibaba Cloud DNS", value: rec },
                    {
                      label: "Vercel projects in this entity",
                      value: `${new Set(related.vercelDomains!.map((x) => x.project)).size} checked, none has ${r.name}`,
                    },
                  ],
                },
          });
        }

        const aws = r.type === "CNAME" ? awsEndpointOf(r.value) : null;
        if (aws && awsHave) {
          const found = awsHave.has(`${aws.kind}:${aws.name}`);
          const kind = DANGLING[aws.kind];
          report("XP-020", {
            ...base,
            pass: found,
            severity: found ? undefined : kind.severity,
            detail: found ? "" : `CNAME ${r.value}, a ${kind.what} that isn't in this entity's AWS accounts. ${kind.risk}`,
            confidence: found ? undefined : "likely",
            evidence: found
              ? null
              : {
                  chain: [
                    { label: "Alibaba Cloud DNS", value: rec },
                    { label: `${cap(kind.what)}s in this entity's AWS accounts`, value: `None is ${aws.name}` },
                  ],
                },
          });
        }
        if (awsHeld && r.type === "A" && (awsHeld.has(r.value) || awsGone.has(r.value))) {
          const found = awsHeld.has(r.value);
          report("XP-020", {
            ...base,
            pass: found,
            detail: found ? "" : `A ${r.value}, which left this entity's AWS accounts on ${awsGone.get(r.value)!.slice(0, 10)}`,
            evidence: found
              ? null
              : {
                  chain: [
                    { label: "Alibaba Cloud DNS", value: rec },
                    { label: "Last held", value: `Keelson saw ${r.value} in the entity's AWS accounts until ${awsGone.get(r.value)!.slice(0, 10)}` },
                  ],
                },
          });
        }

        if (pages && pointsAtGithubPages(r.type, r.value)) {
          const found = pages.has(r.name);
          report("XP-024", {
            ...base,
            pass: found,
            detail: found ? "" : `${r.type} ${r.value}, not the custom domain of any Pages site in this entity`,
            confidence: found ? undefined : "likely",
          });
        }
      }
  },
);
