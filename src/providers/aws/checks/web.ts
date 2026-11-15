// The web edge beyond CloudFront's own settings: application load balancers with no
// web ACL, web ACLs with no rules, load balancers that pass ambiguous requests on,
// CloudFront origins whose S3 bucket is gone, and certificates about to stop
// working (ACM certificates that won't renew, IAM server certificates).

import { date, days, defineChecks } from "./define.ts";
import { GLOBAL } from "../types.ts";

const SOON_DAYS = 30;

export default defineChecks(
  {
    "AED-007": {
      category: "WAF & bots",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-associating-aws-resource.html",
      requires: ["loadBalancers", "waf", "cloudfront"],
      title: "Internet-facing application load balancer has no web ACL",
      why: "Requests reach the application with nothing filtering common attacks, bad bots or floods from single addresses, and no way to block an address quickly during an incident.",
      fix: "In WAF & Shield → Web ACLs, create a web ACL in the load balancer's region with AWS's managed core rule set and a rate-based rule, and associate it with the load balancer. A distribution with a web ACL in front of it, and the load balancer locked to CloudFront, also works.",
    },
    "AED-008": {
      category: "WAF & bots",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-editing.html",
      requires: ["waf"],
      title: "WAF web ACL has no rules",
      why: "The web ACL is in place but has no rules, so it only applies its default action to everything: it looks like protection and filters nothing.",
      fix: "In WAF & Shield → Web ACLs → the web ACL → Rules → Add rules, add AWS's managed core rule set and known bad inputs rule set, and a rate-based rule.",
    },
    "AED-009": {
      category: "Attack surface",
      severity: "low",
      docs: "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#desync-mitigation-mode",
      requires: ["loadBalancers"],
      title: "Load balancer passes ambiguous HTTP requests to its targets",
      why: "Desync mitigation is in monitor mode, so requests that the load balancer and the application could read differently are passed on. That is how HTTP request smuggling slips requests past the load balancer's rules.",
      fix: "In EC2 → Load Balancers → the load balancer → Attributes → Edit, set Desync mitigation mode to Defensive (the default) or Strictest.",
    },
    "AED-010": {
      category: "Attack surface",
      severity: "high",
      docs: "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/DownloadDistS3AndCustomOrigins.html",
      requires: ["cloudfront"],
      attackPath: true,
      title: "CloudFront serves from an S3 bucket that doesn't exist",
      why: "The distribution's origin is a bucket nobody owns. Anyone can create a bucket with that name in their own account and serve their content on your distribution's hostnames.",
      fix: "Create the bucket in this account now so the name is yours, then point the origin at the bucket that should serve the content, or remove the origin and its behaviours.",
    },
    "AED-011": {
      category: "TLS & HTTPS",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/acm/latest/userguide/check-certificate-renewal-status.html",
      requires: ["acm"],
      title: "Certificate in use won't renew and is about to expire",
      why: "The certificate is imported, or ACM can't renew it, so when it expires every load balancer, distribution or API that uses it stops working for visitors.",
      fix: "For an imported certificate, get a new one from its issuer and reimport it under the same ARN. For an ACM certificate, fix what blocks renewal (usually the DNS validation record) in ACM → the certificate → Renewal status.",
    },
    "AED-012": {
      category: "TLS & HTTPS",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_server-certs.html",
      requires: ["serverCertificates"],
      title: "IAM server certificate has expired",
      why: "An expired certificate still attached to a load balancer or distribution breaks HTTPS for its visitors, and an old one left in IAM can be attached again by mistake.",
      fix: "Move whatever uses it to a certificate from ACM, which renews itself, then delete it with aws iam delete-server-certificate.",
    },
  },
  ({ inv, d }, report) => {
    // Load balancers behind a distribution that has a web ACL are already filtered there.
    const fronted = new Set((inv.distributions ?? []).filter((x) => x.waf).flatMap((x) => x.origins.map((o) => o.domain)));
    for (const r of inv.regions) {
      const protectedArns = r.webAcls ? new Set(r.webAcls.flatMap((a) => a.loadBalancers)) : null;
      for (const lb of r.loadBalancers ?? []) {
        const where = { zone: r.name, resource: lb.name, link: d.loadBalancers(r.name) };
        if (lb.type === "application" && lb.internetFacing && protectedArns && lb.arn) {
          const ok = protectedArns.has(lb.arn) || fronted.has(lb.dnsName) || fronted.has(`dualstack.${lb.dnsName}`);
          report("AED-007", { ...where, pass: ok, detail: ok ? "" : "No web ACL is associated, and no distribution with one is in front of it" });
        }
        if (lb.desync)
          report("AED-009", { ...where, pass: lb.desync !== "monitor", detail: lb.desync === "monitor" ? "Desync mitigation is in monitor mode" : "" });
      }
      for (const acl of r.webAcls ?? []) {
        // A regional web ACL protecting nothing filters nothing either way; CloudFront's are judged wherever they are.
        if (acl.scope === "REGIONAL" && !acl.loadBalancers.length) continue;
        report("AED-008", {
          zone: acl.scope === "CLOUDFRONT" ? GLOBAL : r.name,
          resource: acl.name,
          pass: acl.rules > 0,
          detail: acl.rules > 0 ? "" : "No rules or rule groups",
          link: d.console(r.name, "wafv2", `/webacls?region=${acl.scope === "CLOUDFRONT" ? "global" : r.name}`),
        });
      }
      for (const c of r.certificates ?? []) {
        if (!c.inUse || c.renews || c.notAfter == null) continue;
        const left = Math.floor((c.notAfter - inv.now) / 86_400_000);
        report("AED-011", {
          zone: r.name,
          resource: c.domain,
          pass: left > SOON_DAYS,
          severity: left < 0 ? "high" : undefined,
          detail: left > SOON_DAYS ? "" : `${c.type === "IMPORTED" ? "Imported" : "Can't be renewed"}; ${left < 0 ? "expired" : "expires"} ${date(c.notAfter)}`,
          link: d.console(r.name, "acm", `/certificates/${c.id}`),
        });
      }
    }
    for (const dist of inv.distributions ?? [])
      for (const o of dist.origins)
        if (o.missingBucket != null)
          report("AED-010", {
            zone: GLOBAL,
            resource: `${dist.aliases[0] ?? dist.domainName} → ${o.domain}`,
            pass: !o.missingBucket,
            detail: o.missingBucket ? `The bucket behind ${o.domain} doesn't exist` : "",
            link: d.distribution(dist.id),
          });
    for (const c of inv.serverCertificates ?? []) {
      const age = days(c.expiresAt, inv.now);
      if (age == null) continue;
      report("AED-012", {
        zone: GLOBAL,
        resource: c.name,
        pass: age < 0,
        detail: age >= 0 ? `Expired ${date(c.expiresAt)}` : "",
        link: d.serverCertificates,
      });
    }
  },
);
