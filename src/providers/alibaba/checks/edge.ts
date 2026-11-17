// Load balancers (ALB and CLB) and CDN domains: plain HTTP without a redirect, and
// listeners that still accept TLS 1.0 or 1.1.

import { defineChecks } from "./define.ts";
import { GLOBAL } from "../types.ts";

/** Alibaba Cloud's system TLS policies that still allow TLS 1.0 or 1.1. Custom policies aren't judged. */
const OLD_TLS = /^tls_cipher_policy_1_[01]$/;

export default defineChecks(
  {
    "LLB-001": {
      category: "TLS & HTTPS",
      severity: "medium",
      docs: "https://www.alibabacloud.com/help/en/slb/application-load-balancer/use-cases/redirect-http-requests-to-an-https-listener",
      requires: ["loadBalancers"],
      title: "Load balancer serves plain HTTP",
      why: "The internet-facing load balancer answers on HTTP without sending visitors to HTTPS, so their requests and cookies cross the network unencrypted.",
      fix: "In the SLB console → the load balancer → Listener, change the HTTP listener to redirect to the HTTPS listener (ALB: a redirect forwarding rule; CLB: Redirect HTTP to HTTPS).",
    },
    "LLB-002": {
      category: "TLS & HTTPS",
      severity: "medium",
      docs: "https://www.alibabacloud.com/help/en/slb/application-load-balancer/user-guide/tls-security-policies",
      requires: ["loadBalancers"],
      title: "Load balancer accepts TLS 1.0 or 1.1",
      why: "The listener's TLS security policy still negotiates TLS 1.0 or 1.1, which have known weaknesses and fail PCI DSS.",
      fix: "In the SLB console → the load balancer → Listener, edit the HTTPS listener and choose tls_cipher_policy_1_2_strict_with_1_3, or tls_cipher_policy_1_2 if old clients must connect.",
    },
    "LLB-003": {
      category: "TLS & HTTPS",
      severity: "medium",
      docs: "https://www.alibabacloud.com/help/en/cdn/user-guide/configure-an-ssl-certificate",
      requires: ["cdn"],
      title: "CDN domain serves only plain HTTP",
      why: "The accelerated domain has no HTTPS certificate, so visitors' requests, cookies and the content they get cross the network unencrypted and can be read or changed on the way.",
      fix: "In the CDN console → Domain Names → the domain → HTTPS, add a certificate (a free one from Certificate Management Service works), then turn on Force HTTPS redirect.",
    },
  },
  ({ inv, d }, report) => {
    for (const r of inv.regions)
      for (const lb of r.loadBalancers ?? []) {
        if (!lb.listeners) continue;
        const base = { zone: r.name, resource: `${lb.name} (${lb.id})`, link: d.loadBalancer(r.name, lb.type, lb.id) };
        if (lb.internetFacing && lb.type !== "nlb") {
          const plain = lb.listeners.filter((l) => l.protocol === "HTTP" && !l.redirects);
          report("LLB-001", {
            ...base,
            pass: !plain.length,
            detail: plain.length ? `Port ${plain.map((l) => l.port).join(", ")} serves HTTP without redirecting` : "",
          });
        }
        const secure = lb.listeners.filter((l) => l.tlsPolicy);
        const old = secure.filter((l) => OLD_TLS.test(l.tlsPolicy!));
        if (secure.length) report("LLB-002", { ...base, pass: !old.length, detail: [...new Set(old.map((l) => l.tlsPolicy))].join(", ") });
      }
    for (const c of inv.cdnDomains ?? [])
      if (c.online)
        report("LLB-003", { zone: GLOBAL, resource: c.name, pass: c.https, detail: c.https ? "" : "No HTTPS certificate", link: d.cdnDomain(c.name) });
  },
);
