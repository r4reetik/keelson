// How DNS records are recognised as pointing at another provider (Vercel, AWS, Alibaba Cloud,
// GitHub Pages), and what a Cloudflare scan shares with the entity's other accounts.

import type { AlibabaEndpointKind, AwsEndpointKind, ProviderLinks } from "../shared/api.ts";
import type { Inventory } from "./types.ts";

/** Vercel's CNAME targets, and the address ranges its A records use. */
const VERCEL_CNAME = /(^|\.)vercel-dns(-\d+)?\.com\.?$|\.vercel\.app\.?$/i;
const VERCEL_A = /^(76\.76\.21\.\d{1,3}|216\.198\.79\.\d{1,3})$/;

export function pointsAtVercel(type: string, content: string): boolean {
  if (type === "CNAME") return VERCEL_CNAME.test(content);
  if (type === "A") return VERCEL_A.test(content);
  return false;
}

/** GitHub Pages: a CNAME to <owner>.github.io, or the A and AAAA addresses GitHub publishes for apex domains. */
const PAGES_CNAME = /\.github\.io\.?$/i;
const PAGES_ADDR = /^(185\.199\.(108|109|110|111)\.153|2606:50c0:800[0-3]::153)$/i;

/** GitLab Pages on gitlab.com: a site's own name under gitlab.io, or the address GitLab gives for an apex record. */
const GITLAB_PAGES_CNAME = /(^|\.)gitlab\.io\.?$/i;
const GITLAB_PAGES_ADDR = /^(35\.185\.44\.232|2600:1901:0:7b8a::)$/i;

export function pointsAtGitlabPages(type: string, content: string): boolean {
  if (type === "CNAME") return GITLAB_PAGES_CNAME.test(content);
  if (type === "A" || type === "AAAA") return GITLAB_PAGES_ADDR.test(content);
  return false;
}

export function pointsAtGithubPages(type: string, content: string): boolean {
  if (type === "CNAME") return PAGES_CNAME.test(content);
  if (type === "A" || type === "AAAA") return PAGES_ADDR.test(content);
  return false;
}

/**
 * The AWS endpoint a hostname names, when the name alone says which resource it is: a CloudFront
 * distribution, a load balancer, or an S3 bucket (its website or REST endpoint). `name` is what an
 * AWS scan lists it under: the distribution's domain, the load balancer's DNS name, the bucket.
 */
export function awsEndpointOf(target: string): { kind: AwsEndpointKind; name: string } | null {
  const host = target.toLowerCase().replace(/\.$/, "");
  if (/^[a-z0-9]+\.cloudfront\.net$/.test(host)) return { kind: "cloudfront", name: host };
  // Application and classic load balancers are <name>.<region>.elb.amazonaws.com; network ones <name>.elb.<region>.amazonaws.com.
  if (/\.elb\.amazonaws\.com(\.cn)?$|\.elb\.[a-z]{2}(-[a-z]+)+-\d\.amazonaws\.com(\.cn)?$/.test(host))
    return { kind: "elb", name: host.replace(/^dualstack\./, "") };
  const bucket = /^(.+)\.s3(-website)?[.-]([a-z0-9-]+\.)?amazonaws\.com$/.exec(host);
  return bucket ? { kind: "s3", name: bucket[1] } : null;
}

/**
 * What a record that points at a missing AWS endpoint really risks, by kind. A bucket name or a CloudFront
 * alias can be claimed by anyone; a load balancer's name carries a random number, so it can't.
 */
export const DANGLING: Record<AwsEndpointKind, { what: string; severity: "high" | "low"; risk: string }> = {
  s3: { what: "S3 bucket", severity: "high", risk: "Anyone can create a bucket with that name and serve content under this hostname." },
  cloudfront: { what: "CloudFront distribution", severity: "high", risk: "Anyone can add this hostname to their own distribution and serve content under it." },
  elb: {
    what: "load balancer",
    severity: "low",
    risk: "A load balancer's name can't be reused, so this isn't a takeover: the record is dead, or the load balancer is in an AWS account Keelson doesn't scan.",
  },
};

/**
 * The Alibaba Cloud endpoint a hostname names, when the name alone says which resource it is: an OSS bucket
 * (<bucket>.oss-<region>.aliyuncs.com, or an accelerated or internal endpoint), an ALB or NLB load balancer's DNS
 * name, or a CDN domain's CNAME (*.kunlun*.com). `name` is what an Alibaba Cloud scan lists it under.
 */
export function alibabaEndpointOf(target: string): { kind: AlibabaEndpointKind; name: string } | null {
  const host = target.toLowerCase().replace(/\.$/, "");
  const bucket = /^([a-z0-9][a-z0-9-]{1,61}[a-z0-9])\.oss(-[a-z0-9-]+)?\.aliyuncs\.com$/.exec(host);
  if (bucket) return { kind: "oss", name: bucket[1] };
  if (/^(alb|nlb)-[a-z0-9]+\.[a-z0-9-]+\.(alb|nlb)\.(aliyuncs|aliyuncsslb|aliyuncsslbintl)\.com$/.test(host)) return { kind: "slb", name: host };
  if (/\.(ali)?kunlun[a-z]*\.(com|net)$/.test(host)) return { kind: "cdn", name: host };
  return null;
}

/**
 * What a record that points at a missing Alibaba Cloud endpoint risks, by kind. A deleted OSS bucket's name is free
 * again after a few hours, but OSS only serves a custom domain from a bucket once its owner proves they control the
 * domain (or it is in their own Alibaba Cloud DNS); a load balancer's name carries a random ID; and a CDN domain
 * must prove it owns the name before another account can add it.
 */
export const ALIBABA_DANGLING: Record<AlibabaEndpointKind, { what: string; a: string; severity: "medium" | "low"; risk: string }> = {
  oss: {
    what: "OSS bucket",
    a: "an OSS bucket",
    severity: "medium",
    risk: "Anyone can register a deleted bucket's name. OSS won't serve this hostname from it without proof that they own the domain, but anything that still links to the bucket's own address would load their files.",
  },
  slb: {
    what: "load balancer",
    a: "a load balancer",
    severity: "low",
    risk: "A load balancer's DNS name can't be reused, so this isn't a takeover: the record is dead, or the load balancer is in an Alibaba Cloud account Keelson doesn't scan.",
  },
  cdn: {
    what: "CDN domain",
    a: "a CDN domain",
    severity: "low",
    risk: "Alibaba Cloud CDN asks another account to prove it owns the domain before adding it, so this is most likely a dead record, or a domain in an account Keelson doesn't scan.",
  },
};

/** Records that make a hostname answer: what the outside view (src/providers/internet) compares with what it finds. */
const HOST_TYPES = new Set(["A", "AAAA", "CNAME"]);

export function cloudflareLinks(inv: Inventory): ProviderLinks {
  const toVercel: NonNullable<ProviderLinks["toVercel"]> = [];
  const toAws: NonNullable<ProviderLinks["toAws"]> = [];
  const toAlibaba: NonNullable<ProviderLinks["toAlibaba"]> = [];
  const dnsAddresses: NonNullable<ProviderLinks["dnsAddresses"]> = [];
  const cloudflareDns: NonNullable<ProviderLinks["cloudflareDns"]> = [];
  for (const z of inv.zones)
    for (const r of z.dns) {
      const host = r.name.toLowerCase();
      if (HOST_TYPES.has(r.type)) cloudflareDns.push({ host, zone: z.name, type: r.type, target: String(r.content).toLowerCase(), proxied: !!r.proxied });
      if (pointsAtVercel(r.type, r.content)) toVercel.push({ host, zone: z.name, type: r.type, target: r.content, proxied: !!r.proxied });
      const aws = r.type === "CNAME" ? awsEndpointOf(r.content) : null;
      if (aws) toAws.push({ host, zone: z.name, target: r.content, ...aws, proxied: !!r.proxied });
      const alibaba = r.type === "CNAME" ? alibabaEndpointOf(r.content) : null;
      if (alibaba) toAlibaba.push({ host, zone: z.name, target: r.content, ...alibaba, proxied: !!r.proxied });
      if (r.type === "A") dnsAddresses.push({ host, zone: z.name, ip: r.content, proxied: !!r.proxied });
    }
  // Without readable DNS the lists would look empty rather than unknown.
  const cloudflareZones = inv.zones.map((z) => z.name.toLowerCase());
  return inv.zones.every((z) => z.dnsReadable) ? { toVercel, toAws, toAlibaba, dnsAddresses, cloudflareZones, cloudflareDns } : {};
}
