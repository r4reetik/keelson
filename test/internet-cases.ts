// A well-watched entity from outside, and one failing case per internet (Sonar)
// check. The type is Record<InternetCheckId, …>, so a new check without a case
// doesn't compile, and test/internet-checks.test.ts asserts each case really
// makes its check fail.

import type { InternetCheckId } from "../src/providers/internet/checks/index.ts";
import type { EngineOptions } from "../src/core/types.ts";
import { NO_RELATED } from "../src/core/types.ts";
import type { Address, CtCertificate, Domain, Host, InternetInventory } from "../src/providers/internet/types.ts";
import type { AwsLoadBalancerLink, AwsRouteLink, AwsTargetLink } from "../src/shared/api.ts";

export const NOW = "2026-06-01T00:00:00.000Z";
const daysAgo = (n: number) => new Date(Date.parse(NOW) - n * 86_400_000).toISOString();

const cert = (extra: Partial<CtCertificate> = {}): CtCertificate => ({
  id: 1,
  names: ["example.com", "www.example.com"],
  issuer: "Let's Encrypt",
  caa: ["letsencrypt.org"],
  notBefore: daysAgo(5),
  notAfter: daysAgo(-85),
  logged: daysAgo(5),
  ...extra,
});

export const domain = (extra: Partial<Domain> = {}): Domain => ({
  name: "example.com",
  dnsAt: "cloudflare",
  nameservers: null,
  unregistered: false,
  caa: { issue: ["letsencrypt.org"], issuewild: [] },
  certificates: [cert()],
  ...extra,
});

/** An origin AWS holds, behind a proxied hostname, that Shodan has seen with nothing risky open. */
export const address = (extra: Partial<Address> = {}): Address => ({
  ip: "203.0.113.10",
  heldBy: "aws",
  hosts: [{ name: "www.example.com", proxied: true }],
  shodan: { seen: true, ports: [443], services: [], vulns: [], hostnames: [], lastSeen: daysAgo(1), via: "api" },
  ...extra,
});

export const host = (extra: Partial<Host> = {}): Host => ({
  name: "www.example.com",
  domain: "example.com",
  found: ["dns"],
  records: [],
  resolved: null,
  servedBy: "Cloudflare (proxied)",
  loadBalancer: null,
  cloudAddress: null,
  ...extra,
});

const LB_DNS = "web-1234567890.eu-west-1.elb.amazonaws.com";

/** A target with a public address whose security groups let only the load balancer reach it. */
export const target = (extra: Partial<AwsTargetLink> = {}): AwsTargetLink => ({
  kind: "instance",
  id: "i-0example000000001",
  name: "web-1",
  group: "web",
  port: 443,
  health: "healthy",
  publicIp: "203.0.113.30",
  openOnPort: false,
  ...extra,
});

export const route = (extra: Partial<AwsRouteLink> = {}): AwsRouteLink => ({
  rule: "default",
  hosts: [],
  paths: [],
  conditions: [],
  action: "forward",
  authenticates: false,
  detail: null,
  targets: [target()],
  ...extra,
});

/** An internet-facing application load balancer that www.example.com points at, routing it by name. */
export const loadBalancer = (extra: Partial<AwsLoadBalancerLink> = {}): AwsLoadBalancerLink => ({
  name: "web",
  dnsName: LB_DNS,
  account: "example",
  region: "eu-west-1",
  type: "application",
  internetFacing: true,
  web: "cloudflare",
  waf: true,
  listeners: [{ port: 443, protocol: "HTTPS", routes: [route({ rule: "1", hosts: ["www.example.com"] }), route()] }],
  ...extra,
});

export function internetInventory(extra: Partial<InternetInventory> = {}): InternetInventory {
  return {
    accountId: "ext_1",
    now: NOW,
    unreadable: [],
    domains: [domain()],
    hosts: [host({ loadBalancer: LB_DNS })],
    unresolved: 0,
    addresses: [address()],
    loadBalancers: [loadBalancer()],
    exposure: [],
    amass: null,
    ...extra,
  };
}

const seen = (extra: { ports?: number[]; vulns?: { id: string; cvss: number | null }[]; hostnames?: string[] }) => ({
  seen: true as const,
  ports: extra.ports ?? [443],
  services: [],
  vulns: extra.vulns ?? [],
  hostnames: extra.hostnames ?? [],
  lastSeen: null,
  via: "internetdb" as const,
});

export const INTERNET_CASES: Record<InternetCheckId, () => InternetInventory> = {
  "NDS-001": () => internetInventory({ domains: [domain({ dnsAt: null, nameservers: ["ns1.registrar.example"] })] }),
  "NCT-001": () => internetInventory({ domains: [domain({ certificates: [cert({ issuer: "Google Trust Services", caa: ["pki.goog"] })] })] }),
  "NSV-001": () => internetInventory({ addresses: [address({ shodan: seen({ ports: [443, 6379] }) })] }),
  "NSV-002": () => internetInventory({ addresses: [address({ shodan: seen({ ports: [3389] }) })] }),
  "NSV-003": () => internetInventory({ addresses: [address({ shodan: seen({ vulns: [{ id: "CVE-2024-0001", cvss: 9.8 }] }) })] }),
  "XP-012": () => internetInventory({ addresses: [address({ shodan: seen({ hostnames: ["www.example.com"] }) })] }),
  "XP-013": () =>
    internetInventory({
      loadBalancers: [loadBalancer({ listeners: [{ port: 443, protocol: "HTTPS", routes: [route({ targets: [target({ openOnPort: true })] })] }] })],
    }),
  "XP-014": () => internetInventory({ loadBalancers: [loadBalancer({ internetFacing: false })] }),
  "XP-015": () =>
    internetInventory({
      hosts: [host({ name: "www.example.com", loadBalancer: LB_DNS }), host({ name: "old.example.com", servedBy: "Vercel" })],
      loadBalancers: [loadBalancer({ listeners: [{ port: 443, protocol: "HTTPS", routes: [route({ rule: "1", hosts: ["old.example.com"] }), route()] }] })],
    }),
  // The same three, behind an Alibaba Cloud load balancer.
  "XP-025": () =>
    internetInventory({
      loadBalancers: [
        loadBalancer({ provider: "alibaba", listeners: [{ port: 443, protocol: "HTTPS", routes: [route({ targets: [target({ openOnPort: true })] })] }] }),
      ],
    }),
  "XP-026": () => internetInventory({ loadBalancers: [loadBalancer({ provider: "alibaba", internetFacing: false })] }),
  "XP-027": () =>
    internetInventory({
      hosts: [host({ name: "www.example.com", loadBalancer: LB_DNS }), host({ name: "old.example.com", servedBy: "Vercel" })],
      loadBalancers: [
        loadBalancer({
          provider: "alibaba",
          listeners: [{ port: 443, protocol: "HTTPS", routes: [route({ rule: "1", hosts: ["old.example.com"] }), route()] }],
        }),
      ],
    }),
};

/** Every case is judged with the entity's Cloudflare DNS known, so XP-012 runs. */
export const INTERNET_OPTS: Partial<EngineOptions> = { related: { ...NO_RELATED, cloudflareDns: [] } };
