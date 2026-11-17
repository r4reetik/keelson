// What an internet scan (Sonar) collects about one entity: its domains, the hostnames
// under them (from its accounts' DNS, certificate logs and Shodan), and the public
// addresses those hostnames point at, with what Shodan has seen there. Built by
// discover.ts, judged by checks/, and stored for the Attack surface page by views.ts.

import type { AwsExposureLink, AwsLoadBalancerLink, DnsHostRecord } from "../../shared/api.ts";
import type { ProviderId } from "../../shared/providers.ts";
import type { Related } from "../../core/types.ts";
import type { InternetSourceKey } from "./sources.ts";

export type { Related };

/** A certificate from the logs, reduced to what the checks need. Only names under the domain it was found for are kept. */
export interface CtCertificate {
  /** crt.sh's ID, for a link to the certificate. */
  id: number;
  names: string[];
  /** The issuer's organisation, or its common name without one. */
  issuer: string;
  /** The CAA identifiers that let this issuer issue, or null for an issuer Keelson doesn't know. */
  caa: string[] | null;
  notBefore: string;
  notAfter: string;
  /** When the log recorded it. */
  logged: string;
}

export interface Caa {
  issue: string[];
  issuewild: string[];
}

export interface Domain {
  name: string;
  /** The connected platform whose account serves its DNS, or null when none does. */
  dnsAt: ProviderId | null;
  /** Its nameservers from public DNS, looked up for domains no connected account serves; null when not looked up or the lookup failed. */
  nameservers: string[] | null;
  /** The domain doesn't exist in public DNS (NXDOMAIN). */
  unregistered: boolean;
  /** CAA from public DNS: empty lists without CAA, null when the lookup failed. */
  caa: Caa | null;
  /** Certificates from the logs, still valid; null when the logs couldn't be read for this domain. */
  certificates: CtCertificate[] | null;
}

/** Where a hostname was found: DNS, the certificate logs, Shodan, a load balancer's rules, or Amass. */
export type HostSource = "dns" | "certificates" | "shodan" | "loadBalancer" | "amass";

export interface Host {
  name: string;
  /** The entity's domain it is under. */
  domain: string;
  found: HostSource[];
  /** Its records in a connected account's DNS. */
  records: DnsHostRecord[];
  /** Public DNS answer for a host no connected account's DNS lists: its addresses and the CNAME chain. Null when not looked up. */
  resolved: { addresses: string[]; cnames: string[] } | null;
  /** What answers for it, in words: "Cloudflare (proxied)", "Vercel", "AWS", "Outside connected accounts"… */
  servedBy: string;
  /** The DNS name of the AWS or Alibaba Cloud load balancer it reaches (by CNAME, alias, or as a proxied hostname's origin; a CLB by its address), when an account in the entity has it. */
  loadBalancer: string | null;
  /** The address it points at directly that an AWS or Alibaba Cloud account in the entity holds. */
  cloudAddress: string | null;
}

export interface ShodanService {
  port: number;
  transport: string | null;
  product: string | null;
  version: string | null;
}

export interface ShodanVuln {
  id: string;
  cvss: number | null;
}

export interface ShodanView {
  ports: number[];
  /** Product and version per port. InternetDB doesn't give them, only the full API does. */
  services: ShodanService[];
  vulns: ShodanVuln[];
  /** Hostnames Shodan ties to the address, limited to names under the entity's domains. */
  hostnames: string[];
  /** When Shodan last saw the address; InternetDB doesn't say. */
  lastSeen: string | null;
  /** Which Shodan answered: the full API with a key, or InternetDB without one. */
  via: "api" | "internetdb";
}

export interface Address {
  ip: string;
  /** The cloud ("aws", "alibaba") whose account in the entity holds it; null when only the entity's DNS points at it. */
  heldBy: ProviderId | null;
  /** The entity's hostnames that point at it, and whether Cloudflare proxies them (then it is their origin). */
  hosts: { name: string; proxied: boolean }[];
  /** Shodan's view: null when it couldn't be asked, `seen: false` when it has nothing. */
  shodan: (ShodanView & { seen: true }) | { seen: false } | null;
}

export interface InternetInventory {
  accountId: string;
  now: string;
  unreadable: InternetSourceKey[];
  domains: Domain[];
  hosts: Host[];
  /** Names found in the logs or Shodan that no longer resolve: counted, not listed. */
  unresolved: number;
  addresses: Address[];
  /** The entity's AWS and Alibaba Cloud load balancers with their routing, from those accounts' latest scans; empty without either. */
  loadBalancers: AwsLoadBalancerLink[];
  /** The public addresses its AWS and Alibaba Cloud accounts hold, and what their security groups let anyone reach. */
  exposure: AwsExposureLink[];
  /** How Amass ran, when it did: how many names it found that nothing else had. */
  amass: { names: number; added: number; minutes: number } | null;
}
