// What an Alibaba Cloud scan collects: the fields checks read, typed from Alibaba
// Cloud's API references. Payloads are trimmed when they're read, so the inventory
// never holds an AccessKey secret, a function's environment variable, a start-up
// script or a policy document: only what was concluded from them.

import type { AlibabaSourceKey } from "./sources.ts";
import type { AddressHistory } from "../../shared/api.ts";

/** The name findings use for resources that aren't in a region (RAM, OSS settings, CDN, DNS). */
export const GLOBAL = "Global";

export interface AlibabaAccessKey {
  /** The last four characters of the AccessKey ID, enough to find it in the console. */
  hint: string;
  active: boolean;
  createdAt: number | null;
  /** When it was last used; null when never, or when it couldn't be read. */
  lastUsedAt: number | null;
}

export interface AlibabaUser {
  name: string;
  createdAt: number | null;
  /** Whether the user can sign in to the console; null when it couldn't be read. */
  console: boolean | null;
  lastLoginAt: number | null;
  /** A virtual MFA device is bound; null when it couldn't be read. */
  mfa: boolean | null;
  keys: AlibabaAccessKey[] | null;
}

/** Who holds administrator access, and through what. */
export interface AlibabaAdmin {
  kind: "user" | "role";
  name: string;
  /** "the AdministratorAccess policy", "the group admins". */
  via: string;
}

/** One principal a role's trust policy lets assume it. */
export interface AlibabaTrust {
  /** "*", an account ID, a RAM user or role ARN, a service or an identity provider. */
  principal: string;
  kind: "anyone" | "account" | "service" | "federated";
  /** The statement has a condition (an external ID, a source IP, MFA…). */
  conditional: boolean;
  /** For GitHub Actions' OIDC provider: the subjects (oidc:sub) the condition allows, lowercase. Empty: any repository. */
  github?: string[];
}

export interface AlibabaRole {
  name: string;
  trust: AlibabaTrust[];
  admin: boolean;
  /** Created by Alibaba Cloud for one of its services (AliyunServiceRole…). */
  serviceLinked: boolean;
}

export interface AlibabaPolicy {
  name: string;
  /** Allows every action on every resource. */
  fullAdmin: boolean;
  attachments: number;
}

export interface AlibabaEscalation {
  kind: "user" | "group" | "role";
  name: string;
  /** "the policy deploy-tools". */
  via: string;
  /** The actions, or pairs of actions, that make it possible. */
  paths: string[];
}

export interface AlibabaSecurityPreference {
  /** MFA at console sign-in: "mandatory" for every RAM user, "independent" (each user's own setting) or "adaptive" (only for unusual sign-ins). */
  mfaAtLogin: "mandatory" | "independent" | "adaptive";
  /** RAM users may create and delete their own AccessKeys. */
  usersManageKeys: boolean;
}

export interface AlibabaPasswordPolicy {
  minLength: number;
  requireLowercase: boolean;
  requireUppercase: boolean;
  requireNumbers: boolean;
  requireSymbols: boolean;
  /** Days before a password expires; 0 never. */
  maxAge: number;
  /** Previous passwords that can't be reused; 0 none. */
  reusePrevention: number;
  /** Wrong passwords in an hour before the user is locked out; 0 never. */
  maxLoginAttempts: number;
}

/** OSS Block Public Access, for the account or a bucket. */
export interface AlibabaBucket {
  name: string;
  /** "cn-hangzhou", from the bucket's location ("oss-cn-hangzhou"). */
  region: string;
  /** "private", "public-read" or "public-read-write". undefined: unreadable. */
  acl: string | undefined;
  /** The bucket's own Block Public Access. undefined: unreadable. */
  blockPublicAccess: boolean | undefined;
  /**
   * What its bucket policy says, reduced to what checks need: whether it lets anyone in without a condition, and the
   * other accounts it names. null: no policy. undefined: unreadable. The policy itself is never kept.
   */
  policy?: { public: boolean; publicWrite?: boolean; otherAccounts: string[] } | null;
}

export interface AlibabaSecurityRule {
  /** "tcp", "udp", "icmp", "gre" or "all". */
  protocol: string;
  from: number | null;
  to: number | null;
  cidr: string;
}

export interface AlibabaSecurityGroup {
  id: string;
  name: string;
  vpcId: string | null;
  /** Inbound rules that accept the whole internet (0.0.0.0/0 or ::/0), less the ones a higher-priority drop rule shadows. */
  open: AlibabaSecurityRule[];
  /**
   * Who else its inbound rules let reach ports 80 and 443: Cloudflare's ranges, or other public ranges. Private ranges
   * and other security groups don't count, and only the kinds are kept, never the ranges. Absent when its rules
   * couldn't be read.
   */
  webFrom?: { cloudflare: boolean; other: boolean; prefixLists: string[] };
}

export interface AlibabaInstance {
  id: string;
  name: string | null;
  running: boolean;
  publicIp: string | null;
  privateIp: string | null;
  vpcId: string | null;
  /** "classic" or "vpc". */
  network: string;
  securityGroups: string[];
  /** "linux" or "windows"; null when unknown. */
  os: string | null;
  /** Signs in with an SSH key pair rather than a password (Linux). */
  keyPair: boolean;
  /** The metadata service needs a token (security hardening mode). null: unknown. */
  metadataTokens: boolean | null;
  /** The RAM role attached to it, which its software runs as. */
  role: string | null;
  /** The kind of credential found in its start-up script (user data). null: none. undefined: not read. The script itself is never kept. */
  userDataSecret: string | null | undefined;
}

/** A network interface or address holder: what a security group is really attached to, and whether it has a public address. */
export interface AlibabaInterface {
  id: string;
  publicIp: string | null;
  privateIp: string | null;
  securityGroups: string[];
  /** "instance", "load balancer" or Alibaba Cloud's own type. */
  kind: string;
  /** The instance ID, or what owns it. */
  owner: string | null;
}

export interface AlibabaDisk {
  id: string;
  encrypted: boolean;
  /** Attached to an instance. */
  inUse: boolean;
}

export interface AlibabaImage {
  id: string;
  name: string | null;
  /** Accounts it is shared with. */
  sharedWith: string[];
}

export interface AlibabaDatabase {
  id: string;
  name: string | null;
  /** "RDS", "Tair (Redis)" or "MongoDB": the product, which has its own console and whitelist. */
  service: "rds" | "redis" | "mongodb";
  /** "MySQL", "PostgreSQL", "Redis 7.0", "MongoDB 6.0". */
  engine: string;
  /** Has a connection string on the internet. */
  publicEndpoint: boolean;
  /** Whitelist entries that admit every address. */
  openWhitelist: string[];
  /** Connections can use TLS; null when unknown. */
  ssl: boolean | null;
  /** Transparent data encryption is on; null when unknown or not offered for the engine. */
  tde: boolean | null;
  /**
   * Clients in the VPC connect without a password (Tair's and MongoDB's "password-free access"); null when it doesn't
   * apply or is unknown.
   */
  passwordFree?: boolean | null;
}

export interface AlibabaListener {
  port: number | null;
  /** "HTTP", "HTTPS", "TCP", "UDP", "QUIC", "TCPSSL". */
  protocol: string;
  /** The TLS policy of an HTTPS listener ("tls_cipher_policy_1_0"). */
  tlsPolicy: string | null;
  /** Sends HTTP to HTTPS. */
  redirects: boolean;
  /** The backend port a CLB listener forwards to, when it isn't the listener's own. */
  backendPort?: number | null;
  /** A CLB listener's access control: "allow" (a whitelist), "deny" (a blacklist) or null (none). undefined: not read. */
  access?: "allow" | "deny" | null;
  id?: string;
  /** Its routes in the order the load balancer tries them, the default last. undefined: not read; null: couldn't be read. */
  rules?: AlibabaRule[] | null;
}

export interface AlibabaRule {
  /** The rule's priority, or "default". */
  priority: string;
  hosts: string[];
  paths: string[];
  /** Other conditions, by kind (a header by its name, never its value). */
  conditions: string[];
  action: "forward" | "redirect" | "fixed-response" | "other";
  /** A redirect's destination or a fixed response's status code. */
  detail: string | null;
  /** The server groups it forwards to. */
  serverGroups: string[];
}

export interface AlibabaServerGroup {
  id: string;
  name: string;
  /** "Instance", "Ip", "Fc". */
  type: string;
  servers: { id: string; ip: string | null; port: number | null; type: string }[] | null;
}

export interface AlibabaLoadBalancer {
  id: string;
  name: string;
  /** "alb", "nlb" or "clb". */
  type: "alb" | "nlb" | "clb";
  /** The DNS name an ALB or NLB is reached by; a CLB has none. */
  dnsName: string | null;
  /** A CLB's address. */
  address: string | null;
  internetFacing: boolean;
  vpcId: string | null;
  securityGroups: string[];
  listeners: AlibabaListener[] | null;
  /** A CLB's default backend servers (ECS instance IDs). */
  backends?: string[];
}

export interface FoundSecret {
  /** The variable's name. */
  where: string;
  kind: string;
  likely: boolean;
}

export interface AlibabaFunction {
  name: string;
  runtime: string | null;
  role: string | null;
  /** HTTP triggers that let anyone call it. null: triggers unreadable. */
  anonymousTriggers: string[] | null;
  envSecret: FoundSecret | null;
}

export interface AlibabaTrail {
  name: string;
  homeRegion: string;
  /** Records every region ("All"). */
  allRegions: boolean;
  /** Records both reads and writes. */
  allEvents: boolean;
  logging: boolean;
  /** Delivers its events to OSS or Log Service, where they outlive the console's 90 days. */
  delivers: boolean;
  ossBucket: string | null;
  organization: boolean;
}

export interface AlibabaKey {
  id: string;
  description: string | null;
  enabled: boolean;
  /** A symmetric key Keelson's users made, which can rotate. */
  rotatable: boolean;
  rotation: boolean | null;
  deletionDate: number | null;
}

export interface AlibabaSecret {
  name: string;
  createdAt: number | null;
  rotation: boolean;
  /** Last rotated; null when never. */
  rotatedAt: number | null;
}

export interface AlibabaCluster {
  id: string;
  name: string;
  region: string;
  version: string | null;
  /** The API server has a public endpoint. */
  publicEndpoint: boolean;
}

export interface AlibabaLaunchTemplate {
  id: string;
  name: string;
  metadataTokens: boolean | null;
  userDataSecret: string | null;
}

export interface AlibabaRegion {
  name: string;
  securityGroups: AlibabaSecurityGroup[] | null;
  instances: AlibabaInstance[] | null;
  interfaces: AlibabaInterface[] | null;
  /** EIPs the account holds in the region, bound or not. */
  addresses: string[] | null;
  disks: AlibabaDisk[] | null;
  /** Disks are encrypted by default; null when unknown. */
  diskEncryptionByDefault: boolean | null;
  images: AlibabaImage[] | null;
  launchTemplates: AlibabaLaunchTemplate[] | null;
  vpcs: { id: string; flowLogs: boolean | null }[] | null;
  databases: AlibabaDatabase[] | null;
  loadBalancers: AlibabaLoadBalancer[] | null;
  serverGroups?: AlibabaServerGroup[] | null;
  functions: AlibabaFunction[] | null;
  keys: AlibabaKey[] | null;
  secrets: AlibabaSecret[] | null;
  clusters: AlibabaCluster[] | null;
}

export interface AlibabaDnsRecord {
  /** The full name, lowercase, without the trailing dot. */
  name: string;
  type: string;
  value: string;
}

export interface AlibabaDomain {
  name: string;
  /** Enabled host records; null when they couldn't be read. */
  records: AlibabaDnsRecord[] | null;
}

export interface AlibabaCdnDomain {
  name: string;
  /** Where it fetches from: an OSS bucket's endpoint, a domain or an address. */
  origins: string[];
  /** The CNAME Alibaba Cloud gives it ("example.com.w.kunlunsl.com"). */
  cname: string;
  https: boolean;
  online: boolean;
}

export interface AlibabaInventory {
  accountId: string;
  /** The account alias, or null. */
  accountName: string | null;
  now: number;
  unreadable: AlibabaSourceKey[];
  /** The AccessKey Keelson scans with is the main account's own. */
  rootKey: boolean;
  /** The main account's AccessKeys and MFA, from RAM's security practice report. null: no report yet (a new account). undefined: unreadable. */
  root: { accessKeys: number; mfa: boolean } | null | undefined;
  passwordPolicy: AlibabaPasswordPolicy | null | undefined;
  /** RAM's security settings for RAM users. undefined: unreadable. */
  securityPreference: AlibabaSecurityPreference | undefined;
  users: AlibabaUser[] | null;
  admins: AlibabaAdmin[] | null;
  roles: AlibabaRole[] | null;
  policies: AlibabaPolicy[] | null;
  escalations: AlibabaEscalation[] | null;
  /** The account's OSS Block Public Access. null: never set. undefined: unreadable. */
  ossBlock: boolean | null | undefined;
  buckets: AlibabaBucket[] | null;
  regions: AlibabaRegion[];
  /** Each region's name for people ("Singapore", "China (Hangzhou)"), from DescribeRegions. */
  regionNames: Record<string, string>;
  /** Regions that refused the AccessKey: left out, not failed. */
  skippedRegions: string[];
  trails: AlibabaTrail[] | null;
  /** Instances Security Center protects (its agent is online), by instance ID; null when unreadable. */
  protectedInstances: Set<string> | null;
  cdnDomains: AlibabaCdnDomain[] | null;
  domains: AlibabaDomain[] | null;
  /** Addresses Keelson saw leave the account, from the address history. */
  released: AddressHistory["released"];
}
