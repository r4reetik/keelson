// The JSON contract between the server and the web app. Server handlers return
// these shapes (`satisfies`), and the web imports them as types. Keys are camelCase.

import type { Severity, SeverityCounts } from "./severity.ts";
import type { Triage, TriageStatus, SlaDays } from "./triage.ts";
import type { ScopeKind } from "./scope.ts";
import type { ProviderId } from "./providers.ts";
import type { Role } from "./roles.ts";
import type { ImageBuildLink, ImagesSnapshot, WorkloadLink } from "./images.ts";

export type Confidence = "confirmed" | "likely";
export type FindingSource = "custom" | "security_center";

/** One step of a finding's evidence, shown as a numbered list. */
export interface EvidenceStep {
  label: string;
  value: string;
}

export interface Evidence {
  /** How the finding was reached, step by step (correlated checks). */
  chain?: EvidenceStep[];
  /** Security Center insight classes that report the same problem. */
  securityCenter?: string[];
  [key: string]: unknown;
}

export interface Finding {
  fingerprint: string;
  accountId: string;
  /** The platform the account is on. */
  provider: ProviderId;
  /** Other platforms the finding's check compared the account with; empty for a check on one platform. */
  spans: ProviderId[];
  /** Display name of the account. */
  account: string;
  entity: string | null;
  checkId: string;
  source: FindingSource;
  severity: Severity;
  category: string;
  zone: string | null;
  resource: string;
  title: string;
  detail: string;
  /** Where to fix it in the provider's dashboard. */
  link: string | null;
  evidence: Evidence | null;
  firstSeen: string | null;
  why: string | null;
  fix: string | null;
  /** The provider's documentation for the setting. */
  docs: string | null;
  triage: Triage | null;
  /** "confirmed": verified by a probe. "likely": a heuristic or observed traffic. null: read from configuration. */
  confidence: Confidence | null;
  /** The finding was resolved once and came back. */
  reopened: boolean;
  /** Effective status: accepted risk past its expiry reads as open. */
  status: TriageStatus;
  /** Accepted risk or false positive: out of the score and the open counts. */
  settled: boolean;
  overdue: boolean;
  due: string | null;
}

/** A finding in a short list (Overview, notifications). */
export type FindingBrief = Pick<
  Finding,
  "fingerprint" | "checkId" | "title" | "resource" | "severity" | "zone" | "category" | "accountId" | "account" | "confidence" | "provider" | "spans"
>;

/** The same check failing in several places, for "Fix these first". */
export interface FindingGroup {
  checkId: string;
  /** The platforms of the accounts it fails in, and the other platforms its check compares them with. */
  providers: ProviderId[];
  spans: ProviderId[];
  title: string;
  severity: Severity;
  category: string;
  confidence: Confidence | null;
  count: number;
  accounts: string[];
  zones: string[];
  overdue: number;
  /** The single finding when count is 1, so the row can open it directly. */
  fingerprint: string | null;
}

export interface ScanMeta {
  id: number;
  startedAt: string;
  finishedAt: string;
  trigger: string;
  apiCalls: number;
  /** Accounts combined in this view. */
  accounts: number;
  /** The least recent of the combined scans. */
  oldestFinishedAt: string;
}

export interface Coverage {
  /** Data source key, from the provider's source registry (src/core/sources.ts for Cloudflare, src/providers/<id>/sources.ts for the rest). */
  key?: string;
  label: string;
  /** The provider the source belongs to (set when the API combines accounts). */
  provider?: ProviderId;
  ok: boolean;
  status?: number;
  message?: string;
  /** What grants this source, in the provider's terms: a token permission, a team role, IAM actions. */
  permission?: string;
  /** Checks that couldn't run because this source wasn't readable. */
  skippedChecks?: string[];
  /** With several accounts: which ones can't read it. */
  notReadableIn?: { id: string; name: string }[];
}

export interface AccountSummary {
  id: string;
  provider: ProviderId;
  name: string;
  entity: string | null;
  score: number | null;
  categoryScores: Record<string, number | null>;
  counts: SeverityCounts;
  finishedAt: string | null;
}

export interface TrendPoint {
  at: string;
  score: number | null;
  counts: Partial<SeverityCounts>;
}

// ---- session and accounts

export type TokenKind = "user" | "account";

export interface SessionAccount {
  id: string;
  provider: ProviderId;
  name: string | null;
  alias: string | null;
  display: string;
  entityId: number;
  scheduled: boolean;
  tokenHint: string | null;
  tokenKind: TokenKind | null;
  tokenMissing: boolean;
  /** The credential is optional and was left empty. */
  tokenEmpty: boolean;
}

export interface SessionEntity {
  id: number;
  name: string;
  includeInAll: boolean;
}

/** The signed-in person. With sign-in turned off (KEELSON_AUTH=none) everyone is an admin with id 0. */
export interface SessionUser {
  id: number;
  username: string;
  name: string | null;
  role: Role;
  /** Signed in with a one-time password, which must be replaced before anything else. */
  mustChangePassword: boolean;
  /** The entities this user is limited to, or null for every entity. Admins are never limited. */
  entities: number[] | null;
}

/** A user as the Users page lists them. */
export interface UserRow extends SessionUser {
  createdAt: string;
  createdBy: string | null;
  lastLoginAt: string | null;
}

export interface UsersResponse {
  users: UserRow[];
}

/** A new user, or a reset password: the one-time password is shown once and never stored. */
export interface OneTimePasswordResponse {
  user: UserRow;
  password: string;
}

export interface Session {
  version: string;
  /** False only with KEELSON_AUTH=none, when a proxy in front decides who gets in. */
  authRequired: boolean;
  authenticated: boolean;
  /** Nobody can sign in yet: the first person to open Keelson creates the admin account. */
  setupRequired: boolean;
  /** Creating the admin from here needs the setup code from Keelson's log (it isn't opened on this machine). */
  setupCodeRequired: boolean;
  configured: boolean;
  user?: SessionUser;
  accounts?: SessionAccount[];
  entities?: SessionEntity[];
  /** Whether a newer release is out (signed-in users only). */
  update?: UpdateStatus;
}

/** How this copy runs, which decides the upgrade instructions: the Docker image, or a clone of the repository. */
export type InstallKind = "docker" | "source";

export interface UpdateStatus {
  /** Checking is on (Settings) and not switched off with KEELSON_UPDATE_CHECK=off. */
  enabled: boolean;
  /** KEELSON_UPDATE_CHECK=off, so the Settings switch has no effect. */
  lockedOff: boolean;
  current: string;
  install: InstallKind;
  /** The release line this version updates within without breaking changes: "0.4", or "1" from 1.0. */
  line: string;
  /** The newest stable release, when it's newer than this one. */
  latest: { version: string; url: string; publishedAt: string | null; sameLine: boolean } | null;
  /** The newest compatible update on this release line, when the latest starts a new line. */
  inLine: { version: string; url: string } | null;
  /** A release between this version and the latest marks breaking changes. */
  breaking: boolean;
  /** How many releases are newer than this one. */
  newerCount: number;
  checkedAt: string | null;
  /** Why the last check failed; the previous result is kept. */
  error: string | null;
}

export interface EntityNotificationsView {
  minSeverity: Severity;
  slackConfigured: boolean;
  slackHint: string;
  webhookConfigured: boolean;
  webhookHint: string;
}

export interface EntityView extends SessionEntity {
  orgDomains: string[];
  position: number;
  notifications: EntityNotificationsView;
}

export interface AccountRow extends SessionAccount {
  busy: boolean;
  lastScan: { finishedAt: string; score: number | null; counts: Partial<SeverityCounts> } | null;
  lastFailed: { finishedAt: string; error: string } | null;
}

export interface AccountsResponse {
  entities: (EntityView & { accounts: AccountRow[] })[];
}

export interface PermissionProbe {
  source: string;
  permission: string;
  powers: string;
  ok: boolean;
  status?: number;
  message?: string;
}
export interface VisibleAccount {
  id: string;
  name: string;
  added: boolean;
  entityId: number | null;
}
export interface TokenInfo {
  valid: boolean;
  kind: TokenKind | null;
  message?: string;
  status?: string;
  expiresOn?: string | null;
}

export interface VerifyResponse {
  token: TokenInfo;
  accounts: VisibleAccount[];
  probes: Record<string, PermissionProbe[]>;
  /** Accounts whose permissions were probed (the rest are assumed alike). */
  probeLimit: number;
  templateUrl?: string;
}

export interface AddAccountsResponse {
  ok: true;
  added: string[];
  updated: string[];
  entityId: number;
}
export interface TemplateResponse {
  /** A pre-filled token form when the provider has one, otherwise its token page. */
  url: string;
  /** The provider's token page. */
  readAllUrl: string;
  /** Whether `url` is a pre-filled template. */
  template: boolean;
}

// ---- settings and checks

export interface Settings {
  schedule: { enabled: boolean; hourUtc: number; minuteUtc: number };
  retentionDays: number;
  /** Days a finding may stay open before it is flagged overdue (when no due date is set). */
  slaDays: SlaDays;
  /** Live checks that send requests outside the providers' APIs. */
  probes: { takeover: boolean };
  /** Address people use to open Keelson, for links in notifications. */
  baseUrl: string;
  /** Check GitHub daily for a newer release. */
  updates: { check: boolean };
}

export interface CheckRow {
  id: string;
  provider: ProviderId;
  /** Other platforms the check compares an account with. */
  spans: ProviderId[];
  category: string;
  severity: Severity;
  title: string;
  why: string;
  fix: string;
  docs: string | null;
  /** Data sources the check reads. */
  requires: string[];
  evaluated: number;
  failed: number;
  disabled: boolean;
  severityOverride: Severity | null;
}

export interface ChecksResponse {
  scan: ScanMeta | null;
  checks: CheckRow[];
}

// ---- dashboard

export interface Unscanned {
  id: string;
  name: string;
}

export interface TriageCounts {
  open: number;
  inProgress: number;
  accepted: number;
  falsePositive: number;
  /** Critical and high findings with no owner. */
  unowned: number;
  overdue: number;
  reopened: number;
}

export interface AttackPath extends FindingBrief {
  detail: string;
}

/** Before the first scan finishes, only `scan: null` and the accounts waiting for one. */
export type Overview = { scan: null; unscanned: Unscanned[] } | OverviewData;

export interface OverviewData {
  scan: ScanMeta;
  unscanned: Unscanned[];
  score: number | null;
  categoryScores: Record<string, number | null>;
  categoryCounts: Record<string, SeverityCounts>;
  accounts: AccountSummary[];
  /** With accounts from several providers in view: each provider's score, averaged over its accounts. */
  byProvider: ProviderScore[];
  counts: SeverityCounts;
  triage: TriageCounts;
  trend: TrendPoint[];
  previousAt: string | null;
  /** Open critical and high findings grouped by check, most urgent first. */
  fixFirst: FindingGroup[];
  attackPaths: AttackPath[];
  attackPathCount: number;
  newSince: FindingBrief[];
  newSinceCount: number;
  resolvedSince: FindingBrief[];
  coverage: Coverage[];
  securityCenter: { imported: number; corroborated: number; total: number | null };
  valueCounts: ValueCounts | undefined;
}

export interface ProviderScore {
  provider: ProviderId;
  score: number | null;
  accounts: number;
  counts: SeverityCounts;
}

export interface FindingsResponse {
  scan: ScanMeta | null;
  findings: Finding[];
  /** Fingerprints that weren't in each account's previous scan. */
  newFingerprints: string[];
}

export interface FindingEvent {
  at: string;
  kind: "first_seen" | "seen" | "resolved" | "reopened" | "triage";
  by?: string | null;
  /** For triage events: what changed. */
  changes?: Partial<Record<"status" | "owner" | "note" | "dueDate" | "acceptUntil", { from: string | null; to: string | null }>>;
  scanId?: number;
}

/** A finding that has been triaged, as last reported, with its whole history. */
export interface TriagedFinding extends Finding {
  /** Still reported by its account's latest scan. */
  present: boolean;
  /** When a scan stopped finding it, while it's gone. */
  resolvedAt: string | null;
  /** First seen, scan outcomes and every triage change, oldest first. */
  events: FindingEvent[];
}

/** Everything triaged in the scope, most recently changed first. */
export interface TriagedResponse {
  scan: ScanMeta | null;
  findings: TriagedFinding[];
}

/** Owners already used in the entities of the requested accounts, most recently assigned first. */
export interface OwnersResponse {
  owners: string[];
}

/** One finding wherever it lives, with its history. 404 when it never existed. */
export interface FindingDetail {
  finding: Finding | null;
  /** When the finding is no longer reported. */
  resolvedAt: string | null;
  /** Where the finding lives, so the web can switch scope. */
  accountId: string;
  account: string;
  entityId: number | null;
  /** Its last known shape, when it's resolved. */
  last: FindingBrief | null;
  events: FindingEvent[];
}

/**
 * An address or hostname a finding names, looked up in the latest scans of the entity's other accounts: what holds
 * or serves it, and the path there (a DNS record, a CNAME, a load balancer). When the finding is about a port (RDP,
 * SSH, a database), whether the holder's security groups really let anyone reach it.
 */
export interface LocatedItem {
  /** The address or hostname, as the finding names it. */
  value: string;
  kind: "address" | "hostname";
  /**
   * found: an account in the entity holds or serves it. released: one held it and let it go. outside: none of the
   * entity's accounts that list their addresses holds it. unknown: nothing in the entity says either way.
   */
  status: "found" | "released" | "outside" | "unknown";
  /** One line: "Alibaba Cloud: ECS instance web-1 (i-…) in Singapore". */
  summary: string;
  /** From the finding's value to what holds it, like an evidence chain. */
  steps: { label: string; value: string; provider?: ProviderId; link?: string | null }[];
  /** For a finding about a port: whether the holder lets anyone reach it, from its security groups or listeners. */
  ports: { port: number; service: string; open: boolean | null; detail: string }[];
}

export interface LocatedResponse {
  items: LocatedItem[];
  /** The platforms whose accounts in the entity were searched. */
  searched: ProviderId[];
}

export interface ZoneRow {
  name: string;
  account?: string;
  accountId?: string;
  plan: string;
  planName: string;
  status: string;
  paused: boolean;
  proxiedZone: boolean;
  records: number;
  proxied: number;
  ssl: string | null;
  minTls: string | null;
  alwaysHttps: string | null;
  hsts: boolean | null;
  tls13: string | null;
  dnssec: string | null;
  wafManaged: boolean | "n/a" | null;
  owasp: boolean | "n/a" | null;
  rateLimitRules: number | null;
  botProtection: boolean | null;
  aiBots: string | null;
  securityLevel: string | null;
  pageShield: boolean | null;
  leakedCredentials: boolean | null;
  caa: boolean | null;
  traffic: { requests: number; cachedRequests: number; threats: number; bytes: number } | null;
  findings: SeverityCounts;
}

export interface ZonesResponse {
  scan: ScanMeta | null;
  zones: ZoneRow[] | null;
  coverage: Coverage[];
}

export interface Subscription {
  name: string;
  scope: string;
  zone: string | null;
  price: number;
  currency: string;
  frequency: string;
  state: string;
  account?: string;
  accountId?: string;
}

export interface ValueZone {
  name: string;
  account?: string;
  accountId?: string;
  plan: string;
  paid: boolean;
  price: number;
  requests: number | null;
  threats: number | null;
  cached: number | null;
  features: Record<string, boolean | null>;
}

export interface ValueCounts {
  zones: number;
  paidZones: number;
  members: number | null;
  accessApps: number | null;
  serviceTokens: number | null;
  tunnels: number | null;
  healthyTunnels: number;
  workers: number;
  r2Buckets: number;
  ztDevices: number | null;
  gatewayRules: number | null;
  notifications: number | null;
  requests30d: number;
  cachedRequests30d: number;
  threats30d: number;
}

export interface ValueView {
  subscriptions: Subscription[];
  monthly: number;
  zones: ValueZone[];
  counts: ValueCounts;
}
export interface ValueResponse {
  scan: ScanMeta | null;
  value: ValueView | null;
  coverage: Coverage[];
}

export interface ActivityEvent {
  when: string;
  account?: string;
  accountId?: string;
  actor: string;
  actorType: string | null;
  ip: string | null;
  type: string;
  info: string;
  ok: boolean;
  resource: string;
  zone: string | null;
  category: string;
  routine: boolean;
  destructive: boolean;
}

export interface ActivityView {
  available: boolean;
  since: string;
  total: number;
  byCategory: Record<string, number>;
  byActor: Record<string, number>;
  events: ActivityEvent[];
}
export interface ActivityResponse {
  scan: ScanMeta | null;
  activity: ActivityView | null;
  coverage: Coverage[];
}

export interface ScanRow {
  id: number;
  accountId: string;
  account: string;
  startedAt: string;
  finishedAt: string | null;
  trigger: string;
  status: "running" | "done" | "failed";
  score: number | null;
  counts: Partial<SeverityCounts> | null;
  apiCalls: number | null;
  error: string | null;
}

export interface ScansResponse {
  scans: ScanRow[];
  coverage: Coverage[];
}

/** POST /api/scan. */
export interface ScanRequest {
  /** The view to scan: "all", "e:<entity id>" or "a:<account id>". */
  scope: string;
  /** Scan every account in every entity instead, including entities kept out of "All accounts". */
  every?: boolean;
}

export interface ScanStatus {
  running: boolean;
  accountId: string | null;
  scanId: number | null;
  trigger: string | null;
  startedAt: string | null;
  phase: string | null;
  done: number | null;
  total: number | null;
  queued: string[];
  /** The running or queued scans include an account in the current view. */
  inScope: boolean;
  /**
   * Images being read in the background, after scans that had no time for them. It gives way to any scan, so while one
   * runs this says what waits behind it. Null when nothing is left to read.
   */
  background: {
    /** The account whose images are being read; null when the user can't see it. */
    accountId: string | null;
    done: number;
    total: number;
    /** Accounts with images to read after this one. */
    queued: number;
    /** One of those accounts is in the current view. */
    inScope: boolean;
  } | null;
  lastScanAt: string | null;
  lastFailed: { id: number; finishedAt: string; error: string; account: string } | null;
}

export type Report = { scan: null } | ReportData;

export interface ReportData {
  scan: ScanMeta;
  scope: { kind: ScopeKind; label: string; entity: string | null };
  accountId: string | null;
  accounts: AccountSummary[];
  generatedAt: string;
  version: string;
  score: number | null;
  categoryScores: Record<string, number | null>;
  counts: SeverityCounts;
  findings: Finding[];
  coverage: Coverage[];
  zones: ZoneRow[] | null;
  projects: ProjectRow[] | null;
  regions: RegionRow[] | null;
  /** Alibaba Cloud's resources. */
  resources: ResourceRow[] | null;
  repos: RepoRow[] | null;
  valueCounts: ValueCounts | undefined;
  checks: Record<string, { evaluated: number; failed: number }>;
}

/** What a finished scan stores besides its findings. Provider-specific parts are absent for other providers. */
export interface ScanSnapshot {
  accountName: string | null;
  coverage: Coverage[];
  checks: Record<string, { evaluated: number; failed: number }>;
  /** Cloudflare: zones, plans and costs, the audit log, Security Center and live probes. */
  zones?: ZoneRow[];
  value?: ValueView;
  activity?: ActivityView;
  securityCenter?: { imported: number; corroborated: number; total: number | null };
  probes?: { takeover: { probed: number; unclaimed: number } | null };
  /** Vercel: projects. */
  projects?: ProjectRow[];
  /** AWS: regions and the account's global resources. (Alibaba Cloud scans before Keelson listed its resources carry these too.) */
  regions?: RegionRow[];
  /** Alibaba Cloud: every resource the checks read, and the regions that hold them. */
  resources?: ResourcesView;
  /** GitHub: repositories. */
  repos?: RepoRow[];
  /** Internet (Sonar): the entity's domains, hostnames and addresses as seen from outside. */
  surface?: SurfaceView;
  /** AWS and Alibaba Cloud: the public addresses the account held at its last complete scan, and the ones seen to leave it since. */
  addressHistory?: AddressHistory;
  /** Domains the account owns, when no other part of the snapshot lists them (AWS's public hosted zones, Alibaba Cloud DNS's domains). */
  ownedDomains?: string[];
  /** AWS, Alibaba Cloud and GitHub: the container images the scan looked at, with what Trivy found in each. */
  images?: ImagesSnapshot;
  /** What other providers' accounts in the same entity need for checks that span providers. */
  links?: ProviderLinks;
}

/**
 * What one provider shares with the others inside an entity, for checks that span
 * providers. A Cloudflare scan records its DNS records that point at Vercel and at
 * AWS; a Vercel scan records the domains its projects serve; an AWS scan records
 * the endpoints it has. Each scan reads the other side from the latest scans of
 * the entity's other accounts. A list is absent when its scan couldn't read all of
 * it, so an incomplete list is never mistaken for "nothing there".
 */
export interface ProviderLinks {
  /** Cloudflare DNS records whose target is Vercel. */
  toVercel?: { host: string; zone: string; type: string; target: string; proxied: boolean }[];
  /** Vercel project domains, with the project that serves each. */
  vercelDomains?: { host: string; project: string; projectId: string; protectsDeploymentUrls: boolean }[];
  /** Cloudflare DNS records whose target is an AWS endpoint. */
  toAws?: { host: string; zone: string; target: string; kind: AwsEndpointKind; name: string; proxied: boolean }[];
  /** Cloudflare A records: the address each hostname points at, and whether Cloudflare proxies it. */
  dnsAddresses?: { host: string; zone: string; ip: string; proxied: boolean }[];
  /** Endpoints an AWS account has: CloudFront domain names, load balancer DNS names and S3 bucket names. */
  awsEndpoints?: { kind: AwsEndpointKind; name: string }[];
  /** Public IPv4 addresses an AWS account holds: Elastic IPs and the addresses of its network interfaces. */
  awsAddresses?: string[];
  /**
   * Who can reach each of an AWS account's web origins on ports 80 and 443, from their security groups: a load
   * balancer by its DNS name, or a network interface by its public address. Origins Keelson can't judge (no groups
   * of their own, a managed prefix list it couldn't read, no web rule at all) aren't listed.
   */
  awsOrigins?: AwsOrigin[];
  /** Addresses Keelson saw leave an AWS account between scans, with when. A DNS record that still points at one is dangling. */
  awsReleased?: { ip: string; at: string }[];
  /** The AWS account's own ID, so its siblings can tell a role trusted inside the entity from one trusted outside it. */
  awsAccounts?: string[];
  /** Custom domains of a GitHub organization's Pages sites, with the repository that serves each. */
  githubPages?: { host: string; repo: string }[];
  /** The GitHub organization's login, lowercase, so AWS roles can tell a repository inside the entity from one outside it. */
  githubOrgs?: string[];
  /** Every repository of a GitHub organization ("org/name", lowercase), its default branch, and whether a change there needs a reviewed pull request. */
  githubRepos?: { repo: string; defaultBranch: string; reviewed: boolean }[];
  /** Custom domains of a GitLab group's Pages sites, with the project that serves each. */
  gitlabPages?: { host: string; repo: string }[];
  /** The GitLab group's full path, lowercase, with the host of the instance it is on, so cloud roles can tell a project inside the entity from one outside it. */
  gitlabGroups?: { host: string; group: string }[];
  /** Every project of a GitLab group ("group/subgroup/name", lowercase), its instance, its default branch, and whether a change there needs a merge request. */
  gitlabProjects?: { host: string; repo: string; defaultBranch: string; reviewed: boolean }[];
  /** Cloudflare zones, so an outside view can tell a domain whose DNS Keelson reads from one it doesn't. */
  cloudflareZones?: string[];
  /** Cloudflare's host records (A, AAAA, CNAME), with whether Cloudflare proxies each. */
  cloudflareDns?: DnsHostRecord[];
  /** Route 53's public hosted zones. */
  route53Zones?: string[];
  /** Route 53's host records (A, AAAA, CNAME, and aliases as CNAME) in public hosted zones. */
  route53Dns?: DnsHostRecord[];
  /** An AWS account's load balancers with their listeners, routing and targets, so a hostname can be followed to what serves it. */
  awsLoadBalancers?: AwsLoadBalancerLink[];
  /** Every public address an AWS account holds, with what owns it and what its security groups let anyone reach. */
  awsExposure?: AwsExposureLink[];
  /** Cloudflare DNS records whose target is an Alibaba Cloud endpoint (an OSS bucket, a load balancer, a CDN domain). */
  toAlibaba?: { host: string; zone: string; target: string; kind: AlibabaEndpointKind; name: string; proxied: boolean }[];
  /** Endpoints an Alibaba Cloud account has: OSS buckets, ALB and NLB DNS names, CDN domains. */
  alibabaEndpoints?: { kind: AlibabaEndpointKind; name: string }[];
  /** Public IPv4 addresses an Alibaba Cloud account holds: EIPs, instances' public addresses and load balancers' addresses. */
  alibabaAddresses?: string[];
  /** Addresses Keelson saw leave an Alibaba Cloud account between scans, with when. A DNS record that still points at one is dangling. */
  alibabaReleased?: { ip: string; at: string }[];
  /** The Alibaba Cloud account's own ID (UID), so its siblings can tell a role trusted inside the entity from one trusted outside it. */
  alibabaAccounts?: string[];
  /**
   * Who can reach each of an Alibaba Cloud account's web origins on ports 80 and 443, from their security groups, in the
   * same shape as AWS's: a load balancer by its DNS name, or an instance or network interface by its public address.
   */
  alibabaOrigins?: AwsOrigin[];
  /** Alibaba Cloud DNS's domains. */
  alidnsZones?: string[];
  /** Alibaba Cloud DNS's host records (A, AAAA, CNAME) that are enabled. */
  alidnsDns?: DnsHostRecord[];
  /** An Alibaba Cloud account's load balancers (ALB, NLB, CLB) with their listeners, routing and backend servers, in AWS's shape. */
  alibabaLoadBalancers?: AwsLoadBalancerLink[];
  /** Every public address an Alibaba Cloud account holds, with what owns it and what its security groups let anyone reach. */
  alibabaExposure?: AwsExposureLink[];
  /** An AWS account's workloads that run container images (ECS services), each with its images and how the internet reaches it. */
  awsWorkloads?: WorkloadLink[];
  /** An Alibaba Cloud account's workloads that run container images (ECI container groups, Function Compute functions, SAE applications). */
  alibabaWorkloads?: WorkloadLink[];
  /** The images a GitHub organization's workflows build and push, by repository. */
  githubImageBuilds?: ImageBuildLink[];
}

/** An AWS load balancer as a hostname that names it reaches it. Alibaba Cloud publishes its ALBs, NLBs and CLBs in the same shape. */
export interface AwsLoadBalancerLink {
  /** The cloud it is in; absent: AWS. */
  provider?: "aws" | "alibaba";
  name: string;
  /** Its DNS name; a CLB, which has none, by its address. */
  dnsName: string;
  /** The AWS account's alias, or its ID without one. */
  account: string;
  region: string;
  /** "application", "network", "gateway" or "classic". */
  type: string;
  internetFacing: boolean;
  /** Who its own security groups let in on ports 80 and 443 (see AwsOrigin); null without groups of its own or when Keelson can't tell. */
  web: AwsOrigin["web"] | null;
  /** A WAF web ACL filters it, on it or on a distribution in front of it; null when unknown or not applicable. */
  waf: boolean | null;
  listeners: AwsListenerLink[];
}

export interface AwsListenerLink {
  port: number | null;
  protocol: string;
  /** Its routes in the order the load balancer tries them, the default last; null when they couldn't be read. */
  routes: AwsRouteLink[] | null;
}

export interface AwsRouteLink {
  /** The rule's priority, or "default". */
  rule: string;
  /** Host header values it matches (* and ? wildcards); empty: any host. */
  hosts: string[];
  paths: string[];
  /** Other conditions, by kind (a header by its name, never its value). */
  conditions: string[];
  action: "forward" | "redirect" | "fixed-response" | "other";
  /** Visitors sign in (Cognito or OpenID Connect) before it forwards. */
  authenticates: boolean;
  /** A redirect's destination or a fixed response's status code. */
  detail: string | null;
  /** What it forwards to; null when its target groups or their targets couldn't be read. */
  targets: AwsTargetLink[] | null;
}

export interface AwsTargetLink {
  /** "instance", "ip", "lambda" or "alb". */
  kind: string;
  /** The instance ID, private address, function or load balancer name. */
  id: string;
  /** The instance's Name tag. */
  name: string | null;
  /** The target group's name ("" for a classic load balancer's instances). */
  group: string;
  port: number | null;
  health: string | null;
  /** Its public address: with one, it can be reached without the load balancer if its security groups let anyone in. */
  publicIp: string | null;
  /** Its security groups let anyone (0.0.0.0/0 or ::/0) reach `port`; null when unknown. */
  openOnPort: boolean | null;
}

/** A public address an AWS account holds, and what its security groups let anyone reach there. */
export interface AwsExposureLink {
  ip: string;
  account: string;
  region: string;
  /** What has it, as AWS's checks name it: "instance web-1 (i-…)", "load balancer web-alb", "NAT gateway eni-…". */
  resource: string;
  /** Inbound rules that admit 0.0.0.0/0 or ::/0, with the groups that hold them; null when the groups couldn't be read. */
  open: { protocol: string; from: number | null; to: number | null; groups: string[] }[] | null;
}

/** One DNS record that names a host, as a platform that serves the zone lists it. */
export interface DnsHostRecord {
  host: string;
  zone: string;
  type: string;
  target: string;
  proxied: boolean;
}

/** How an AWS account's public addresses changed over its scans: what it holds, and what it gave up and when. */
export interface AddressHistory {
  held: string[];
  released: { ip: string; at: string }[];
}

/**
 * An AWS web origin and who its security groups let in on ports 80 and 443: "open" when one admits 0.0.0.0/0 or ::/0,
 * "cloudflare" when only Cloudflare's ranges (and private ones) are admitted, "other" when public ranges outside
 * Cloudflare's are. `groups` are the open ones for "open", and every attached one otherwise.
 */
export interface AwsOrigin {
  kind: "elb" | "ip";
  /** The load balancer's DNS name, or the public address. */
  name: string;
  region: string;
  /** What it is, as AWS's XP-006 names it: "load balancer web-alb", "instance web-1 (i-…)". */
  resource: string;
  web: "open" | "cloudflare" | "other";
  groups: { id: string; name: string }[];
}

/** The kinds of AWS endpoint a DNS record can point at by name. */
export type AwsEndpointKind = "cloudfront" | "elb" | "s3";

/** The kinds of Alibaba Cloud endpoint a DNS record can point at by name: an OSS bucket, an ALB or NLB load balancer, a CDN domain. */
export type AlibabaEndpointKind = "oss" | "slb" | "cdn";

/** Every list in ProviderLinks: the scanner merges each across an entity's accounts. */
export const LINK_KEYS = [
  "toVercel",
  "vercelDomains",
  "toAws",
  "dnsAddresses",
  "awsEndpoints",
  "awsAddresses",
  "awsOrigins",
  "awsReleased",
  "awsAccounts",
  "githubPages",
  "githubOrgs",
  "githubRepos",
  "gitlabPages",
  "gitlabGroups",
  "gitlabProjects",
  "cloudflareZones",
  "cloudflareDns",
  "route53Zones",
  "route53Dns",
  "awsLoadBalancers",
  "awsExposure",
  "toAlibaba",
  "alibabaEndpoints",
  "alibabaAddresses",
  "alibabaReleased",
  "alibabaAccounts",
  "alibabaOrigins",
  "alidnsZones",
  "alidnsDns",
  "alibabaLoadBalancers",
  "alibabaExposure",
  "awsWorkloads",
  "alibabaWorkloads",
  "githubImageBuilds",
] as const satisfies readonly (keyof ProviderLinks)[];
export type LinkKey = (typeof LINK_KEYS)[number];

/** The provider whose scans publish each list. When one of its accounts in the entity didn't, the merged list is incomplete. */
export const LINK_PROVIDER: Record<LinkKey, ProviderId> = {
  toVercel: "cloudflare",
  toAws: "cloudflare",
  dnsAddresses: "cloudflare",
  vercelDomains: "vercel",
  awsEndpoints: "aws",
  awsAddresses: "aws",
  awsOrigins: "aws",
  awsReleased: "aws",
  awsAccounts: "aws",
  githubPages: "github",
  githubOrgs: "github",
  githubRepos: "github",
  gitlabPages: "gitlab",
  gitlabGroups: "gitlab",
  gitlabProjects: "gitlab",
  cloudflareZones: "cloudflare",
  cloudflareDns: "cloudflare",
  route53Zones: "aws",
  route53Dns: "aws",
  awsLoadBalancers: "aws",
  awsExposure: "aws",
  toAlibaba: "cloudflare",
  alibabaEndpoints: "alibaba",
  alibabaAddresses: "alibaba",
  alibabaReleased: "alibaba",
  alibabaAccounts: "alibaba",
  alibabaOrigins: "alibaba",
  alidnsZones: "alibaba",
  alidnsDns: "alibaba",
  alibabaLoadBalancers: "alibaba",
  alibabaExposure: "alibaba",
  awsWorkloads: "aws",
  alibabaWorkloads: "alibaba",
  githubImageBuilds: "github",
};

/** One region of an AWS or Alibaba Cloud account as the Regions page shows it, or the account's global resources. */
export interface RegionRow {
  /** The region ("eu-west-1", "cn-hangzhou"), or "Global" for IAM or RAM, object storage, the CDN and DNS. */
  name: string;
  account?: string;
  accountId?: string;
  /** The account's platform, added when the rows are served. */
  provider?: ProviderId;
  /** What was found there, by kind: "Instances", "Buckets"… Kinds that couldn't be read are left out. */
  resources: { label: string; count: number }[];
  /** Whether GuardDuty is on; null when it couldn't be read or doesn't apply (Global, or a platform without it). */
  guardDuty: boolean | null;
  /** The credential was refused in this region, so nothing there was checked. */
  skipped: boolean;
  findings: SeverityCounts;
}

export interface RegionsResponse {
  scan: ScanMeta | null;
  regions: RegionRow[] | null;
  coverage: Coverage[];
}

/**
 * One cloud resource, as the Resources page lists it (Alibaba Cloud): what it is in the cloud's own words, where it
 * is, whether and how the internet reaches it, and its open findings. Only what the checks already read is shown.
 */
export interface ResourceRow {
  /** The product's own name for it: "ECS instance", "CLB", "OSS bucket", "Tair (Redis)". */
  kind: string;
  /** What it is for, which groups kinds on the page. */
  group: ResourceGroup;
  id: string;
  name: string;
  /** Its region, or "Global" for RAM, OSS settings, CDN and DNS. A bucket has its region. */
  region: string;
  /** How the internet reaches it ("Public address 203.0.113.7", "Public endpoint, whitelist 0.0.0.0/0"), or null when it doesn't. */
  exposure: string | null;
  /** A few facts the checks read: "Linux", "MySQL 8.0", "Runs as role web", "No MFA". */
  facts: string[];
  link: string | null;
  findings: SeverityCounts;
  account?: string;
  accountId?: string;
}

export type ResourceGroup = "Compute" | "Networking" | "Storage" | "Databases" | "Identity" | "Edge";
export const RESOURCE_GROUPS: ResourceGroup[] = ["Compute", "Networking", "Storage", "Databases", "Identity", "Edge"];

/** A region with something in it, with its name for people ("Singapore") when the cloud gives one. */
export interface ResourceRegion {
  name: string;
  label: string | null;
  resources: number;
  account?: string;
  accountId?: string;
}

export interface ResourcesView {
  rows: ResourceRow[];
  /** Regions that hold something; empty ones are counted in `emptyRegions`. */
  regions: ResourceRegion[];
  emptyRegions: number;
  /** Regions that refused the credential, so nothing there was read. */
  skippedRegions: string[];
}

export interface ResourcesResponse {
  scan: ScanMeta | null;
  resources: ResourcesView | null;
  coverage: Coverage[];
}

/** A Vercel project as the Projects page shows it. */
export interface ProjectRow {
  id: string;
  name: string;
  account?: string;
  accountId?: string;
  framework: string | null;
  nodeVersion: string | null;
  git: string | null;
  domains: string[];
  /** Who can open preview deployments: "Vercel Authentication", "Password", "Trusted IPs" or "Public". */
  previews: string;
  /** Whether *.vercel.app production URLs are protected too. */
  productionUrls: string;
  firewall: boolean | null;
  managedRules: string[] | null;
  envVars: number | null;
  sensitiveEnvVars: number | null;
  gitForkProtection: boolean | null;
  findings: SeverityCounts;
}

/** A GitHub repository as the Repositories page shows it. */
export interface RepoRow {
  name: string;
  account?: string;
  accountId?: string;
  /** The organization's login on GitHub, so "owner/repo" can be copied; null when the scan didn't record it. */
  owner?: string | null;
  /** Where the repository is opened, on a platform people host themselves (Gitea); absent where the owner and name say it. */
  url?: string | null;
  /** "public", "private" or "internal". */
  visibility: string;
  archived: boolean;
  defaultBranch: string;
  /** How the default branch is protected: "Pull request, 2 approvals", "Protected", "None"; null when unreadable or the repository is archived or empty. */
  protection: string | null;
  secretScanning: boolean | null;
  pushProtection: boolean | null;
  /** Open alerts by kind; null when that kind couldn't be read. Dependabot and code scanning count critical and high only. */
  alerts: { secrets: number | null; dependabot: number | null; codeScanning: number | null };
  /** The Pages site's custom domain, "github.io" without one, or null without a site. */
  pages: string | null;
  /** What it depends on, from its SBOM; null when its manifest and lock files weren't read. */
  dependencies?: RepoDependencySummary | null;
  findings: SeverityCounts;
}

/** A repository's dependencies in a line of the Repositories page. */
export interface RepoDependencySummary {
  /** When its SBOM was made: the last time a manifest or lock file changed. */
  generatedAt: string;
  /** Its main languages by share of code, from GitHub, largest first. */
  languages: { name: string; share: number }[];
  ecosystems: string[];
  /** Projects in it (more than one in a monorepo), not counting its workflows. */
  parts: number;
  /** Null when Syft isn't installed. */
  packages: number | null;
  /** Packages with at least one known vulnerability; null when Grype didn't run. */
  vulnerable: number | null;
  /** Known vulnerabilities by severity, counted once per package. */
  vulns: { critical: number; high: number; medium: number; low: number } | null;
  /** Vulnerabilities attackers are known to exploit (CISA KEV). */
  exploited: number | null;
  /** Packages under a strong copyleft license; null when Grant didn't run. */
  copyleft: number | null;
  /** Projects that install dependencies without a lock file. */
  unlocked: number;
  /** Some files were too large or too many to read. */
  partial: boolean;
}

/** One of the entity's domains, as an internet scan (Sonar) sees it. */
export interface SurfaceDomainRow {
  name: string;
  /** The entity's name: Sonar has one account per entity. */
  account?: string;
  accountId?: string;
  /** The platform whose connected account serves its DNS, or null when none does. */
  dns: ProviderId | null;
  nameservers: string[] | null;
  /** Certificates in the logs that are still valid; null when the logs couldn't be read. */
  certificates: number | null;
  /** Who issued them, most first. */
  issuers: string[];
  /** The authorities its CAA records allow (";" for none); empty without CAA, null when the lookup failed. */
  caa: string[] | null;
  findings: SeverityCounts;
}

export interface SurfaceHostRow {
  name: string;
  domain: string;
  account?: string;
  accountId?: string;
  /** Where it was found: "DNS", "Certificate logs", "Shodan". */
  found: string[];
  /** What it points at: records, or the public DNS answer. */
  points: string;
  servedBy: string;
  /** Where its requests go in a connected AWS account; null when it reaches neither a load balancer nor an address one holds. */
  route?: SurfaceHostRoute | null;
  findings: SeverityCounts;
}

/** A hostname followed into AWS: the load balancer it reaches and the rules that match it, or the address it points at. */
export interface SurfaceHostRoute {
  /** The load balancer whose rules decide, as in SurfaceView.loadBalancers. */
  loadBalancer: string | null;
  /** Load balancers in front of it, in order: a network load balancer that forwards to an application one. */
  via?: string[];
  /** Each listener with only the routes a request for this hostname can take. */
  listeners: SurfaceListener[];
  /** An address an AWS account holds that it points at directly. */
  address: { ip: string; resource: string; open: string[] | null } | null;
}

export interface SurfaceListener {
  port: number | null;
  protocol: string;
  /** Null when the routing couldn't be read. */
  routes: SurfaceRouteRow[] | null;
}

export interface SurfaceRouteRow {
  /** "default" or the rule's priority. */
  rule: string;
  /** What it matches: "api.example.com /admin/*", or "Any request". */
  match: string;
  /** What it does: "Forwards to web", "Signs visitors in, then forwards to admin", "Redirects to HTTPS". */
  action: string;
  /** Null when its targets couldn't be read. */
  targets: { label: string; port: number | null; health: string | null; publicIp: string | null; direct: boolean }[] | null;
}

/** One of the entity's AWS or Alibaba Cloud load balancers, with the hostnames that reach it and its routing. */
export interface SurfaceLoadBalancerRow {
  /** The cloud it is in; absent in views stored before Alibaba Cloud: AWS. */
  provider?: "aws" | "alibaba";
  name: string;
  /** The entity's name: Sonar has one account per entity. */
  account?: string;
  accountId?: string;
  /** The cloud account's alias, or its ID without one. */
  awsAccount: string;
  region: string;
  type: string;
  internetFacing: boolean;
  web: AwsOrigin["web"] | null;
  waf: boolean | null;
  hosts: string[];
  /** Hostnames its rules name that no DNS record points at it. */
  unpointed: string[];
  listeners: SurfaceListener[];
  findings: SeverityCounts;
}

export interface SurfaceAddressRow {
  ip: string;
  account?: string;
  accountId?: string;
  /** "AWS" when an AWS account in the entity holds it, null when only its DNS points at it. */
  heldBy: string | null;
  hosts: string[];
  /** Whether a proxied hostname uses it as its origin. */
  origin: boolean;
  /** What Shodan has seen: null when it couldn't be asked, `seen: false` when it knows nothing. */
  shodan: { seen: boolean; ports: number[]; products: string[]; vulns: number; lastSeen: string | null } | null;
  /** What has the address in AWS ("instance web-1 (i-…)"), when an AWS account in the entity holds it. */
  resource?: string | null;
  /** What its security groups let anyone reach ("tcp 443", "all traffic"); null when unknown or not held in AWS. */
  open?: string[] | null;
  findings: SeverityCounts;
}

export interface SurfaceView {
  domains: SurfaceDomainRow[];
  hosts: SurfaceHostRow[];
  addresses: SurfaceAddressRow[];
  /** The entity's AWS load balancers; absent on scans from before they were followed. */
  loadBalancers?: SurfaceLoadBalancerRow[];
  /** Names from the logs or Shodan that don't resolve (or weren't looked up past the limit). */
  unresolved: number;
  /** What Amass added, when it ran: names it returned, how many nothing else had found, and how long it took. */
  amass?: { names: number; added: number; minutes: number } | null;
}

export interface SurfaceResponse {
  scan: ScanMeta | null;
  surface: SurfaceView | null;
  coverage: Coverage[];
}

export interface ReposResponse {
  scan: ScanMeta | null;
  repos: RepoRow[] | null;
  coverage: Coverage[];
}

export interface ProjectsResponse {
  scan: ScanMeta | null;
  projects: ProjectRow[] | null;
  coverage: Coverage[];
}

/** Error bodies: `code` tells the web app what to do about it. */
export interface ApiError {
  error: string;
  /** setup: no account connected; scope: unknown view; auth: sign in; password: replace a one-time password first; role: the role can't do this. */
  code?: "setup" | "scope" | "auth" | "password" | "role";
}
