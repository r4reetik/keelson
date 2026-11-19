// Reads an Alibaba Cloud account into the typed inventory the checks use. RAM,
// OSS, CDN and DNS are read once; everything else in every region ECS lists as
// available. Like AWS's, a region that refuses the AccessKey is skipped and
// recorded rather than failing the scan, and a product that isn't offered in a
// region, or that the account never opened, reads as empty, not as a gap.
//
// What isn't kept: AccessKey IDs (only their last four characters), policy
// documents (reduced in policy.ts), start-up scripts and environment variables
// (scanned in memory for credentials, only the kind found is kept), and anything
// stored in a bucket or a secret, which Keelson never asks for.

import { AlibabaError, type AlibabaClient, type Json } from "./client.ts";
import { ALIBABA_SOURCE_KEYS, ALIBABA_SOURCES, HOME_REGION, type AlibabaSourceKey } from "./sources.ts";
import { bucketPolicy, escalationPaths, grantsEverything, listOf, statements, trustOf, type Statement } from "./policy.ts";
import { find, items, text, type XmlNode } from "../../core/xml.ts";
import { inCloudflare, isInternal } from "../../core/cloudflare-ranges.ts";
import { secretInVariables, secretKindIn } from "../../core/secret-patterns.ts";
import type { ProgressEvent } from "../../core/types.ts";
import type {
  AlibabaAccessKey,
  AlibabaAdmin,
  AlibabaBucket,
  AlibabaCdnDomain,
  AlibabaCluster,
  AlibabaDatabase,
  AlibabaDomain,
  AlibabaEscalation,
  AlibabaFunction,
  AlibabaInstance,
  AlibabaInterface,
  AlibabaInventory,
  AlibabaKey,
  AlibabaListener,
  AlibabaLoadBalancer,
  AlibabaPasswordPolicy,
  AlibabaSecurityPreference,
  AlibabaPolicy,
  AlibabaRegion,
  AlibabaRole,
  AlibabaRule,
  AlibabaSecret,
  AlibabaSecurityGroup,
  AlibabaServerGroup,
  AlibabaTrail,
  AlibabaUser,
} from "./types.ts";

const REGION_CONCURRENCY = 4;
const ITEM_CONCURRENCY = 6;
const MAX_PAGES = 50;
/** Things that cost a request each (a group's rules, an instance's user data, a key's details) are read up to this many per region. */
export const MAX_ITEMS = 200;
const MAX_USERS = 1000;
const MAX_BUCKETS = 1000;
const MAX_DOMAINS = 200;

/** Alibaba Cloud's system policies that give everything, or everything in RAM (which is the same in a few steps). */
const ADMIN_POLICIES = ["AdministratorAccess"];
const RAM_ADMIN_POLICY = "AliyunRAMFullAccess";

export async function collectAlibaba(client: AlibabaClient, onProgress: (p: ProgressEvent) => void = () => {}): Promise<AlibabaInventory> {
  onProgress({ phase: "Reading the account" });
  const identity = await client.rpc("sts", null, "GetCallerIdentity");
  client.note("identity", true);
  const accountId = String(identity?.AccountId ?? "");
  client.accountId = accountId;
  const rootKey = identity?.IdentityType === "Account" || /:root$/.test(String(identity?.Arn ?? ""));
  // The alias is only a display name: an account without one, or a key that can't read it, shows its ID.
  const accountName = await client
    .rpc("ram", null, "GetAccountAlias")
    .then((d) => (d?.AccountAlias ? String(d.AccountAlias) : null))
    .catch(() => null);

  onProgress({ phase: "Reading RAM" });
  const [root, passwordPolicy, securityPreference, users, details] = await Promise.all([
    // A report exists from an account's second day; before that it is "not found", and nothing is judged.
    client
      .readOptional("accountSecurity", () => client.rpc("ims", null, "GetAccountSecurityPracticeReport"))
      .then((d) => {
        const info = d?.AccountSecurityPracticeInfo?.AccountSecurityPracticeUserInfo;
        return d === undefined
          ? undefined
          : info
            ? { accessKeys: Number(info.RootWithAccessKey ?? 0), mfa: info.BindMfa === true || info.BindMfa === "true" }
            : null;
      }),
    client.readOptional("passwordPolicy", () => client.rpc("ram", null, "GetPasswordPolicy")).then((d) => (d ? toPasswordPolicy(d) : d)),
    client.read("securityPreference", () => client.rpc("ims", null, "GetSecurityPreference")).then((d) => (d ? toSecurityPreference(d) : undefined)),
    client.read("ramUsers", () => readUsers(client)),
    readIdentities(client),
  ]);

  onProgress({ phase: "Reading OSS" });
  const [ossBlock, buckets] = await Promise.all([
    client
      .readOptional("ossAccount", () => client.oss(null, { publicAccessBlock: "" }))
      .then((d) => (d ? text(find(d, "BlockPublicAccess")) === "true" : d === null ? null : undefined)),
    readBuckets(client, accountId),
  ]);

  onProgress({ phase: "Reading regions" });
  const regionDoc = await client.read("regions", () => client.rpc("ecs", HOME_REGION, "DescribeRegions", { AcceptLanguage: "en-US" }));
  // A sold-out region takes no new instances but still runs the ones it has, so it is read like the others.
  const regionList = listOf<Json>(regionDoc?.Regions?.Region);
  const names: string[] = regionDoc ? regionList.map((r) => String(r.RegionId)) : [HOME_REGION];
  const regionNames = Object.fromEntries(regionList.flatMap((r) => (r.LocalName ? [[String(r.RegionId), String(r.LocalName)]] : [])));
  const regions: AlibabaRegion[] = [];
  const skippedRegions: string[] = [];
  let refusal: unknown = null;
  let done = 0;
  await pool(names, REGION_CONCURRENCY, async (name) => {
    try {
      regions.push(await readRegion(client, name));
    } catch (e) {
      skippedRegions.push(name);
      refusal ??= e;
    }
    onProgress({ phase: "Reading regions", done: ++done, total: names.length });
  });
  regions.sort((a, b) => a.name.localeCompare(b.name));
  // Every region refused: that is a permission problem, not a quiet account.
  if (!regions.length && refusal) for (const k of ALIBABA_SOURCE_KEYS) if (ALIBABA_SOURCES[k].regional) client.note(k, false, refusal);

  onProgress({ phase: "Reading ActionTrail, Security Center, CDN and DNS" });
  const [trails, protectedInstances, cdnDomains, domains, clusters] = await Promise.all([
    client.readIn("actiontrail", [] as AlibabaTrail[], () =>
      readTrails(
        client,
        regions.map((r) => r.name),
      ),
    ),
    readProtected(client),
    client.readIn("cdn", [] as AlibabaCdnDomain[], () => readCdn(client)),
    client.readIn("dns", [] as AlibabaDomain[], () => readDns(client)),
    client.read("clusters", () =>
      readClusters(
        client,
        regions.map((r) => r.name),
      ),
    ),
  ]);
  for (const r of regions) r.clusters = clusters ? clusters.filter((c) => c.region === r.name) : null;

  return {
    accountId,
    accountName,
    now: Date.now(),
    unreadable: [...client.coverage.values()].filter((c) => !c.ok).map((c) => c.key),
    rootKey,
    root,
    passwordPolicy,
    securityPreference,
    users,
    admins: details?.admins ?? null,
    roles: details?.roles ?? null,
    policies: details?.policies ?? null,
    escalations: details?.escalations ?? null,
    ossBlock,
    buckets,
    regions,
    regionNames,
    skippedRegions: skippedRegions.sort(),
    trails,
    protectedInstances,
    cdnDomains,
    domains,
    released: [],
  };
}

// ---- pagination

/** Pages by PageNumber and PageSize until TotalCount is reached or a page comes back short. */
async function byPage<T>(fetch: (page: number) => Promise<Json>, itemsOf: (page: Json) => T[], size: number, total = "TotalCount"): Promise<T[]> {
  const out: T[] = [];
  for (let n = 1; n <= MAX_PAGES; n++) {
    const page = await fetch(n);
    const got = itemsOf(page);
    out.push(...got);
    const count = Number(page?.[total] ?? page?.PageInfo?.TotalCount ?? Number.NaN);
    if (got.length < size || (Number.isFinite(count) && out.length >= count)) break;
  }
  return out;
}

/** Pages by a continuation token (NextToken, Marker, nextToken) until there is none. */
async function byToken<T>(
  fetch: (token: string | null) => Promise<Json>,
  itemsOf: (page: Json) => T[],
  next: (page: Json) => string | null | undefined,
): Promise<T[]> {
  const out: T[] = [];
  let token: string | null = null;
  for (let n = 0; n < MAX_PAGES; n++) {
    const page = await fetch(token);
    out.push(...itemsOf(page));
    token = next(page) || null;
    if (!token) break;
  }
  return out;
}

/** RAM's lists page with Marker and IsTruncated. */
const byMarker = <T>(fetch: (params: Record<string, string>) => Promise<Json>, itemsOf: (page: Json) => T[]) =>
  byToken(
    (marker) => fetch({ MaxItems: "1000", ...(marker ? { Marker: marker } : {}) }),
    itemsOf,
    (p) => (p?.IsTruncated ? p.Marker : null),
  );

/** "2026-01-01T00:00:00Z" or an epoch in milliseconds, as IMS gives LastLoginDate. */
function time(v: unknown): number | null {
  if (v == null || v === "") return null;
  const s = String(v);
  const t = /^\d{12,}$/.test(s) ? Number(s) : Date.parse(s);
  return Number.isFinite(t) ? t : null;
}

const str = (v: unknown): string | null => (v == null || v === "" ? null : String(v));
const num = (v: unknown): number | null => (v == null || v === "" || !Number.isFinite(Number(v)) ? null : Number(v));

// ---- RAM

/** RAM's security settings. MFAOperationForLogin replaced EnforceMFAForLogin, which older answers still carry alone. */
function toSecurityPreference(d: Json): AlibabaSecurityPreference {
  const p = d?.SecurityPreference ?? {};
  const login = p.LoginProfilePreference ?? {};
  const op = String(login.MFAOperationForLogin ?? "").toLowerCase();
  return {
    mfaAtLogin: op === "mandatory" || op === "adaptive" || op === "independent" ? op : login.EnforceMFAForLogin === true ? "mandatory" : "independent",
    usersManageKeys: p.AccessKeyPreference?.AllowUserToManageAccessKeys === true,
  };
}

function toPasswordPolicy(d: Json): AlibabaPasswordPolicy {
  const p = d?.PasswordPolicy ?? {};
  return {
    minLength: Number(p.MinimumPasswordLength ?? 8),
    requireLowercase: !!p.RequireLowercaseCharacters,
    requireUppercase: !!p.RequireUppercaseCharacters,
    requireNumbers: !!p.RequireNumbers,
    requireSymbols: !!p.RequireSymbols,
    maxAge: Number(p.MaxPasswordAge ?? 0),
    reusePrevention: Number(p.PasswordReusePrevention ?? 0),
    // RAM spells it MaxLoginAttemps.
    maxLoginAttempts: Number(p.MaxLoginAttemps ?? p.MaxLoginAttempts ?? 0),
  };
}

/** RAM users with their console access, MFA and AccessKeys, through IMS (which also gives each user's last sign-in). */
async function readUsers(client: AlibabaClient): Promise<AlibabaUser[]> {
  const list = (
    await byMarker(
      (q) => client.rpc("ims", null, "ListUsers", q),
      (p) => listOf<Json>(p?.Users?.User),
    )
  ).slice(0, MAX_USERS);
  const users: AlibabaUser[] = [];
  await pool(list, ITEM_CONCURRENCY, async (u) => {
    const upn = String(u.UserPrincipalName ?? "");
    const q = { UserPrincipalName: upn };
    const [profile, mfa, keys] = await Promise.all([
      client.optional(() => client.rpc("ims", null, "GetLoginProfile", q)),
      client.optional(() => client.rpc("ims", null, "GetUserMFAInfo", q)),
      client.rpc("ims", null, "ListAccessKeys", q),
    ]);
    const accessKeys: AlibabaAccessKey[] = await Promise.all(
      listOf<Json>(keys?.AccessKeys?.AccessKey).map(async (k) => {
        const id = String(k.AccessKeyId ?? "");
        const used = await client.rpc("ims", null, "GetAccessKeyLastUsed", { UserPrincipalName: upn, UserAccessKeyId: id }).catch(() => null);
        return { hint: id.slice(-4), active: k.Status === "Active", createdAt: time(k.CreateDate), lastUsedAt: time(used?.AccessKeyLastUsed?.LastUsedDate) };
      }),
    );
    const login = profile?.LoginProfile;
    users.push({
      name: upn.split("@")[0] || String(u.UserName ?? u.DisplayName ?? ""),
      createdAt: time(u.CreateDate),
      console: !!login && (login.Status == null || login.Status === "Active"),
      lastLoginAt: time(u.LastLoginDate) ?? time(login?.LastLoginTime),
      mfa: mfa == null ? false : mfa.IsMFAEnable === false ? false : !!(mfa.MFADevice?.SerialNumber || mfa.IsMFAEnable),
      keys: accessKeys,
    });
  });
  return users.sort((a, b) => a.name.localeCompare(b.name));
}

interface Identities {
  admins: AlibabaAdmin[] | null;
  roles: AlibabaRole[] | null;
  policies: AlibabaPolicy[] | null;
  escalations: AlibabaEscalation[] | null;
}

/** Who is an administrator, which custom policies grant what, and who roles trust. */
async function readIdentities(client: AlibabaClient): Promise<Identities> {
  const policyRead = await client.read("ramPolicies", async () => {
    const custom = await byMarker(
      (q) => client.rpc("ram", null, "ListPolicies", { PolicyType: "Custom", ...q }),
      (p) => listOf<Json>(p?.Policies?.Policy),
    );
    const docs = new Map<string, Statement[]>();
    await pool(custom, ITEM_CONCURRENCY, async (p) => {
      const d = await client.rpc("ram", null, "GetPolicy", { PolicyType: "Custom", PolicyName: String(p.PolicyName) });
      docs.set(String(p.PolicyName), statements(d?.DefaultPolicyVersion?.PolicyDocument));
    });
    const policies: AlibabaPolicy[] = custom.map((p) => ({
      name: String(p.PolicyName),
      fullAdmin: grantsEverything(docs.get(String(p.PolicyName)) ?? []),
      attachments: Number(p.AttachmentCount ?? 0),
    }));
    // Who each policy that matters is attached to: system administrator policies, RAM's full access, and custom policies that grant everything or a way up.
    const entitiesOf = (type: "System" | "Custom", name: string) =>
      client.rpc("ram", null, "ListEntitiesForPolicy", { PolicyType: type, PolicyName: name }).then((e) => ({
        users: listOf<Json>(e?.Users?.User).map((u) => String(u.UserName)),
        groups: listOf<Json>(e?.Groups?.Group).map((g) => String(g.GroupName)),
        roles: listOf<Json>(e?.Roles?.Role).map((r) => String(r.RoleName)),
      }));
    const adminVia = new Map<string, string>(); // "user:alex" → "the AdministratorAccess policy"
    const escalations = new Map<string, AlibabaEscalation>();
    const groupUsers = new Map<string, string[]>();
    const usersOf = async (group: string) => {
      if (!groupUsers.has(group))
        groupUsers.set(
          group,
          (
            await byMarker(
              (q) => client.rpc("ram", null, "ListUsersForGroup", { GroupName: group, ...q }),
              (p) => listOf<Json>(p?.Users?.User),
            )
          ).map((u) => String(u.UserName)),
        );
      return groupUsers.get(group)!;
    };
    const grantAdmin = async (via: string, e: Awaited<ReturnType<typeof entitiesOf>>) => {
      for (const u of e.users) if (!adminVia.has(`user:${u}`)) adminVia.set(`user:${u}`, via);
      for (const r of e.roles) if (!adminVia.has(`role:${r}`)) adminVia.set(`role:${r}`, via);
      for (const g of e.groups) for (const u of await usersOf(g)) if (!adminVia.has(`user:${u}`)) adminVia.set(`user:${u}`, `the group ${g}`);
    };
    const escalate = (via: string, paths: string[], e: Awaited<ReturnType<typeof entitiesOf>>) => {
      const add = (kind: AlibabaEscalation["kind"], name: string) => {
        const key = `${kind}:${name}`;
        const prev = escalations.get(key);
        if (prev) prev.paths = [...new Set([...prev.paths, ...paths])];
        else escalations.set(key, { kind, name, via, paths: [...paths] });
      };
      for (const u of e.users) add("user", u);
      for (const g of e.groups) add("group", g);
      for (const r of e.roles) add("role", r);
    };
    for (const name of ADMIN_POLICIES) await grantAdmin(`the ${name} policy`, await entitiesOf("System", name));
    for (const p of policies) {
      if (!p.attachments) continue;
      const st = docs.get(p.name) ?? [];
      const paths = escalationPaths(st);
      if (!p.fullAdmin && !paths.length) continue;
      const e = await entitiesOf("Custom", p.name);
      if (p.fullAdmin) await grantAdmin(`the custom policy ${p.name}`, e);
      else escalate(`the policy ${p.name}`, paths, e);
    }
    escalate(`the ${RAM_ADMIN_POLICY} policy`, ["ram:* (attach any policy to itself)"], await entitiesOf("System", RAM_ADMIN_POLICY));
    const admins: AlibabaAdmin[] = [...adminVia].map(([key, via]) => ({
      kind: key.startsWith("user:") ? "user" : "role",
      name: key.slice(key.indexOf(":") + 1),
      via,
    }));
    // Administrators already have everything; a group whose every member is an administrator is left out too.
    const isAdmin = (kind: string, name: string) => adminVia.has(`${kind}:${name}`);
    const ups = [...escalations.values()].filter((e) => !isAdmin(e.kind, e.name));
    return { admins, policies, escalations: ups };
  });

  const roles = await client.read("ramRoles", async () => {
    const providers = await client
      .rpc("ims", null, "ListOIDCProviders", { MaxItems: "100" })
      .then((d) => listOf<Json>(d?.OIDCProviders?.OIDCProvider))
      .catch(() => [] as Json[]);
    const github = new Set(
      providers.filter((p) => /^https:\/\/token\.actions\.githubusercontent\.com\/?$/.test(String(p.IssuerUrl))).map((p) => String(p.Arn)),
    );
    const list = await byMarker(
      (q) => client.rpc("ram", null, "ListRoles", q),
      (p) => listOf<Json>(p?.Roles?.Role),
    );
    const out: AlibabaRole[] = [];
    await pool(list, ITEM_CONCURRENCY, async (r) => {
      const name = String(r.RoleName);
      const d = await client.rpc("ram", null, "GetRole", { RoleName: name });
      const role = d?.Role ?? {};
      out.push({
        name,
        trust: trustOf(statements(role.AssumeRolePolicyDocument), github),
        admin: false,
        serviceLinked: role.IsServiceLinkedRole === true || /^AliyunServiceRoleFor/.test(name),
      });
    });
    return out.sort((a, b) => a.name.localeCompare(b.name));
  });

  const roleAdmins = policyRead ? new Set(policyRead.admins.filter((a) => a.kind === "role").map((a) => a.name)) : null;
  if (roles && roleAdmins) for (const r of roles) r.admin = roleAdmins.has(r.name);
  return {
    admins: policyRead?.admins ?? null,
    roles,
    policies: policyRead?.policies ?? null,
    escalations: policyRead?.escalations ?? null,
  };
}

// ---- OSS

async function readBuckets(client: AlibabaClient, accountId: string): Promise<AlibabaBucket[] | null> {
  const list = await client.read("ossBuckets", () =>
    byToken(
      (marker) => client.oss(null, { "max-keys": "1000", ...(marker ? { marker } : {}) }),
      (d: XmlNode) => items(find(d, "Buckets")),
      (d: XmlNode) => (text(find(d, "IsTruncated")) === "true" ? text(find(d, "NextMarker")) : null),
    ),
  );
  if (!list) return null;
  const buckets: AlibabaBucket[] = list.slice(0, MAX_BUCKETS).map((b) => ({
    name: text(b, "Name") ?? "",
    region: text(b, "Region") ?? (text(b, "Location") ?? "").replace(/^oss-/, ""),
    acl: undefined,
    blockPublicAccess: undefined,
    policy: undefined,
  }));
  await pool(buckets, ITEM_CONCURRENCY, async (b) => {
    const at = { name: b.name, region: b.region };
    const access = await client.read("ossBucketAccess", async () => {
      const [acl, block] = await Promise.all([client.oss(at, { acl: "" }), client.optional(() => client.oss(at, { publicAccessBlock: "" }))]);
      return { acl: text(find(acl, "Grant")) ?? "private", block: block ? text(find(block, "BlockPublicAccess")) === "true" : false };
    });
    if (access) {
      b.acl = access.acl;
      b.blockPublicAccess = access.block;
    }
    const doc = await client.readOptional("bucketPolicies", () => client.oss(at, { policy: "" }, true));
    b.policy = doc === undefined ? undefined : doc === null ? null : bucketPolicy(statements(doc), accountId);
  });
  return buckets.sort((a, b) => a.name.localeCompare(b.name));
}

// ---- regions

const OPEN_CIDRS = new Set(["0.0.0.0/0", "::/0"]);

/** "22/22" → [22, 22]; "-1/-1" (every port) → [null, null]. */
function portRange(v: unknown): [number | null, number | null] {
  const [a, b] = String(v ?? "-1/-1")
    .split("/")
    .map(Number);
  return a < 0 || !Number.isFinite(a) ? [null, null] : [a, Number.isFinite(b) ? b : a];
}

/**
 * A security group's inbound rules reduced to the ones that accept the internet, less any a drop rule of higher or
 * equal priority covers, and who else may reach ports 80 and 443. Only kinds are kept, never the ranges.
 */
export function toSecurityGroup(g: Json, permissions: Json[]): AlibabaSecurityGroup {
  const ingress = permissions.filter((p) => (p.Direction ?? "ingress") === "ingress");
  const rule = (p: Json) => {
    const protocol = String(p.IpProtocol ?? "ALL").toLowerCase();
    const [from, to] = portRange(p.PortRange);
    return {
      protocol: protocol === "all" ? "all" : protocol,
      from,
      to,
      priority: Number(p.Priority ?? 1),
      cidr: String(p.SourceCidrIp || p.Ipv6SourceCidrIp || ""),
    };
  };
  const drops = ingress
    .filter((p) => String(p.Policy ?? "Accept").toLowerCase() === "drop" && OPEN_CIDRS.has(String(p.SourceCidrIp || p.Ipv6SourceCidrIp)))
    .map(rule);
  const covers = (d: ReturnType<typeof rule>, r: ReturnType<typeof rule>) =>
    d.priority <= r.priority &&
    (d.protocol === "all" ||
      (d.protocol === r.protocol && (d.from == null || (r.from != null && d.from <= r.from && r.to != null && d.to != null && r.to <= d.to))));
  const accepts = ingress.filter((p) => String(p.Policy ?? "Accept").toLowerCase() === "accept");
  const open = accepts
    .filter((p) => OPEN_CIDRS.has(String(p.SourceCidrIp || p.Ipv6SourceCidrIp)))
    .map(rule)
    .filter((r) => !drops.some((d) => covers(d, r)))
    .map(({ protocol, from, to, cidr }) => ({ protocol, from, to, cidr }))
    // Rules that differ only in what isn't kept (destination, NIC type, description) read the same: one is enough.
    .filter((r, i, all) => all.findIndex((x) => x.protocol === r.protocol && x.from === r.from && x.to === r.to && x.cidr === r.cidr) === i);
  const webFrom = { cloudflare: false, other: false, prefixLists: [] as string[] };
  for (const p of accepts) {
    const r = rule(p);
    const web = r.protocol === "all" || (r.protocol === "tcp" && (r.from == null || [80, 443].some((port) => r.from! <= port && port <= (r.to ?? r.from!))));
    if (!web) continue;
    if (p.SourcePrefixListId) webFrom.prefixLists.push(String(p.SourcePrefixListId));
    const cidr = String(p.SourceCidrIp || p.Ipv6SourceCidrIp || "");
    if (!cidr || OPEN_CIDRS.has(cidr) || isInternal(cidr)) continue;
    if (inCloudflare(cidr)) webFrom.cloudflare = true;
    else webFrom.other = true;
  }
  return { id: String(g.SecurityGroupId), name: String(g.SecurityGroupName || g.SecurityGroupId), vpcId: str(g.VpcId), open, webFrom };
}

/** A start-up script, base64 as ECS returns it, scanned for credentials and dropped. Only the kind found is returned. */
export function secretInUserData(encoded: string | null | undefined): string | null {
  if (!encoded) return null;
  let script: string;
  try {
    script = Buffer.from(encoded, "base64").toString("utf8");
  } catch {
    return null;
  }
  return secretKindIn(script);
}

async function readRegion(client: AlibabaClient, region: string): Promise<AlibabaRegion> {
  const ecs = (action: string, params: Record<string, string> = {}) => client.rpc("ecs", region, action, params);
  // The first read decides whether the region is open to the AccessKey at all.
  let groupList: Json[];
  try {
    groupList = await byPage(
      (n) => ecs("DescribeSecurityGroups", { PageSize: "50", PageNumber: String(n) }),
      (p) => listOf<Json>(p?.SecurityGroups?.SecurityGroup),
      50,
    );
    client.note("securityGroups", true);
  } catch (e) {
    if (e instanceof AlibabaError && e.denied) throw e;
    client.note("securityGroups", false, e);
    groupList = [];
  }

  const [groups, instances, network, disks, images, templates, vpcs, databases, loadBalancers, functions, kms] = await Promise.all([
    client.read("securityGroups", async () => {
      const out: AlibabaSecurityGroup[] = [];
      await pool(groupList.slice(0, MAX_ITEMS), ITEM_CONCURRENCY, async (g) => {
        const d = await ecs("DescribeSecurityGroupAttribute", { SecurityGroupId: String(g.SecurityGroupId), Direction: "ingress" });
        out.push(toSecurityGroup(g, listOf<Json>(d?.Permissions?.Permission)));
      });
      return out;
    }),
    client.read("instances", () => readInstances(client, region)),
    client.read("networkInterfaces", async () => {
      const [enis, eips] = await Promise.all([
        byToken(
          (t) => ecs("DescribeNetworkInterfaces", { MaxResults: "500", ...(t ? { NextToken: t } : {}) }),
          (p) => listOf<Json>(p?.NetworkInterfaceSets?.NetworkInterfaceSet),
          (p) => p?.NextToken,
        ),
        byPage(
          (n) => client.rpc("vpc", region, "DescribeEipAddresses", { PageSize: "100", PageNumber: String(n) }),
          (p) => listOf<Json>(p?.EipAddresses?.EipAddress),
          100,
        ),
      ]);
      return { enis, eips };
    }),
    client.read("disks", async () => {
      const list = await byPage(
        (n) => ecs("DescribeDisks", { PageSize: "100", PageNumber: String(n) }),
        (p) => listOf<Json>(p?.Disks?.Disk),
        100,
      );
      const byDefault = await ecs("DescribeDiskEncryptionByDefaultStatus")
        .then((d) => (typeof d?.Encrypted === "boolean" ? d.Encrypted : null))
        .catch(() => null);
      return { list, byDefault };
    }),
    client.read("images", async () => {
      const own = await byPage(
        (n) => ecs("DescribeImages", { ImageOwnerAlias: "self", PageSize: "100", PageNumber: String(n) }),
        (p) => listOf<Json>(p?.Images?.Image),
        100,
      );
      return Promise.all(
        own.slice(0, MAX_ITEMS).map(async (i) => {
          const d = await ecs("DescribeImageSharePermission", { ImageId: String(i.ImageId), PageSize: "100" });
          const groups = listOf<Json>(d?.ShareGroups?.ShareGroup).map((g) => String(g.Group));
          return {
            id: String(i.ImageId),
            name: str(i.ImageName),
            // A share group of "all" is every Alibaba Cloud account: a community image.
            sharedWith: [
              ...(groups.includes("all") || i.IsPublic === true ? ["all"] : []),
              ...listOf<Json>(d?.Accounts?.Account).map((a) => String(a.AliyunId)),
            ],
          };
        }),
      );
    }),
    client.read("launchTemplates", async () => {
      const list = await byPage(
        (n) => ecs("DescribeLaunchTemplates", { PageSize: "50", PageNumber: String(n) }),
        (p) => listOf<Json>(p?.LaunchTemplateSets?.LaunchTemplateSet),
        50,
      );
      return Promise.all(
        list.slice(0, MAX_ITEMS).map(async (t) => {
          const d = await ecs("DescribeLaunchTemplateVersions", { LaunchTemplateId: String(t.LaunchTemplateId), DefaultVersion: "true", DetailFlag: "true" });
          const data = listOf<Json>(d?.LaunchTemplateVersionSets?.LaunchTemplateVersionSet)[0]?.LaunchTemplateData ?? {};
          return {
            id: String(t.LaunchTemplateId),
            name: String(t.LaunchTemplateName ?? t.LaunchTemplateId),
            metadataTokens: data.HttpTokens ? data.HttpTokens === "required" : data.HttpEndpoint === "disabled",
            userDataSecret: secretInUserData(data.UserData),
          };
        }),
      );
    }),
    client.read("vpcs", async () => {
      const [list, logs] = await Promise.all([
        byPage(
          (n) => client.rpc("vpc", region, "DescribeVpcs", { PageSize: "50", PageNumber: String(n) }),
          (p) => listOf<Json>(p?.Vpcs?.Vpc),
          50,
        ),
        byPage(
          (n) => client.rpc("vpc", region, "DescribeFlowLogs", { PageSize: "50", PageNumber: String(n) }),
          (p) => listOf<Json>(p?.FlowLogs?.FlowLog),
          50,
        ),
      ]);
      const active = logs.filter((f) => f.Status === "Active");
      return list.map((v) => {
        const id = String(v.VpcId);
        return { id, flowLogs: active.some((f) => (f.ResourceType === "VPC" && f.ResourceId === id) || f.VpcId === id) };
      });
    }),
    Promise.all([
      client.readIn("databases", [] as AlibabaDatabase[], () => readDatabases(client, region)),
      client.readIn("redis", [] as AlibabaDatabase[], () => readRedis(client, region)),
      client.readIn("mongodb", [] as AlibabaDatabase[], () => readMongo(client, region)),
    ]).then((parts) => (parts.every((p) => p === null) ? null : parts.flatMap((p) => p ?? []))),
    client.read("loadBalancers", () => readLoadBalancers(client, region)),
    client.readIn("functions", [] as AlibabaFunction[], () => readFunctions(client, region)),
    client.readIn("kms", { keys: [] as AlibabaKey[], secrets: [] as AlibabaSecret[] }, () => readKms(client, region)),
  ]);

  // Instances' start-up scripts, scanned for credentials and dropped.
  const running = (instances ?? []).filter((i) => i.running);
  if (running.length && running.length <= MAX_ITEMS * 2)
    await client.read("userData", () =>
      pool(running, ITEM_CONCURRENCY, async (i) => {
        const d = await ecs("DescribeUserData", { InstanceId: i.id });
        i.userDataSecret = secretInUserData(d?.UserData);
      }),
    );

  // Server groups behind the load balancers, with their servers.
  const serverGroups = loadBalancers?.length
    ? await client
        .read("lbRouting", () => readServerGroups(client, region, loadBalancers))
        .then((g) => {
          if (!g) for (const l of loadBalancers.flatMap((lb) => lb.listeners ?? [])) if (l.rules === undefined) l.rules = null;
          return g;
        })
    : loadBalancers
      ? []
      : null;

  return {
    name: region,
    securityGroups: groups,
    instances,
    interfaces: network && instances ? toInterfaces(network.enis, network.eips, instances, loadBalancers ?? []) : null,
    addresses: network ? network.eips.flatMap((e) => (e.IpAddress ? [String(e.IpAddress)] : [])) : null,
    disks: disks ? disks.list.map((k) => ({ id: String(k.DiskId), encrypted: k.Encrypted === true, inUse: k.Status === "In_use" })) : null,
    diskEncryptionByDefault: disks?.byDefault ?? null,
    images,
    launchTemplates: templates,
    vpcs,
    databases,
    loadBalancers,
    serverGroups,
    functions,
    keys: kms?.keys ?? null,
    secrets: kms?.secrets ?? null,
    clusters: null,
  };
}

async function readInstances(client: AlibabaClient, region: string): Promise<AlibabaInstance[]> {
  const list = await byToken(
    (t) => client.rpc("ecs", region, "DescribeInstances", { MaxResults: "100", ...(t ? { NextToken: t } : {}) }),
    (p) => listOf<Json>(p?.Instances?.Instance),
    (p) => p?.NextToken,
  );
  const instances: AlibabaInstance[] = list.map((i) => {
    const publicIps = [...listOf<string>(i.PublicIpAddress?.IpAddress), ...(i.EipAddress?.IpAddress ? [String(i.EipAddress.IpAddress)] : [])];
    const tokens = i.MetadataOptions?.HttpTokens;
    return {
      id: String(i.InstanceId),
      name: str(i.InstanceName),
      running: i.Status === "Running",
      publicIp: publicIps[0] ?? null,
      privateIp: listOf<string>(i.VpcAttributes?.PrivateIpAddress?.IpAddress)[0] ?? listOf<string>(i.InnerIpAddress?.IpAddress)[0] ?? null,
      vpcId: str(i.VpcAttributes?.VpcId),
      network: String(i.InstanceNetworkType ?? "vpc").toLowerCase(),
      securityGroups: listOf<string>(i.SecurityGroupIds?.SecurityGroupId).map(String),
      os: i.OSType ? String(i.OSType).toLowerCase() : null,
      keyPair: !!i.KeyPairName,
      // A metadata service that is turned off gives nothing away.
      metadataTokens: i.MetadataOptions?.HttpEndpoint === "disabled" ? true : tokens ? tokens === "required" : null,
      role: null,
      userDataSecret: undefined,
    };
  });
  // The RAM role each instance runs as, fifty instances at a time: the most DescribeInstanceRamRole takes.
  for (let at = 0; at < instances.length; at += 50) {
    const batch = instances.slice(at, at + 50);
    const d = await client.rpc("ecs", region, "DescribeInstanceRamRole", { InstanceIds: JSON.stringify(batch.map((i) => i.id)), PageSize: "50" });
    for (const s of listOf<Json>(d?.InstanceRamRoleSets?.InstanceRamRoleSet)) {
      const inst = batch.find((i) => i.id === s.InstanceId);
      if (inst && s.RamRoleName) inst.role = String(s.RamRoleName);
    }
  }
  return instances;
}

/**
 * What a security group is attached to: every network interface (with its public address, from an EIP or the
 * instance's own), and instances in the classic network, which have no interface of their own in the list.
 */
function toInterfaces(enis: Json[], eips: Json[], instances: AlibabaInstance[], loadBalancers: AlibabaLoadBalancer[]): AlibabaInterface[] {
  const eipOf = new Map(eips.flatMap((e) => (e.InstanceId ? [[String(e.InstanceId), String(e.IpAddress)] as const] : [])));
  const out: AlibabaInterface[] = enis.map((n) => {
    const id = String(n.NetworkInterfaceId);
    const owner = str(n.InstanceId ?? n.Attachment?.InstanceId);
    const inst = owner ? instances.find((i) => i.id === owner) : undefined;
    const primary = n.Type === "Primary";
    return {
      id,
      publicIp: str(n.AssociatedPublicIp?.PublicIpAddress) ?? eipOf.get(id) ?? (primary && inst ? inst.publicIp : null),
      privateIp: str(n.PrivateIpAddress),
      securityGroups: listOf<string>(n.SecurityGroupIds?.SecurityGroupId).map(String),
      kind: owner?.startsWith("i-") ? "instance" : n.ServiceManaged ? "service" : "network interface",
      owner,
    };
  });
  for (const i of instances)
    if (!out.some((n) => n.owner === i.id))
      out.push({ id: i.id, publicIp: i.publicIp, privateIp: i.privateIp, securityGroups: i.securityGroups, kind: "instance", owner: i.id });
  // ALBs and NLBs with security groups answer on addresses Alibaba Cloud manages: they count as what their groups expose.
  for (const lb of loadBalancers)
    if (lb.securityGroups.length && lb.address)
      out.push({
        id: lb.id,
        publicIp: lb.internetFacing ? lb.address : null,
        privateIp: null,
        securityGroups: lb.securityGroups,
        kind: "load balancer",
        owner: lb.name,
      });
  return out;
}

async function readDatabases(client: AlibabaClient, region: string): Promise<AlibabaDatabase[]> {
  const list = await byPage(
    (n) => client.rpc("rds", region, "DescribeDBInstances", { PageSize: "100", PageNumber: String(n) }),
    (p) => listOf<Json>(p?.Items?.DBInstance),
    100,
    "TotalRecordCount",
  );
  const out: AlibabaDatabase[] = [];
  await pool(list.slice(0, MAX_ITEMS), ITEM_CONCURRENCY, async (db) => {
    const id = String(db.DBInstanceId);
    const q = { DBInstanceId: id };
    const [ips, net, ssl, tde] = await Promise.all([
      client.rpc("rds", region, "DescribeDBInstanceIPArrayList", q),
      client.rpc("rds", region, "DescribeDBInstanceNetInfo", q),
      client.rpc("rds", region, "DescribeDBInstanceSSL", q).catch(() => null),
      client.rpc("rds", region, "DescribeDBInstanceTDE", q).catch(() => null),
    ]);
    const entries = listOf<Json>(ips?.Items?.DBInstanceIPArray)
      .filter((a) => !/^(hidden|ali_dms_group)$/i.test(String(a.DBInstanceIPArrayName ?? "")))
      .flatMap((a) => String(a.SecurityIPList ?? "").split(","))
      .map((x) => x.trim());
    const sslOn = ssl ? /^(yes|on|true|1|enable|enabled)$/i.test(String(ssl.SSLEnabled ?? "")) : null;
    out.push({
      id,
      name: str(db.DBInstanceDescription),
      service: "rds",
      engine: String(db.Engine ?? "database"),
      publicEndpoint: listOf<Json>(net?.DBInstanceNetInfos?.DBInstanceNetInfo).some((i) => i.IPType === "Public") || db.DBInstanceNetType === "Internet",
      openWhitelist: everyone(entries),
      ssl: sslOn,
      tde: tde?.TDEStatus ? tde.TDEStatus === "Enabled" : null,
    });
  });
  return out.sort((a, b) => a.id.localeCompare(b.id));
}

/** Whitelist entries that admit every address. */
const everyone = (entries: string[]) => [...new Set(entries.map((x) => x.trim()).filter((x) => x === "0.0.0.0/0" || x === "0.0.0.0" || x === "%"))];

/** Whitelist groups, less the hidden ones Alibaba Cloud's own services (DAS, DMS, DTS) add. */
const whitelist = (groups: Json[]) =>
  groups.filter((g) => String(g.SecurityIpGroupAttribute ?? "").toLowerCase() !== "hidden").flatMap((g) => String(g.SecurityIpList ?? "").split(","));

/**
 * Tair (Redis) instances: whether they have a public endpoint, who their whitelist admits, whether VPC clients connect
 * without a password ("password-free access": VpcAuthMode Close), and TLS. Tair and Redis open source are listed apart.
 */
async function readRedis(client: AlibabaClient, region: string): Promise<AlibabaDatabase[]> {
  const list = (
    await Promise.all(
      ["Redis", "Tair"].map((type) =>
        byPage(
          (n) => client.rpc("kvstore", region, "DescribeInstances", { InstanceType: type, PageSize: "50", PageNumber: String(n) }),
          (p) => listOf<Json>(p?.Instances?.KVStoreInstance),
          50,
        ),
      ),
    )
  ).flat();
  const out: AlibabaDatabase[] = [];
  await pool(list.slice(0, MAX_ITEMS), ITEM_CONCURRENCY, async (db) => {
    const id = String(db.InstanceId);
    const q = { InstanceId: id };
    const [attr, ips, net, ssl] = await Promise.all([
      client.rpc("kvstore", region, "DescribeInstanceAttribute", q),
      client.rpc("kvstore", region, "DescribeSecurityIps", q),
      client.rpc("kvstore", region, "DescribeDBInstanceNetInfo", q),
      client.rpc("kvstore", region, "DescribeInstanceSSL", q).catch(() => null),
    ]);
    const a = listOf<Json>(attr?.Instances?.DBInstanceAttribute)[0] ?? {};
    const mode = String(a.VpcAuthMode ?? "");
    out.push({
      id,
      name: str(db.InstanceName),
      service: "redis",
      engine: `${db.InstanceType === "Tair" ? "Tair" : "Redis"}${db.EngineVersion ? ` ${db.EngineVersion}` : ""}`,
      publicEndpoint: listOf<Json>(net?.NetInfoItems?.InstanceNetInfo).some((i) => i.IPType === "Public" || String(i.DBInstanceNetType) === "0"),
      openWhitelist: everyone(whitelist(listOf<Json>(ips?.SecurityIpGroups?.SecurityIpGroup))),
      ssl: ssl?.SSLEnabled ? ssl.SSLEnabled === "Enable" : null,
      tde: null,
      // On Tair, "Close" turns password authentication off for clients in the VPC.
      passwordFree: mode === "Close" ? true : mode === "Open" ? false : null,
    });
  });
  return out.sort((a, b) => a.id.localeCompare(b.id));
}

/**
 * ApsaraDB for MongoDB replica sets and sharded clusters, read like Tair. Careful: MongoDB's VpcAuthMode means the
 * opposite of Tair's, "Open" being password-free access turned on.
 */
async function readMongo(client: AlibabaClient, region: string): Promise<AlibabaDatabase[]> {
  const list = (
    await Promise.all(
      ["replicate", "sharding"].map((type) =>
        byPage(
          (n) => client.rpc("dds", region, "DescribeDBInstances", { DBInstanceType: type, PageSize: "100", PageNumber: String(n) }),
          (p) => listOf<Json>(p?.DBInstances?.DBInstance),
          100,
        ),
      ),
    )
  ).flat();
  const out: AlibabaDatabase[] = [];
  await pool(list.slice(0, MAX_ITEMS), ITEM_CONCURRENCY, async (db) => {
    const id = String(db.DBInstanceId);
    const q = { DBInstanceId: id };
    const [ips, net, ssl] = await Promise.all([
      client.rpc("dds", region, "DescribeSecurityIps", q),
      client.rpc("dds", region, "DescribeShardingNetworkAddress", q),
      client.rpc("dds", region, "DescribeDBInstanceSSL", q).catch(() => null),
    ]);
    const addresses = [...listOf<Json>(net?.NetworkAddresses?.NetworkAddress), ...listOf<Json>(net?.CompatibleConnections?.CompatibleConnection)];
    const mode = String(db.VpcAuthMode ?? "");
    out.push({
      id,
      name: str(db.DBInstanceDescription),
      service: "mongodb",
      engine: `MongoDB${db.EngineVersion ? ` ${db.EngineVersion}` : ""}`,
      publicEndpoint: addresses.some((x) => String(x.NetworkType).toLowerCase() === "public"),
      openWhitelist: everyone([...whitelist(listOf<Json>(ips?.SecurityIpGroups?.SecurityIpGroup)), ...String(ips?.SecurityIps ?? "").split(",")]),
      ssl: ssl?.SSLStatus ? ssl.SSLStatus === "Open" : null,
      tde: null,
      passwordFree: mode === "Open" ? true : mode === "Close" ? false : null,
    });
  });
  return out.sort((a, b) => a.id.localeCompare(b.id));
}

/** TLS policies on HTTPS listeners. A custom policy (spolicy-…) isn't a system one, and isn't judged. */
const tlsOf = (v: unknown): string | null => (typeof v === "string" && v.startsWith("tls_cipher_policy") ? v : null);

/** ALB, NLB and CLB load balancers with their listeners and, for ALB and CLB, their forwarding rules. */
async function readLoadBalancers(client: AlibabaClient, region: string): Promise<AlibabaLoadBalancer[]> {
  const nonEmpty = <T>(fn: () => Promise<T[]>): Promise<T[]> =>
    fn().catch((e) => {
      if (e instanceof AlibabaError && e.noEndpoint) return [];
      throw e;
    });
  const [albs, nlbs, clbs] = await Promise.all([
    nonEmpty(async () => {
      const list = await byToken(
        (t) => client.rpc("alb", region, "ListLoadBalancers", { MaxResults: "100", ...(t ? { NextToken: t } : {}) }),
        (p) => listOf<Json>(p?.LoadBalancers),
        (p) => p?.NextToken,
      );
      if (!list.length) return [];
      const [listeners, rules] = await Promise.all([
        byToken(
          (t) => client.rpc("alb", region, "ListListeners", { MaxResults: "100", ...(t ? { NextToken: t } : {}) }),
          (p) => listOf<Json>(p?.Listeners),
          (p) => p?.NextToken,
        ),
        byToken(
          (t) => client.rpc("alb", region, "ListRules", { MaxResults: "100", ...(t ? { NextToken: t } : {}) }),
          (p) => listOf<Json>(p?.Rules),
          (p) => p?.NextToken,
        ),
      ]);
      return list.map((lb): AlibabaLoadBalancer => {
        const id = String(lb.LoadBalancerId);
        return {
          id,
          name: String(lb.LoadBalancerName || id),
          type: "alb",
          dnsName: str(lb.DNSName)?.toLowerCase() ?? null,
          address: null,
          internetFacing: String(lb.AddressType).toLowerCase() === "internet",
          vpcId: str(lb.VpcId),
          securityGroups: listOf<string>(lb.SecurityGroupIds).map(String),
          listeners: listeners
            .filter((l) => l.LoadBalancerId === id)
            .map((l) => {
              const own = rules.filter((r) => r.ListenerId === l.ListenerId).map(toAlbRule);
              const defaults = listOf<Json>(l.DefaultActions);
              const fallback: AlibabaRule = {
                priority: "default",
                hosts: [],
                paths: [],
                conditions: [],
                action: defaults.some((a) => a.Type === "ForwardGroup") ? "forward" : "other",
                detail: null,
                serverGroups: defaults.flatMap((a) => listOf<Json>(a.ForwardGroupConfig?.ServerGroupTuples).map((t) => String(t.ServerGroupId))),
              };
              const ordered = [...own.sort((a, b) => Number(a.priority) - Number(b.priority)), fallback];
              const protocol = String(l.ListenerProtocol ?? "").toUpperCase();
              return {
                id: String(l.ListenerId),
                port: num(l.ListenerPort),
                protocol,
                tlsPolicy: protocol === "HTTPS" ? tlsOf(l.SecurityPolicyId) : null,
                // An HTTP listener whose rules send everything to HTTPS before anything is forwarded.
                redirects:
                  protocol === "HTTP" &&
                  own.some((r) => r.action === "redirect" && /^https/i.test(r.detail ?? "") && !r.hosts.length && r.paths.every((p) => p === "/*")),
                rules: ordered,
              } satisfies AlibabaListener;
            }),
        };
      });
    }),
    nonEmpty(async () => {
      const list = await byToken(
        (t) => client.rpc("nlb", region, "ListLoadBalancers", { MaxResults: "100", ...(t ? { NextToken: t } : {}) }),
        (p) => listOf<Json>(p?.LoadBalancers),
        (p) => p?.NextToken,
      );
      if (!list.length) return [];
      const listeners = await byToken(
        (t) => client.rpc("nlb", region, "ListListeners", { MaxResults: "100", ...(t ? { NextToken: t } : {}) }),
        (p) => listOf<Json>(p?.Listeners),
        (p) => p?.NextToken,
      );
      return list.map((lb): AlibabaLoadBalancer => {
        const id = String(lb.LoadBalancerId);
        return {
          id,
          name: String(lb.LoadBalancerName || id),
          type: "nlb",
          dnsName: str(lb.DNSName)?.toLowerCase() ?? null,
          address: null,
          internetFacing: String(lb.AddressType).toLowerCase() === "internet",
          vpcId: str(lb.VpcId),
          securityGroups: listOf<string>(lb.SecurityGroupIds).map(String),
          listeners: listeners
            .filter((l) => l.LoadBalancerId === id)
            .map((l) => {
              const protocol = String(l.ListenerProtocol ?? "").toUpperCase();
              return {
                id: String(l.ListenerId),
                port: num(l.ListenerPort),
                protocol,
                tlsPolicy: protocol === "TCPSSL" ? tlsOf(l.SecurityPolicyId) : null,
                redirects: false,
                rules: [
                  {
                    priority: "default",
                    hosts: [],
                    paths: [],
                    conditions: [],
                    action: "forward",
                    detail: null,
                    serverGroups: l.ServerGroupId ? [String(l.ServerGroupId)] : [],
                  },
                ],
              };
            }),
        };
      });
    }),
    nonEmpty(async () => {
      const list = await byPage(
        (n) => client.rpc("slb", region, "DescribeLoadBalancers", { PageSize: "100", PageNumber: String(n) }),
        (p) => listOf<Json>(p?.LoadBalancers?.LoadBalancer),
        100,
      );
      const out: AlibabaLoadBalancer[] = [];
      // Every CLB listener in the region in one list, for its access control and backend port. Its own permission, so a
      // policy without it only leaves out the check that needs it.
      const access = list.length
        ? await client.read("lbAccess", () =>
            byToken(
              (t) => client.rpc("slb", region, "DescribeLoadBalancerListeners", { MaxResults: "100", ...(t ? { NextToken: t } : {}) }),
              (p) => listOf<Json>(p?.Listeners),
              (p) => p?.NextToken,
            ),
          )
        : [];
      await pool(list.slice(0, MAX_ITEMS), ITEM_CONCURRENCY, async (lb) => {
        const id = String(lb.LoadBalancerId);
        const attr = await client.rpc("slb", region, "DescribeLoadBalancerAttribute", { LoadBalancerId: id });
        const listeners: AlibabaListener[] = [];
        for (const l of listOf<Json>(attr?.ListenerPortsAndProtocol?.ListenerPortAndProtocol)) {
          const port = num(l.ListenerPort);
          const protocol = String(l.ListenerProtocol ?? "").toUpperCase();
          const web = protocol === "HTTP" || protocol === "HTTPS";
          const detail = web
            ? await client.rpc("slb", region, `DescribeLoadBalancer${protocol}ListenerAttribute`, { LoadBalancerId: id, ListenerPort: String(port) })
            : null;
          const rules: AlibabaRule[] = listOf<Json>(detail?.Rules?.Rule).map((r, i) => ({
            priority: String(i + 1),
            hosts: r.Domain ? [String(r.Domain)] : [],
            paths: r.Url ? [String(r.Url)] : [],
            conditions: [],
            action: "forward",
            detail: null,
            serverGroups: r.VServerGroupId ? [String(r.VServerGroupId)] : [],
          }));
          rules.push({
            priority: "default",
            hosts: [],
            paths: [],
            conditions: [],
            action: l.ListenerForward === "on" ? "redirect" : "forward",
            detail: l.ListenerForward === "on" ? `HTTPS:${l.ForwardPort ?? 443}` : null,
            serverGroups: detail?.VServerGroupId ? [String(detail.VServerGroupId)] : [],
          });
          const acl = access?.find((x) => x.LoadBalancerId === id && num(x.ListenerPort) === port && String(x.ListenerProtocol).toUpperCase() === protocol);
          listeners.push({
            port,
            protocol,
            backendPort: acl ? num(acl.BackendServerPort) : undefined,
            access: !access ? undefined : acl?.AclStatus !== "on" ? null : acl.AclType === "black" ? "deny" : "allow",
            tlsPolicy: protocol === "HTTPS" ? tlsOf(detail?.TLSCipherPolicy) : null,
            redirects: protocol === "HTTP" && l.ListenerForward === "on",
            rules: web ? rules : [{ priority: "default", hosts: [], paths: [], conditions: [], action: "forward", detail: null, serverGroups: [] }],
          });
        }
        out.push({
          id,
          name: String(lb.LoadBalancerName || id),
          type: "clb",
          dnsName: null,
          address: str(lb.Address),
          internetFacing: String(lb.AddressType).toLowerCase() === "internet",
          vpcId: str(lb.VpcId),
          securityGroups: [],
          listeners,
          backends: listOf<Json>(attr?.BackendServers?.BackendServer).map((b) => String(b.ServerId)),
        });
      });
      return out;
    }),
  ]);
  return [...albs, ...nlbs, ...clbs].sort((a, b) => a.name.localeCompare(b.name));
}

/** An ALB forwarding rule: its conditions (a header by its name, never its value) and what it does. */
function toAlbRule(r: Json): AlibabaRule {
  const conditions = listOf<Json>(r.RuleConditions);
  const actions = listOf<Json>(r.RuleActions).sort((a, b) => Number(a.Order ?? 0) - Number(b.Order ?? 0));
  const last = actions.find((a) => ["ForwardGroup", "Redirect", "FixedResponse"].includes(a.Type));
  const redirect = last?.RedirectConfig;
  return {
    priority: String(r.Priority ?? ""),
    hosts: conditions.filter((c) => c.Type === "Host").flatMap((c) => listOf<string>(c.HostConfig?.Values).map(String)),
    paths: conditions.filter((c) => c.Type === "Path").flatMap((c) => listOf<string>(c.PathConfig?.Values).map(String)),
    conditions: conditions
      .filter((c) => c.Type !== "Host" && c.Type !== "Path")
      .map((c) => (c.Type === "Header" ? `header ${c.HeaderConfig?.Key ?? ""}`.trim() : String(c.Type ?? "other").toLowerCase())),
    action: last?.Type === "ForwardGroup" ? "forward" : last?.Type === "Redirect" ? "redirect" : last?.Type === "FixedResponse" ? "fixed-response" : "other",
    detail: redirect
      ? // Parts a redirect leaves out keep the request's own (its protocol, host, port or path).
        `${redirect.Protocol ?? "same protocol"}://${redirect.Host ?? "same host"}${redirect.Port ? `:${redirect.Port}` : ""}${redirect.Path ?? ""}`
      : last?.FixedResponseConfig
        ? String(last.FixedResponseConfig.HttpCode ?? "")
        : null,
    serverGroups: last?.Type === "ForwardGroup" ? listOf<Json>(last.ForwardGroupConfig?.ServerGroupTuples).map((t) => String(t.ServerGroupId)) : [],
  };
}

/** The server groups the load balancers' rules forward to, with their servers. */
async function readServerGroups(client: AlibabaClient, region: string, lbs: AlibabaLoadBalancer[]): Promise<AlibabaServerGroup[]> {
  const ids = [...new Set(lbs.flatMap((lb) => (lb.listeners ?? []).flatMap((l) => (l.rules ?? []).flatMap((r) => r.serverGroups))))].slice(0, MAX_ITEMS);
  const albGroups = ids.filter((id) => id.startsWith("sgp-"));
  const clbGroups = ids.filter((id) => id.startsWith("rsp-"));
  const out: AlibabaServerGroup[] = [];
  if (albGroups.length) {
    const groups = await byToken(
      (t) => client.rpc("alb", region, "ListServerGroups", { MaxResults: "100", ...(t ? { NextToken: t } : {}) }),
      (p) => listOf<Json>(p?.ServerGroups),
      (p) => p?.NextToken,
    ).catch((e) => (e instanceof AlibabaError && e.noEndpoint ? [] : Promise.reject(e)));
    await pool(albGroups, ITEM_CONCURRENCY, async (id) => {
      const g = groups.find((x) => x.ServerGroupId === id);
      const servers = await byToken(
        (t) => client.rpc("alb", region, "ListServerGroupServers", { ServerGroupId: id, MaxResults: "100", ...(t ? { NextToken: t } : {}) }),
        (p) => listOf<Json>(p?.Servers),
        (p) => p?.NextToken,
      );
      out.push({
        id,
        name: String(g?.ServerGroupName ?? id),
        type: String(g?.ServerGroupType ?? "Instance"),
        servers: servers.map((s) => ({ id: String(s.ServerId), ip: str(s.ServerIp), port: num(s.Port), type: String(s.ServerType ?? "Ecs") })),
      });
    });
  }
  await pool(clbGroups, ITEM_CONCURRENCY, async (id) => {
    const d = await client.rpc("slb", region, "DescribeVServerGroupAttribute", { VServerGroupId: id });
    out.push({
      id,
      name: String(d?.VServerGroupName ?? id),
      type: "Instance",
      servers: listOf<Json>(d?.BackendServers?.BackendServer).map((s) => ({
        id: String(s.ServerId),
        ip: str(s.ServerIp),
        port: num(s.Port),
        type: String(s.Type ?? "ecs"),
      })),
    });
  });
  // NLB server groups aren't read: an NLB filters nothing a direct request would skip, so its routing isn't followed.
  return out;
}

async function readFunctions(client: AlibabaClient, region: string): Promise<AlibabaFunction[]> {
  const list = await byToken(
    (t) =>
      client.roa("fc", region, "ListFunctions", "/2023-03-30/functions", { limit: "100", ...(t ? { nextToken: t } : {}) }).catch((e) => {
        // Where Function Compute 3.0 isn't offered (ap-southeast-6, on a real account) its endpoint still resolves and
        // answers every request with 503 "temporary failure". On the first page that means "not offered here"; later
        // pages, or any other error, stay failures.
        if (!t && e instanceof AlibabaError && e.status === 503) throw Object.assign(new AlibabaError(0, "NoEndpoint", e.message), { host: e.host });
        throw e;
      }),
    (p) => listOf<Json>(p?.functions),
    (p) => p?.nextToken,
  );
  const out: AlibabaFunction[] = [];
  await pool(list.slice(0, MAX_ITEMS), ITEM_CONCURRENCY, async (f) => {
    const name = String(f.functionName);
    const triggers = await client
      .roa("fc", region, "ListTriggers", `/2023-03-30/functions/${name}/triggers`, { limit: "100" })
      .then((d) => listOf<Json>(d?.triggers))
      .catch(() => null);
    const anonymous = triggers
      ? triggers
          .filter((t) => String(t.triggerType).toLowerCase() === "http")
          .filter((t) => {
            try {
              const cfg = typeof t.triggerConfig === "string" ? JSON.parse(t.triggerConfig) : (t.triggerConfig ?? {});
              return String(cfg.authType ?? "").toLowerCase() === "anonymous";
            } catch {
              return false;
            }
          })
          .map((t) => String(t.triggerName))
      : null;
    out.push({
      name,
      runtime: str(f.runtime),
      // "acs:ram::<uid>:role/<name>" → the role's name, as RAM lists it.
      role: f.role ? String(f.role).split("/").pop()! : null,
      anonymousTriggers: anonymous,
      envSecret: f.environmentVariables && typeof f.environmentVariables === "object" ? secretInVariables(f.environmentVariables) : null,
      // Only the image's name: the registry password a function can carry beside it is never read.
      image: str(f.customContainerConfig?.image),
    });
  });
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

async function readKms(client: AlibabaClient, region: string): Promise<{ keys: AlibabaKey[]; secrets: AlibabaSecret[] }> {
  const [keyList, secretList] = await Promise.all([
    byPage(
      (n) => client.rpc("kms", region, "ListKeys", { PageSize: "100", PageNumber: String(n) }),
      (p) => listOf<Json>(p?.Keys?.Key),
      100,
    ),
    byPage(
      (n) => client.rpc("kms", region, "ListSecrets", { PageSize: "100", PageNumber: String(n) }),
      (p) => listOf<Json>(p?.SecretList?.Secret),
      100,
    ),
  ]);
  const keys: AlibabaKey[] = [];
  await pool(keyList.slice(0, MAX_ITEMS), ITEM_CONCURRENCY, async (k) => {
    const m = (await client.rpc("kms", region, "DescribeKey", { KeyId: String(k.KeyId) }))?.KeyMetadata ?? {};
    // Keys Alibaba Cloud services create for themselves (their creator isn't an account ID) rotate on the service's terms.
    const customer = /^\d+$/.test(String(m.Creator ?? ""));
    keys.push({
      id: String(m.KeyId ?? k.KeyId),
      description: str(m.Description),
      enabled: m.KeyState === "Enabled",
      rotatable: customer && m.KeyUsage === "ENCRYPT/DECRYPT" && /AES|SM4/i.test(String(m.KeySpec ?? "")) && (m.Origin ?? "Aliyun_KMS") === "Aliyun_KMS",
      rotation: m.AutomaticRotation ? m.AutomaticRotation === "Enabled" : null,
      deletionDate: m.KeyState === "PendingDeletion" ? time(m.DeleteDate) : null,
    });
  });
  const secrets: AlibabaSecret[] = [];
  await pool(secretList.slice(0, MAX_ITEMS), ITEM_CONCURRENCY, async (s) => {
    // Only the secret's settings and dates: its value is never asked for.
    const d = await client.rpc("kms", region, "DescribeSecret", { SecretName: String(s.SecretName) });
    secrets.push({
      name: String(s.SecretName),
      createdAt: time(d?.CreateTime ?? s.CreateTime),
      rotation: d?.AutomaticRotation === "Enabled",
      rotatedAt: time(d?.LastRotationDate) ?? time(d?.UpdateTime),
    });
  });
  return { keys, secrets };
}

/** ACK clusters, asked of each region and kept once each (an endpoint may answer for other regions too). */
async function readClusters(client: AlibabaClient, regions: string[]): Promise<AlibabaCluster[]> {
  const seen = new Map<string, AlibabaCluster>();
  let read = 0;
  let failure: unknown = null;
  await pool(regions, REGION_CONCURRENCY, async (region) => {
    try {
      const list = await byPage(
        (n) => client.roa("cs", region, "DescribeClustersV1", "/api/v1/clusters", { region_id: region, page_size: "100", page_number: String(n) }),
        (p) => listOf<Json>(p?.clusters),
        100,
      );
      read++;
      for (const c of list) {
        let master: Json = {};
        try {
          master = typeof c.master_url === "string" && c.master_url ? JSON.parse(c.master_url) : (c.master_url ?? {});
        } catch {
          /* an unreadable master_url: no public endpoint known */
        }
        seen.set(String(c.cluster_id), {
          id: String(c.cluster_id),
          name: String(c.name ?? c.cluster_id),
          region: String(c.region_id ?? region),
          version: str(c.current_version),
          publicEndpoint: !!master.api_server_endpoint,
        });
      }
    } catch (e) {
      if (e instanceof AlibabaError && e.noEndpoint) return;
      failure ??= e;
    }
  });
  if (!read && failure) throw failure;
  return [...seen.values()];
}

/** Trails, asked of each region and kept once each. */
async function readTrails(client: AlibabaClient, regions: string[]): Promise<AlibabaTrail[]> {
  const seen = new Map<string, AlibabaTrail>();
  let read = 0;
  let failure: unknown = null;
  await pool(regions.length ? regions : [HOME_REGION], REGION_CONCURRENCY, async (region) => {
    try {
      const d = await client.rpc("actiontrail", region, "DescribeTrails");
      read++;
      for (const t of listOf<Json>(d?.TrailList))
        seen.set(`${t.HomeRegion}/${t.Name}`, {
          name: String(t.Name),
          homeRegion: String(t.HomeRegion ?? region),
          allRegions: String(t.TrailRegion ?? "").toLowerCase() === "all",
          allEvents: String(t.EventRW ?? "").toLowerCase() === "all",
          logging: String(t.Status ?? "").toLowerCase() === "enable",
          delivers: !!(t.OssBucketName || t.SlsProjectArn),
          ossBucket: str(t.OssBucketName),
          organization: t.IsOrganizationTrail === true,
        });
    } catch (e) {
      if (e instanceof AlibabaError && e.noEndpoint) return;
      failure ??= e;
    }
  });
  if (!read && failure) throw failure;
  return [...seen.values()];
}

/**
 * Instances Security Center's agent protects. Security Center answers in Shanghai for the China site and in
 * Singapore for the international one; an account is on one of them, so both are asked and their answers joined.
 */
async function readProtected(client: AlibabaClient): Promise<Set<string> | null> {
  const ask = (host: string) =>
    byPage(
      (n) => client.rpc("sas", null, "DescribeCloudCenterInstances", { MachineTypes: "ecs", PageSize: "100", CurrentPage: String(n) }, host),
      (p) => listOf<Json>(p?.Instances),
      100,
    );
  const answers = await Promise.allSettled([ask("tds.cn-shanghai.aliyuncs.com"), ask("tds.ap-southeast-1.aliyuncs.com")]);
  const ok = answers.flatMap((a) => (a.status === "fulfilled" ? [a.value] : []));
  if (!ok.length) {
    const reason = (answers[0] as PromiseRejectedResult).reason;
    if (reason instanceof AlibabaError && reason.noEndpoint) {
      client.note("securityCenter", true);
      return new Set();
    }
    client.note("securityCenter", false, reason);
    return null;
  }
  client.note("securityCenter", true);
  return new Set(ok.flat().flatMap((i) => (String(i.ClientStatus).toLowerCase() === "online" && i.InstanceId ? [String(i.InstanceId)] : [])));
}

async function readCdn(client: AlibabaClient): Promise<AlibabaCdnDomain[]> {
  const list = await byPage(
    (n) => client.rpc("cdn", null, "DescribeUserDomains", { PageSize: "500", PageNumber: String(n) }),
    (p) => listOf<Json>(p?.Domains?.PageData),
    500,
  );
  return list.map((d) => ({
    name: String(d.DomainName).toLowerCase(),
    cname: String(d.Cname ?? "").toLowerCase(),
    origins: listOf<Json>(d.Sources?.Source).flatMap((o) => (o.Content ? [String(o.Content).toLowerCase()] : [])),
    https: String(d.SslProtocol ?? "").toLowerCase() === "on",
    online: String(d.DomainStatus ?? "").toLowerCase() === "online",
  }));
}

const HOST_TYPES = new Set(["A", "AAAA", "CNAME"]);

async function readDns(client: AlibabaClient): Promise<AlibabaDomain[]> {
  const list = (
    await byPage(
      (n) => client.rpc("alidns", null, "DescribeDomains", { PageSize: "100", PageNumber: String(n) }),
      (p) => listOf<Json>(p?.Domains?.Domain),
      100,
    )
  ).slice(0, MAX_DOMAINS);
  const out: AlibabaDomain[] = [];
  await pool(list, ITEM_CONCURRENCY, async (d) => {
    const name = String(d.DomainName).toLowerCase();
    const records = await byPage(
      (n) => client.rpc("alidns", null, "DescribeDomainRecords", { DomainName: name, PageSize: "500", PageNumber: String(n) }),
      (p) => listOf<Json>(p?.DomainRecords?.Record),
      500,
    ).catch(() => null);
    out.push({
      name,
      records: records
        ? records
            .filter((r) => String(r.Status ?? "Enable").toLowerCase() === "enable" && HOST_TYPES.has(String(r.Type)))
            .map((r) => ({
              name: r.RR === "@" || !r.RR ? name : `${String(r.RR).toLowerCase()}.${name}`,
              type: String(r.Type),
              value: String(r.Value ?? "")
                .toLowerCase()
                .replace(/\.$/, ""),
            }))
        : null,
    });
  });
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

async function pool<T>(list: T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, list.length) }, async () => {
      while (next < list.length) await fn(list[next++]);
    }),
  );
}

export type { AlibabaSourceKey };
