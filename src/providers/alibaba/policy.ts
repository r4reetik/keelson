// RAM and OSS policy documents reduced to what checks need: whether a policy grants
// everything, which escalation paths it opens, who a role's trust policy lets in
// (and, for GitHub Actions, which subjects), and whether a bucket policy lets anyone
// or other accounts in. The documents themselves are dropped as soon as they're
// read; test/alibaba.test.ts checks that none is stored.

import type { AlibabaTrust } from "./types.ts";

export interface Statement {
  Effect?: string;
  Action?: string | string[];
  NotAction?: string | string[];
  Resource?: string | string[];
  Principal?: string | string[] | { RAM?: string | string[]; Service?: string | string[]; Federated?: string | string[] };
  Condition?: Record<string, Record<string, string | string[]>>;
}

export const listOf = <T>(v: T | T[] | undefined | null): T[] => (v == null ? [] : Array.isArray(v) ? v : [v]);

/** A policy document as RAM and OSS return it: a JSON string. Only its statements are looked at, and none of it is stored. */
export function statements(doc: string | null | undefined): Statement[] {
  if (!doc) return [];
  try {
    return listOf((JSON.parse(doc) as { Statement?: Statement | Statement[] }).Statement);
  } catch {
    return [];
  }
}

const allows = (s: Statement) => (s.Effect ?? "Allow").toLowerCase() === "allow";

/** Allows every action on every resource, without a condition. */
export const grantsEverything = (st: Statement[]): boolean =>
  st.some((s) => allows(s) && !s.Condition && listOf(s.Action).some((a) => a === "*" || a === "*:*") && listOf(s.Resource).includes("*"));

/** Whether an Allow statement grants the action (exact, or by a trailing wildcard such as "ram:*" or "ram:Attach*"). */
function grants(st: Statement[], action: string): boolean {
  const a = action.toLowerCase();
  return st.some(
    (s) =>
      allows(s) &&
      listOf(s.Action).some((x) => {
        const p = x.toLowerCase();
        return p === "*" || p === a || (p.endsWith("*") && a.startsWith(p.slice(0, -1)));
      }),
  );
}

/** Single actions that let an identity give itself, or someone it controls, more access. */
const SELF_ESCALATION = [
  "ram:AttachPolicyToUser",
  "ram:AttachPolicyToGroup",
  "ram:AttachPolicyToRole",
  "ram:CreatePolicyVersion",
  "ram:SetDefaultPolicyVersion",
  "ram:AddUserToGroup",
  "ram:CreateAccessKey",
  "ram:CreateLoginProfile",
  "ram:UpdateLoginProfile",
  "ram:UpdateRole",
];
/** Handing a role to something the identity starts, which then runs with the role's access. */
const PASS_ROLE: [string, string][] = [
  ["ecs:RunInstances", "an ECS instance"],
  ["ecs:CreateInstance", "an ECS instance"],
  ["ecs:AttachInstanceRamRole", "an ECS instance"],
  ["fc:CreateFunction", "a Function Compute function"],
  ["fc:UpdateFunction", "a Function Compute function"],
];

/** The escalation paths a set of statements opens, in words. Administrators aren't judged: they already have everything. */
export function escalationPaths(st: Statement[]): string[] {
  if (grantsEverything(st)) return [];
  const out = SELF_ESCALATION.filter((a) => grants(st, a));
  if (grants(st, "ram:PassRole"))
    for (const [action, what] of PASS_ROLE) if (grants(st, action)) out.push(`ram:PassRole with ${action} (give a role to ${what})`);
  return [...new Set(out)];
}

const GITHUB_ISSUER = "https://token.actions.githubusercontent.com";

/**
 * The GitHub subjects a statement's condition allows: every value of oidc:sub under a String… operator. Negated
 * operators don't narrow who may assume the role, so they're left out.
 */
function githubSubjects(condition: Statement["Condition"]): string[] {
  const out: string[] = [];
  for (const [op, claims] of Object.entries(condition ?? {})) {
    if (!/String(Equals|Like)/i.test(op) || /Not/i.test(op)) continue;
    for (const [claim, values] of Object.entries(claims ?? {}))
      if (claim.toLowerCase() === "oidc:sub") out.push(...listOf(values).map((v) => String(v).toLowerCase()));
  }
  return out;
}

/** Whether a condition names GitHub's issuer (oidc:iss), for a provider Keelson couldn't look up. */
const namesGithub = (condition: Statement["Condition"]) =>
  Object.values(condition ?? {}).some((claims) =>
    Object.entries(claims ?? {}).some(([k, v]) => k.toLowerCase() === "oidc:iss" && listOf(v).some((x) => String(x).replace(/\/$/, "") === GITHUB_ISSUER)),
  );

/** The host of an issuer's address ("https://gitlab.com" → "gitlab.com"), or null when it isn't one. */
export function issuerHost(issuer: unknown): string | null {
  try {
    return new URL(String(issuer)).host.toLowerCase() || null;
  } catch {
    return null;
  }
}

/** The issuer a condition names (oidc:iss), as a host, for a provider Keelson couldn't look up. */
function issuerIn(condition: Statement["Condition"]): string | null {
  for (const claims of Object.values(condition ?? {}))
    for (const [k, v] of Object.entries(claims ?? {})) if (k.toLowerCase() === "oidc:iss") return issuerHost(listOf(v)[0]);
  return null;
}

/**
 * Who a role's trust policy lets assume it. `githubProviders` holds the ARNs of the account's OIDC providers whose
 * issuer is GitHub's; `issuers` the issuer's host of every other one, by ARN.
 */
export function trustOf(st: Statement[], githubProviders: Set<string>, issuers: Map<string, string> = new Map()): AlibabaTrust[] {
  const out: AlibabaTrust[] = [];
  for (const s of st) {
    if (!allows(s)) continue;
    const conditional = !!s.Condition && Object.keys(s.Condition).length > 0;
    if (s.Principal === "*") {
      out.push({ principal: "*", kind: "anyone", conditional });
      continue;
    }
    if (!s.Principal || typeof s.Principal !== "object" || Array.isArray(s.Principal)) continue;
    for (const p of listOf(s.Principal.RAM))
      out.push(p === "*" ? { principal: "*", kind: "anyone", conditional } : { principal: p, kind: "account", conditional });
    for (const p of listOf(s.Principal.Service)) out.push({ principal: p, kind: "service", conditional });
    for (const p of listOf(s.Principal.Federated)) {
      const github = githubProviders.has(p) || (/:oidc-provider\//.test(p) && namesGithub(s.Condition));
      // Another OIDC provider is kept with its issuer's host and its subject patterns, as GitHub's is: never the rest of the policy.
      const host = github || !/:oidc-provider\//.test(p) ? null : (issuers.get(p) ?? issuerIn(s.Condition));
      out.push(
        github
          ? { principal: p, kind: "federated", conditional, github: githubSubjects(s.Condition) }
          : host
            ? { principal: p, kind: "federated", conditional, oidc: { host, subjects: githubSubjects(s.Condition) } }
            : { principal: p, kind: "federated", conditional },
      );
    }
  }
  return out;
}

/** The OSS conditions that keep a statement from being public (Alibaba Cloud's own rules for Block Public Access). */
const NARROWING = /^acs:(SourceVpcId|SourceVpc|AccessId|SourceVpcIp|SourceIp)$/i;

/**
 * What a bucket policy allows: whether an Allow statement lets anyone in ("*" without a narrowing condition), and
 * the other principals it names that look like accounts (a 16-digit ID, or an ARN in another account).
 */
export function bucketPolicy(st: Statement[], ownAccount: string): { public: boolean; publicWrite: boolean; otherAccounts: string[] } {
  let open = false;
  let write = false;
  const others = new Set<string>();
  for (const s of st) {
    if (!allows(s)) continue;
    const principals = typeof s.Principal === "string" ? [s.Principal] : Array.isArray(s.Principal) ? (s.Principal as string[]) : listOf(s.Principal?.RAM);
    const narrowed = Object.values(s.Condition ?? {}).some((claims) => Object.keys(claims ?? {}).some((k) => NARROWING.test(k)));
    if (principals.includes("*") && !narrowed) {
      open = true;
      // Uploading, overwriting or deleting objects, or changing the bucket itself.
      if (listOf(s.Action).some((x) => /^(\*|oss:\*|oss:(Put|Delete|Append|Copy|Restore|Post)[\w*]*)$/i.test(x))) write = true;
    }
    for (const p of principals) {
      const account = /^(\d{16})$/.exec(p)?.[1] ?? /^acs:ram::(\d{16}):/.exec(p)?.[1];
      if (account && account !== ownAccount) others.add(account);
    }
  }
  return { public: open, publicWrite: write, otherAccounts: [...others] };
}
