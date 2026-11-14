// One GitHub scan's reads: the organization's settings, owners, Actions policy,
// webhooks and other installed Apps; every repository the App reaches, with its
// default branch's protection and rulesets, deploy keys, webhooks and Pages site;
// and the organization's open Dependabot, code scanning and secret scanning alerts.
//
// Secrets never enter the inventory: secret scanning alerts are read with
// hide_secret and their value field is dropped regardless, only the scheme and
// host of webhook URLs are kept, and deploy keys keep their title and access only.

import type { GithubClient, GithubError, Json } from "./client.ts";
import type {
  BranchProtection,
  BranchRule,
  CodeScanningAlert,
  DependabotAlert,
  GithubActions,
  GithubHook,
  GithubInventory,
  GithubOrg,
  GithubRepo,
  OtherApp,
  SecretAlert,
} from "./types.ts";
import type { ProgressEvent } from "../../core/types.ts";

const REPO_CONCURRENCY = 6;
const MAX_ALERTS = 5000;

export async function collectGithub(client: GithubClient, accountId: string, onProgress: (p: ProgressEvent) => void = () => {}): Promise<GithubInventory> {
  const org = client.org;
  onProgress({ phase: "Reading the organization" });
  const [orgBody, owners, actions, workflow, hooks, apps] = await Promise.all([
    client.orgSettings().then(
      (b) => {
        client.note("orgSettings", true);
        return b;
      },
      (e) => {
        client.note("orgSettings", false, e);
        return null;
      },
    ),
    client.list<Json>("members", `/orgs/${org}/members?role=admin`),
    client.get("actions", `/orgs/${org}/actions/permissions`),
    client.get("actions", `/orgs/${org}/actions/permissions/workflow`),
    client.list<Json>("orgHooks", `/orgs/${org}/hooks`),
    client.list<Json>("installations", `/orgs/${org}/installations`, { key: "installations" }),
  ]);

  onProgress({ phase: "Reading repositories" });
  const listed = (await client.list<Json>("repos", "/installation/repositories", { key: "repositories" })) ?? [];
  const repos: GithubRepo[] = [];
  let done = 0;
  await pool(listed, REPO_CONCURRENCY, async (r: Json) => {
    repos.push(await readRepo(client, r));
    onProgress({ phase: "Reading repositories", done: ++done, total: listed.length });
  });
  repos.sort((a, b) => a.name.localeCompare(b.name));

  onProgress({ phase: "Reading security alerts" });
  const [dependabot, codeScanning, secretScanning] = await Promise.all([
    client.list<Json>("dependabot", `/orgs/${org}/dependabot/alerts?state=open`, { max: MAX_ALERTS }),
    client.list<Json>("codeScanning", `/orgs/${org}/code-scanning/alerts?state=open`, { max: MAX_ALERTS }),
    client.list<Json>("secretScanning", `/orgs/${org}/secret-scanning/alerts?state=open&hide_secret=true`, { max: MAX_ALERTS }),
  ]);

  const inst = client.installation;
  return {
    accountId,
    accountName: orgBody ? (str(orgBody.name) ?? str(orgBody.login)) : (inst?.login ?? null),
    login: inst?.login ?? decodeURIComponent(org),
    now: Date.now(),
    unreadable: [...client.coverage.values()].filter((c) => !c.ok).map((c) => c.key),
    appId: inst?.appId ?? null,
    selectedRepos: inst?.selection === "selected",
    org: orgBody ? toOrg(orgBody) : null,
    owners: owners ? owners.map((m) => String(m.login ?? "")) : null,
    actions: actions && workflow ? toActions(actions, workflow) : null,
    hooks: hooks ? hooks.map(toHook) : null,
    apps: apps ? apps.map(toApp) : null,
    repos,
    dependabot: dependabot ? dependabot.map(toDependabot) : null,
    codeScanning: codeScanning ? codeScanning.map(toCodeScanning) : null,
    secretScanning: secretScanning ? secretScanning.map(toSecretAlert) : null,
  };
}

/**
 * One repository. Archived repositories can't change, so only what they are is kept; the rest get their
 * settings, default branch protection, deploy keys, webhooks and Pages site.
 */
async function readRepo(client: GithubClient, listed: Json): Promise<GithubRepo> {
  const path = `/repos/${client.org}/${encodeURIComponent(String(listed.name))}`;
  const base = toRepo(listed);
  if (base.archived) return base;
  const branch = encodeURIComponent(base.defaultBranch);
  const [detail, protection, rules, keys, hooks, pages, dependabotAlerts, codeScanning] = await Promise.all([
    client.raw(path).catch(() => null),
    base.empty ? Promise.resolve(null) : client.getOptional("protection", `${path}/branches/${branch}/protection`),
    base.empty ? Promise.resolve([]) : client.get<Json[]>("rules", `${path}/rules/branches/${branch}`),
    client.list<Json>("deployKeys", `${path}/keys`),
    client.list<Json>("repoHooks", `${path}/hooks`),
    base.hasPages ? client.getOptional("pages", `${path}/pages`) : Promise.resolve(null),
    dependabotEnabled(client, path),
    base.empty ? Promise.resolve(null) : codeScanningRan(client, path),
  ]);
  const sa = detail?.security_and_analysis;
  // GitHub leaves the security settings out when the App can't administer the repository.
  if (detail && !sa) client.note("codeSecurity", false, Object.assign(new Error("GitHub didn't include the repository's security settings."), { status: 403 }));
  else if (sa) client.note("codeSecurity", true);
  return {
    ...base,
    security: sa
      ? {
          secretScanning: status(sa.secret_scanning),
          pushProtection: status(sa.secret_scanning_push_protection),
          dependabotUpdates: status(sa.dependabot_security_updates),
        }
      : null,
    protection: protection === undefined ? undefined : protection ? toProtection(protection) : null,
    rules: rules ? (Array.isArray(rules) ? rules : []).map(toRule) : null,
    deployKeys: keys ? keys.map((k) => ({ title: String(k.title ?? ""), readOnly: k.read_only !== false, createdAt: time(k.created_at) })) : null,
    hooks: hooks ? hooks.map(toHook) : null,
    dependabotAlerts,
    codeScanning,
    pages: pages === undefined ? undefined : pages ? { cname: str(pages.cname)?.toLowerCase() ?? null, httpsEnforced: bool(pages.https_enforced) } : null,
  };
}

/** GitHub answers 204 when Dependabot alerts are on and 404 when they're off. */
async function dependabotEnabled(client: GithubClient, path: string): Promise<boolean | null> {
  try {
    await client.raw(`${path}/vulnerability-alerts`);
    client.note("dependabotSetup", true);
    return true;
  } catch (e) {
    if ((e as GithubError).status === 404) {
      client.note("dependabotSetup", true);
      return false;
    }
    client.note("dependabotSetup", false, e);
    return null;
  }
}

/**
 * Whether code scanning has analysed the repository. No analysis is a 404, or an empty list; a private
 * repository without GitHub Code Security answers 403 saying so, which means "not set up", not a missing permission.
 */
async function codeScanningRan(client: GithubClient, path: string): Promise<boolean | null> {
  try {
    const body = await client.raw(`${path}/code-scanning/analyses?per_page=1`);
    client.note("codeScanningSetup", true);
    return Array.isArray(body) && body.length > 0;
  } catch (e) {
    const err = e as GithubError;
    if (err.status === 404 || (err.status === 403 && /advanced security|code security|not enabled/i.test(err.message))) {
      client.note("codeScanningSetup", true);
      return false;
    }
    client.note("codeScanningSetup", false, e);
    return null;
  }
}

const str = (v: unknown): string | null => (typeof v === "string" && v ? v : null);
const bool = (v: unknown): boolean | null => (typeof v === "boolean" ? v : null);
const time = (v: unknown): number | null => {
  const t = typeof v === "string" ? Date.parse(v) : Number.NaN;
  return Number.isFinite(t) ? t : null;
};
/** GitHub's { status: "enabled" | "disabled" }. */
const status = (v: Json): boolean | null => (v?.status === "enabled" ? true : v?.status === "disabled" ? false : null);

function toOrg(o: Json): GithubOrg {
  return {
    login: String(o.login ?? ""),
    name: str(o.name),
    plan: str(o.plan?.name),
    twoFactorRequired: bool(o.two_factor_requirement_enabled),
    defaultRepoPermission: str(o.default_repository_permission),
    membersCanCreatePublicRepos: bool(o.members_can_create_public_repositories),
    membersCanForkPrivateRepos: bool(o.members_can_fork_private_repositories),
  };
}

function toRepo(r: Json): GithubRepo {
  return {
    name: String(r.name ?? ""),
    private: r.private !== false,
    visibility: String(r.visibility ?? (r.private === false ? "public" : "private")),
    archived: !!r.archived,
    fork: !!r.fork,
    empty: r.size === 0 && !r.pushed_at,
    defaultBranch: String(r.default_branch ?? "main"),
    pushedAt: time(r.pushed_at),
    hasPages: !!r.has_pages,
    security: null,
    protection: undefined,
    rules: null,
    deployKeys: null,
    hooks: null,
    dependabotAlerts: null,
    codeScanning: null,
    pages: null,
  };
}

function toProtection(p: Json): BranchProtection {
  const pr = p.required_pull_request_reviews;
  return {
    reviews: pr ? Number(pr.required_approving_review_count ?? 0) : null,
    enforceAdmins: !!p.enforce_admins?.enabled,
    allowForcePushes: !!p.allow_force_pushes?.enabled,
    allowDeletions: !!p.allow_deletions?.enabled,
  };
}

function toRule(r: Json): BranchRule {
  const n = r.parameters?.required_approving_review_count;
  return { type: String(r.type ?? ""), reviews: typeof n === "number" ? n : null };
}

/** "https://hooks.example.com/x?token=…" -> "https://hooks.example.com". */
export function originOf(u: unknown): string {
  if (typeof u !== "string") return "";
  try {
    const x = new URL(u);
    return `${x.protocol}//${x.host}`;
  } catch {
    return "";
  }
}

function toHook(h: Json): GithubHook {
  const insecure = h.config?.insecure_ssl;
  return { id: Number(h.id), endpoint: originOf(h.config?.url), insecureSsl: insecure === "1" || insecure === 1, active: h.active !== false };
}

function toActions(a: Json, w: Json): GithubActions {
  return {
    enabledRepos: str(a.enabled_repositories),
    allowedActions: str(a.allowed_actions),
    defaultWorkflowPermissions: str(w.default_workflow_permissions),
    canApprovePullRequests: bool(w.can_approve_pull_request_reviews),
  };
}

function toApp(i: Json): OtherApp {
  const perms = (i.permissions ?? {}) as Record<string, string>;
  return {
    slug: String(i.app_slug ?? i.app_id ?? ""),
    appId: Number(i.app_id),
    selection: String(i.repository_selection ?? ""),
    writes: Object.entries(perms)
      .filter(([, v]) => v === "write" || v === "admin")
      .map(([k]) => k)
      .sort(),
  };
}

function toDependabot(a: Json): DependabotAlert {
  return {
    repo: String(a.repository?.name ?? ""),
    severity: String(a.security_vulnerability?.severity ?? a.security_advisory?.severity ?? "unknown").toLowerCase(),
    pkg: String(a.dependency?.package?.name ?? a.security_vulnerability?.package?.name ?? ""),
    advisory: String(a.security_advisory?.ghsa_id ?? ""),
    createdAt: time(a.created_at),
  };
}

function toCodeScanning(a: Json): CodeScanningAlert {
  return {
    repo: String(a.repository?.name ?? ""),
    severity: String(a.rule?.security_severity_level ?? a.rule?.severity ?? "unknown").toLowerCase(),
    rule: String(a.rule?.description ?? a.rule?.id ?? ""),
    tool: String(a.tool?.name ?? ""),
    createdAt: time(a.created_at),
  };
}

/** Everything but the secret: GitHub would send its value in `secret` without hide_secret. */
function toSecretAlert(a: Json): SecretAlert {
  return {
    number: Number(a.number),
    repo: String(a.repository?.name ?? ""),
    kind: String(a.secret_type_display_name ?? a.secret_type ?? "secret"),
    validity: String(a.validity ?? "unknown"),
    pushProtectionBypassed: !!a.push_protection_bypassed,
    createdAt: time(a.created_at),
  };
}

async function pool<T>(items: T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (next < items.length) await fn(items[next++]);
    }),
  );
}
