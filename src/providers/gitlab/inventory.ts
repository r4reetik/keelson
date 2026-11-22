// One GitLab scan's reads: the group's settings, members and webhooks, and
// every project in it and its subgroups with the rule on its default branch,
// its merge request approvals, webhooks, deploy keys, deploy tokens and Pages
// domains; then each project's dependency files for its software bill of
// materials (src/core/sbom; never the code).
//
// Secrets never enter the inventory: a webhook keeps the scheme and host of its
// address (GitLab never returns its token), a deploy key keeps its title and
// access, and a deploy token its name, scopes and expiry (GitLab never returns
// its value). CI/CD variables aren't read at all: the API returns their values.

import type { GitlabClient, GitlabError, Json } from "./client.ts";
import { OWNER, type GitlabApprovals, type GitlabBranchRule, type GitlabHook, type GitlabInventory, type GitlabProject } from "./types.ts";
import type { ProgressEvent } from "../../core/types.ts";
import type { AccountCache } from "../../store/repo.ts";
import { collectDependencies, type CodeHost } from "../../core/sbom/index.ts";

const PROJECT_CONCURRENCY = 6;
/** Pages of a project's file list read in one go (100 entries each); a larger one is walked folder by folder. */
const MAX_TREE_PAGES = 60;

/** Where a scan keeps SBOMs between scans and Grype's database; without it, dependencies aren't read. */
export interface DependencyStore {
  cache: AccountCache;
  toolDir: string | null;
}

export async function collectGitlab(
  client: GitlabClient,
  accountId: string,
  group: Json,
  onProgress: (p: ProgressEvent) => void = () => {},
  deps: DependencyStore | null = null,
): Promise<GitlabInventory> {
  const g = `/groups/${client.groupId}`;
  onProgress({ phase: "Reading the group" });
  // The settings that matter are shown only to an Owner: without them the group's own checks are skipped.
  const settings = typeof group?.require_two_factor_authentication === "boolean";
  client.note(
    "group",
    settings,
    settings ? undefined : Object.assign(new Error("GitLab shows a group's security settings only to its Owners."), { status: 403 }),
  );
  const [memberList, hooks] = await Promise.all([
    client.list<Json>("members", `${g}/members/all`),
    client.list<Json>("groupHooks", `${g}/hooks`, { absentOn: [404] }),
  ]);

  onProgress({ phase: "Reading projects" });
  const listed = (await client.list<Json>("projects", `${g}/projects?include_subgroups=true&with_shared=false&order_by=path&sort=asc`)) ?? [];
  const projects: GitlabProject[] = [];
  let done = 0;
  await pool(listed, PROJECT_CONCURRENCY, async (body) => {
    projects.push(await readProject(client, body));
    onProgress({ phase: "Reading projects", done: ++done, total: listed.length });
  });
  projects.sort((a, b) => a.name.localeCompare(b.name));

  onProgress({ phase: "Reading dependency manifests" });
  // A copy the instance pulls from elsewhere is somebody else's code: its dependencies aren't this group's to fix.
  const targets = projects.map((p) => ({ name: p.name, archived: p.archived || p.mirror, empty: p.empty || !p.defaultBranch, defaultBranch: p.defaultBranch }));
  const dependencies = deps ? await collectDependencies(codeHost(client, projects), targets, deps.cache, deps.toolDir, onProgress) : null;

  return {
    accountId,
    accountName: String(group?.full_name || group?.name || client.org),
    login: client.org,
    base: client.base,
    now: Date.now(),
    group: settings
      ? {
          visibility: String(group.visibility ?? ""),
          requireTwoFactor: group.require_two_factor_authentication === true,
          shareLock: group.share_with_group_lock === true,
        }
      : null,
    // A bot is a project or group access token's own user, not a person.
    members: memberList
      ? memberList
          .filter((m) => m?.state !== "blocked" && !/_bot(_|$)|^(project|group)_\d+_bot/.test(String(m?.username ?? "")))
          .map((m) => ({ username: String(m.username ?? ""), level: Number(m.access_level) || 0 }))
      : null,
    hooks: hooks ? hooks.map(toHook) : null,
    groupHooksAbsent: !!hooks?.absent,
    projects,
    dependencies,
    unreadable: [...client.coverage.values()].filter((c) => !c.ok).map((c) => c.key),
  };
}

/** Scheme and host of an address. Its path and query can carry a token. */
function endpointOf(address: unknown): string {
  try {
    const u = new URL(String(address ?? ""));
    return `${u.protocol}//${u.host}`;
  } catch {
    return "";
  }
}

const toHook = (h: Json): GitlabHook => ({ endpoint: endpointOf(h?.url), verifiesTls: h?.enable_ssl_verification !== false });

/** Whether a protected branch's name covers a branch: an exact name, or a wildcard where * is any run of characters. */
export function ruleCovers(pattern: string, branch: string): boolean {
  if (!pattern.includes("*")) return pattern === branch;
  return new RegExp(
    `^${pattern
      .split("*")
      .map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
      .join(".*")}$`,
  ).test(branch);
}

/** The rule that applies to a branch. GitLab adds up every rule that matches, so the most permissive of them counts. */
export function ruleFor(rules: Json[], branch: string): GitlabBranchRule | null {
  const matching = rules.filter((r) => ruleCovers(String(r?.name ?? ""), branch));
  if (!matching.length) return null;
  // Exact rule first, for its name; each setting is the loosest any matching rule allows.
  const named = matching.find((r) => r.name === branch) ?? matching[0];
  const levels = matching.flatMap((r) => (Array.isArray(r.push_access_levels) ? r.push_access_levels : []));
  const roles = levels.filter((l: Json) => l?.user_id == null && l?.group_id == null && l?.deploy_key_id == null).map((l: Json) => Number(l.access_level) || 0);
  const allowed = roles.filter((l: number) => l > 0);
  return {
    rule: String(named.name ?? ""),
    pushLevel: allowed.length ? Math.min(...allowed) : 0,
    pushNamed: levels.some((l: Json) => l?.user_id != null || l?.group_id != null || l?.deploy_key_id != null),
    forcePush: matching.some((r) => r.allow_force_push === true),
  };
}

async function readProject(client: GitlabClient, body: Json): Promise<GitlabProject> {
  const id = Number(body.id);
  const fullPath = String(body.path_with_namespace ?? "");
  const p = `/projects/${id}`;
  const project: GitlabProject = {
    id,
    name: fullPath.startsWith(`${client.org}/`) ? fullPath.slice(client.org.length + 1) : fullPath,
    fullPath,
    visibility: body.visibility === "public" ? "public" : body.visibility === "internal" ? "internal" : "private",
    archived: body.archived === true,
    empty: body.empty_repo === true,
    mirror: body.mirror === true,
    defaultBranch: String(body.default_branch ?? ""),
    updatedAt: Date.parse(String(body.last_activity_at ?? "")) || null,
    url: String(body.web_url ?? `${client.base}/${fullPath}`),
    license: null,
    protection: undefined,
    approvals: undefined,
    hooks: null,
    deployKeys: null,
    deployTokens: null,
    pagesDomains: null,
    registry: body.container_registry_access_level !== "disabled" && body.container_registry_enabled !== false,
  };
  // An archived project takes no changes: what it is, is all that's kept.
  if (project.archived) return project;
  const pagesOn = body.pages_access_level !== "disabled";
  const [rules, approvalRules, hooks, keys, tokens, domains, detail] = await Promise.all([
    client.list<Json>("protection", `${p}/protected_branches`),
    // A plan without approval rules answers 404, or 403 to everyone, depending on the version: neither is a role to raise.
    client.list<Json>("approvals", `${p}/approval_rules`, { absentOn: [403, 404] }),
    client.list<Json>("projectHooks", `${p}/hooks`),
    client.list<Json>("deployKeys", `${p}/deploy_keys`),
    client.list<Json>("deployTokens", `${p}/deploy_tokens?active=true`),
    pagesOn ? client.list<Json>("pages", `${p}/pages/domains`, { absentOn: [404] }) : ([] as Json[]),
    // The license GitLab detects comes only with the project asked for by itself.
    client.raw(`${p}?license=true`).catch(() => null),
  ]);
  if (rules) project.protection = ruleFor(rules, project.defaultBranch);
  if (hooks) project.hooks = hooks.map(toHook);
  if (keys) project.deployKeys = keys.map((k) => ({ title: String(k.title ?? ""), canPush: k.can_push === true }));
  if (tokens)
    project.deployTokens = tokens
      .filter((t) => t?.revoked !== true && t?.expired !== true)
      .map((t) => ({
        name: String(t.name ?? ""),
        scopes: Array.isArray(t.scopes) ? t.scopes.map(String) : [],
        expiresAt: typeof t.expires_at === "string" ? t.expires_at : null,
      }));
  if (domains) project.pagesDomains = domains.map((d) => String(d?.domain ?? "").toLowerCase()).filter(Boolean);
  if (typeof detail?.license?.key === "string") project.license = spdx(detail.license);
  if (approvalRules) project.approvals = approvalRules.absent ? null : await readApprovals(client, p, approvalRules);
  return project;
}

/** GitLab's license keys are lowercase ("mit", "gpl-3.0"); its SPDX ID is in the nickname-free name when it has one. */
const spdx = (license: Json): string =>
  String(license.spdx_id || license.key || "")
    .toUpperCase()
    .replace(/^(A?GPL|LGPL|MPL|EPL|BSD|APACHE)/, (m) => (m === "APACHE" ? "Apache" : m));

async function readApprovals(client: GitlabClient, p: string, rules: Json[]): Promise<GitlabApprovals | undefined> {
  const required = Math.max(0, ...rules.map((r) => Number(r?.approvals_required) || 0));
  // Nothing has to be approved, so there is nothing for the settings to weaken.
  if (!required) return { required, resetOnPush: true, authorApproves: false };
  try {
    const s = await client.raw(`${p}/approvals`);
    return { required, resetOnPush: s?.reset_approvals_on_push !== false, authorApproves: s?.merge_requests_author_approval === true };
  } catch (e) {
    client.note("approvals", false, e as GitlabError);
    return undefined;
  }
}

/**
 * The client as the dependency pipeline reads it. The pipeline asks in GitHub's words (a branch's whole file list,
 * a folder's by its ID, a file by its blob ID, the languages); GitLab lists files by path and in pages, names
 * projects by number, and gives a folder no ID to ask by, so a folder's "ID" here is its path.
 */
export function codeHost(client: GitlabClient, projects: Pick<GitlabProject, "id" | "name" | "defaultBranch">[]): CodeHost {
  const byName = new Map(projects.map((p) => [p.name, p]));
  const entry = (e: Json) => ({
    path: String(e.path),
    type: e.type === "tree" ? "tree" : "blob",
    sha: e.type === "tree" ? `dir:${e.path}` : String(e.id),
    size: 0,
  });
  return {
    org: client.org,
    // The pipeline asks whether the list of repositories was complete; here that is the list of projects.
    coverage: { get: () => client.coverage.get("projects") },
    note: (source, ok, err) => client.note(source, ok, err),
    async raw(path) {
      const m = /^\/repos\/.+?\/([^/]+)\/(git\/trees\/|git\/blobs\/|languages$)(.*)$/.exec(path);
      const project = m ? byName.get(decodeURIComponent(m[1])) : undefined;
      if (!m || !project) throw Object.assign(new Error("Unknown project"), { status: 404 });
      const p = `/projects/${project.id}`;
      if (m[2] === "languages") return client.raw(`${p}/languages`);
      if (m[2] === "git/blobs/") return client.raw(`${p}/repository/blobs/${m[3]}`);
      const ref = encodeURIComponent(project.defaultBranch);
      // One folder, by the path that stands in for its ID: its own entries, named from the folder as GitHub names them.
      if (m[3].startsWith("dir:")) {
        const dir = m[3].slice(4);
        const { items } = await pages(client, `${p}/repository/tree?ref=${ref}&path=${encodeURIComponent(dir)}&per_page=100&pagination=keyset`, 20);
        return { tree: items.map((e) => ({ ...entry(e), path: String(e.name) })) };
      }
      const { items, more } = await pages(client, `${p}/repository/tree?ref=${ref}&recursive=true&per_page=100&pagination=keyset`, MAX_TREE_PAGES);
      return { sha: "dir:", tree: items.map(entry), truncated: more };
    },
  };
}

/** A list paged by key: each answer names the next page in its Link header. */
async function pages(client: GitlabClient, first: string, max: number): Promise<{ items: Json[]; more: boolean }> {
  const items: Json[] = [];
  let next: string | null = first;
  for (let n = 0; next && n < max; n++) {
    const page: { body: Json; next: string; link: string | null } = await client.send(next);
    const got: Json[] = Array.isArray(page.body) ? page.body : [];
    items.push(...got);
    next = got.length ? page.link : null;
  }
  return { items, more: !!next };
}

async function pool<T>(items: readonly T[], size: number, work: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(size, items.length) }, async () => {
      while (next < items.length) await work(items[next++]);
    }),
  );
}

export { OWNER };
