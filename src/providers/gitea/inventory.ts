// One Gitea scan's reads: the organization, its members and teams, which
// members sign in without two-factor authentication (told only to a site
// administrator), its webhooks, and every repository with the rule on its
// default branch, its webhooks, deploy keys, collaborators from outside the
// organization and push mirrors, and each repository's dependency files for
// its software bill of materials (src/core/sbom; never the code). One request
// without the token tells whether the instance shows public repositories to
// anyone who reaches it.
//
// Secrets never enter the inventory: a webhook keeps the scheme and host of its
// address and never its secret or authorization header, a deploy key keeps its
// title and access, and a push mirror keeps the host it pushes to (its address
// can carry a password).

import type { GiteaClient, GiteaError, Json } from "./client.ts";
import type { GiteaBranchRule, GiteaHook, GiteaInventory, GiteaRepo, GiteaTeam } from "./types.ts";
import type { ProgressEvent } from "../../core/types.ts";
import type { AccountCache } from "../../store/repo.ts";
import { collectDependencies, type CodeHost } from "../../core/sbom/index.ts";

const REPO_CONCURRENCY = 6;
/** Teams whose members are read: the ones that can administer something. An organization rarely has more. */
const MAX_TEAMS = 40;
/** Collaborators whose access is looked up, per repository. */
const MAX_OUTSIDERS = 30;

/** Where a scan keeps SBOMs between scans and Grype's database; without it, dependencies aren't read. */
export interface DependencyStore {
  cache: AccountCache;
  toolDir: string | null;
}

/** How many pages of a repository's file list are read in one go; a larger one is walked folder by folder. */
const MAX_TREE_PAGES = 30;

/**
 * The client as the dependency pipeline reads it. Gitea names the three reads as GitHub does and answers in the
 * same shapes, except that a long file list comes in pages: they are put together here, so the pipeline sees one.
 */
export function codeHost(client: GiteaClient): CodeHost {
  return {
    org: client.org,
    coverage: client.coverage,
    note: (source, ok, err) => client.note(source, ok, err),
    async raw(path) {
      const tree = /^(.*\/git\/trees\/[^?]+)\?recursive=1$/.exec(path);
      if (!tree) return client.raw(path);
      const first = await client.raw(`${tree[1]}?recursive=true&per_page=1000&page=1`);
      const entries = [...(Array.isArray(first?.tree) ? first.tree : [])];
      let more = first?.truncated === true;
      for (let page = 2; more && page <= MAX_TREE_PAGES; page++) {
        const next = await client.raw(`${tree[1]}?recursive=true&per_page=1000&page=${page}`);
        const got = Array.isArray(next?.tree) ? next.tree : [];
        entries.push(...got);
        more = next?.truncated === true && got.length > 0;
      }
      return { sha: first?.sha, tree: entries, truncated: more };
    },
  };
}

export async function collectGitea(
  client: GiteaClient,
  accountId: string,
  onProgress: (p: ProgressEvent) => void = () => {},
  deps: DependencyStore | null = null,
): Promise<GiteaInventory> {
  const org = encodeURIComponent(client.org);
  onProgress({ phase: "Reading the organization" });
  const [orgBody, memberList, teamList, hooks, version] = await Promise.all([
    client.get<Json>("org", `/orgs/${org}`),
    client.list<Json>("members", `/orgs/${org}/members`),
    client.list<Json>("teams", `/orgs/${org}/teams`),
    client.list<Json>("orgHooks", `/orgs/${org}/hooks`),
    client.raw("/version").then(
      (v) => String(v?.version ?? "") || null,
      () => null,
    ),
  ]);
  const members = memberList ? memberList.map(loginOf).filter(Boolean) : null;
  const teams = teamList ? await readTeams(client, teamList) : null;
  const noTwoFactor = members ? await readNoTwoFactor(client, new Set(members)) : null;

  onProgress({ phase: "Reading repositories" });
  const listed = (await client.list<Json>("repos", `/orgs/${org}/repos`)) ?? [];
  const inOrg = new Set(members ?? []);
  const repos: GiteaRepo[] = [];
  let done = 0;
  await pool(listed, REPO_CONCURRENCY, async (body) => {
    repos.push(await readRepo(client, org, body, String(orgBody?.visibility ?? ""), members ? inOrg : null));
    onProgress({ phase: "Reading repositories", done: ++done, total: listed.length });
  });
  repos.sort((a, b) => a.name.localeCompare(b.name));

  onProgress({ phase: "Reading dependency manifests" });
  // A copy the instance pulls from elsewhere is somebody else's code: its dependencies aren't this organization's to fix.
  const targets = repos.map((r) => ({ name: r.name, archived: r.archived || r.mirror, empty: r.empty || !r.defaultBranch, defaultBranch: r.defaultBranch }));
  const dependencies = deps ? await collectDependencies(codeHost(client), targets, deps.cache, deps.toolDir, onProgress) : null;
  const anonymous = await readAnonymous(client, org, repos);

  return {
    accountId,
    accountName: String(orgBody?.full_name || orgBody?.username || orgBody?.name || client.org),
    login: client.org,
    base: client.base,
    version,
    now: Date.now(),
    visibility: orgBody ? String(orgBody.visibility ?? "") || null : null,
    members,
    teams,
    noTwoFactor,
    hooks: hooks ? hooks.map(toHook) : null,
    repos,
    dependencies,
    anonymous,
    unreadable: [...client.coverage.values()].filter((c) => !c.ok).map((c) => c.key),
  };
}

const loginOf = (u: Json): string => String(u?.login ?? u?.username ?? "").toLowerCase();

async function readTeams(client: GiteaClient, list: Json[]): Promise<GiteaTeam[]> {
  const teams: GiteaTeam[] = list.map((t) => ({
    name: String(t.name ?? ""),
    permission: String(t.permission ?? "none"),
    allRepos: t.includes_all_repositories === true,
    members: null,
  }));
  const powerful = list.map((t, i) => [t, teams[i]] as const).filter(([, t]) => t.permission === "owner" || t.permission === "admin");
  await pool(powerful.slice(0, MAX_TEAMS), 4, async ([body, team]) => {
    const found = await client.list<Json>("teams", `/teams/${Number(body.id)}/members`);
    team.members = found ? found.map(loginOf).filter(Boolean) : null;
  });
  return teams;
}

/**
 * Members without two-factor authentication. Gitea answers this only to a site administrator, with a filter on its
 * list of users; an instance too old to know the filter ignores it and returns everyone. So the opposite filter is
 * asked too: when the same person is in both answers the filter did nothing, and nothing is concluded.
 */
async function readNoTwoFactor(client: GiteaClient, members: Set<string>): Promise<string[] | null> {
  const without = await client.list<Json>("twoFactor", "/admin/users?is_2fa_enabled=false", { max: 20_000 });
  if (!without) return null;
  const withIt = await client.list<Json>("twoFactor", "/admin/users?is_2fa_enabled=true", { max: 20_000 });
  if (!withIt) return null;
  const enrolled = new Set(withIt.map(loginOf));
  if (without.some((u) => enrolled.has(loginOf(u)))) {
    client.note(
      "twoFactor",
      false,
      Object.assign(new Error("This Gitea version doesn't say who has two-factor authentication. Gitea 1.25 and later do."), { status: 0 }),
    );
    return null;
  }
  return without.map(loginOf).filter((l) => members.has(l));
}

/** Scheme and host of an address. Its path and query can carry a token (a chat webhook's whole secret is its path). */
function endpointOf(address: unknown): string {
  try {
    const u = new URL(String(address ?? ""));
    return `${u.protocol}//${u.host}`;
  } catch {
    return "";
  }
}

const toHook = (h: Json): GiteaHook => ({ type: String(h?.type ?? ""), endpoint: endpointOf(h?.config?.url), active: h?.active !== false });

/**
 * Whether a protection rule's pattern covers a branch. Gitea's patterns are globs where * stays within one path
 * segment and ** crosses them; a rule without wildcards names one branch.
 */
export function ruleCovers(pattern: string, branch: string): boolean {
  if (!/[*?[\]{}]/.test(pattern)) return pattern === branch;
  const source = pattern
    .replace(/[.+^$()|\\]/g, "\\$&")
    .replace(/\*\*/g, "\u0000")
    .replace(/\*/g, "[^/]*")
    .replace(/\u0000/g, ".*")
    .replace(/\?/g, "[^/]")
    .replace(/\{([^}]*)\}/g, (_m, alternatives: string) => `(?:${alternatives.split(",").join("|")})`);
  try {
    return new RegExp(`^${source}$`).test(branch);
  } catch {
    return false;
  }
}

/** The rule that applies to a branch: Gitea takes the first that matches, by priority and then as listed. */
export function ruleFor(rules: Json[], branch: string): GiteaBranchRule | null {
  const sorted = [...rules].sort((a, b) => (Number(a?.priority) || 0) - (Number(b?.priority) || 0));
  const r = sorted.find((x) => ruleCovers(String(x?.rule_name || x?.branch_name || ""), branch));
  if (!r) return null;
  const approvals = Number(r.required_approvals) || 0;
  return {
    rule: String(r.rule_name || r.branch_name || ""),
    directPush: r.enable_push === false ? "nobody" : r.enable_push_whitelist === true ? "listed" : "anyone",
    approvals,
    freshApproval: r.dismiss_stale_approvals === true || r.ignore_stale_approvals === true,
    // Before 1.23 a protected branch never took a force push, and the field isn't there.
    forcePush: typeof r.enable_force_push === "boolean" ? r.enable_force_push && r.enable_force_push_allowlist !== true : null,
    adminsBypass: typeof r.block_admin_merge_override === "boolean" ? !r.block_admin_merge_override : null,
  };
}

async function readRepo(client: GiteaClient, org: string, body: Json, orgVisibility: string, members: Set<string> | null): Promise<GiteaRepo> {
  const name = String(body.name ?? "");
  const path = `/repos/${org}/${encodeURIComponent(name)}`;
  const repo: GiteaRepo = {
    name,
    // A repository that isn't private is as visible as its organization: everyone, or everyone signed in.
    visibility:
      body.private === true ? "private" : body.internal === true || orgVisibility === "limited" || orgVisibility === "private" ? "internal" : "public",
    archived: body.archived === true,
    empty: body.empty === true,
    fork: body.fork === true,
    mirror: body.mirror === true,
    defaultBranch: String(body.default_branch ?? ""),
    updatedAt: Date.parse(String(body.updated_at ?? "")) || null,
    url: String(body.html_url ?? `${client.base}/${client.org}/${name}`),
    license: Array.isArray(body.licenses) && body.licenses.length ? String(body.licenses[0]) : null,
    protection: undefined,
    hooks: null,
    deployKeys: null,
    outsiders: null,
    pushMirrors: null,
  };
  const [rules, hooks, keys, collaborators, mirrors] = await Promise.all([
    // Every rule comes in one answer: this list isn't paged.
    client.get<Json[]>("protection", `${path}/branch_protections`),
    client.list<Json>("repoHooks", `${path}/hooks`),
    client.list<Json>("deployKeys", `${path}/keys`),
    members ? client.list<Json>("collaborators", `${path}/collaborators`) : null,
    // Push mirrors came with Gitea 1.17; an instance without them has none.
    client.list<Json>("pushMirrors", `${path}/push_mirrors`, { optional: true }),
  ]);
  if (rules) repo.protection = ruleFor(Array.isArray(rules) ? rules : [], repo.defaultBranch);
  if (hooks) repo.hooks = hooks.map(toHook);
  if (keys) repo.deployKeys = keys.map((k) => ({ title: String(k.title ?? ""), readOnly: k.read_only !== false }));
  if (mirrors) repo.pushMirrors = [...new Set(mirrors.map((m) => hostOnly(m?.remote_address)).filter(Boolean))];
  if (collaborators && members) {
    const outside = collaborators.map(loginOf).filter((l) => l && !members.has(l));
    repo.outsiders = [];
    for (const login of outside.slice(0, MAX_OUTSIDERS)) {
      try {
        const p = await client.raw(`${path}/collaborators/${encodeURIComponent(login)}/permission`);
        repo.outsiders.push({ login, permission: String(p?.permission ?? "read") });
      } catch (e) {
        client.note("collaborators", false, e as GiteaError);
        repo.outsiders = null;
        break;
      }
    }
  }
  return repo;
}

/** The host a mirror pushes to: "github.com". Its address can carry a username and password, which are never kept. */
function hostOnly(address: unknown): string {
  const text = String(address ?? "");
  try {
    return new URL(text).host.toLowerCase();
  } catch {
    // git@host:path
    return (/^[^@\s]+@([^:/\s]+)[:/]/.exec(text)?.[1] ?? "").toLowerCase();
  }
}

/**
 * Asks for one public repository without the token. An instance that requires sign-in answers 401, 403 or 404; one
 * that doesn't hands it over. With no public repository there is nothing to ask for.
 */
async function readAnonymous(client: GiteaClient, org: string, repos: GiteaRepo[]): Promise<boolean | null> {
  const open = repos.find((r) => r.visibility === "public");
  if (!open) {
    client.note("anonymous", true);
    return null;
  }
  try {
    const status = await client.anonymous(`/repos/${org}/${encodeURIComponent(open.name)}`);
    client.note("anonymous", true);
    return status === 200;
  } catch (e) {
    client.note("anonymous", false, e);
    return null;
  }
}

async function pool<T>(items: readonly T[], size: number, work: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(size, items.length) }, async () => {
      while (next < items.length) await work(items[next++]);
    }),
  );
}
