// What a GitLab scan stores for the dashboard: one row per project for the
// Repositories page, in the shape GitHub's rows have, and what the group shares
// with the entity's other accounts: its path, its projects with whether their
// default branch needs a merge request, and its Pages sites' custom domains.

import { countBySeverity } from "../../shared/severity.ts";
import { dependencySummary } from "../github/views.ts";
import { DEVELOPER, type GitlabInventory, type GitlabProject } from "./types.ts";
import type { ProviderLinks, RepoRow } from "../../shared/api.ts";
import type { Result } from "../../core/types.ts";

/** Whether changes to the default branch arrive as merge requests: protected, and developers can't push to it. */
const reviewed = (p: GitlabProject): boolean => !!p.protection && !(p.protection.pushLevel > 0 && p.protection.pushLevel <= DEVELOPER);

function protectionOf(p: GitlabProject): string | null {
  if (p.archived || p.mirror || p.empty || p.protection === undefined) return null;
  if (!p.protection) return "None";
  if (!reviewed(p)) return "Protected";
  const n = p.approvals?.required ?? 0;
  return `Merge request${n ? `, ${n} approval${n === 1 ? "" : "s"}` : ""}`;
}

export function repoRows(inv: GitlabInventory, failures: Result[]): RepoRow[] {
  const deps = new Map((inv.dependencies?.repos ?? []).map((d) => [d.repo, d]));
  const grype = !inv.unreadable.includes("grype") && !!inv.dependencies?.tools.grype;
  const grant = !inv.unreadable.includes("grant") && !!inv.dependencies?.tools.grant;
  return inv.projects.map((p) => ({
    name: p.name,
    owner: inv.login,
    url: p.url,
    visibility: p.visibility,
    archived: p.archived,
    defaultBranch: p.defaultBranch,
    protection: protectionOf(p),
    secretScanning: null,
    pushProtection: null,
    alerts: { secrets: null, dependabot: null, codeScanning: null },
    pages: null,
    dependencies: deps.has(p.name) ? dependencySummary(deps.get(p.name)!, grype, grant) : null,
    findings: countBySeverity(failures.filter((f) => f.zone === p.name)),
  }));
}

/**
 * What this group shares with the entity's other accounts. A list is left out when it couldn't all be read: an
 * incomplete one would make a DNS record or a cloud role look like nobody's.
 */
export function gitlabLinks(inv: GitlabInventory): ProviderLinks {
  const host = new URL(inv.base).host.toLowerCase();
  const out: ProviderLinks = { gitlabGroups: [{ host, group: inv.login.toLowerCase() }] };
  const every = !inv.unreadable.includes("projects");
  if (every && !inv.unreadable.includes("pages"))
    out.gitlabPages = inv.projects.flatMap((p) => (p.pagesDomains ?? []).map((d) => ({ host: d, repo: p.fullPath })));
  if (every && !inv.unreadable.includes("protection"))
    out.gitlabProjects = inv.projects.map((p) => ({
      host,
      repo: p.fullPath.toLowerCase(),
      defaultBranch: p.defaultBranch,
      // An archived project can't be pushed to.
      reviewed: p.archived || reviewed(p),
    }));
  return out;
}
