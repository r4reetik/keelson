// What a GitHub scan stores for the dashboard: one row per repository for the
// Repositories page, and the Pages custom domains Cloudflare's checks need.

import { branchGuard } from "./checks/branches.ts";
import { countBySeverity } from "../../shared/severity.ts";
import type { ProviderLinks, RepoRow } from "../../shared/api.ts";
import type { Result } from "../../core/types.ts";
import type { GithubInventory, GithubRepo } from "./types.ts";

function protectionOf(r: GithubRepo): string | null {
  if (r.archived || r.empty || r.protection === undefined || !r.rules) return null;
  const g = branchGuard(r);
  if (g.pullRequests) return `Pull request${g.reviews ? `, ${g.reviews} approval${g.reviews === 1 ? "" : "s"}` : ""}`;
  return g.protected ? "Protected" : "None";
}

export function repoRows(inv: GithubInventory, failures: Result[]): RepoRow[] {
  const count = (list: { repo: string; severity?: string }[] | null, name: string, serious: boolean) =>
    list ? list.filter((a) => a.repo === name && (!serious || a.severity === "critical" || a.severity === "high")).length : null;
  return inv.repos.map((r) => ({
    name: r.name,
    visibility: r.visibility,
    archived: r.archived,
    defaultBranch: r.defaultBranch,
    protection: protectionOf(r),
    secretScanning: r.security?.secretScanning ?? null,
    pushProtection: r.security?.pushProtection ?? null,
    alerts: {
      secrets: count(inv.secretScanning, r.name, false),
      dependabot: count(inv.dependabot, r.name, true),
      codeScanning: count(inv.codeScanning, r.name, true),
    },
    pages: r.pages ? (r.pages.cname ?? "github.io") : null,
    findings: countBySeverity(failures.filter((f) => f.zone === r.name)),
  }));
}

/**
 * What this organization shares with the entity's other accounts: its login, its Pages custom domains (for
 * Cloudflare's checks), and its repositories with whether their default branch needs a reviewed pull request
 * (for AWS roles that GitHub Actions can assume).
 */
export function githubLinks(inv: GithubInventory): ProviderLinks {
  const out: ProviderLinks = { githubOrgs: [inv.login.toLowerCase()] };
  // Repositories the App can't see, or a site or branch that couldn't be read, would make a list look complete when it isn't.
  const everyRepo = !inv.selectedRepos && !inv.unreadable.includes("repos");
  if (everyRepo && !inv.unreadable.includes("pages"))
    out.githubPages = inv.repos.flatMap((r) => (r.pages?.cname ? [{ host: r.pages.cname, repo: r.name }] : []));
  if (everyRepo && !inv.unreadable.includes("protection") && !inv.unreadable.includes("rules"))
    out.githubRepos = inv.repos.map((r) => ({
      repo: `${inv.login}/${r.name}`.toLowerCase(),
      defaultBranch: r.defaultBranch,
      // An archived repository can't be pushed to; an empty one has no branch yet, so nothing protects it.
      reviewed: r.archived || (r.protection !== undefined && !!r.rules && branchGuard(r).pullRequests),
    }));
  return out;
}
