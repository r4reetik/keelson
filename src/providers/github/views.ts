// What a GitHub scan stores for the dashboard: one row per repository for the
// Repositories page, and the Pages custom domains Cloudflare's checks need.

import { branchGuard } from "./checks/branches.ts";
import { countBySeverity } from "../../shared/severity.ts";
import type { ProviderLinks, RepoDependencySummary, RepoRow } from "../../shared/api.ts";
import type { RepoDependencies } from "../../shared/dependencies.ts";
import type { Result } from "../../core/types.ts";
import type { GithubInventory, GithubRepo } from "./types.ts";

function protectionOf(r: GithubRepo): string | null {
  if (r.archived || r.empty || r.protection === undefined || !r.rules) return null;
  const g = branchGuard(r);
  if (g.pullRequests) return `Pull request${g.reviews ? `, ${g.reviews} approval${g.reviews === 1 ? "" : "s"}` : ""}`;
  return g.protected ? "Protected" : "None";
}

/** A repository's dependencies in a line: languages, projects, packages, vulnerabilities and licenses. */
export function dependencySummary(d: RepoDependencies, grype: boolean, grant: boolean): RepoDependencySummary {
  const total = Object.values(d.languages ?? {}).reduce((a, b) => a + b, 0);
  const languages = Object.entries(d.languages ?? {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([name, bytes]) => ({ name, share: total ? Math.round((1000 * bytes) / total) / 10 : 0 }));
  const pkgs = d.packages;
  const vulns = { critical: 0, high: 0, medium: 0, low: 0 };
  let exploited = 0;
  for (const p of pkgs ?? [])
    for (const v of p.vulns) {
      if (v.severity in vulns) vulns[v.severity as keyof typeof vulns]++;
      if (v.kev) exploited++;
    }
  const code = d.parts.filter((p) => !p.workflows);
  return {
    generatedAt: new Date(d.generatedAt).toISOString(),
    languages,
    ecosystems: [...new Set([...code.flatMap((p) => p.ecosystems), ...(pkgs ?? []).map((p) => p.ecosystem)])].sort(),
    parts: code.length,
    packages: pkgs ? pkgs.length : null,
    vulnerable: pkgs && grype ? pkgs.filter((p) => p.vulns.length).length : null,
    vulns: pkgs && grype ? vulns : null,
    exploited: pkgs && grype ? exploited : null,
    copyleft: pkgs && grant ? pkgs.filter((p) => p.licenseRisk === "strong").length : null,
    unlocked: code.filter((p) => p.unpinned.length).length,
    partial: d.partial,
  };
}

export function repoRows(inv: GithubInventory, failures: Result[]): RepoRow[] {
  const count = (list: { repo: string; severity?: string }[] | null, name: string, serious: boolean) =>
    list ? list.filter((a) => a.repo === name && (!serious || a.severity === "critical" || a.severity === "high")).length : null;
  const deps = new Map((inv.dependencies?.repos ?? []).map((d) => [d.repo, d]));
  const grype = !inv.unreadable.includes("grype") && !!inv.dependencies?.tools.grype;
  const grant = !inv.unreadable.includes("grant") && !!inv.dependencies?.tools.grant;
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
    dependencies: deps.has(r.name) ? dependencySummary(deps.get(r.name)!, grype, grant) : null,
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
  // Which images each repository's workflows push: complete only when every repository's workflows were read.
  if (everyRepo && inv.dependencies && !inv.unreadable.includes("manifests"))
    out.githubImageBuilds = inv.dependencies.repos.flatMap((d) => (d.builds ?? []).map((b) => ({ ...b, repo: `${inv.login}/${d.repo}`.toLowerCase() })));
  return out;
}
