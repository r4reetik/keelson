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

/** The custom domains this organization's Pages sites serve, for Cloudflare's checks in the same entity. */
export function githubLinks(inv: GithubInventory): ProviderLinks {
  // A site that couldn't be read, or repositories the App can't see, would make a hostname look unclaimed.
  if (inv.selectedRepos || inv.unreadable.includes("pages") || inv.unreadable.includes("repos")) return {};
  const githubPages = inv.repos.flatMap((r) => (r.pages?.cname ? [{ host: r.pages.cname, repo: r.name }] : []));
  return { githubPages };
}
