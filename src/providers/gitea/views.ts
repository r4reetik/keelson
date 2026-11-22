// What a Gitea scan stores for the dashboard: one row per repository for the
// Repositories page, in the shape GitHub's rows have, with its dependencies in
// a line. What only GitHub has (secret scanning, its alerts, Pages) stays null.

import { countBySeverity } from "../../shared/severity.ts";
import { dependencySummary } from "../github/views.ts";
import type { RepoRow } from "../../shared/api.ts";
import type { Result } from "../../core/types.ts";
import type { GiteaInventory, GiteaRepo } from "./types.ts";

function protectionOf(r: GiteaRepo): string | null {
  if (r.archived || r.mirror || r.empty || r.protection === undefined) return null;
  const p = r.protection;
  if (!p) return "None";
  if (p.directPush === "anyone") return "Protected";
  return `Pull request${p.approvals ? `, ${p.approvals} approval${p.approvals === 1 ? "" : "s"}` : ""}`;
}

export function repoRows(inv: GiteaInventory, failures: Result[]): RepoRow[] {
  const deps = new Map((inv.dependencies?.repos ?? []).map((d) => [d.repo, d]));
  const grype = !inv.unreadable.includes("grype") && !!inv.dependencies?.tools.grype;
  const grant = !inv.unreadable.includes("grant") && !!inv.dependencies?.tools.grant;
  return inv.repos.map((r) => ({
    name: r.name,
    owner: inv.login,
    url: r.url,
    visibility: r.visibility,
    archived: r.archived,
    defaultBranch: r.defaultBranch,
    protection: protectionOf(r),
    secretScanning: null,
    pushProtection: null,
    alerts: { secrets: null, dependabot: null, codeScanning: null },
    pages: null,
    dependencies: deps.has(r.name) ? dependencySummary(deps.get(r.name)!, grype, grant) : null,
    findings: countBySeverity(failures.filter((f) => f.zone === r.name)),
  }));
}
