// How Gitea check modules are written: the same shape as the other providers'
// (see src/core/checks/define.ts), over a Gitea inventory. A finding's `zone` is
// the repository's name, or null for what belongs to the whole organization.

import { checksFor } from "../../../core/checks/define.ts";
import type { EngineOptions } from "../../../core/types.ts";
import type { GiteaSourceKey } from "../sources.ts";
import type { GiteaInventory, GiteaRepo } from "../types.ts";

export interface GiteaContext {
  inv: GiteaInventory;
  opts: EngineOptions;
  /** Links into the instance's own pages. */
  d: ReturnType<typeof dash>;
}

export const defineChecks = checksFor<GiteaContext, GiteaSourceKey>();

export function dash(inv: Pick<GiteaInventory, "login" | "base">) {
  const org = encodeURIComponent(inv.login);
  return {
    org: (page = "") => `${inv.base}/org/${org}${page ? `/${page}` : ""}`,
    repo: (name: string, page = "") => `${inv.base}/${org}/${encodeURIComponent(name)}${page ? `/${page}` : ""}`,
    user: (login: string) => `${inv.base}/${encodeURIComponent(login)}`,
  };
}

/** Repositories that can still change: not archived, and not a copy the instance pulls from elsewhere. */
export const active = (inv: GiteaInventory): GiteaRepo[] => inv.repos.filter((r) => !r.archived && !r.mirror);

/** Repositories with code on a default branch, where a rule on it means something. */
export const withCode = (inv: GiteaInventory): GiteaRepo[] => active(inv).filter((r) => !r.empty && !!r.defaultBranch);

/** The members of the organization's owner teams, or null when no such team's members could be read. */
export function owners(inv: GiteaInventory): string[] | null {
  const teams = (inv.teams ?? []).filter((t) => t.permission === "owner");
  if (!teams.length || teams.some((t) => !t.members)) return null;
  return [...new Set(teams.flatMap((t) => t.members!))];
}
