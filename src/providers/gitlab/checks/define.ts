// How GitLab check modules are written: the same shape as the other providers'
// (see src/core/checks/define.ts), over a GitLab inventory. A finding's `zone` is
// the project's path below the group, or null for what belongs to the group.

import { checksFor } from "../../../core/checks/define.ts";
import type { EngineOptions } from "../../../core/types.ts";
import type { GitlabSourceKey } from "../sources.ts";
import type { GitlabInventory, GitlabProject, Related } from "../types.ts";

export interface GitlabContext {
  inv: GitlabInventory;
  opts: EngineOptions;
  /** Links into the instance's own pages. */
  d: ReturnType<typeof dash>;
  /** What the entity's other providers know, for checks that span providers. */
  related: Related;
}

export const defineChecks = checksFor<GitlabContext, GitlabSourceKey>();

export function dash(inv: Pick<GitlabInventory, "login" | "base">) {
  return {
    group: (page = "") => `${inv.base}/groups/${inv.login}${page ? `/-/${page}` : ""}`,
    project: (name: string, page = "") => `${inv.base}/${inv.login}/${name}${page ? `/-/${page}` : ""}`,
  };
}

/** Projects that can still change: not archived, and not a copy the instance pulls from elsewhere. */
export const active = (inv: GitlabInventory): GitlabProject[] => inv.projects.filter((p) => !p.archived && !p.mirror);

/** Projects with code on a default branch, where a rule on it means something. */
export const withCode = (inv: GitlabInventory): GitlabProject[] => active(inv).filter((p) => !p.empty && !!p.defaultBranch);
