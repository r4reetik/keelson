// How GitHub check modules are written: the same shape as the other providers'
// (see src/core/checks/define.ts), over a GitHub inventory. A finding's `zone` is
// the repository's name, or null for settings of the whole organization.
//
//   export default defineChecks({
//     "GBR-001": { category: "Change risk", severity: "medium", title: "…", why: "…", fix: "…", requires: ["protection", "rules"] },
//   }, ({ inv, d }, report) => {
//     for (const r of active(inv)) report("GBR-001", { zone: r.name, resource: r.name, pass: …, link: d.repo(r.name, "settings/rules") });
//   });

import { checksFor } from "../../../core/checks/define.ts";
import type { EngineOptions } from "../../../core/types.ts";
import type { GithubSourceKey } from "../sources.ts";
import type { GithubInventory, GithubRepo, Related } from "../types.ts";

export interface GithubContext {
  inv: GithubInventory;
  opts: EngineOptions;
  /** Links into GitHub's settings pages. */
  d: ReturnType<typeof dash>;
  /** What the entity's other providers know, for checks that span providers. */
  related: Related;
}

export const defineChecks = checksFor<GithubContext, GithubSourceKey>();

export function dash(inv: Pick<GithubInventory, "login">) {
  const org = encodeURIComponent(inv.login);
  const settings = (page: string) => `https://github.com/organizations/${org}/settings/${page}`;
  return {
    settings,
    owners: `https://github.com/orgs/${org}/people?query=role%3Aowner`,
    repo: (name: string, page = "") => `https://github.com/${org}/${encodeURIComponent(name)}${page ? `/${page}` : ""}`,
  };
}

/** Repositories that can still change: not archived. Archived ones are read-only on GitHub. */
export const active = (inv: GithubInventory): GithubRepo[] => inv.repos.filter((r) => !r.archived);

/** Repositories with code on a default branch, where branch protection means something. */
export const withCode = (inv: GithubInventory): GithubRepo[] => active(inv).filter((r) => !r.empty);
