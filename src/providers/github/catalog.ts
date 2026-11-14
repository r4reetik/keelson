// The GitHub check catalog, built from the modules in checks/index.ts.

import { GITHUB_MODULES, type GithubCheckId } from "./checks/index.ts";
import type { CheckMeta } from "../../core/checks/define.ts";
import type { GithubSourceKey } from "./sources.ts";

export interface GithubCheckDef extends CheckMeta<GithubSourceKey> {
  id: GithubCheckId;
}

export const GITHUB_CHECKS: GithubCheckDef[] = GITHUB_MODULES.flatMap((m) =>
  Object.entries(m.meta).map(([id, meta]) => ({ id: id as GithubCheckId, ...(meta as CheckMeta<GithubSourceKey>) })),
);

export const GITHUB_CHECK_BY_ID: Record<string, GithubCheckDef> = Object.fromEntries(GITHUB_CHECKS.map((c) => [c.id, c]));
