// The Gitea check catalog, built from the modules in checks/index.ts.

import { GITEA_MODULES, type GiteaCheckId } from "./checks/index.ts";
import type { CheckMeta } from "../../core/checks/define.ts";
import type { GiteaSourceKey } from "./sources.ts";

export interface GiteaCheckDef extends CheckMeta<GiteaSourceKey> {
  id: GiteaCheckId;
}

export const GITEA_CHECKS: GiteaCheckDef[] = GITEA_MODULES.flatMap((m) =>
  Object.entries(m.meta).map(([id, meta]) => ({ id: id as GiteaCheckId, ...(meta as CheckMeta<GiteaSourceKey>) })),
);

export const GITEA_CHECK_BY_ID: Record<string, GiteaCheckDef> = Object.fromEntries(GITEA_CHECKS.map((c) => [c.id, c]));
