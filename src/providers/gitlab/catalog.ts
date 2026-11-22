// The GitLab check catalog, built from the modules in checks/index.ts.

import { GITLAB_MODULES, type GitlabCheckId } from "./checks/index.ts";
import type { CheckMeta } from "../../core/checks/define.ts";
import type { GitlabSourceKey } from "./sources.ts";

export interface GitlabCheckDef extends CheckMeta<GitlabSourceKey> {
  id: GitlabCheckId;
}

export const GITLAB_CHECKS: GitlabCheckDef[] = GITLAB_MODULES.flatMap((m) =>
  Object.entries(m.meta).map(([id, meta]) => ({ id: id as GitlabCheckId, ...(meta as CheckMeta<GitlabSourceKey>) })),
);

export const GITLAB_CHECK_BY_ID: Record<string, GitlabCheckDef> = Object.fromEntries(GITLAB_CHECKS.map((c) => [c.id, c]));
