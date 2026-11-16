// The internet (Sonar) check catalog, built from the modules in checks/index.ts.

import { INTERNET_MODULES, type InternetCheckId } from "./checks/index.ts";
import type { CheckMeta } from "../../core/checks/define.ts";
import type { InternetSourceKey } from "./sources.ts";

export interface InternetCheckDef extends CheckMeta<InternetSourceKey> {
  id: InternetCheckId;
}

export const INTERNET_CHECKS: InternetCheckDef[] = INTERNET_MODULES.flatMap((m) =>
  Object.entries(m.meta).map(([id, meta]) => ({ id: id as InternetCheckId, ...(meta as CheckMeta<InternetSourceKey>) })),
);

export const INTERNET_CHECK_BY_ID: Record<string, InternetCheckDef> = Object.fromEntries(INTERNET_CHECKS.map((c) => [c.id, c]));
