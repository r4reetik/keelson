// The Alibaba Cloud check catalog, built from the modules in checks/index.ts.

import { ALIBABA_MODULES, type AlibabaCheckId } from "./checks/index.ts";
import type { CheckMeta } from "../../core/checks/define.ts";
import type { AlibabaSourceKey } from "./sources.ts";

export interface AlibabaCheckDef extends CheckMeta<AlibabaSourceKey> {
  id: AlibabaCheckId;
}

export const ALIBABA_CHECKS: AlibabaCheckDef[] = ALIBABA_MODULES.flatMap((m) =>
  Object.entries(m.meta).map(([id, meta]) => ({ id: id as AlibabaCheckId, ...(meta as CheckMeta<AlibabaSourceKey>) })),
);

export const ALIBABA_CHECK_BY_ID: Record<string, AlibabaCheckDef> = Object.fromEntries(ALIBABA_CHECKS.map((c) => [c.id, c]));
