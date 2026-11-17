// Turns an Alibaba Cloud inventory into evaluations, findings and scores, with the
// same summary step as the other providers (src/core/engine.ts). Pure: no I/O.

import { Evaluator, type CheckModule } from "../../core/checks/define.ts";
import { summarize, type Evaluation } from "../../core/engine.ts";
import { NO_RELATED, type EngineOptions } from "../../core/types.ts";
import { ALIBABA_MODULES } from "./checks/index.ts";
import { dash, type AlibabaContext } from "./checks/define.ts";
import { ALIBABA_CHECK_BY_ID } from "./catalog.ts";
import type { AlibabaSourceKey } from "./sources.ts";
import type { AlibabaInventory } from "./types.ts";

export function evaluateAlibaba(inv: AlibabaInventory, opts: EngineOptions): Evaluation {
  const ev = new Evaluator(opts);
  const ctx: AlibabaContext = { inv, opts, d: dash, related: { ...NO_RELATED, ...opts.related } };
  for (const m of ALIBABA_MODULES as readonly CheckModule<string, AlibabaContext, AlibabaSourceKey>[]) ev.runWith(m, ctx, inv.unreadable);
  return summarize(inv.accountId, ev.results, opts, ALIBABA_CHECK_BY_ID);
}
