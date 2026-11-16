// Turns an entity's outside view into evaluations, findings and scores, with the
// same summary step as the other providers (src/core/engine.ts). Pure: no I/O.

import { Evaluator, type CheckModule } from "../../core/checks/define.ts";
import { summarize, type Evaluation } from "../../core/engine.ts";
import { NO_RELATED, type EngineOptions } from "../../core/types.ts";
import { INTERNET_MODULES } from "./checks/index.ts";
import { INTERNET_CHECK_BY_ID } from "./catalog.ts";
import type { InternetContext } from "./checks/define.ts";
import type { InternetSourceKey } from "./sources.ts";
import type { InternetInventory } from "./types.ts";

export function evaluateInternet(inv: InternetInventory, opts: EngineOptions): Evaluation {
  const ev = new Evaluator(opts);
  const ctx: InternetContext = { inv, opts, related: { ...NO_RELATED, ...opts.related } };
  for (const m of INTERNET_MODULES as readonly CheckModule<string, InternetContext, InternetSourceKey>[]) ev.runWith(m, ctx, inv.unreadable);
  return summarize(inv.accountId, ev.results, opts, INTERNET_CHECK_BY_ID);
}
