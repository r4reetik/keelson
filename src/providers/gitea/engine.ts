// Turns a Gitea inventory into evaluations, findings and scores, with the same
// summary step as the other providers (src/core/engine.ts). Pure: no I/O.

import { Evaluator, type CheckModule } from "../../core/checks/define.ts";
import { summarize, type Evaluation } from "../../core/engine.ts";
import type { EngineOptions } from "../../core/types.ts";
import { GITEA_MODULES } from "./checks/index.ts";
import { dash, type GiteaContext } from "./checks/define.ts";
import { GITEA_CHECK_BY_ID } from "./catalog.ts";
import type { GiteaSourceKey } from "./sources.ts";
import type { GiteaInventory } from "./types.ts";

export function evaluateGitea(inv: GiteaInventory, opts: EngineOptions): Evaluation {
  const ev = new Evaluator(opts);
  const ctx: GiteaContext = { inv, opts, d: dash(inv) };
  for (const m of GITEA_MODULES as readonly CheckModule<string, GiteaContext, GiteaSourceKey>[]) ev.runWith(m, ctx, inv.unreadable);
  return summarize(inv.accountId, ev.results, opts, GITEA_CHECK_BY_ID);
}
