// Turns a GitHub inventory into evaluations, findings and scores, with the same
// summary step as the other providers (src/core/engine.ts). Pure: no I/O.

import { Evaluator, type CheckModule } from "../../core/checks/define.ts";
import { summarize, type Evaluation } from "../../core/engine.ts";
import { NO_RELATED, type EngineOptions } from "../../core/types.ts";
import { GITHUB_MODULES } from "./checks/index.ts";
import { dash, type GithubContext } from "./checks/define.ts";
import { GITHUB_CHECK_BY_ID } from "./catalog.ts";
import type { GithubSourceKey } from "./sources.ts";
import type { GithubInventory } from "./types.ts";

export function evaluateGithub(inv: GithubInventory, opts: EngineOptions): Evaluation {
  const ev = new Evaluator(opts);
  const ctx: GithubContext = { inv, opts, d: dash(inv), related: { ...NO_RELATED, ...opts.related } };
  for (const m of GITHUB_MODULES as readonly CheckModule<string, GithubContext, GithubSourceKey>[]) ev.runWith(m, ctx, inv.unreadable);
  return summarize(inv.accountId, ev.results, opts, GITHUB_CHECK_BY_ID);
}
