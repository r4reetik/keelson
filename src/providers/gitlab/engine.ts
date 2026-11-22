// Turns a GitLab inventory into evaluations, findings and scores, with the same
// summary step as the other providers (src/core/engine.ts). Pure: no I/O.

import { Evaluator, type CheckModule } from "../../core/checks/define.ts";
import { summarize, type Evaluation } from "../../core/engine.ts";
import { NO_RELATED, type EngineOptions } from "../../core/types.ts";
import { GITLAB_MODULES } from "./checks/index.ts";
import { dash, type GitlabContext } from "./checks/define.ts";
import { GITLAB_CHECK_BY_ID } from "./catalog.ts";
import type { GitlabSourceKey } from "./sources.ts";
import type { GitlabInventory } from "./types.ts";

export function evaluateGitlab(inv: GitlabInventory, opts: EngineOptions): Evaluation {
  const ev = new Evaluator(opts);
  const ctx: GitlabContext = { inv, opts, d: dash(inv), related: { ...NO_RELATED, ...opts.related } };
  for (const m of GITLAB_MODULES as readonly CheckModule<string, GitlabContext, GitlabSourceKey>[]) ev.runWith(m, ctx, inv.unreadable);
  return summarize(inv.accountId, ev.results, opts, GITLAB_CHECK_BY_ID);
}
