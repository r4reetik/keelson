// The default branch of every repository with code: whether a change needs a
// pull request, whether an approval still counts after more commits are pushed,
// whether its history can be rewritten, and whether owners skip the rules. Classic branch protection and rulesets (the repository's and the
// organization's) count the same; either one is enough.

import { defineChecks, withCode } from "./define.ts";
import { DAY_MS } from "../../../shared/time.ts";
import type { GithubRepo } from "../types.ts";

/** A repository nobody has pushed to for this long is rated lower: an unreviewed change there is less likely, and it likely deploys nothing. */
const IDLE_DAYS = 365;

/** What protects the branch, combining classic protection and every ruleset that applies to it. */
export function branchGuard(r: GithubRepo) {
  const p = r.protection;
  const rules = r.rules ?? [];
  const prRule = rules.find((x) => x.type === "pull_request");
  return {
    protected: !!p || rules.length > 0,
    pullRequests: p?.reviews != null || !!prRule,
    reviews: Math.max(p?.reviews ?? 0, prRule?.reviews ?? 0),
    blocksForcePush: (!!p && !p.allowForcePushes) || rules.some((x) => x.type === "non_fast_forward"),
    blocksDeletion: (!!p && !p.allowDeletions) || rules.some((x) => x.type === "deletion"),
    /** A push after an approval needs a new one: stale approvals are dismissed, or the last push must be approved by someone else. */
    freshApproval:
      (p?.reviews != null && (p.dismissStale || p.lastPushApproval)) || rules.some((x) => x.type === "pull_request" && (x.dismissStale || x.lastPushApproval)),
    /** Only classic protection can let administrators past it; rulesets name their bypass list instead. */
    adminsBypass: !!p && p.reviews != null && !p.enforceAdmins && !prRule,
  };
}

export default defineChecks(
  {
    "GBR-001": {
      category: "Change risk",
      severity: "medium",
      docs: "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets",
      requires: ["protection", "rules"],
      title: "Default branch accepts changes without a pull request",
      why: "Anyone with write access, or a token or deploy key that has it, can push straight to the branch your releases come from, with no review and nothing in the history to stop it.",
      fix: "1. Under the organization's Settings → Repository → Rulesets (or the repository's Settings → Rules), create a branch ruleset targeting the default branch. 2. Turn on Require a pull request before merging, with at least one approval. 3. Turn on Block force pushes and Restrict deletions.",
    },
    "GBR-002": {
      category: "Change risk",
      severity: "medium",
      docs: "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets",
      requires: ["protection", "rules"],
      title: "Default branch history can be rewritten or deleted",
      why: "The branch is protected, but a force push or deletion is still allowed. That rewrites or removes reviewed history, which also removes the evidence of what was there.",
      fix: "In the rule or ruleset that protects the default branch, turn on Block force pushes and Restrict deletions.",
    },
    "GBR-004": {
      category: "Change risk",
      severity: "medium",
      docs: "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#require-a-pull-request-before-merging",
      requires: ["protection", "rules"],
      title: "An approved pull request can change before it merges",
      why: "The default branch needs an approval, but the approval stays after new commits are pushed. Someone can get a harmless change approved, then push something else to the same pull request and merge it without anyone reviewing it.",
      fix: "In the rule or ruleset that protects the default branch, turn on Dismiss stale pull request approvals when new commits are pushed. Also turn on Require approval of the most recent reviewable push, so a reviewer can't push to a pull request and approve their own change.",
    },
    "GBR-003": {
      category: "Change risk",
      severity: "low",
      docs: "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#do-not-allow-bypassing-the-above-settings",
      requires: ["protection", "rules"],
      title: "Administrators can skip the default branch's review rule",
      why: "Branch protection requires a pull request, but repository administrators and owners can push past it. Their logins and tokens are the ones most worth stealing.",
      fix: "In the branch protection rule, tick Do not allow bypassing the above settings, or move the rule to a ruleset and list only who may bypass it.",
    },
  },
  ({ inv, d }, report) => {
    for (const r of withCode(inv)) {
      if (r.protection === undefined || !r.rules) continue;
      const g = branchGuard(r);
      const where = { zone: r.name, resource: `${r.name}:${r.defaultBranch}`, link: d.repo(r.name, "settings/rules") };
      const idle = r.pushedAt != null && inv.now - r.pushedAt > IDLE_DAYS * DAY_MS;
      const unreviewed = g.protected ? `${r.defaultBranch} is protected, but doesn't require a pull request` : `${r.defaultBranch} has no protection`;
      report("GBR-001", {
        ...where,
        pass: g.pullRequests,
        severity: !g.pullRequests && idle ? "low" : undefined,
        detail: g.pullRequests ? "" : idle ? `${unreviewed}; last push ${new Date(r.pushedAt!).toISOString().slice(0, 10)}` : unreviewed,
      });
      if (!g.protected) continue;
      const gaps = [!g.blocksForcePush && "force pushes", !g.blocksDeletion && "deletion"].filter(Boolean);
      report("GBR-002", { ...where, pass: !gaps.length, detail: gaps.length ? `${r.defaultBranch} allows ${gaps.join(" and ")}` : "" });
      if (g.pullRequests) report("GBR-003", { ...where, pass: !g.adminsBypass, detail: g.adminsBypass ? "Administrators aren't held to the rule" : "" });
      // Without a required approval there is nothing to go stale; GBR-001 covers that branch.
      if (g.reviews > 0)
        report("GBR-004", {
          ...where,
          pass: g.freshApproval,
          detail: g.freshApproval ? "" : `An approval of a pull request into ${r.defaultBranch} still counts after new commits`,
        });
    }
  },
);
