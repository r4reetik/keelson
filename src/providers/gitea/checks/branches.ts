// The default branch of every repository with code: whether a change needs a
// pull request, whether an approval still counts after more commits are pushed,
// whether its history can be rewritten, and whether administrators skip the
// rule. One rule applies to a branch: the first whose pattern covers it.

import { defineChecks, withCode } from "./define.ts";
import { DAY_MS } from "../../../shared/time.ts";

/** A repository nobody has changed for this long is rated lower: an unreviewed change there is less likely. */
const IDLE_DAYS = 365;
const DOCS = "https://docs.gitea.com/usage/access-control/protected-branches";

export default defineChecks(
  {
    "TEB-001": {
      category: "Change risk",
      severity: "medium",
      docs: DOCS,
      requires: ["protection"],
      title: "Default branch accepts changes without a pull request",
      why: "Anyone with write access, or a token or deploy key that has it, can push straight to the branch your releases come from, with no review and nothing to stop it.",
      fix: "1. Open the repository's Settings → Branches and add a rule for the default branch. 2. Under Push, choose Disable push, so changes arrive as pull requests. 3. Set Required approvals to at least 1.",
    },
    "TEB-002": {
      category: "Change risk",
      severity: "medium",
      docs: DOCS,
      requires: ["protection"],
      title: "Default branch history can be rewritten",
      why: "The branch has a rule, but it lets anyone with write access force push. That replaces reviewed history, and removes the evidence of what was there.",
      fix: "In the rule for the default branch (Settings → Branches), set Force push to Disable, or to an allowlist of the few who need it.",
    },
    "TEB-003": {
      category: "Change risk",
      severity: "medium",
      docs: DOCS,
      requires: ["protection"],
      title: "An approved pull request can change before it merges",
      why: "The default branch needs an approval, but the approval stays after new commits are pushed. Someone can get a harmless change approved, then push something else to the same pull request and merge it unreviewed.",
      fix: "In the rule for the default branch (Settings → Branches), turn on Dismiss stale approvals, or Ignore stale approvals so they stop counting.",
    },
    "TEB-004": {
      category: "Change risk",
      severity: "low",
      docs: DOCS,
      requires: ["protection"],
      title: "Administrators can merge past the default branch's rule",
      why: "The rule requires a pull request, but repository administrators and owners can merge without meeting it. Their sign-ins and tokens are the ones most worth stealing.",
      fix: "In the rule for the default branch (Settings → Branches), turn on Block merge on administrators' override (Gitea 1.23 and later).",
    },
  },
  ({ inv, d }, report) => {
    for (const r of withCode(inv)) {
      if (r.protection === undefined) continue;
      const p = r.protection;
      const where = { zone: r.name, resource: `${r.name}:${r.defaultBranch}`, link: d.repo(r.name, "settings/branches") };
      const idle = r.updatedAt != null && inv.now - r.updatedAt > IDLE_DAYS * DAY_MS;
      const open = !p || p.directPush === "anyone";
      const what = p ? `${r.defaultBranch} has a rule, but anyone with write access can still push to it` : `${r.defaultBranch} has no rule`;
      report("TEB-001", {
        ...where,
        pass: !open,
        severity: open && idle ? "low" : undefined,
        detail: open ? (idle ? `${what}; last changed ${new Date(r.updatedAt!).toISOString().slice(0, 10)}` : what) : "",
      });
      if (!p) continue;
      // An instance that doesn't say never allowed it: a protected branch took no force push before the setting existed.
      report("TEB-002", {
        ...where,
        pass: p.forcePush !== true,
        detail: p.forcePush ? `${r.defaultBranch} takes force pushes from anyone with write access` : "",
      });
      if (p.approvals > 0)
        report("TEB-003", {
          ...where,
          pass: p.freshApproval,
          detail: p.freshApproval ? "" : `An approval of a pull request into ${r.defaultBranch} still counts after new commits`,
        });
      if (!open && p.adminsBypass != null)
        report("TEB-004", { ...where, pass: !p.adminsBypass, detail: p.adminsBypass ? "Administrators aren't held to the rule" : "" });
    }
  },
);
