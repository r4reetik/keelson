// The default branch of every project with code: whether a change needs a merge
// request, whether its history can be rewritten, whether an approval still
// counts after more commits are pushed, and whether maintainers push past the
// merge request. GitLab adds up every protected branch rule that matches, so the
// loosest one counts.

import { defineChecks, withCode } from "./define.ts";
import { DEVELOPER } from "../types.ts";
import { DAY_MS } from "../../../shared/time.ts";

/** A project nobody has touched for this long is rated lower: an unreviewed change there is less likely. */
const IDLE_DAYS = 365;
const DOCS = "https://docs.gitlab.com/user/project/repository/branches/protected/";

export default defineChecks(
  {
    "GLB-001": {
      category: "Change risk",
      severity: "medium",
      docs: DOCS,
      requires: ["protection"],
      title: "Default branch accepts changes without a merge request",
      why: "Every developer, and every token or deploy key with their access, can push straight to the branch your releases come from, with no review and nothing to stop it.",
      fix: "1. Open the project's Settings → Repository → Protected branches. 2. Protect the default branch with Allowed to push and merge set to No one, so changes arrive as merge requests. 3. Set Allowed to merge to Maintainers, or to Developers and Maintainers with a required approval.",
    },
    "GLB-002": {
      category: "Change risk",
      severity: "medium",
      docs: DOCS,
      requires: ["protection"],
      title: "Default branch history can be rewritten",
      why: "The branch is protected, but force pushes are allowed. That replaces reviewed history, and removes the evidence of what was there.",
      fix: "In the project's Settings → Repository → Protected branches, turn off Allowed to force push for the default branch.",
    },
    "GLB-003": {
      category: "Change risk",
      severity: "medium",
      docs: "https://docs.gitlab.com/user/project/merge_requests/approvals/settings/",
      requires: ["approvals"],
      title: "An approved merge request can change before it merges",
      why: "Merge requests need an approval, but the approval stays after new commits are pushed, or the author can give it themselves. Someone can get a harmless change approved, then push something else and merge it unreviewed.",
      fix: "In the project's Settings → Merge requests → Approval settings, turn on Remove all approvals when commits are added to the source branch, and Prevent approval by merge request creator.",
    },
    "GLB-004": {
      category: "Change risk",
      severity: "low",
      docs: DOCS,
      requires: ["protection"],
      title: "Maintainers can push to the default branch without a merge request",
      why: "Developers go through merge requests, but maintainers and owners can push directly, as can the people and groups the rule names. Their sign-ins and tokens are the ones most worth stealing, and what they push is reviewed by nobody.",
      fix: "In the project's Settings → Repository → Protected branches, set Allowed to push and merge to No one for the default branch.",
    },
  },
  ({ inv, d }, report) => {
    for (const p of withCode(inv)) {
      const where = { zone: p.name, resource: `${p.name}:${p.defaultBranch}`, link: d.project(p.name, "settings/repository") };
      if (p.protection !== undefined) {
        const rule = p.protection;
        const idle = p.updatedAt != null && inv.now - p.updatedAt > IDLE_DAYS * DAY_MS;
        const open = !rule || (rule.pushLevel > 0 && rule.pushLevel <= DEVELOPER);
        const what = rule ? `Developers can push to ${p.defaultBranch}` : `${p.defaultBranch} isn't protected`;
        report("GLB-001", {
          ...where,
          pass: !open,
          severity: open && idle ? "low" : undefined,
          detail: open ? (idle ? `${what}; last active ${new Date(p.updatedAt!).toISOString().slice(0, 10)}` : what) : "",
        });
        if (rule) {
          report("GLB-002", { ...where, pass: !rule.forcePush, detail: rule.forcePush ? `${p.defaultBranch} takes force pushes` : "" });
          // Judged where developers already go through merge requests; where they don't, the first check says so.
          if (!open) {
            const direct = rule.pushLevel > 0 || rule.pushNamed;
            report("GLB-004", {
              ...where,
              pass: !direct,
              detail: direct
                ? rule.pushLevel > 0
                  ? "Maintainers can push directly"
                  : "The people, groups or deploy keys named on the rule can push directly"
                : "",
            });
          }
        }
      }
      // Null: the instance's plan has no approval rules, so there is nothing to judge.
      if (p.approvals && p.approvals.required > 0) {
        const a = p.approvals;
        const weak = [!a.resetOnPush && "approvals stay after new commits", a.authorApproves && "the author can approve"].filter(Boolean);
        report("GLB-003", {
          ...where,
          link: d.project(p.name, "settings/merge_requests"),
          pass: !weak.length,
          detail: weak.length ? `In ${p.name}, ${weak.join(" and ")}` : "",
        });
      }
    }
  },
);
