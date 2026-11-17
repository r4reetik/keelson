// IAM roles that GitHub Actions can assume, through GitHub's OIDC provider
// (token.actions.githubusercontent.com). What protects such a role is the trust
// policy's condition on the token's subject: which repository, and which branch or
// environment, may assume it. AID-012 needs only the role. The two XP- checks compare
// it with the entity's GitHub organizations, from their latest scans, and are
// skipped when the entity has none.

import { defineChecks } from "./define.ts";
import { judgeGithubTrust, pushReasons, shortList as list } from "../../../core/github-trust.ts";
import { GLOBAL, type AwsRole } from "../types.ts";

/** The GitHub subjects a role trusts, or null when GitHub Actions can't assume it. An empty list means any repository. */
function githubTrust(r: AwsRole): string[] | null {
  const trusts = r.trust.filter((t) => t.github);
  if (!trusts.length) return null;
  return trusts.some((t) => !t.github!.length) ? [] : trusts.flatMap((t) => t.github!);
}

export default defineChecks(
  {
    "AID-012": {
      category: "Identity & access",
      severity: "critical",
      docs: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html#idp_oidc_Create_GitHub",
      requires: ["iamDetails"],
      attackPath: true,
      title: "GitHub Actions in any repository can assume this IAM role",
      why: "The role trusts GitHub's OIDC provider without limiting the token's subject to your repositories. A workflow in anyone's repository, on any GitHub account, can get a token GitHub signs and assume the role.",
      fix: "Open the role in IAM → Trust relationships and add a condition on token.actions.githubusercontent.com:sub naming your organization and repository, for example repo:your-org/your-repo:ref:refs/heads/main or repo:your-org/your-repo:environment:production.",
    },
    "XP-010": {
      spans: ["github"],
      category: "Identity & access",
      severity: "high",
      docs: "https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect",
      requires: ["iamDetails"],
      title: "IAM role trusts GitHub repositories outside the entity",
      why: "GitHub Actions in a GitHub organization that isn't one of the entity's can assume this role. That organization's members, and anyone who gets write access to its repositories, get the role's AWS access.",
      fix: "1. If the organization is yours, add it to this entity in Keelson. 2. If it belongs to a vendor, confirm they still need the role and limit it to the repository and branch they use. 3. Otherwise remove it from the role's trust policy.",
    },
    "XP-011": {
      spans: ["github"],
      category: "Identity & access",
      severity: "high",
      docs: "https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect#example-subject-claims",
      requires: ["iamDetails"],
      attackPath: true,
      title: "Anyone who can push to the repository can assume this IAM role",
      why: "The role trusts GitHub Actions from a repository in the entity, either from any branch or pull request, or from a default branch that takes changes without review. Anyone with write access, or a stolen token or deploy key that has it, can push a workflow and act as the role in AWS.",
      fix: "1. Limit the trust policy's subject to the protected default branch (repo:org/repo:ref:refs/heads/main) or, better, to a GitHub environment with required reviewers (repo:org/repo:environment:production). 2. Require a reviewed pull request on that branch in GitHub.",
    },
  },
  ({ inv, d, related }, report) => {
    if (!inv.roles) return;
    for (const r of inv.roles) {
      const subjects = githubTrust(r);
      if (!subjects) continue;
      const where = { zone: GLOBAL, resource: r.name, link: d.role(r.name) };
      const admin = r.admin ? ", and the role has administrator access" : "";
      const v = judgeGithubTrust(subjects, related.githubOrgs, related.githubRepos);

      report("AID-012", { ...where, pass: !v.open.length, detail: v.open.length ? `Trusts GitHub Actions with ${list(v.open)}${admin}` : "" });
      if (v.open.length) continue;

      if (v.outside)
        report("XP-010", {
          ...where,
          pass: !v.outside.length,
          severity: v.outside.length && r.admin ? "critical" : undefined,
          confidence: v.outside.length ? "likely" : undefined,
          detail: v.outside.length ? `GitHub organization${v.outside.length === 1 ? "" : "s"} ${list(v.outside)} can assume it${admin}` : "",
        });

      // A role limited to environments, or to repositories outside the entity, isn't judged here.
      if (!v.trusted) continue;
      const reasons = pushReasons(v);
      report("XP-011", {
        ...where,
        pass: !reasons.length,
        severity: reasons.length && r.admin ? "critical" : undefined,
        detail: reasons.length ? `GitHub Actions can assume it from ${reasons.join(", and from ")}${admin}` : "",
      });
    }
  },
);
