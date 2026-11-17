// Ways into more access than a RAM identity was given: policies that let a user,
// group or role give itself more, and roles that GitHub Actions can assume through
// GitHub's OIDC provider. The two XP- checks compare such a role with the entity's
// GitHub organizations, from their latest scans, and are skipped when the entity has
// none.

import { defineChecks, list } from "./define.ts";
import { judgeGithubTrust, pushReasons } from "../../../core/github-trust.ts";
import { GLOBAL, type AlibabaRole } from "../types.ts";

/** The GitHub subjects a role trusts, or null when GitHub Actions can't assume it. An empty list means any repository. */
function githubTrust(r: AlibabaRole): string[] | null {
  const trusts = r.trust.filter((t) => t.github);
  if (!trusts.length) return null;
  return trusts.some((t) => !t.github!.length) ? [] : trusts.flatMap((t) => t.github!);
}

export default defineChecks(
  {
    "LID-011": {
      category: "Identity & access",
      severity: "high",
      docs: "https://www.alibabacloud.com/help/en/ram/user-guide/policy-elements",
      requires: ["ramPolicies"],
      title: "RAM identity can give itself more access",
      why: "Its policies let it attach policies, change a policy's version, create AccessKeys or console passwords for others, or hand a role to a new instance or function. Any of these turns its limited access into whatever it chooses, up to administrator.",
      fix: "Remove the listed actions from the identity's policies, or limit their Resource to what it really manages. Keep RAM administration with a small group of administrators who sign in with MFA.",
    },
    "LID-012": {
      category: "Identity & access",
      severity: "critical",
      docs: "https://www.alibabacloud.com/help/en/ram/user-guide/manage-an-oidc-idp",
      requires: ["ramRoles"],
      attackPath: true,
      title: "GitHub Actions in any repository can assume this RAM role",
      why: "The role trusts GitHub's OIDC provider without limiting the token's subject to your repositories. A workflow in anyone's repository, on any GitHub account, can get a token GitHub signs and assume the role.",
      fix: "Open the role in RAM → Roles → Trust Policy and add a condition on oidc:sub naming your organization and repository, for example repo:your-org/your-repo:ref:refs/heads/main or repo:your-org/your-repo:environment:production.",
    },
    "XP-022": {
      spans: ["github"],
      category: "Identity & access",
      severity: "high",
      docs: "https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect",
      requires: ["ramRoles"],
      title: "RAM role trusts GitHub repositories outside the entity",
      why: "GitHub Actions in a GitHub organization that isn't one of the entity's can assume this role. That organization's members, and anyone who gets write access to its repositories, get the role's access to your Alibaba Cloud account.",
      fix: "1. If the organization is yours, add it to this entity in Keelson. 2. If it belongs to a vendor, confirm they still need the role and limit it to the repository and branch they use. 3. Otherwise remove it from the role's trust policy.",
    },
    "XP-023": {
      spans: ["github"],
      category: "Identity & access",
      severity: "high",
      docs: "https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect#example-subject-claims",
      requires: ["ramRoles"],
      attackPath: true,
      title: "Anyone who can push to the repository can assume this RAM role",
      why: "The role trusts GitHub Actions from a repository in the entity, either from any branch or pull request, or from a default branch that takes changes without review. Anyone with write access, or a stolen token or deploy key that has it, can push a workflow and act as the role in Alibaba Cloud.",
      fix: "1. Limit the trust policy's oidc:sub to the protected default branch (repo:org/repo:ref:refs/heads/main) or, better, to a GitHub environment with required reviewers (repo:org/repo:environment:production). 2. Require a reviewed pull request on that branch in GitHub.",
    },
  },
  ({ inv, d, related }, report) => {
    for (const e of inv.escalations ?? [])
      report("LID-011", {
        zone: GLOBAL,
        resource: `${e.kind} ${e.name}`,
        pass: false,
        detail: `Through ${e.via}: ${e.paths.join("; ")}`,
        link: e.kind === "role" ? d.role(e.name) : e.kind === "user" ? d.user(e.name) : d.policies,
      });
    if (inv.escalations) report.passIfNone("LID-011", "account", GLOBAL);

    for (const r of inv.roles ?? []) {
      const subjects = githubTrust(r);
      if (!subjects) continue;
      const where = { zone: GLOBAL, resource: r.name, link: d.role(r.name) };
      const admin = r.admin ? ", and the role has administrator access" : "";
      const v = judgeGithubTrust(subjects, related.githubOrgs, related.githubRepos);

      report("LID-012", { ...where, pass: !v.open.length, detail: v.open.length ? `Trusts GitHub Actions with ${list(v.open)}${admin}` : "" });
      if (v.open.length) continue;

      if (v.outside)
        report("XP-022", {
          ...where,
          pass: !v.outside.length,
          severity: v.outside.length && r.admin ? "critical" : undefined,
          confidence: v.outside.length ? "likely" : undefined,
          detail: v.outside.length ? `GitHub organization${v.outside.length === 1 ? "" : "s"} ${list(v.outside)} can assume it${admin}` : "",
        });

      // A role limited to environments, or to repositories outside the entity, isn't judged here.
      if (!v.trusted) continue;
      const reasons = pushReasons(v);
      report("XP-023", {
        ...where,
        pass: !reasons.length,
        severity: reasons.length && r.admin ? "critical" : undefined,
        detail: reasons.length ? `GitHub Actions can assume it from ${reasons.join(", and from ")}${admin}` : "",
      });
    }
  },
);
