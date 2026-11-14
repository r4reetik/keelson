// IAM roles that GitHub Actions can assume, through GitHub's OIDC provider
// (token.actions.githubusercontent.com). What protects such a role is the trust
// policy's condition on the token's subject: which repository, and which branch or
// environment, may assume it. AID-012 needs only the role. The two XP- checks compare
// it with the entity's GitHub organizations, from their latest scans, and are
// skipped when the entity has none.

import { defineChecks } from "./define.ts";
import { GLOBAL, type AwsRole } from "../types.ts";

/** IAM's StringLike patterns: * is any run of characters, ? is one. */
const glob = (p: string) =>
  new RegExp(
    `^${p
      .replace(/[.+^${}()|[\]\\]/g, "\\$&")
      .replace(/\*/g, ".*")
      .replace(/\?/g, ".")}$`,
  );
/** The owner a subject names ("repo:org/app:…" → "org"), or null when it doesn't name one exactly. */
const ownerOf = (sub: string) => /^repo:([^/*?]+)\//.exec(sub)?.[1] ?? null;
/** A subject that lets any GitHub owner in: no subject at all, or a wildcard where the owner goes. */
const anyOwner = (sub: string) => sub === "*" || /^repo:[^/]*[*?]/.test(sub) || /^repo\*/.test(sub);
/** A branch name nobody would protect, to test whether a pattern lets any branch in. */
const SOME_BRANCH = "keelson-any-branch";

/** The GitHub subjects a role trusts, or null when GitHub Actions can't assume it. An empty list means any repository. */
function githubTrust(r: AwsRole): string[] | null {
  const trusts = r.trust.filter((t) => t.github);
  if (!trusts.length) return null;
  return trusts.some((t) => !t.github!.length) ? [] : trusts.flatMap((t) => t.github!);
}

const list = (items: string[]) => `${items.slice(0, 3).join(", ")}${items.length > 3 ? ` and ${items.length - 3} more` : ""}`;

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
    const orgs = related.githubOrgs ? new Set(related.githubOrgs) : null;
    const repos = related.githubRepos;
    for (const r of inv.roles) {
      const subjects = githubTrust(r);
      if (!subjects) continue;
      const where = { zone: GLOBAL, resource: r.name, link: d.role(r.name) };
      const admin = r.admin ? ", and the role has administrator access" : "";

      const open = !subjects.length ? ["no subject condition"] : subjects.filter(anyOwner);
      report("AID-012", { ...where, pass: !open.length, detail: open.length ? `Trusts GitHub Actions with ${list(open)}${admin}` : "" });
      if (open.length) continue;

      const owners = [...new Set(subjects.map(ownerOf).filter((o): o is string => !!o))];
      if (orgs && owners.length) {
        const outside = owners.filter((o) => !orgs.has(o));
        report("XP-010", {
          ...where,
          pass: !outside.length,
          severity: outside.length && r.admin ? "critical" : undefined,
          confidence: outside.length ? "likely" : undefined,
          detail: outside.length ? `GitHub organization${outside.length === 1 ? "" : "s"} ${list(outside)} can assume it${admin}` : "",
        });
      }

      if (repos) {
        const patterns = subjects.map(glob);
        const allows = (sub: string) => patterns.some((p) => p.test(sub));
        const anyBranch: string[] = [];
        const unreviewed: string[] = [];
        let trusted = 0;
        for (const repo of repos) {
          const base = `repo:${repo.repo}:`;
          const fromAny = allows(`${base}ref:refs/heads/${SOME_BRANCH}`) || allows(`${base}pull_request`);
          const fromDefault = allows(`${base}ref:refs/heads/${repo.defaultBranch.toLowerCase()}`);
          if (!fromAny && !fromDefault) continue;
          trusted++;
          if (fromAny) anyBranch.push(repo.repo);
          else if (!repo.reviewed) unreviewed.push(`${repo.repo} (${repo.defaultBranch})`);
        }
        // A role limited to environments, or to repositories outside the entity, isn't judged here.
        if (!trusted) continue;
        const reasons = [
          anyBranch.length ? `any branch or pull request of ${list(anyBranch)}` : null,
          unreviewed.length ? `the unreviewed default branch of ${list(unreviewed)}` : null,
        ].filter(Boolean);
        report("XP-011", {
          ...where,
          pass: !reasons.length,
          severity: reasons.length && r.admin ? "critical" : undefined,
          detail: reasons.length ? `GitHub Actions can assume it from ${reasons.join(", and from ")}${admin}` : "",
        });
      }
    }
  },
);
