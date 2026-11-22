// IAM roles that GitLab CI can assume, through GitLab's OIDC provider
// (gitlab.com, or an instance its users host). What protects such a role is the
// trust policy's condition on the token's subject: which project, and which
// branch, may assume it. AID-016 needs only the role. The two XP- checks compare
// it with the entity's GitLab groups and projects on that instance, from their
// latest scans, and are skipped when the entity has none there.

import { defineChecks } from "./define.ts";
import { pushReasons, shortList as list } from "../../../core/github-trust.ts";
import { judgeGitlabTrust } from "../../../core/gitlab-trust.ts";
import { GLOBAL, type AwsRole } from "../types.ts";

const DOCS = "https://docs.gitlab.com/ci/cloud_services/aws/";

/** The subjects a role trusts from one GitLab instance, or null when that instance's CI can't assume it. An empty list means any project. */
function gitlabTrust(r: AwsRole, hosts: Set<string>): { host: string; subjects: string[] } | null {
  const trusts = r.trust.filter((t) => t.oidc && hosts.has(t.oidc.host));
  if (!trusts.length) return null;
  const host = trusts[0].oidc!.host;
  const same = trusts.filter((t) => t.oidc!.host === host);
  return { host, subjects: same.some((t) => !t.oidc!.subjects.length) ? [] : same.flatMap((t) => t.oidc!.subjects) };
}

export default defineChecks(
  {
    "AID-016": {
      category: "Identity & access",
      severity: "critical",
      docs: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html",
      requires: ["iamDetails"],
      attackPath: true,
      title: "GitLab CI in any project can assume this IAM role",
      why: "The role trusts GitLab's OIDC provider without limiting the token's subject to your projects. A pipeline in anyone's project on that GitLab can get a token GitLab signs and assume the role. On gitlab.com, that is anyone with an account.",
      fix: "Open the role in IAM → Trust relationships and add a condition on the provider's sub claim (gitlab.com:sub) naming your group, project and branch, for example project_path:your-group/your-project:ref_type:branch:ref:main.",
    },
    "XP-029": {
      spans: ["gitlab"],
      category: "Identity & access",
      severity: "high",
      docs: DOCS,
      requires: ["iamDetails"],
      title: "IAM role trusts GitLab projects outside the entity",
      why: "GitLab CI in a group that isn't one of the entity's can assume this role. That group's members, and anyone who gets write access to its projects, get the role's AWS access.",
      fix: "1. If the group is yours, add it to this entity in Keelson. 2. If it belongs to a vendor, confirm they still need the role and limit it to the project and branch they use. 3. Otherwise remove it from the role's trust policy.",
    },
    "XP-030": {
      spans: ["gitlab"],
      category: "Identity & access",
      severity: "high",
      docs: DOCS,
      requires: ["iamDetails"],
      attackPath: true,
      title: "Anyone who can push to the GitLab project can assume this IAM role",
      why: "The role trusts GitLab CI from a project in the entity, either from any branch, or from a default branch developers can push to without a merge request. Anyone with that access, or a stolen token or deploy key that has it, can push a pipeline that assumes the role.",
      fix: "1. Limit the trust policy's subject to the protected default branch (project_path:group/project:ref_type:branch:ref:main). 2. Protect that branch so nobody pushes to it without a merge request, with a required approval. 3. For production, use a protected environment and a role only its jobs can assume.",
    },
  },
  ({ inv, d, related }, report) => {
    if (!inv.roles) return;
    // gitlab.com is GitLab whoever is asking; an instance of its own is known as GitLab once one of the entity's groups is on it.
    const hosts = new Set(["gitlab.com", ...(related.gitlabGroups ?? []).map((g) => g.host)]);
    for (const r of inv.roles) {
      const trust = gitlabTrust(r, hosts);
      if (!trust) continue;
      const where = { zone: GLOBAL, resource: r.name, link: d.role(r.name) };
      const admin = r.admin ? ", and the role has administrator access" : "";
      const groups = related.gitlabGroups?.filter((g) => g.host === trust.host) ?? null;
      const projects = related.gitlabProjects?.filter((p) => p.host === trust.host) ?? null;
      const v = judgeGitlabTrust(trust.subjects, groups, projects);

      report("AID-016", {
        ...where,
        pass: !v.open.length,
        // On an instance of your own, "any project" is anyone with an account there, not anyone at all.
        severity: v.open.length && trust.host !== "gitlab.com" ? "high" : undefined,
        detail: v.open.length ? `Trusts GitLab CI on ${trust.host} with ${list(v.open)}${admin}` : "",
      });
      if (v.open.length) continue;

      // Without a group of the entity on that instance there is nothing to compare with.
      if (v.outside && groups?.length)
        report("XP-029", {
          ...where,
          pass: !v.outside.length,
          severity: v.outside.length && r.admin ? "critical" : undefined,
          confidence: v.outside.length ? "likely" : undefined,
          detail: v.outside.length ? `GitLab group${v.outside.length === 1 ? "" : "s"} ${list(v.outside)} on ${trust.host} can assume it${admin}` : "",
        });

      // A role limited to projects outside the entity isn't judged here.
      if (!v.trusted) continue;
      const reasons = pushReasons(v);
      report("XP-030", {
        ...where,
        pass: !reasons.length,
        severity: reasons.length && r.admin ? "critical" : undefined,
        detail: reasons.length ? `GitLab CI can assume it from ${reasons.join(", and from ")}${admin}`.replace("or pull request ", "") : "",
      });
    }
  },
);
