// Checks that need GitLab: RAM roles that GitLab CI can assume through an OIDC
// provider (gitlab.com, or an instance its users host), and Alibaba Cloud DNS
// records that point at GitLab Pages. LID-016 needs only the role. The XP- checks
// compare with the entity's GitLab groups, projects and Pages sites, from their
// latest scans, and are skipped when the entity has none (on that instance).

import { defineChecks, list } from "./define.ts";
import { pushReasons } from "../../../core/github-trust.ts";
import { judgeGitlabTrust } from "../../../core/gitlab-trust.ts";
import { pointsAtGitlabPages } from "../../../core/links.ts";
import { GLOBAL, type AlibabaRole } from "../types.ts";

const DOCS = "https://docs.gitlab.com/ci/secrets/id_token_authentication/";

/** The subjects a role trusts from one GitLab instance, or null when that instance's CI can't assume it. An empty list means any project. */
function gitlabTrust(r: AlibabaRole, hosts: Set<string>): { host: string; subjects: string[] } | null {
  const trusts = r.trust.filter((t) => t.oidc && hosts.has(t.oidc.host));
  if (!trusts.length) return null;
  const host = trusts[0].oidc!.host;
  const same = trusts.filter((t) => t.oidc!.host === host);
  return { host, subjects: same.some((t) => !t.oidc!.subjects.length) ? [] : same.flatMap((t) => t.oidc!.subjects) };
}

export default defineChecks(
  {
    "LID-016": {
      category: "Identity & access",
      severity: "critical",
      docs: "https://www.alibabacloud.com/help/en/ram/user-guide/overview-of-oidc-based-sso",
      requires: ["ramRoles"],
      attackPath: true,
      title: "GitLab CI in any project can assume this RAM role",
      why: "The role trusts GitLab's OIDC provider without limiting the token's subject to your projects. A pipeline in anyone's project on that GitLab can get a token GitLab signs and assume the role. On gitlab.com, that is anyone with an account.",
      fix: "Open the role in the RAM console → Trust Policy and add a condition on oidc:sub naming your group, project and branch, for example project_path:your-group/your-project:ref_type:branch:ref:main.",
    },
    "XP-031": {
      spans: ["gitlab"],
      category: "Identity & access",
      severity: "high",
      docs: DOCS,
      requires: ["ramRoles"],
      title: "RAM role trusts GitLab projects outside the entity",
      why: "GitLab CI in a group that isn't one of the entity's can assume this role. That group's members, and anyone who gets write access to its projects, get the role's Alibaba Cloud access.",
      fix: "1. If the group is yours, add it to this entity in Keelson. 2. If it belongs to a vendor, confirm they still need the role and limit it to the project and branch they use. 3. Otherwise remove it from the role's trust policy.",
    },
    "XP-032": {
      spans: ["gitlab"],
      category: "Identity & access",
      severity: "high",
      docs: DOCS,
      requires: ["ramRoles"],
      attackPath: true,
      title: "Anyone who can push to the GitLab project can assume this RAM role",
      why: "The role trusts GitLab CI from a project in the entity, either from any branch, or from a default branch developers can push to without a merge request. Anyone with that access, or a stolen token or deploy key that has it, can push a pipeline that assumes the role.",
      fix: "1. Limit the trust policy's oidc:sub to the protected default branch (project_path:group/project:ref_type:branch:ref:main). 2. Protect that branch so nobody pushes to it without a merge request, with a required approval. 3. For production, use a protected environment and a role only its jobs can assume.",
    },
    "XP-033": {
      spans: ["gitlab"],
      category: "DNS",
      severity: "high",
      docs: "https://docs.gitlab.com/user/project/pages/custom_domains_ssl_tls_certification/",
      requires: ["dns"],
      attackPath: true,
      title: "Alibaba Cloud DNS record points at GitLab Pages, but no Pages site in the entity uses it",
      why: "The record sends visitors to GitLab Pages, yet none of the entity's GitLab groups has a Pages site with this hostname. GitLab asks for a verification record before it serves a custom domain; a record left from a deleted site, with its verification record still in DNS, lets whoever recreates the site's address serve content under your name.",
      fix: "1. If the site moved or was retired, delete the record in Alibaba Cloud DNS, and the _gitlab-pages-verification-code TXT record beside it. 2. If it should be live, add the hostname under the project's Deploy → Pages → Domains and verify it.",
    },
  },
  ({ inv, d, related }, report) => {
    // gitlab.com is GitLab whoever is asking; an instance of its own is known as GitLab once one of the entity's groups is on it.
    const hosts = new Set(["gitlab.com", ...(related.gitlabGroups ?? []).map((g) => g.host)]);
    for (const r of inv.roles ?? []) {
      const trust = gitlabTrust(r, hosts);
      if (!trust) continue;
      const where = { zone: GLOBAL, resource: r.name, link: d.role(r.name) };
      const admin = r.admin ? ", and the role has administrator access" : "";
      const groups = related.gitlabGroups?.filter((g) => g.host === trust.host) ?? null;
      const projects = related.gitlabProjects?.filter((p) => p.host === trust.host) ?? null;
      const v = judgeGitlabTrust(trust.subjects, groups, projects);

      report("LID-016", {
        ...where,
        pass: !v.open.length,
        // On an instance of your own, "any project" is anyone with an account there, not anyone at all.
        severity: v.open.length && trust.host !== "gitlab.com" ? "high" : undefined,
        detail: v.open.length ? `Trusts GitLab CI on ${trust.host} with ${list(v.open)}${admin}` : "",
      });
      if (v.open.length) continue;

      // Without a group of the entity on that instance there is nothing to compare with.
      if (v.outside && groups?.length)
        report("XP-031", {
          ...where,
          pass: !v.outside.length,
          severity: v.outside.length && r.admin ? "critical" : undefined,
          confidence: v.outside.length ? "likely" : undefined,
          detail: v.outside.length ? `GitLab group${v.outside.length === 1 ? "" : "s"} ${list(v.outside)} on ${trust.host} can assume it${admin}` : "",
        });

      // A role limited to projects outside the entity isn't judged here.
      if (!v.trusted) continue;
      const reasons = pushReasons(v);
      report("XP-032", {
        ...where,
        pass: !reasons.length,
        severity: reasons.length && r.admin ? "critical" : undefined,
        detail: reasons.length ? `GitLab CI can assume it from ${reasons.join(", and from ")}${admin}`.replace("or pull request ", "") : "",
      });
    }

    const sites = related.gitlabPages ? new Set(related.gitlabPages.map((p) => p.host.toLowerCase())) : null;
    if (!sites) return;
    for (const z of inv.domains ?? [])
      for (const r of z.records ?? []) {
        if (!pointsAtGitlabPages(r.type, r.value)) continue;
        const found = sites.has(r.name.toLowerCase());
        report("XP-033", {
          zone: GLOBAL,
          resource: r.name,
          link: d.dnsDomain(z.name),
          pass: found,
          detail: found ? "" : `${r.type} ${r.value}, not the custom domain of any Pages site in this entity`,
          confidence: found ? undefined : "likely",
        });
      }
  },
);
