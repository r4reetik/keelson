// How a cloud role that GitLab CI can assume through GitLab's OIDC provider is
// judged, from the subjects its trust policy allows. GitLab's subject says
// which project a job runs in and from which ref:
// "project_path:<group>/<project>:ref_type:branch:ref:<branch>" (or
// ref_type:tag), with * and ? wildcards in the policy. The verdict has the same
// shape as GitHub's (./github-trust.ts), so both read alike in a finding.

import type { ProviderLinks } from "../shared/api.ts";
import type { GithubTrustVerdict } from "./github-trust.ts";

/** StringLike patterns: * is any run of characters, ? is one. */
const glob = (p: string) =>
  new RegExp(
    `^${p
      .replace(/[.+^${}()|[\]\\]/g, "\\$&")
      .replace(/\*/g, ".*")
      .replace(/\?/g, ".")}$`,
  );
/** The top-level group a subject names ("project_path:group/sub/app:…" → "group"), or null when it doesn't name one exactly. */
const groupOf = (sub: string) => /^project_path:([^/*?:]+)\//.exec(sub)?.[1] ?? null;
/** A subject that lets any group's projects in: a wildcard where the group goes. */
const anyGroup = (sub: string) => sub === "*" || /^project_path:[^/:]*[*?]/.test(sub) || /^project_path\*/.test(sub) || !sub.startsWith("project_path:");
/** A branch name nobody would protect, to test whether a pattern lets any branch in. */
const SOME_BRANCH = "keelson-any-branch";

/**
 * Judges the subjects a role trusts (empty: no subject condition) against the entity's GitLab groups and projects on
 * the instance the role's OIDC provider names. `groups` and `projects` are null when the entity's aren't known.
 */
export function judgeGitlabTrust(
  subjects: string[],
  groups: NonNullable<ProviderLinks["gitlabGroups"]> | null,
  projects: NonNullable<ProviderLinks["gitlabProjects"]> | null,
): GithubTrustVerdict {
  const open = !subjects.length ? ["no subject condition"] : subjects.filter(anyGroup);
  if (open.length) return { open, outside: null, anyBranch: null, unreviewed: null, trusted: null };
  const named = [...new Set(subjects.map(groupOf).filter((g): g is string => !!g))];
  // A group in the entity vouches for everything under its top-level group's path.
  const known = groups ? new Set(groups.map((g) => g.group.split("/")[0])) : null;
  const outside = known && named.length ? named.filter((g) => !known.has(g)) : null;
  if (!projects) return { open, outside, anyBranch: null, unreviewed: null, trusted: null };
  const patterns = subjects.map(glob);
  const allows = (sub: string) => patterns.some((p) => p.test(sub));
  const anyBranch: string[] = [];
  const unreviewed: string[] = [];
  let trusted = 0;
  for (const p of projects) {
    const base = `project_path:${p.repo}:ref_type:branch:ref:`;
    const fromAny = allows(`${base}${SOME_BRANCH}`);
    const fromDefault = allows(`${base}${p.defaultBranch.toLowerCase()}`);
    if (!fromAny && !fromDefault) continue;
    trusted++;
    if (fromAny) anyBranch.push(p.repo);
    else if (!p.reviewed) unreviewed.push(`${p.repo} (${p.defaultBranch})`);
  }
  return { open, outside, anyBranch, unreviewed, trusted };
}
