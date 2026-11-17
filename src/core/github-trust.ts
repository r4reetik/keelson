// How a cloud role that GitHub Actions can assume through GitHub's OIDC provider is
// judged, from the subjects its trust policy allows. AWS IAM roles and Alibaba
// Cloud RAM roles are read differently, but their subject conditions mean the same
// thing: "repo:<owner>/<repo>:ref:refs/heads/<branch>", "…:environment:<name>",
// "…:pull_request", with * and ? wildcards. Both providers' checks use this.
// GitHub's immutable subjects add the owner's and repository's IDs after an @
// ("repo:org@123/app@456:…", the default for repositories created from July 2026):
// they are judged by their names like the others.

import type { ProviderLinks } from "../shared/api.ts";

/** "repo:org@123/app@456:ref:…" → "repo:org/app:ref:…"; other subjects are unchanged. */
export const withoutIds = (sub: string) => sub.replace(/^repo:([^/@:]*)(?:@[^/:]*)?\/([^/@:]*)(?:@[^:]*)?(?=:|$)/, "repo:$1/$2");

/** StringLike patterns: * is any run of characters, ? is one. */
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

export interface GithubTrustVerdict {
  /** Subjects that let any repository in; empty when the role names its owners. "no subject condition" when there is none. */
  open: string[];
  /** Owners outside the entity's GitHub organizations; null when the entity's organizations aren't known. */
  outside: string[] | null;
  /** Repositories in the entity whose every branch or pull request may assume it; null when the repositories aren't known. */
  anyBranch: string[] | null;
  /** "org/repo (main)" for repositories whose default branch may assume it but takes changes without review. */
  unreviewed: string[] | null;
  /** How many of the entity's repositories may assume it, from a branch or pull request; 0 for roles limited to environments. */
  trusted: number | null;
}

/** Judges the subjects a role trusts (empty: no subject condition) against the entity's GitHub organizations and repositories. */
export function judgeGithubTrust(withIds: string[], orgs: ProviderLinks["githubOrgs"] | null, repos: ProviderLinks["githubRepos"] | null): GithubTrustVerdict {
  const subjects = withIds.map(withoutIds);
  const open = !subjects.length ? ["no subject condition"] : subjects.filter(anyOwner);
  if (open.length) return { open, outside: null, anyBranch: null, unreviewed: null, trusted: null };
  const owners = [...new Set(subjects.map(ownerOf).filter((o): o is string => !!o))];
  const known = orgs ? new Set(orgs) : null;
  const outside = known && owners.length ? owners.filter((o) => !known.has(o)) : null;
  if (!repos) return { open, outside, anyBranch: null, unreviewed: null, trusted: null };
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
  return { open, outside, anyBranch, unreviewed, trusted };
}

/** "a, b, c and 2 more". */
export const shortList = (items: string[]) => `${items.slice(0, 3).join(", ")}${items.length > 3 ? ` and ${items.length - 3} more` : ""}`;

/** Why anyone who can push may assume the role, or an empty list. */
export function pushReasons(v: GithubTrustVerdict): string[] {
  return [
    v.anyBranch?.length ? `any branch or pull request of ${shortList(v.anyBranch)}` : null,
    v.unreviewed?.length ? `the unreviewed default branch of ${shortList(v.unreviewed)}` : null,
  ].filter((r): r is string => !!r);
}
