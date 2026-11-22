// What a Gitea scan holds in memory: the organization, who is in it and how
// they sign in, its teams, webhooks, and each repository with what protects
// its default branch and who and what can reach it from outside.

import type { GiteaSourceKey } from "./sources.ts";
import type { DependencyInventory } from "../../core/sbom/index.ts";

export interface GiteaTeam {
  name: string;
  /** "owner", "admin", "write", "read" or "none". */
  permission: string;
  /** The team reaches every repository of the organization, including ones made later. */
  allRepos: boolean;
  /** Lowercase usernames; null when the team's members couldn't be read. */
  members: string[] | null;
}

/** A webhook, without its address's path or query (which often carry a secret), its secret or its authorization header. */
export interface GiteaHook {
  /** "gitea", "slack", "discord"… */
  type: string;
  /** Scheme and host of where it delivers: "https://ci.example.com". Empty when the address couldn't be read as one. */
  endpoint: string;
  active: boolean;
}

/** The rule that protects a repository's default branch, reduced to what the checks judge. */
export interface GiteaBranchRule {
  /** The rule's pattern: a branch name, or a glob such as "release/*". */
  rule: string;
  /** Who may push without a pull request: anyone with write access, only the people and teams the rule lists, or nobody. */
  directPush: "anyone" | "listed" | "nobody";
  /** Approvals a pull request needs. */
  approvals: number;
  /** An approval stops counting when new commits are pushed (dismissed, or ignored as stale). */
  freshApproval: boolean;
  /** Force pushes are allowed to anyone with write access. Null on an instance that doesn't say (before 1.23 they never were). */
  forcePush: boolean | null;
  /** Administrators can merge past the rule. Null on an instance that doesn't say. */
  adminsBypass: boolean | null;
}

export interface GiteaRepo {
  name: string;
  /** "public" (anyone the instance lets in), "internal" (signed-in users, in an organization that isn't public) or "private". */
  visibility: "public" | "internal" | "private";
  archived: boolean;
  empty: boolean;
  fork: boolean;
  /** A copy the instance pulls from somewhere else: nobody pushes to it. */
  mirror: boolean;
  defaultBranch: string;
  /** When it last changed (ms), or null when Gitea didn't say. */
  updatedAt: number | null;
  /** Where people open it. */
  url: string;
  /** Its own license as Gitea detects it (an SPDX ID such as "MIT"); null without one. */
  license: string | null;
  /** The rule on the default branch; null without one; undefined when rules couldn't be read. */
  protection: GiteaBranchRule | null | undefined;
  hooks: GiteaHook[] | null;
  deployKeys: { title: string; readOnly: boolean }[] | null;
  /** People with their own access to the repository who aren't members of the organization. */
  outsiders: { login: string; permission: string }[] | null;
  /** Hosts the repository is pushed to after each change. */
  pushMirrors: string[] | null;
}

export interface GiteaInventory {
  accountId: string;
  /** The organization's display name. */
  accountName: string;
  /** Its name in addresses. */
  login: string;
  /** The instance's address, for links. */
  base: string;
  /** The instance's version, as it says; null when it didn't. */
  version: string | null;
  now: number;
  /** "public", "limited" (signed-in users) or "private"; null when the organization couldn't be read. */
  visibility: string | null;
  /** Lowercase usernames; null when unreadable. */
  members: string[] | null;
  teams: GiteaTeam[] | null;
  /** Members who sign in without two-factor authentication; null when Gitea didn't say (it tells only site administrators). */
  noTwoFactor: string[] | null;
  hooks: GiteaHook[] | null;
  repos: GiteaRepo[];
  /** What each repository depends on (src/core/sbom); null when dependency files weren't read. */
  dependencies: DependencyInventory | null;
  /** The instance showed a public repository to a request without a token; null when there was none to ask for. */
  anonymous: boolean | null;
  unreadable: GiteaSourceKey[];
}
