// What a GitLab scan holds in memory: the group and its settings, its members,
// its webhooks, and each project with what protects its default branch, what
// can reach it from outside, its Pages domains, its dependencies and its images.

import type { GitlabSourceKey } from "./sources.ts";
import type { DependencyInventory } from "../../core/sbom/index.ts";
import type { ImageBacklog, ImageHighlights } from "../../core/images.ts";
import type { ImagesSnapshot, WorkloadLink } from "../../shared/images.ts";

export type { Related } from "../../core/types.ts";

/** GitLab's roles as numbers: 0 nobody, 30 Developer, 40 Maintainer, 50 Owner, 60 an instance administrator. */
export const DEVELOPER = 30;
export const OWNER = 50;

/** A webhook, without its address's path or query (which often carry a secret), its token or its headers' values. */
export interface GitlabHook {
  /** Scheme and host of where it delivers. Empty when the address couldn't be read as one. */
  endpoint: string;
  /** Whether the receiver's certificate is checked. */
  verifiesTls: boolean;
}

/** The rule on a project's default branch, reduced to what the checks judge. */
export interface GitlabBranchRule {
  /** The rule's name: a branch, or a wildcard such as "release-*". */
  rule: string;
  /** The lowest role that may push without a merge request: 0 when nobody may, 30 Developer, 40 Maintainer. Users and groups named on the rule count as their own access. */
  pushLevel: number;
  /** People or groups are named on the rule as allowed to push, besides roles. */
  pushNamed: boolean;
  forcePush: boolean;
}

/** Merge request approvals (Premium and Ultimate). */
export interface GitlabApprovals {
  /** The most approvals any rule asks for; 0 when none is required. */
  required: number;
  /** Approvals are removed when new commits are pushed. */
  resetOnPush: boolean;
  /** The author of a merge request may approve it. */
  authorApproves: boolean;
}

export interface GitlabProject {
  id: number;
  /** Its path below the group: "api", or "backend/api" in a subgroup. A finding's zone. */
  name: string;
  /** "group/backend/api". */
  fullPath: string;
  visibility: "public" | "internal" | "private";
  archived: boolean;
  empty: boolean;
  /** A copy the instance pulls from elsewhere. */
  mirror: boolean;
  defaultBranch: string;
  /** When it was last active (ms); null when GitLab didn't say. */
  updatedAt: number | null;
  url: string;
  /** Its own license as an SPDX ID; null without one or when it wasn't read. */
  license: string | null;
  /** The rule on the default branch; null without one; undefined when rules couldn't be read. */
  protection: GitlabBranchRule | null | undefined;
  /** Null when the instance's plan has no approval rules; undefined when they couldn't be read. */
  approvals: GitlabApprovals | null | undefined;
  hooks: GitlabHook[] | null;
  deployKeys: { title: string; canPush: boolean }[] | null;
  deployTokens: { name: string; scopes: string[]; expiresAt: string | null }[] | null;
  /** Custom domains of its Pages site; null when they couldn't be read. */
  pagesDomains: string[] | null;
  /** Whether it has a container registry worth listing. */
  registry: boolean;
}

export interface GitlabInventory {
  accountId: string;
  /** The group's display name. */
  accountName: string;
  /** Its full path. */
  login: string;
  /** The instance's address, for links. */
  base: string;
  now: number;
  group: {
    visibility: string;
    requireTwoFactor: boolean;
    /** Projects can't be shared with other groups. */
    shareLock: boolean;
  } | null;
  /** Direct and inherited members, without bots; null when unreadable. */
  members: { username: string; level: number }[] | null;
  /** Null when unreadable or the plan has none; `groupHooksAbsent` tells the two apart. */
  hooks: GitlabHook[] | null;
  groupHooksAbsent: boolean;
  projects: GitlabProject[];
  dependencies: DependencyInventory | null;
  unreadable: GitlabSourceKey[];
  /** The images this scan looked at and what Trivy found in each, with the workloads known in the entity (set by the provider). */
  images?: { snapshot: ImagesSnapshot; scans: Map<string, ImageHighlights>; workloads: WorkloadLink[]; later?: ImageBacklog | null };
}
