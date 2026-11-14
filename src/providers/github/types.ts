// What a GitHub scan collects: the fields checks read, typed from GitHub's REST
// reference (docs.github.com/rest). Payloads are trimmed when they're read, so the
// inventory never holds a leaked secret's value (alerts are read with
// hide_secret, and the field is dropped anyway), a webhook's path or secret, or a
// deploy key.

import type { GithubSourceKey } from "./sources.ts";
import type { Related } from "../../core/types.ts";

export type { Related };

export interface GithubOrg {
  login: string;
  name: string | null;
  plan: string | null;
  twoFactorRequired: boolean | null;
  /** What every member can do in every repository: "none", "read", "write" or "admin". */
  defaultRepoPermission: string | null;
  membersCanCreatePublicRepos: boolean | null;
  membersCanForkPrivateRepos: boolean | null;
}

export interface BranchProtection {
  /** Approving reviews a pull request needs; null when pull requests aren't required. */
  reviews: number | null;
  enforceAdmins: boolean;
  allowForcePushes: boolean;
  allowDeletions: boolean;
}

/** One rule of a ruleset that applies to the default branch. */
export interface BranchRule {
  type: string;
  /** For "pull_request": approving reviews required. */
  reviews: number | null;
}

export interface GithubHook {
  id: number;
  /** Scheme and host only: the rest of a webhook URL can carry a secret. */
  endpoint: string;
  insecureSsl: boolean;
  active: boolean;
}

export interface GithubRepo {
  name: string;
  private: boolean;
  visibility: string;
  archived: boolean;
  fork: boolean;
  /** No commits yet: nothing to protect. */
  empty: boolean;
  defaultBranch: string;
  pushedAt: number | null;
  hasPages: boolean;
  /** Secret scanning, push protection and Dependabot security updates; null when GitHub didn't say. */
  security: { secretScanning: boolean | null; pushProtection: boolean | null; dependabotUpdates: boolean | null } | null;
  /** The default branch's classic protection: null when there is none, undefined when it couldn't be read. */
  protection: BranchProtection | null | undefined;
  /** Ruleset rules on the default branch, from the repository and the organization; null when unreadable. */
  rules: BranchRule[] | null;
  deployKeys: { title: string; readOnly: boolean; createdAt: number | null }[] | null;
  hooks: GithubHook[] | null;
  /** Whether Dependabot alerts are on; null when it couldn't be read, or the repository is archived. */
  dependabotAlerts: boolean | null;
  /** Whether code scanning has analysed the repository; null when it couldn't be read, or the repository is archived or empty. */
  codeScanning: boolean | null;
  /** The Pages site: null when there is none, undefined when it couldn't be read. */
  pages: { cname: string | null; httpsEnforced: boolean | null } | null | undefined;
}

export interface GithubActions {
  /** Which repositories may run Actions: "all", "none" or "selected". */
  enabledRepos: string | null;
  /** Which actions may run: "all", "local_only" or "selected". */
  allowedActions: string | null;
  /** The GITHUB_TOKEN's default: "read" or "write". */
  defaultWorkflowPermissions: string | null;
  canApprovePullRequests: boolean | null;
}

/** Another GitHub App installed on the organization. */
export interface OtherApp {
  slug: string;
  appId: number;
  /** "all" or "selected" repositories. */
  selection: string;
  /** Permissions it holds with write or admin access. */
  writes: string[];
}

export interface DependabotAlert {
  repo: string;
  severity: string;
  pkg: string;
  advisory: string;
  createdAt: number | null;
}

export interface CodeScanningAlert {
  repo: string;
  severity: string;
  rule: string;
  tool: string;
  createdAt: number | null;
}

/** A leaked secret GitHub found. Its value is never read. */
export interface SecretAlert {
  number: number;
  repo: string;
  /** GitHub's name for the kind of secret ("Amazon AWS Access Key ID"). */
  kind: string;
  /** "active", "inactive" or "unknown": whether the secret still works, where GitHub can tell. */
  validity: string;
  pushProtectionBypassed: boolean;
  createdAt: number | null;
}

export interface GithubInventory {
  /** Keelson's ID for the organization: "gh_<number>". */
  accountId: string;
  accountName: string | null;
  login: string;
  now: number;
  /** Sources the App couldn't read; every check that requires one is skipped. */
  unreadable: GithubSourceKey[];
  /** Keelson's own App, so it isn't reported as another App with access. */
  appId: number | null;
  /** The installation reaches only some repositories: the rest aren't checked. */
  selectedRepos: boolean;
  org: GithubOrg | null;
  owners: string[] | null;
  actions: GithubActions | null;
  hooks: GithubHook[] | null;
  apps: OtherApp[] | null;
  repos: GithubRepo[];
  dependabot: DependabotAlert[] | null;
  codeScanning: CodeScanningAlert[] | null;
  secretScanning: SecretAlert[] | null;
}
