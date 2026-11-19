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
  /** Whether members with admin access to a repository can delete or transfer it. */
  membersCanDeleteRepos: boolean | null;
  /** Whether members with admin access to a repository can change it between private and public. */
  membersCanChangeVisibility: boolean | null;
}

export interface BranchProtection {
  /** Approving reviews a pull request needs; null when pull requests aren't required. */
  reviews: number | null;
  enforceAdmins: boolean;
  allowForcePushes: boolean;
  allowDeletions: boolean;
  /** A new push dismisses earlier approvals. */
  dismissStale: boolean;
  /** The last push must be approved by someone other than whoever pushed it. */
  lastPushApproval: boolean;
}

/** One rule of a ruleset that applies to the default branch. */
export interface BranchRule {
  type: string;
  /** For "pull_request": approving reviews required. */
  reviews: number | null;
  /** For "pull_request": a new push dismisses earlier approvals. */
  dismissStale?: boolean;
  /** For "pull_request": the last push must be approved by someone other than whoever pushed it. */
  lastPushApproval?: boolean;
}

/** A self-hosted runner: a machine of the organization's that runs workflow jobs. */
export interface SelfHostedRunner {
  name: string;
  os: string;
  /** Takes one job and is then removed, so a job can't leave anything behind for the next. */
  ephemeral: boolean;
  /** The organization runner group it belongs to; null for a repository's own runner. */
  groupId: number | null;
}

/** An organization's runner group: which repositories may send jobs to its runners. */
export interface RunnerGroup {
  id: number;
  name: string;
  /** "all", "selected" or "private" repositories. */
  visibility: string;
  /** Public repositories may use it (an enterprise's group says so for its organizations). */
  allowsPublic: boolean;
  /** Only the workflows it names may use it. */
  restrictedToWorkflows: boolean;
  /** For "selected": the repositories' names; null when they couldn't be read. */
  repos: string[] | null;
}

/** Whether pull requests from forks run workflows, and with what. */
export interface ForkPrPolicy {
  /** Public repositories: whose fork pull requests wait for a maintainer before workflows run. */
  approval: string | null;
  /** Private repositories: null when GitHub didn't answer (the plan doesn't offer it). */
  private: { runs: boolean; secrets: boolean; writeTokens: boolean; needsApproval: boolean } | null;
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
  /** The repository's own license as GitHub detects it (an SPDX ID such as "MIT"); null without one. */
  license: string | null;
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
  /** Public repositories only: the repository's own self-hosted runners; null when not read. */
  runners: SelfHostedRunner[] | null;
  /** Public repositories only: whether it has published a release; null when not read. */
  releases: boolean | null;
  /** Where it publishes releases: whether they're immutable once published; null when not read. */
  immutableReleases: boolean | null;
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
  forkPrs: ForkPrPolicy | null;
  runnerGroups: RunnerGroup[] | null;
  /** The organization's self-hosted runners. */
  runners: SelfHostedRunner[] | null;
  repos: GithubRepo[];
  dependabot: DependabotAlert[] | null;
  codeScanning: CodeScanningAlert[] | null;
  secretScanning: SecretAlert[] | null;
  /** Each repository's dependencies, from its manifest and lock files (Syft, Grype, Grant); null when none could be read. */
  dependencies: DependencyInventory | null;
  /** The images this scan looked at and what Trivy found in each, with the workloads known in the entity (set by the provider). */
  images?: { snapshot: ImagesSnapshot; scans: Map<string, ImageHighlights>; workloads: WorkloadLink[] };
}

export type { ActionUse, DepPackage, DepUsage, DepVuln, RepoDependencies } from "../../shared/dependencies.ts";
import type { RepoDependencies } from "../../shared/dependencies.ts";
import type { ImageHighlights } from "../../core/images.ts";
import type { ImagesSnapshot, WorkloadLink } from "../../shared/images.ts";

export interface DependencyInventory {
  repos: RepoDependencies[];
  /** Versions of the tools that ran; null for one that isn't installed. */
  tools: { syft: string | null; grype: string | null; grant: string | null };
  /** When Grype's vulnerability database was built. */
  dbBuilt: string | null;
}
