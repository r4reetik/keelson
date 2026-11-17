// Every GitHub data source a scan reads. Like the other providers' registries,
// each has a coverage label, the App permission that grants it (as GitHub's App
// settings name it), and an optional probe for the Add accounts flow.

import type { GithubClient } from "./client.ts";

export interface GithubSource {
  label: string;
  /** The App permission that grants it, as the App's settings page words it. */
  permission: string;
  /** A cheap request that proves the App can read this source in an organization (Add accounts). */
  probe?: (client: GithubClient) => Promise<unknown>;
}

const ORG_ADMIN = "Organization permissions → Administration: Read-only";
const REPO_ADMIN = "Repository permissions → Administration: Read-only";

const DEFS = {
  orgSettings: {
    label: "Organization settings",
    permission: ORG_ADMIN,
    probe: (c) => c.orgSettings(),
  },
  members: {
    label: "Organization owners",
    permission: "Organization permissions → Members: Read-only",
    probe: (c) => c.raw(`/orgs/${c.org}/members?role=admin&per_page=1`),
  },
  actions: { label: "Actions permissions", permission: ORG_ADMIN, probe: (c) => c.raw(`/orgs/${c.org}/actions/permissions`) },
  orgHooks: {
    label: "Organization webhooks",
    permission: "Organization permissions → Webhooks: Read-only",
    probe: (c) => c.raw(`/orgs/${c.org}/hooks?per_page=1`),
  },
  installations: { label: "Installed GitHub Apps", permission: ORG_ADMIN, probe: (c) => c.raw(`/orgs/${c.org}/installations?per_page=1`) },
  forkPrs: { label: "Workflow policy for fork pull requests", permission: ORG_ADMIN },
  runners: {
    label: "Self-hosted runners and runner groups",
    permission: "Organization permissions → Self-hosted runners: Read-only",
    probe: (c) => c.raw(`/orgs/${c.org}/actions/runner-groups?per_page=1`),
  },
  repos: {
    label: "Repositories",
    permission: "Repository permissions → Metadata: Read-only (always granted)",
    probe: (c) => c.raw("/installation/repositories?per_page=1"),
  },
  codeSecurity: { label: "Code security settings", permission: REPO_ADMIN },
  protection: { label: "Branch protection", permission: REPO_ADMIN },
  rules: { label: "Rulesets that apply to default branches", permission: "Repository permissions → Metadata: Read-only (always granted)" },
  deployKeys: { label: "Deploy keys", permission: REPO_ADMIN },
  repoHooks: { label: "Repository webhooks", permission: "Repository permissions → Webhooks: Read-only" },
  pages: { label: "GitHub Pages sites", permission: "Repository permissions → Pages: Read-only" },
  repoRunners: { label: "Public repositories' own self-hosted runners", permission: REPO_ADMIN },
  releases: { label: "Whether public repositories publish releases", permission: "None: a public repository's releases are public" },
  immutableReleases: { label: "Whether releases are immutable", permission: REPO_ADMIN },
  dependabotSetup: { label: "Whether Dependabot alerts are on", permission: REPO_ADMIN },
  codeScanningSetup: { label: "Whether code scanning has run", permission: "Repository permissions → Code scanning alerts: Read-only" },
  dependabot: {
    label: "Dependabot alerts",
    permission: "Repository permissions → Dependabot alerts: Read-only",
    probe: (c) => c.raw(`/orgs/${c.org}/dependabot/alerts?per_page=1`),
  },
  codeScanning: {
    label: "Code scanning alerts",
    permission: "Repository permissions → Code scanning alerts: Read-only",
    probe: (c) => c.raw(`/orgs/${c.org}/code-scanning/alerts?per_page=1`),
  },
  manifests: {
    label: "Manifest and lock files, for each repository's SBOM (never the code)",
    permission: "Repository permissions → Contents: Read-only",
  },
  syft: {
    label: "Software bill of materials (Anchore Syft)",
    permission: "Syft installed where Keelson runs: on the PATH, or its path in KEELSON_SYFT (not in the Docker image yet)",
  },
  grype: {
    label: "Known vulnerabilities in dependencies (Anchore Grype)",
    permission:
      "Grype installed where Keelson runs: on the PATH, or its path in KEELSON_GRYPE (not in the Docker image yet). Its database, about 3 GB, is downloaded from Anchore into the data folder",
  },
  grant: {
    label: "Dependency licenses (Anchore Grant)",
    permission: "Grant installed where Keelson runs: on the PATH, or its path in KEELSON_GRANT (not in the Docker image yet)",
  },
  secretScanning: {
    label: "Secret scanning alerts",
    permission: "Repository permissions → Secret scanning alerts: Read-only",
    probe: (c) => c.raw(`/orgs/${c.org}/secret-scanning/alerts?per_page=1&hide_secret=true`),
  },
} satisfies Record<string, GithubSource>;

export type GithubSourceKey = keyof typeof DEFS;
export const GITHUB_SOURCES: Record<GithubSourceKey, GithubSource> = DEFS;
export const GITHUB_SOURCE_KEYS = Object.keys(DEFS) as GithubSourceKey[];
