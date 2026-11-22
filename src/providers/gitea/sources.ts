// Every Gitea data source a scan reads. Like the other providers' registries,
// each has a coverage label, what grants it (a token scope, as Gitea's token
// form names it, and who the token must belong to), and an optional probe for
// the Add accounts flow.

import type { GiteaClient } from "./client.ts";

export interface GiteaSource {
  label: string;
  /** The token scope that grants it, and whose token it must be. */
  permission: string;
  /** A cheap request that proves the token can read this source in an organization (Add accounts). */
  probe?: (client: GiteaClient) => Promise<unknown>;
}

const ORG = "Token scope organization: Read";
const REPO_ADMIN = "Token scope repository: Read, on a token of someone who administers the repository (an owner of the organization does)";

const DEFS = {
  org: { label: "Organization settings", permission: ORG, probe: (c) => c.raw(`/orgs/${c.org}`) },
  members: { label: "Organization members", permission: ORG, probe: (c) => c.raw(`/orgs/${c.org}/members?limit=1`) },
  teams: { label: "Teams, their access and their members", permission: ORG, probe: (c) => c.raw(`/orgs/${c.org}/teams?limit=1`) },
  twoFactor: {
    label: "Which users sign in without two-factor authentication",
    permission: "Token scope admin: Read, on a token of a site administrator. Gitea tells nobody else",
    probe: (c) => c.raw("/admin/users?is_2fa_enabled=false&limit=1"),
  },
  orgHooks: {
    label: "Organization webhooks",
    permission: `${ORG}, on a token of an owner of the organization`,
    probe: (c) => c.raw(`/orgs/${c.org}/hooks?limit=1`),
  },
  repos: {
    label: "Repositories",
    permission: "Token scopes organization: Read and repository: Read, with access to all repositories (public, private and limited)",
    probe: (c) => c.raw(`/orgs/${c.org}/repos?limit=1`),
  },
  protection: { label: "Branch protection", permission: REPO_ADMIN },
  repoHooks: { label: "Repository webhooks", permission: REPO_ADMIN },
  deployKeys: { label: "Deploy keys", permission: REPO_ADMIN },
  collaborators: { label: "Collaborators outside the organization", permission: REPO_ADMIN },
  pushMirrors: { label: "Push mirrors", permission: REPO_ADMIN },
  manifests: {
    label: "Manifest and lock files, for each repository's SBOM (never the code)",
    permission: "Token scope repository: Read, with access to all repositories",
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
  anonymous: {
    label: "Whether the instance shows public repositories without signing in",
    permission: "None: one request without the token",
  },
} satisfies Record<string, GiteaSource>;

export type GiteaSourceKey = keyof typeof DEFS;
export const GITEA_SOURCES: Record<GiteaSourceKey, GiteaSource> = DEFS;
export const GITEA_SOURCE_KEYS = Object.keys(DEFS) as GiteaSourceKey[];
