// Every GitLab data source a scan reads. Like the other providers' registries,
// each has a coverage label, what grants it (the read_api scope, and the role
// the token's user or the group access token needs), and an optional probe for
// the Add accounts flow.

import type { GitlabClient } from "./client.ts";
import { toolNeed } from "../../shared/tools.ts";

export interface GitlabSource {
  label: string;
  /** The token scope that grants it, and the role it needs in the group. */
  permission: string;
  /** A cheap request that proves the token can read this source in a group (Add accounts). */
  probe?: (client: GitlabClient) => Promise<unknown>;
}

const OWNER = "Token scope read_api, on a token with the Owner role in the group";
const MAINTAINER = "Token scope read_api, on a token with at least the Maintainer role in the project (an Owner of the group has it)";
const g = (c: GitlabClient) => `/groups/${c.groupId}`;

const DEFS = {
  group: { label: "Group settings", permission: OWNER, probe: (c) => c.raw(`${g(c)}?with_projects=false`) },
  members: { label: "Group members and their roles", permission: "Token scope read_api", probe: (c) => c.raw(`${g(c)}/members/all?per_page=1`) },
  groupHooks: { label: "Group webhooks (GitLab Premium and Ultimate)", permission: OWNER },
  projects: {
    label: "Projects, in the group and its subgroups",
    permission: "Token scope read_api",
    probe: (c) => c.raw(`${g(c)}/projects?include_subgroups=true&with_shared=false&per_page=1`),
  },
  protection: { label: "Protected branches", permission: "Token scope read_api, on a token with at least the Developer role" },
  approvals: { label: "Merge request approval rules and settings (GitLab Premium and Ultimate)", permission: MAINTAINER },
  projectHooks: { label: "Project webhooks", permission: MAINTAINER },
  deployKeys: { label: "Deploy keys", permission: MAINTAINER },
  deployTokens: { label: "Deploy tokens (never their values)", permission: MAINTAINER },
  pages: { label: "GitLab Pages custom domains", permission: MAINTAINER },
  manifests: {
    label: "Manifest and lock files and CI configuration, for each project's SBOM (never the code)",
    permission: "Token scope read_api, on a token with at least the Reporter role",
  },
  syft: {
    label: "Software bill of materials (Anchore Syft)",
    permission: toolNeed("syft"),
  },
  grype: {
    label: "Known vulnerabilities in dependencies (Anchore Grype)",
    permission: toolNeed("grype"),
  },
  grant: {
    label: "Dependency licenses (Anchore Grant)",
    permission: toolNeed("grant"),
  },
  registry: { label: "Container registry repositories and their tags", permission: "Token scope read_api, on a token with at least the Reporter role" },
  trivy: {
    label: "Packages, vulnerabilities and stored credentials in public container images (Aqua Trivy)",
    permission: toolNeed("trivy"),
  },
  kev: {
    label: "CISA's catalog of known exploited vulnerabilities",
    permission: "None: a public file, read from www.cisa.gov without a credential",
  },
} satisfies Record<string, GitlabSource>;

export type GitlabSourceKey = keyof typeof DEFS;
export const GITLAB_SOURCES: Record<GitlabSourceKey, GitlabSource> = DEFS;
export const GITLAB_SOURCE_KEYS = Object.keys(DEFS) as GitlabSourceKey[];
