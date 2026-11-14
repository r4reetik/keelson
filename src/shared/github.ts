// What Keelson's GitHub App may read, in GitHub's permission names. The same list
// pre-fills the App's registration page (the Add accounts steps) and limits the
// token Keelson asks for on every scan, so even an App given more than this gets
// a token that can only read these. Portable: used by the server and the web.

/** GitHub's permission names, each with the level Keelson asks for: always read. */
export const GITHUB_APP_PERMISSIONS = {
  metadata: "Repository metadata",
  administration: "Repository administration",
  repository_hooks: "Repository webhooks",
  pages: "Pages",
  vulnerability_alerts: "Dependabot alerts",
  security_events: "Code scanning alerts",
  secret_scanning_alerts: "Secret scanning alerts",
  organization_administration: "Organization administration",
  members: "Organization members",
  organization_hooks: "Organization webhooks",
} as const;

export type GithubPermission = keyof typeof GITHUB_APP_PERMISSIONS;
export const GITHUB_PERMISSION_KEYS = Object.keys(GITHUB_APP_PERMISSIONS) as GithubPermission[];

/**
 * GitHub's page for registering an App, pre-filled with Keelson's name and read permissions and no webhook.
 * Under an organization when one is named, so the App belongs to it; otherwise under the person's own account.
 */
export function githubAppTemplate(org: string | null): string {
  const owner = org?.trim();
  // App names are unique across GitHub, so the organization's name goes in it (34 characters at most).
  const name = `Keelson ${owner || "scanner"}`.slice(0, 34);
  const params = new URLSearchParams({ name, url: "https://github.com/r4reetik/keelson", public: "false", webhook_active: "false" });
  for (const k of GITHUB_PERMISSION_KEYS) params.set(k, "read");
  return `https://github.com/${owner ? `organizations/${encodeURIComponent(owner)}/` : ""}settings/apps/new?${params}`;
}
