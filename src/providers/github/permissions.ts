// Credential verification, the organization picker and the permission probe for
// the Add accounts dialog. The credential is a GitHub App; the organizations it
// can read are the ones it's installed on.

import { BAD_FORMAT, GithubClient, parseCredentials, type GithubError } from "./client.ts";
import { GITHUB_SOURCES, GITHUB_SOURCE_KEYS } from "./sources.ts";
import { GITHUB_CHECKS } from "./catalog.ts";
import type { PermissionProbe, TokenInfo } from "../../shared/api.ts";

/** Keelson's ID for an organization: GitHub's number with a prefix, so it can't be mistaken for an AWS account. */
export const accountIdOf = (orgId: number) => `gh_${orgId}`;
export const orgIdOf = (accountId: string) => Number(accountId.replace(/^gh_/, ""));

export async function verifyGithubApp(token: string): Promise<TokenInfo> {
  if (!parseCredentials(token)) return { valid: false, kind: null, message: BAD_FORMAT };
  try {
    await new GithubClient(token).installations();
    // "account": the App belongs to the organization, not to a person.
    return { valid: true, kind: "account", status: "active", expiresOn: null };
  } catch (e) {
    const err = e as GithubError;
    return { valid: false, kind: null, message: err.message };
  }
}

/** Organizations the App is installed on. An installation on a personal account isn't offered: it has no organization settings. */
export async function listGithubAccounts(token: string): Promise<{ id: string; name: string }[]> {
  const installations = await new GithubClient(token).installations();
  return installations.filter((i) => i.type === "Organization").map((i) => ({ id: accountIdOf(i.accountId), name: i.login }));
}

/** One request per source with a probe, and the checks each source powers. */
export async function probeGithub(token: string, accountId: string): Promise<PermissionProbe[]> {
  const client = new GithubClient(token);
  await client.connect(orgIdOf(accountId));
  return Promise.all(
    GITHUB_SOURCE_KEYS.filter((k) => GITHUB_SOURCES[k].probe).map(async (k): Promise<PermissionProbe> => {
      const s = GITHUB_SOURCES[k];
      const titles = [...new Set(GITHUB_CHECKS.filter((c) => c.requires?.includes(k)).map((c) => c.title))];
      const base = {
        source: s.label,
        permission: s.permission,
        powers: titles.length ? `${titles.length} check${titles.length === 1 ? "" : "s"}, e.g. ${titles.slice(0, 2).join("; ")}` : "Inventory",
      };
      try {
        await s.probe!(client);
        return { ...base, ok: true };
      } catch (e) {
        const err = e as GithubError;
        return { ...base, ok: false, status: err.status, message: err.message };
      }
    }),
  );
}
