// Credential verification, the group picker and the permission probe for the
// Add accounts flow. The credential is an instance's address and an access
// token; the groups it can read are the top-level groups its user (or the
// group access token's bot) is at least a Reporter in.

import { accountIdOf, BAD_FORMAT, GitlabClient, parseCredential, type GitlabError } from "./client.ts";
import { GITLAB_SOURCES, GITLAB_SOURCE_KEYS } from "./sources.ts";
import { GITLAB_CHECKS } from "./catalog.ts";
import type { PermissionProbe, TokenInfo } from "../../shared/api.ts";

export async function verifyGitlab(token: string): Promise<TokenInfo> {
  if (!parseCredential(token)) return { valid: false, kind: null, message: BAD_FORMAT };
  const client = new GitlabClient(token);
  try {
    // The token describes itself: whether it is still active, and when it expires.
    const self = await client.raw("/personal_access_tokens/self");
    if (self?.revoked === true || self?.active === false)
      return { valid: false, kind: null, message: "This token was revoked or has expired. Create a new one." };
    return { valid: true, kind: "user", status: "active", expiresOn: typeof self?.expires_at === "string" ? self.expires_at : null };
  } catch (e) {
    const err = e as GitlabError;
    if (err.status === 401 || !err.status) return { valid: false, kind: null, message: err.message };
    // An older instance has no such address; the token is good if it can list anything.
    try {
      await client.raw("/groups?per_page=1");
      return { valid: true, kind: "user", status: "active", expiresOn: null };
    } catch (e2) {
      return { valid: false, kind: null, message: (e2 as GitlabError).message };
    }
  }
}

export async function listGitlabAccounts(token: string): Promise<{ id: string; name: string }[]> {
  const client = new GitlabClient(token);
  return (await client.groups()).map((g) => ({ id: accountIdOf(client.base, g.id), name: g.name || g.path }));
}

/** One request per source with a probe, and the checks each source powers. */
export async function probeGitlab(token: string, accountId: string): Promise<PermissionProbe[]> {
  const client = new GitlabClient(token);
  const group = await client.connect(accountId);
  return Promise.all(
    GITLAB_SOURCE_KEYS.filter((k) => GITLAB_SOURCES[k].probe).map(async (k): Promise<PermissionProbe> => {
      const s = GITLAB_SOURCES[k];
      const titles = [...new Set(GITLAB_CHECKS.filter((c) => c.requires?.includes(k)).map((c) => c.title))];
      const base = {
        source: s.label,
        permission: s.permission,
        powers: titles.length ? `${titles.length} check${titles.length === 1 ? "" : "s"}, e.g. ${titles.slice(0, 2).join("; ")}` : "Inventory",
      };
      try {
        await s.probe!(client);
        // GitLab answers for a group whoever asks, and leaves its security settings out for anyone but an Owner.
        if (k === "group" && typeof group?.require_two_factor_authentication !== "boolean")
          return { ...base, ok: false, status: 403, message: "GitLab shows a group's security settings only to its Owners." };
        return { ...base, ok: true };
      } catch (e) {
        const err = e as GitlabError;
        return { ...base, ok: false, status: err.status, message: err.message };
      }
    }),
  );
}
