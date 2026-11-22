// Credential verification, the organization picker and the permission probe for
// the Add accounts flow. The credential is an instance's address and an access
// token; the organizations it can read are the ones the token's user belongs to.

import { accountIdOf, BAD_FORMAT, GiteaClient, parseCredential, type GiteaError } from "./client.ts";
import { GITEA_SOURCES, GITEA_SOURCE_KEYS } from "./sources.ts";
import { GITEA_CHECKS } from "./catalog.ts";
import type { PermissionProbe, TokenInfo } from "../../shared/api.ts";

export async function verifyGitea(token: string): Promise<TokenInfo> {
  if (!parseCredential(token)) return { valid: false, kind: null, message: BAD_FORMAT };
  try {
    await new GiteaClient(token).raw("/user");
    return { valid: true, kind: "user", status: "active", expiresOn: null };
  } catch (e) {
    const err = e as GiteaError;
    // Without the user scope the token still works for organizations: that it was refused for a scope means it is valid.
    if (err.status === 403) return { valid: true, kind: "user", status: "active", expiresOn: null };
    return { valid: false, kind: null, message: err.message };
  }
}

export async function listGiteaAccounts(token: string): Promise<{ id: string; name: string }[]> {
  const client = new GiteaClient(token);
  return (await client.organizations()).map((o) => ({ id: accountIdOf(client.base, o.id), name: o.fullName || o.name }));
}

/** One request per source with a probe, and the checks each source powers. */
export async function probeGitea(token: string, accountId: string): Promise<PermissionProbe[]> {
  const client = new GiteaClient(token);
  await client.connect(accountId);
  return Promise.all(
    GITEA_SOURCE_KEYS.filter((k) => GITEA_SOURCES[k].probe).map(async (k): Promise<PermissionProbe> => {
      const s = GITEA_SOURCES[k];
      const titles = [...new Set(GITEA_CHECKS.filter((c) => c.requires?.includes(k)).map((c) => c.title))];
      const base = {
        source: s.label,
        permission: s.permission,
        powers: titles.length ? `${titles.length} check${titles.length === 1 ? "" : "s"}, e.g. ${titles.slice(0, 2).join("; ")}` : "Inventory",
      };
      try {
        await s.probe!(client);
        return { ...base, ok: true };
      } catch (e) {
        const err = e as GiteaError;
        return { ...base, ok: false, status: err.status, message: err.message };
      }
    }),
  );
}
