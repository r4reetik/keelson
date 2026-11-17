// AccessKey verification, the account the key belongs to, and the permission probe
// for the Add accounts flow. An AccessKey belongs to one Alibaba Cloud account, so
// the "accounts it can read" are that one.

import { AlibabaClient, parseCredentials, type AlibabaError } from "./client.ts";
import { ALIBABA_SOURCES, ALIBABA_SOURCE_KEYS } from "./sources.ts";
import { ALIBABA_CHECKS } from "./catalog.ts";
import type { PermissionProbe, TokenInfo } from "../../shared/api.ts";

const BAD_FORMAT =
  "Enter the AccessKey ID (it starts with LTAI) and its AccessKey secret. STS tokens (STS.…) expire within hours and can't be used for daily scans.";

/** A client for the key, or the reason it can't be one. */
export function clientFor(token: string, accountId = ""): AlibabaClient {
  const creds = parseCredentials(token);
  if (!creds) throw new Error(BAD_FORMAT);
  return new AlibabaClient(creds, accountId);
}

async function identityOf(client: AlibabaClient): Promise<{ account: string; root: boolean }> {
  const d = await client.rpc("sts", null, "GetCallerIdentity");
  return { account: String(d?.AccountId ?? ""), root: d?.IdentityType === "Account" || /:root$/.test(String(d?.Arn ?? "")) };
}

export async function verifyAlibabaKey(token: string): Promise<TokenInfo> {
  if (!parseCredentials(token)) return { valid: false, kind: null, message: BAD_FORMAT };
  try {
    const { root } = await identityOf(clientFor(token));
    // "account": the key is the main account's, which a check reports on its own.
    return { valid: true, kind: root ? "account" : "user", status: "active", expiresOn: null };
  } catch (e) {
    const err = e as AlibabaError;
    return {
      valid: false,
      kind: null,
      message: err.denied ? "Alibaba Cloud didn't accept this AccessKey. Check that it is enabled and that the secret was copied completely." : err.message,
    };
  }
}

/** The one account the key belongs to, named by its alias when it has one. */
export async function listAlibabaAccounts(token: string): Promise<{ id: string; name: string }[]> {
  const client = clientFor(token);
  const { account } = await identityOf(client);
  if (!account) return [];
  const alias = await client
    .rpc("ram", null, "GetAccountAlias")
    .then((d) => (d?.AccountAlias ? String(d.AccountAlias) : null))
    .catch(() => null);
  return [{ id: account, name: alias ?? account }];
}

/** One request per source with a probe, and the checks each source powers. */
export async function probeAlibaba(token: string, accountId: string): Promise<PermissionProbe[]> {
  const client = clientFor(token, accountId);
  return Promise.all(
    ALIBABA_SOURCE_KEYS.filter((k) => ALIBABA_SOURCES[k].probe).map(async (k): Promise<PermissionProbe> => {
      const s = ALIBABA_SOURCES[k];
      const titles = [...new Set(ALIBABA_CHECKS.filter((c) => c.requires?.includes(k)).map((c) => c.title))];
      const base = {
        source: s.label,
        permission: s.permission,
        powers: titles.length ? `${titles.length} check${titles.length === 1 ? "" : "s"}, e.g. ${titles.slice(0, 2).join("; ")}` : "Inventory",
      };
      try {
        await s.probe!(client);
        return { ...base, ok: true };
      } catch (e) {
        const err = e as AlibabaError;
        // A product the account never opened has nothing to read: that isn't a missing permission.
        if (err.noEndpoint) return { ...base, ok: true };
        return { ...base, ok: false, status: err.status, message: err.message };
      }
    }),
  );
}
