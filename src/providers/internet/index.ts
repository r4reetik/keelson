// The internet as a provider: Sonar, the entity's external attack surface. Keelson
// makes one account per entity (PROVIDER_INFO.internet.perEntity), scanned after
// the entity's other accounts, whose latest scans give it the domains, DNS records
// and addresses to start from. Its only credential is an optional Shodan API key.
// This first part is passive: it reads certificate logs, public DNS and Shodan, and
// sends nothing to the entity's own hosts.

import { InternetClient } from "./client.ts";
import { discover, INPUTS, ROUTING_INPUTS } from "./discover.ts";
import { amass } from "./amass.ts";
import { evaluateInternet } from "./engine.ts";
import { INTERNET_CHECKS } from "./catalog.ts";
import { surfaceView } from "./views.ts";
import { fetchEc2Prefixes } from "../../core/aws-ranges.ts";
import { NO_RELATED } from "../../core/types.ts";
import { PROVIDER_INFO } from "../../shared/providers.ts";
import type { PermissionProbe, TokenInfo } from "../../shared/api.ts";
import type { Provider } from "../types.ts";
import type { InternetError } from "./client.ts";

export async function verifyShodanKey(key: string): Promise<TokenInfo> {
  if (!key.trim()) return { valid: true, kind: "account", status: "active", expiresOn: null };
  try {
    const plan = await new InternetClient(key).plan();
    return { valid: true, kind: "account", status: plan ? `Shodan plan: ${plan}` : "active", expiresOn: null };
  } catch (e) {
    return { valid: false, kind: null, message: (e as InternetError).message };
  }
}

/** What a key (or none) gives, in the Add accounts flow's terms. */
async function probeShodan(key: string): Promise<PermissionProbe[]> {
  const powers = (ids: string[]) =>
    `${ids.length} check${ids.length === 1 ? "" : "s"}, e.g. ${INTERNET_CHECKS.filter((c) => ids.includes(c.id))
      .map((c) => c.title)
      .slice(0, 2)
      .join("; ")}`;
  const shodanChecks = INTERNET_CHECKS.filter((c) => c.requires?.includes("shodan")).map((c) => c.id);
  if (!key.trim())
    return [
      {
        source: "Shodan host data",
        permission: "Without a key, Shodan's free InternetDB: ports and known vulnerabilities, without products",
        powers: powers(shodanChecks),
        ok: true,
      },
      {
        source: "Subdomains Shodan has seen",
        permission: "a Shodan API key on a plan with query credits",
        powers: "Finding more hostnames",
        ok: false,
        message: "No key",
      },
    ];
  const client = new InternetClient(key);
  const dns = await client.subdomains("example.com").then(
    () => ({ ok: true as const }),
    (e) => ({ ok: false as const, status: (e as InternetError).status, message: (e as InternetError).message }),
  );
  return [
    { source: "Shodan host data", permission: "Any Shodan API key", powers: powers(shodanChecks), ok: true },
    { source: "Subdomains Shodan has seen", permission: "a Shodan API key on a plan with query credits", powers: "Finding more hostnames", ...dns },
  ];
}

export const internet: Provider = {
  info: PROVIDER_INFO.internet,
  checks: INTERNET_CHECKS.map((c) => ({ ...c, provider: "internet" as const })),
  tokenHelp: () => ({ url: "https://account.shodan.io/", templateUrl: null }),
  verify: (key) => verifyShodanKey(key),
  // Accounts are the entities (perEntity); the account routes list them.
  listAccounts: async () => [],
  probe: (key) => probeShodan(key),
  async scan({ token, account, engine, onProgress }) {
    const client = new InternetClient(token);
    try {
      const related = { ...NO_RELATED, ...engine.related };
      const ec2 = related.awsAddresses ? await fetchEc2Prefixes().catch(() => null) : null;
      const inv = await discover(client, { accountId: account.id, orgDomains: engine.orgDomains, related, ec2, amass: amass.path(), onProgress });
      inv.unreadable = [...client.coverage.values()].filter((c) => !c.ok).map((c) => c.key);
      onProgress({ phase: "Evaluating checks" });
      const evaluation = evaluateInternet(inv, engine);
      return {
        accountName: PROVIDER_INFO.internet.label,
        evaluation,
        snapshot: {
          surface: surfaceView(
            inv,
            evaluation.findings.filter((f) => !f.pass),
          ),
        },
        coverage: [...client.coverage.values()].map((c) =>
          c.ok ? c : { ...c, skippedChecks: INTERNET_CHECKS.filter((ch) => ch.requires?.includes(c.key)).map((ch) => ch.id) },
        ),
        calls: client.calls,
      };
    } catch (e) {
      throw Object.assign(e as Error, { calls: client.calls });
    }
  },
  ownedDomains: () => [],
  reads: [...INPUTS, ...ROUTING_INPUTS],
};
