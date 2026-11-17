// Alibaba Cloud as a provider: one account per AccessKey, scanned with signed GET
// requests for the read actions src/shared/alibaba.ts names, and nothing else. Give
// the key's RAM user the custom policy from the Add accounts flow; nothing more.

import { collectAlibaba } from "./inventory.ts";
import { evaluateAlibaba } from "./engine.ts";
import { ALIBABA_CHECKS } from "./catalog.ts";
import { clientFor, listAlibabaAccounts, probeAlibaba, verifyAlibabaKey } from "./permissions.ts";
import { addressHistory, alibabaLinks, hostedDomains, ownAddresses, resourceView } from "./views.ts";
import { PROVIDER_INFO } from "../../shared/providers.ts";
import type { Provider } from "../types.ts";

export const alibaba: Provider = {
  info: PROVIDER_INFO.alibaba,
  checks: ALIBABA_CHECKS.map((c) => ({ ...c, provider: "alibaba" as const })),
  tokenHelp: () => ({ url: "https://ram.console.alibabacloud.com/users/create", templateUrl: null }),
  verify: (token) => verifyAlibabaKey(token),
  listAccounts: listAlibabaAccounts,
  probe: probeAlibaba,
  async scan({ token, account, engine, previous, onProgress }) {
    const client = clientFor(token, account.id);
    try {
      const inv = await collectAlibaba(client, onProgress);
      if (inv.accountId !== account.id)
        throw new Error(`This AccessKey belongs to Alibaba Cloud account ${inv.accountId}, not ${account.id}. Replace it on the Accounts page.`);
      // Addresses the account held at its last complete scan and doesn't now were released: DNS that still points at them is dangling.
      const history = addressHistory(previous?.addressHistory, inv.skippedRegions.length ? null : ownAddresses(inv), inv.now);
      inv.released = history.released;
      onProgress({ phase: "Evaluating checks" });
      const evaluation = evaluateAlibaba(inv, engine);
      const failures = evaluation.findings.filter((f) => !f.pass);
      return {
        accountName: inv.accountName,
        evaluation,
        snapshot: { resources: resourceView(inv, failures), links: alibabaLinks(inv), ownedDomains: hostedDomains(inv), addressHistory: history },
        coverage: [...client.coverage.values()].map((c) =>
          c.ok ? c : { ...c, skippedChecks: ALIBABA_CHECKS.filter((ch) => ch.requires?.includes(c.key)).map((ch) => ch.id) },
        ),
        calls: client.calls,
      };
    } catch (e) {
      throw Object.assign(e as Error, { calls: client.calls });
    }
  },
  ownedDomains: (snap) => snap.ownedDomains ?? [],
};
