// Gitea as a provider: organizations on an instance its users host themselves,
// read with an access token that carries read scopes only. Every request is a
// GET to that instance's /api/v1. Forgejo serves the same API.

import { GiteaClient, parseCredential } from "./client.ts";
import { collectGitea } from "./inventory.ts";
import { evaluateGitea } from "./engine.ts";
import { GITEA_CHECKS } from "./catalog.ts";
import { listGiteaAccounts, probeGitea, verifyGitea } from "./permissions.ts";
import { repoRows } from "./views.ts";
import { PROVIDER_INFO } from "../../shared/providers.ts";
import type { Provider } from "../types.ts";
import { saveDependencyViews } from "../../core/sbom/index.ts";

export const gitea: Provider = {
  info: PROVIDER_INFO.gitea,
  checks: GITEA_CHECKS.map((c) => ({ ...c, provider: "gitea" as const })),
  tokenHelp: () => ({ url: "https://docs.gitea.com/development/api-usage", templateUrl: null }),
  verify: (token) => verifyGitea(token),
  listAccounts: listGiteaAccounts,
  probe: probeGitea,
  instanceOf: (token) => {
    const parsed = parseCredential(token);
    return parsed ? new URL(parsed.base).origin : null;
  },
  async scan({ token, account, engine, cache, toolDir, onProgress }) {
    const client = new GiteaClient(token);
    try {
      onProgress({ phase: "Connecting to the organization" });
      await client.connect(account.id);
      const inv = await collectGitea(client, account.id, onProgress, { cache, toolDir });
      onProgress({ phase: "Evaluating checks" });
      const evaluation = evaluateGitea(inv, engine);
      const failures = evaluation.findings.filter((f) => !f.pass);
      saveDependencyViews(inv.dependencies, inv.unreadable, cache);
      return {
        accountName: inv.accountName,
        evaluation,
        snapshot: { repos: repoRows(inv, failures) },
        coverage: [...client.coverage.values()].map((c) =>
          c.ok ? c : { ...c, skippedChecks: GITEA_CHECKS.filter((ch) => ch.requires?.includes(c.key)).map((ch) => ch.id) },
        ),
        calls: client.calls,
      };
    } catch (e) {
      throw Object.assign(e as Error, { calls: client.calls });
    }
  },
  ownedDomains: () => [],
};
