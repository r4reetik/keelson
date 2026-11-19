// GitHub as a provider: organizations scanned through a GitHub App the user
// registers with read permissions only. Keelson asks for a read-only installation
// token on each scan; every other request is GET.

import { GithubClient } from "./client.ts";
import { collectGithub } from "./inventory.ts";
import { scanGithubImages } from "./images.ts";
import { evaluateGithub } from "./engine.ts";
import { GITHUB_CHECKS } from "./catalog.ts";
import { listGithubAccounts, orgIdOf, probeGithub, verifyGithubApp } from "./permissions.ts";
import { githubLinks, repoRows } from "./views.ts";
import { githubAppTemplate } from "../../shared/github.ts";
import { PROVIDER_INFO } from "../../shared/providers.ts";
import type { Provider } from "../types.ts";
import type { AccountCache } from "../../store/repo.ts";
import type { GithubInventory } from "./types.ts";

export const github: Provider = {
  info: PROVIDER_INFO.github,
  checks: GITHUB_CHECKS.map((c) => ({ ...c, provider: "github" as const })),
  tokenHelp: () => ({ url: "https://github.com/settings/apps", templateUrl: githubAppTemplate(null) }),
  verify: (token) => verifyGithubApp(token),
  listAccounts: listGithubAccounts,
  probe: probeGithub,
  async scan({ token, account, engine, previous, cache, toolDir, onProgress }) {
    const client = new GithubClient(token);
    try {
      onProgress({ phase: "Connecting to the organization" });
      await client.connect(orgIdOf(account.id));
      const inv = await collectGithub(client, account.id, onProgress, { cache, toolDir });
      await scanGithubImages(client, inv, { cache, toolDir, related: engine.related ?? {}, onProgress, previous: previous?.images });
      onProgress({ phase: "Evaluating checks" });
      const evaluation = evaluateGithub(inv, engine);
      const failures = evaluation.findings.filter((f) => !f.pass);
      saveDependencyViews(inv, cache);
      return {
        accountName: inv.accountName,
        evaluation,
        snapshot: { repos: repoRows(inv, failures), links: githubLinks(inv), images: inv.images?.snapshot },
        coverage: [...client.coverage.values()].map((c) =>
          c.ok ? c : { ...c, skippedChecks: GITHUB_CHECKS.filter((ch) => ch.requires?.includes(c.key)).map((ch) => ch.id) },
        ),
        calls: client.calls,
      };
    } catch (e) {
      throw Object.assign(e as Error, { calls: client.calls });
    }
  },
  ownedDomains: () => [],
};

/**
 * Each repository's dependencies as the Repositories page shows them (`deps:<repo>`), replaced on every scan; a
 * repository whose dependencies weren't read this time keeps its last view only while its SBOM is cached.
 */
function saveDependencyViews(inv: GithubInventory, cache: AccountCache): void {
  const deps = inv.dependencies;
  if (!deps) return;
  const seen = new Set<string>();
  for (const d of deps.repos) {
    seen.add(d.repo);
    cache.put(`deps:${d.repo}`, { dependencies: d, tools: deps.tools, dbBuilt: deps.dbBuilt, unreadable: inv.unreadable });
  }
  const kept = new Set(cache.keys("sbom:").map((k) => k.slice(5)));
  for (const key of cache.keys("deps:")) if (!seen.has(key.slice(5)) && !kept.has(key.slice(5))) cache.delete(key);
}
