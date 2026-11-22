// GitLab as a provider: top-level groups on gitlab.com or on an instance its
// users host, read with an access token that has the read_api scope. Every
// request is a GET to that instance's /api/v4.

import { GitlabClient, parseCredential } from "./client.ts";
import { collectGitlab } from "./inventory.ts";
import { scanGitlabImages } from "./images.ts";
import { evaluateGitlab } from "./engine.ts";
import { GITLAB_CHECKS } from "./catalog.ts";
import { listGitlabAccounts, probeGitlab, verifyGitlab } from "./permissions.ts";
import { gitlabLinks, repoRows } from "./views.ts";
import { PROVIDER_INFO } from "../../shared/providers.ts";
import type { Provider } from "../types.ts";
import { saveDependencyViews } from "../../core/sbom/index.ts";

export const gitlab: Provider = {
  info: PROVIDER_INFO.gitlab,
  checks: GITLAB_CHECKS.map((c) => ({ ...c, provider: "gitlab" as const })),
  tokenHelp: () => ({ url: "https://docs.gitlab.com/user/profile/personal_access_tokens/", templateUrl: null }),
  verify: (token) => verifyGitlab(token),
  listAccounts: listGitlabAccounts,
  probe: probeGitlab,
  instanceOf: (token) => {
    const parsed = parseCredential(token);
    return parsed ? new URL(parsed.base).origin : null;
  },
  async scan({ token, account, engine, previous, cache, toolDir, onProgress }) {
    const client = new GitlabClient(token);
    try {
      onProgress({ phase: "Connecting to the group" });
      const group = await client.connect(account.id);
      const inv = await collectGitlab(client, account.id, group, onProgress, { cache, toolDir });
      await scanGitlabImages(client, inv, { cache, toolDir, related: engine.related ?? {}, onProgress, previous: previous?.images });
      onProgress({ phase: "Evaluating checks" });
      const evaluation = evaluateGitlab(inv, engine);
      const failures = evaluation.findings.filter((f) => !f.pass);
      saveDependencyViews(inv.dependencies, inv.unreadable, cache);
      return {
        accountName: inv.accountName,
        evaluation,
        snapshot: { repos: repoRows(inv, failures), links: gitlabLinks(inv), images: inv.images?.snapshot },
        coverage: [...client.coverage.values()].map((c) =>
          c.ok ? c : { ...c, skippedChecks: GITLAB_CHECKS.filter((ch) => ch.requires?.includes(c.key)).map((ch) => ch.id) },
        ),
        calls: client.calls,
        backlog: inv.images?.later ?? null,
      };
    } catch (e) {
      throw Object.assign(e as Error, { calls: client.calls });
    }
  },
  ownedDomains: () => [],
};
