// A well-configured Gitea organization, and one failing case per Gitea check.
// The type is Record<GiteaCheckId, …>, so a new check without a case doesn't
// compile, and test/gitea-checks.test.ts asserts each case really makes its
// check fail.

import type { GiteaCheckId } from "../src/providers/gitea/checks/index.ts";
import type { GiteaBranchRule, GiteaInventory, GiteaRepo } from "../src/providers/gitea/types.ts";
import type { DepPackage } from "../src/shared/dependencies.ts";
import { dependencies, pkg, repoDeps, vuln } from "./github-cases.ts";

export const NOW = Date.parse("2026-06-01T00:00:00Z");
const days = (n: number) => NOW + n * 86_400_000;
const BASE = "https://git.example.com";

export const rule = (extra: Partial<GiteaBranchRule> = {}): GiteaBranchRule => ({
  rule: "main",
  directPush: "nobody",
  approvals: 1,
  freshApproval: true,
  forcePush: false,
  adminsBypass: false,
  ...extra,
});

export function repo(extra: Partial<GiteaRepo> = {}): GiteaRepo {
  return {
    name: "web",
    visibility: "private",
    archived: false,
    empty: false,
    fork: false,
    mirror: false,
    defaultBranch: "main",
    updatedAt: days(-2),
    url: `${BASE}/example/web`,
    license: "MIT",
    protection: rule(),
    hooks: [{ type: "gitea", endpoint: "https://ci.example.com", active: true }],
    deployKeys: [{ title: "ci", readOnly: true }],
    outsiders: [{ login: "auditor", permission: "read" }],
    pushMirrors: ["git.example.com"],
    ...extra,
  };
}

export function giteaInventory(extra: Partial<GiteaInventory> = {}): GiteaInventory {
  return {
    accountId: "gt_0a1b2c3d_1",
    accountName: "Example",
    login: "example",
    base: BASE,
    version: "1.25.4",
    now: NOW,
    visibility: "limited",
    members: ["ana", "ben", "chloe"],
    teams: [
      { name: "Owners", permission: "owner", allRepos: true, members: ["ana", "ben"] },
      { name: "developers", permission: "write", allRepos: false, members: null },
      { name: "release", permission: "admin", allRepos: false, members: ["chloe"] },
    ],
    noTwoFactor: [],
    hooks: [{ type: "gitea", endpoint: "https://ci.example.com", active: true }],
    // One repository anyone signed in can see, on an instance that asks everyone to sign in.
    repos: [repo(), repo({ name: "handbook", visibility: "public", url: `${BASE}/example/handbook` })],
    // The same fixtures as GitHub's: the pipeline and its checks are shared.
    dependencies: dependencies([
      repoDeps({ actions: [{ action: "docker/login-action", ref: "0123456789abcdef0123456789abcdef01234567", workflow: ".gitea/workflows/ci.yml" }] }),
    ]),
    anonymous: false,
    unreadable: [],
    ...extra,
  };
}

const withPackages = (...packages: DepPackage[]) => giteaInventory({ dependencies: dependencies([repoDeps({ packages })]) });

export const GITEA_CASES: Record<GiteaCheckId, () => GiteaInventory> = {
  "TED-001": () => withPackages(pkg({ vulns: [vuln({ kev: true, severity: "medium", epss: 0.9 })] })),
  "TED-002": () => withPackages(pkg({ vulns: [vuln()] })),
  "TED-003": () => withPackages(pkg({ name: "left-padd", vulns: [vuln({ id: "MAL-2026-1", aliases: [], severity: "critical", fixedIn: null })] })),
  "TED-004": () =>
    giteaInventory({
      dependencies: dependencies([repoDeps({ actions: [{ action: "mock-actions/deploy", ref: "v2", workflow: ".gitea/workflows/ci.yml" }] })]),
    }),
  "TED-005": () => giteaInventory({ dependencies: dependencies([repoDeps({ parts: [{ ...repoDeps().parts[0], lockfile: null, unpinned: ["left-pad"] }] })]) }),
  "TED-006": () => withPackages(pkg({ name: "readline", licenses: ["GPL-3.0-only"], licenseRisk: "strong" })),
  "TEI-001": () => giteaInventory({ noTwoFactor: ["ben"] }),
  "TEI-002": () =>
    giteaInventory({ teams: [{ name: "Owners", permission: "owner", allRepos: true, members: ["ana", "ben", "chloe", "dan", "erin", "farid"] }] }),
  "TEI-003": () =>
    giteaInventory({
      teams: [
        { name: "Owners", permission: "owner", allRepos: true, members: ["ana"] },
        { name: "ops", permission: "admin", allRepos: true, members: ["ben"] },
      ],
    }),
  "TEI-004": () => giteaInventory({ repos: [repo({ outsiders: [{ login: "contractor", permission: "admin" }] })] }),
  "TEB-001": () => giteaInventory({ repos: [repo({ protection: null })] }),
  "TEB-002": () => giteaInventory({ repos: [repo({ protection: rule({ forcePush: true }) })] }),
  "TEB-003": () => giteaInventory({ repos: [repo({ protection: rule({ freshApproval: false }) })] }),
  "TEB-004": () => giteaInventory({ repos: [repo({ protection: rule({ adminsBypass: true }) })] }),
  "TER-001": () => giteaInventory({ anonymous: true, repos: [repo({ visibility: "public" })] }),
  "TER-002": () => giteaInventory({ repos: [repo({ pushMirrors: ["github.com"] })] }),
  "TEH-001": () => giteaInventory({ hooks: [{ type: "slack", endpoint: "http://chat.example.com", active: true }] }),
  "TEH-002": () => giteaInventory({ repos: [repo({ deployKeys: [{ title: "deploy", readOnly: false }] })] }),
};
