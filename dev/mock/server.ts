// Keelson against mocked provider APIs (Cloudflare, Vercel, AWS, Alibaba Cloud, GitHub, a GitLab instance and a Gitea instance) and Sonar's sources (crt.sh, Shodan), in memory:
// three Cloudflare accounts, a Vercel team, an AWS account, an Alibaba Cloud account and a GitHub organization in two entities,
// plus a Vercel-only entity with a personal account. Everything is scanned twice,
// so trends, "new since last scan" and the checks that span providers have data.
// One mock user per role signs in with MOCK_PASSWORD, plus "client", a manager
// limited to Other Ltd; with --signup there are none, so Keelson starts at creating the admin.
// Run with `npm run dev -- --mock` (or `node dev/mock/server.ts`).

import "../../src/warnings.ts";
import { isLoopback, start } from "../../src/main.ts";
import { env } from "../../src/env.ts";
import { installMockCloudflare, MOCK_ACCOUNT, MOCK_ACCOUNT_2, MOCK_ACCOUNT_3, MOCK_TOKEN_2 } from "./cloudflare.ts";
import { installMockVercel } from "./vercel.ts";
import { installMockAws, mockAws } from "./aws.ts";
import { installMockAlibaba, mockAlibaba } from "./alibaba.ts";
import { installMockGithub } from "./github.ts";
import { installMockGitea } from "./gitea.ts";
import { installMockGitlab } from "./gitlab.ts";
import { installMockInternet } from "./internet.ts";
import { installMockNetworks, seedNetworks } from "./networks.ts";
import { MOCK_DIGEST, mockTrivy } from "./trivy.ts";
import { trivyLimits } from "../../src/core/trivy.ts";
import { seedAccount, seedAlibaba, seedAws, seedGitea, seedGithub, seedGitlab, seedInternet, seedTriageHistory, seedVercel } from "./accounts.ts";
import { providerList } from "../../src/shared/providers.ts";
import { ROLES, ROLE_INFO } from "../../src/shared/roles.ts";
import { hashPasswordSync } from "../../src/server/passwords.ts";

/** Every mock user's password. Mock users exist only in this in-memory server. */
export const MOCK_PASSWORD = "mock-password";

installMockCloudflare();
installMockVercel();
installMockAws();
installMockAlibaba();
installMockGithub();
installMockGitea();
installMockGitlab();
// After Cloudflare's, so Sonar's public DNS answers come first.
installMockInternet();
installMockNetworks();
const port = Number(process.env.KEELSON_PORT || 4317);
// This machine only, unless `npm run dev -- --host` shares it with the network.
const host = env("HOST") || "127.0.0.1";
const running = await start({
  host,
  port,
  dataDir: null,
  insecureNoAuth: false,
  trustProxy: false,
  allowedHosts: [],
  schedule: false,
  updateCheck: false,
});
const { repo, vault, scanner } = running;
const signup = process.argv.includes("--signup");
if (!signup) {
  const passwordHash = hashPasswordSync(MOCK_PASSWORD);
  for (const role of ROLES)
    repo.users.create({ username: role, name: `Mock ${ROLE_INFO[role].label}`, role, passwordHash, mustChangePassword: false, createdBy: null });
}
repo.settings.save({ ...repo.settings.get(), probes: { takeover: false } });
seedAccount(repo, vault, { entity: "Mock Group" });
seedAccount(repo, vault, { id: MOCK_ACCOUNT_3, name: "Mock Co Staging", entity: "Mock Group" });
const other = seedAccount(repo, vault, { id: MOCK_ACCOUNT_2, token: MOCK_TOKEN_2, name: "Other Ltd", entity: "Other Ltd" });
repo.entities.update(other.entityId, { ...repo.entities.get(other.entityId)!, orgDomains: ["other.example"], includeInAll: false });
// A client's manager, who sees only their own company.
if (!signup)
  repo.users.create({
    username: "client",
    name: "Mock Client",
    role: "manager",
    passwordHash: hashPasswordSync(MOCK_PASSWORD),
    mustChangePassword: false,
    createdBy: null,
    entities: [other.entityId],
  });
seedVercel(repo, vault, { entity: "Mock Group", personal: { entity: "Side Projects" } });
seedAws(repo, vault, { entity: "Mock Group" });
seedAlibaba(repo, vault, { entity: "Mock Group" });
seedGithub(repo, vault, { entity: "Mock Group" });
seedGitea(repo, vault, { entity: "Mock Group" });
seedGitlab(repo, vault, { entity: "Mock Group" });
seedInternet(repo, vault, { entity: "Mock Group" });
// Three networks: AWS and the self-hosted Gitea are scanned through the office's, GitHub through another.
seedNetworks(repo, vault);
await scanner.start("setup").done;
// Between the scans the AWS account gives up an Elastic IP and the Alibaba Cloud account an EIP, so the second one finds the DNS records still pointing at them.
mockAws.released = true;
mockAlibaba.released = true;
await scanner.start("manual").done;
// Once more for Cloudflare, which was scanned before AWS noticed the address was gone.
await scanner.start("manual", [MOCK_ACCOUNT]).done;
seedTriageHistory(repo, MOCK_ACCOUNT);
// From here on, the first scan of the AWS account shows the background reader: an older build turns out to have been
// pulled lately, the scan has no time for it, and reading it takes long enough to watch in the top bar.
mockAws.oldBuildPulled = true;
trivyLimits.totalSeconds = -1;
mockTrivy.beforeImage = (ref) => (ref.includes(MOCK_DIGEST.webOld) ? new Promise((done) => setTimeout(done, 25_000)) : undefined);
console.log(`\n  Keelson (mock ${providerList()} data)\n\n  Open:  ${running.url}`);
if (signup && running.auth.setupCode && !isLoopback(host)) console.log(`  Setup code, for creating the admin from another machine: ${running.auth.setupCode}`);
console.log(
  signup
    ? "  Users: none yet, so it starts at creating the admin.\n"
    : `  Users: ${ROLES.join(", ")} (one per role) and client (a manager who sees only Other Ltd), password ${MOCK_PASSWORD}\n`,
);
