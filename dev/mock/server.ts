// Keelson against mocked provider APIs (Cloudflare, Vercel and AWS), in memory:
// three Cloudflare accounts, a Vercel team and an AWS account in two entities,
// plus a Vercel-only entity with a personal account. Everything is scanned twice,
// so trends, "new since last scan" and the checks that span providers have data.
// One mock user per role signs in with MOCK_PASSWORD, plus "client", a manager
// limited to Other Ltd; with --signup there are none, so Keelson starts at creating the admin.
// Run with `npm run dev -- --mock` (or `node dev/mock/server.ts`).

import "../../src/warnings.ts";
import { start } from "../../src/main.ts";
import { installMockCloudflare, MOCK_ACCOUNT, MOCK_ACCOUNT_2, MOCK_ACCOUNT_3, MOCK_TOKEN_2 } from "./cloudflare.ts";
import { installMockVercel } from "./vercel.ts";
import { installMockAws, mockAws } from "./aws.ts";
import { seedAccount, seedAws, seedTriageHistory, seedVercel } from "./accounts.ts";
import { providerList } from "../../src/shared/providers.ts";
import { ROLES, ROLE_INFO } from "../../src/shared/roles.ts";
import { hashPasswordSync } from "../../src/server/passwords.ts";

/** Every mock user's password. Mock users exist only in this in-memory server. */
export const MOCK_PASSWORD = "mock-password";

installMockCloudflare();
installMockVercel();
installMockAws();
const port = Number(process.env.KEELSON_PORT || 4317);
const running = await start({
  host: "127.0.0.1",
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
await scanner.start("setup").done;
// Between the scans the AWS account gives up an Elastic IP, so the second one finds the DNS records still pointing at it.
mockAws.released = true;
await scanner.start("manual").done;
// Once more for Cloudflare, which was scanned before AWS noticed the address was gone.
await scanner.start("manual", [MOCK_ACCOUNT]).done;
seedTriageHistory(repo, MOCK_ACCOUNT);
console.log(`\n  Keelson (mock ${providerList()} data)\n\n  Open:  ${running.url}`);
console.log(
  signup
    ? "  Users: none yet, so it starts at creating the admin.\n"
    : `  Users: ${ROLES.join(", ")} (one per role) and client (a manager who sees only Other Ltd), password ${MOCK_PASSWORD}\n`,
);
