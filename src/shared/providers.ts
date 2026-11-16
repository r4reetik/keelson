// The platforms Keelson scans. Every account belongs to exactly one provider, and
// an entity can hold accounts from several. Adding a provider starts here; see
// "Adding a provider" in CONTRIBUTING.md for the rest.
//
// Everything the UI and the server say about a provider comes from PROVIDER_INFO,
// so no screen has to branch on a provider's name.

export const PROVIDERS = ["cloudflare", "vercel", "aws", "github", "internet"] as const;
export type ProviderId = (typeof PROVIDERS)[number];

/** One input of a provider's credential. Most providers have one; AWS has a key ID and a secret, a GitHub App its ID and private key. */
export interface CredentialField {
  label: string;
  /** Hidden while typing. A key ID is shown, a secret isn't. */
  secret: boolean;
  placeholder?: string;
  /** May be left empty: the provider then reads only what needs no credential. */
  optional?: boolean;
}

export interface ProviderInfo {
  id: ProviderId;
  label: string;
  /** What the provider calls an account, singular and plural ("account", "team"). */
  account: string;
  accounts: string;
  /** What one scanned resource is called in the provider's inventory page, and what a finding's `zone` holds. */
  resource: string;
  /** What Keelson checks there, for the platform choice. */
  blurb: string;
  /** The same in a sentence: "It checks …". */
  covers: string;
  /** What the credential is called, in the provider's words ("API token", "access key"). */
  credential: string;
  /** The credential's inputs, in order. Several are joined with ":" before they're sent (CREDENTIAL_SEPARATOR). */
  fields: CredentialField[];
  /** Whether the provider can issue a credential that only reads. Where it can't, Keelson's GET-only rule is the protection. */
  readOnlyCredential: boolean;
  /** What kind of credential an account uses, when the provider has several (a user's or an account's): shown on the Accounts page. */
  credentialKinds?: { user?: string; account?: string };
  /** What the provider calls the place its settings are changed: "dashboard", "console". */
  dashboard: string;
  /** The only place the credential is sent. */
  apiHost: string;
  /** Hostname endings of the provider's dashboard and docs, to name where a link goes. */
  sites: string[];
  /** What to do when a valid credential reaches no account. */
  noAccounts: string;
  /** What a credential needs to read a source it can't: completes "…skipped until the <credential> …". */
  needsToRead: string;
  /** What an account ID looks like, for the error when one doesn't. */
  idHint: string;
  /** IDs that are compared lowercase. */
  lowercaseIds: boolean;
  /**
   * Keelson makes one account per entity instead of reading accounts from the credential (the internet as seen
   * from outside). Add accounts lists the entities to watch, each account stays in its entity, and it is scanned
   * after the entity's other accounts, whose latest scans it reads.
   */
  perEntity?: boolean;
}

export const CREDENTIAL_SEPARATOR = ":";

export const PROVIDER_INFO: Record<ProviderId, ProviderInfo> = {
  cloudflare: {
    id: "cloudflare",
    label: "Cloudflare",
    account: "account",
    accounts: "accounts",
    resource: "zone",
    blurb: "Zones, DNS, WAF, Zero Trust, Workers and more",
    covers: "zones, DNS, the WAF, Zero Trust and Workers",
    credential: "API token",
    fields: [{ label: "API token", secret: true }],
    credentialKinds: { user: "User token", account: "Account token" },
    dashboard: "dashboard",
    readOnlyCredential: true,
    apiHost: "api.cloudflare.com",
    sites: ["cloudflare.com"],
    noAccounts: "Edit the token in Cloudflare and include at least one account.",
    needsToRead: "gets the permissions",
    idHint: "A Cloudflare account ID is 32 hexadecimal characters.",
    lowercaseIds: true,
  },
  vercel: {
    id: "vercel",
    label: "Vercel",
    account: "team",
    accounts: "teams",
    resource: "project",
    blurb: "Projects, deployment protection, secrets, firewall and domains",
    covers: "deployment protection, secrets, the firewall and domains",
    credential: "access token",
    fields: [{ label: "Access token", secret: true }],
    dashboard: "dashboard",
    readOnlyCredential: false,
    apiHost: "api.vercel.com",
    sites: ["vercel.com"],
    noAccounts: "Create a token scoped to the team you want to scan, or to Full Account.",
    needsToRead: "belongs to someone whose role can read them",
    idHint: "That isn't a Vercel team or account ID.",
    lowercaseIds: false,
  },
  aws: {
    id: "aws",
    label: "AWS",
    account: "account",
    accounts: "accounts",
    resource: "region",
    blurb: "IAM, S3, security groups, databases, CloudFront, load balancers and Route 53",
    covers: "IAM, S3, security groups, databases, CloudFront, load balancers and Route 53",
    credential: "access key",
    fields: [
      { label: "Access key ID", secret: false, placeholder: "AKIA…" },
      { label: "Secret access key", secret: true },
    ],
    credentialKinds: { user: "IAM user key", account: "Root user key" },
    dashboard: "console",
    readOnlyCredential: true,
    apiHost: "*.amazonaws.com",
    sites: ["aws.amazon.com", "amazonaws.com"],
    noAccounts: "Check that the access key is active and belongs to an IAM user in the account you want to scan.",
    needsToRead: "gets the permissions",
    idHint: "An AWS account ID is 12 digits.",
    lowercaseIds: false,
  },
  github: {
    id: "github",
    label: "GitHub",
    account: "organization",
    accounts: "organizations",
    resource: "repository",
    blurb: "Organization settings, branch protection, code security alerts, Actions and webhooks",
    covers: "organization settings, branch protection, code security alerts, Actions and webhooks",
    credential: "GitHub App",
    fields: [
      { label: "App ID", secret: false, placeholder: "1234567" },
      { label: "Private key", secret: true, placeholder: "-----BEGIN RSA PRIVATE KEY-----…" },
    ],
    dashboard: "settings",
    // The App is given read permissions only, and Keelson asks GitHub for a token limited to reading on every scan.
    readOnlyCredential: true,
    apiHost: "api.github.com",
    sites: ["github.com"],
    noAccounts: "Install the GitHub App on the organizations you want to scan, from the App's settings under Install App.",
    needsToRead: "gets the read permission",
    idHint: "A GitHub organization ID in Keelson is gh_ followed by its number.",
    lowercaseIds: false,
  },
  internet: {
    id: "internet",
    label: "Internet",
    account: "entity",
    accounts: "entities",
    resource: "domain",
    blurb: "Sonar: what your domains and addresses expose, from certificate logs and Shodan",
    covers: "what the entity's domains and addresses expose, from certificate transparency logs and Shodan",
    credential: "Shodan API key",
    fields: [{ label: "Shodan API key (optional)", secret: true, optional: true }],
    dashboard: "Shodan account",
    // Shodan keys can't write anything, and Keelson only searches with it.
    readOnlyCredential: true,
    apiHost: "api.shodan.io",
    sites: ["shodan.io", "crt.sh"],
    noAccounts: "Create an entity first by adding an account on another platform.",
    needsToRead: "belongs to a Shodan plan that includes it",
    idHint: "An internet account ID in Keelson is ext_ followed by its entity's number.",
    lowercaseIds: true,
    perEntity: true,
  },
};

export const isProvider = (v: unknown): v is ProviderId => typeof v === "string" && (PROVIDERS as readonly string[]).includes(v);

/** Account IDs as each provider issues them: Cloudflare's are 32 hex characters, Vercel's are team or user IDs, AWS's are 12 digits, GitHub's are gh_ and the organization's number, and the internet's are ext_ and the entity's number. */
export const ACCOUNT_ID_PATTERN: Record<ProviderId, RegExp> = {
  cloudflare: /^[0-9a-f]{32}$/,
  vercel: /^(team_)?[A-Za-z0-9]{8,40}$/,
  aws: /^\d{12}$/,
  // GitHub's organization IDs are plain numbers, which would pass for AWS's; the prefix keeps them apart.
  github: /^gh_\d{1,20}$/,
  // One per entity, named after it (accountIdForEntity).
  internet: /^ext_\d{1,9}$/,
};

/** The account that watches an entity from the internet (PROVIDER_INFO.internet.perEntity). */
export const accountIdForEntity = (entityId: number) => `ext_${entityId}`;
export const entityOfAccountId = (id: string): number | null => (/^ext_(\d{1,9})$/.test(id) ? Number(id.slice(4)) : null);

/** The provider an account ID can belong to, judged by its shape. The strictest shapes are tried first: 12 digits would also pass as a Vercel user ID. */
const BY_STRICTEST_ID: ProviderId[] = ["cloudflare", "aws", "github", "internet", "vercel"];
export const providerForId = (id: string): ProviderId | null => BY_STRICTEST_ID.find((p) => ACCOUNT_ID_PATTERN[p].test(id)) ?? null;

/** Providers that are platforms with accounts of their own, not the per-entity view from outside (Sonar). */
export const PLATFORMS: readonly ProviderId[] = PROVIDERS.filter((p) => !PROVIDER_INFO[p].perEntity);

/** "Cloudflare", "Cloudflare and Vercel", "Cloudflare, Vercel and AWS". Without a list, every platform (not Sonar's internet). */
export function providerList(providers: readonly ProviderId[] = PLATFORMS, last = "and"): string {
  const labels = providers.map((p) => PROVIDER_INFO[p].label);
  return labels.length < 2 ? labels.join("") : `${labels.slice(0, -1).join(", ")} ${last} ${labels[labels.length - 1]}`;
}

/**
 * What a finding's `zone` is called for the providers in view. One platform uses its own word ("Zone",
 * "Project", "Region"); a view that mixes platforms says "Location", the one word that covers them all.
 */
export function zoneWord(providers: readonly string[]): string {
  const words = [...new Set((providers.length ? providers.filter(isProvider) : (["cloudflare"] as ProviderId[])).map((p) => PROVIDER_INFO[p].resource))];
  const text = words.length === 1 ? words[0] : LOCATION;
  return text[0].toUpperCase() + text.slice(1);
}

/** The generic word for where in an account a finding is: a zone, a project or a region. */
export const LOCATION = "location";

/** The provider whose dashboard or docs a link goes to, by its address. */
export function providerOfUrl(url: string): ProviderId | null {
  try {
    const h = new URL(url).hostname;
    return PROVIDERS.find((p) => PROVIDER_INFO[p].sites.some((s) => h === s || h.endsWith(`.${s}`))) ?? null;
  } catch {
    return null;
  }
}
