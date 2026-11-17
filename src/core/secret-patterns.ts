// Patterns for credentials written straight into text that should only hold
// commands or configuration: a Vercel build command, an EC2 start-up script, a
// Lambda function's or ECS task's environment variables. Providers share them, so
// a kind of secret found on one platform is found on the others. The text is only
// held while it is scanned; findings carry the kind, never the value.

/**
 * Credentials written straight into text (a build command, a start-up script), by kind. A reference to a variable (`$NPM_TOKEN`,
 * `${TOKEN}`) is fine and doesn't match. Only the kind is ever reported, never the value.
 */
const LITERAL = String.raw`(?!\$)`;
export const SECRET_IN_TEXT: [string, RegExp][] = [
  ["an npm auth token", new RegExp(String.raw`_authToken=${LITERAL}[^\s'"]{8,}`)],
  ["a GitHub token", /\b(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})/],
  ["an AWS access key", /\bAKIA[0-9A-Z]{16}\b/],
  ["an Alibaba Cloud AccessKey", /\bLTAI[A-Za-z0-9]{12,30}\b/],
  ["a Slack token", /\bxox[abprs]-[A-Za-z0-9-]{10,}/],
  ["a Stripe secret key", /\b[sr]k_live_[A-Za-z0-9]{16,}/],
  ["a password in a URL", new RegExp(String.raw`[a-z][a-z0-9+.-]*://[^/\s:@]+:${LITERAL}[^@\s/]{3,}@`, "i")],
  ["a bearer token", new RegExp(String.raw`Bearer\s+${LITERAL}[A-Za-z0-9._~+/-]{20,}`)],
  ["a private key", /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY/],
  ["a token passed on the command line", new RegExp(`--(token|password|api-key)[ =]${LITERAL}[A-Za-z0-9._-]{16,}`)],
];
export const secretKindIn = (text: string): string | null => SECRET_IN_TEXT.find(([, re]) => re.test(text))?.[0] ?? null;

/** Names that usually hold a secret. Public keys meant for browsers (publishable, anon, site keys) are left out. */
const SECRET_NAME =
  /(SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE|API_?KEY|ACCESS_?KEY|_KEY$|^KEY$|CREDENTIAL|DATABASE_URL|POSTGRES_URL|REDIS_URL|MONGODB_URI|_DSN$|CONNECTION_STRING|SIGNING|SALT)/i;
const PUBLIC_NAME = /(PUBLISHABLE|ANON_KEY|SITE_KEY|PUBLIC_KEY|_ID$|_URL$(?<!DATABASE_URL|POSTGRES_URL|REDIS_URL))/i;
export const looksSecret = (key: string): boolean => SECRET_NAME.test(key) && !PUBLIC_NAME.test(key);

/** A value that points at a secret kept elsewhere rather than holding one: an ARN, a parameter path, a reference. */
const REFERENCE = /^(arn:|\/|\$|\{\{resolve:|ssm:|secretsmanager:)/i;

/**
 * The first credential in a set of environment variables: by its value's format (confirmed), or else by a secret-looking
 * name with a literal value of some length (likely). Only the variable's name and the kind are returned, never the value.
 */
export function secretInVariables(vars: Record<string, unknown>): { where: string; kind: string; likely: boolean } | null {
  let byName: { where: string; kind: string; likely: boolean } | null = null;
  for (const [name, raw] of Object.entries(vars)) {
    const value = typeof raw === "string" ? raw : "";
    const kind = secretKindIn(`${name}=${value}`);
    if (kind) return { where: name, kind, likely: false };
    if (!byName && looksSecret(name) && value.length >= 8 && !REFERENCE.test(value)) byName = { where: name, kind: "a secret-looking value", likely: true };
  }
  return byName;
}
