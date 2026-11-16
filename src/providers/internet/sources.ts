// Every source an internet scan (Sonar) reads. None of them is a platform's API:
// the entity's other accounts, public certificate transparency logs, public DNS
// and Shodan. Like the other providers' registries, each has a coverage label and
// what it needs, so a source that couldn't be read skips the checks built on it.

export interface InternetSource {
  label: string;
  /** What it needs, in the words the Accounts page shows. */
  permission: string;
}

const DEFS = {
  related: {
    label: "Domains, DNS records and addresses of the entity's other accounts",
    permission: "None: read from their latest scans. Every account in the entity needs a scan since Sonar was added.",
  },
  certificates: { label: "Certificate transparency logs (crt.sh)", permission: "None: the logs are public" },
  dns: { label: "Public DNS lookups", permission: "None: public DNS over HTTPS" },
  shodan: {
    label: "What Shodan has seen on the entity's addresses",
    permission: "a Shodan API key for service details, or none for Shodan's free InternetDB",
  },
  shodanDns: { label: "Subdomains Shodan has seen", permission: "a Shodan API key on a plan with query credits" },
  routing: {
    label: "Load balancers, their rules and targets, and security groups in the entity's AWS accounts",
    permission: "None: read from the AWS accounts' latest scans. Each needs a scan since this was added.",
  },
  amass: {
    label: "Subdomains Amass found (OWASP Amass, passive)",
    permission: "Amass 5 installed where Keelson runs: on the PATH, or its path in KEELSON_AMASS (not in the Docker image yet)",
  },
} satisfies Record<string, InternetSource>;

export type InternetSourceKey = keyof typeof DEFS;
export const INTERNET_SOURCES: Record<InternetSourceKey, InternetSource> = DEFS;
export const INTERNET_SOURCE_KEYS = Object.keys(DEFS) as InternetSourceKey[];
