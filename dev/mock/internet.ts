// What Sonar asks, mocked: crt.sh's certificate logs, Shodan's API and InternetDB,
// and public DNS for the names only the logs know. Fictional throughout: names
// under .example, addresses from the documentation ranges. Install it after the
// mock Cloudflare, so its DNS answers come first and the rest fall through.
//
// The mock entity's picture from outside:
//  - mock.example's CAA allows Let's Encrypt only, but the logs hold a recent certificate from Google Trust
//    Services for staging.mock.example, a name Cloudflare's DNS doesn't list; it resolves to 203.0.113.40,
//    where Shodan has seen SSH.
//  - mock-legacy.example (one of the entity's own domains) has its DNS at a registrar Keelson doesn't read; the
//    logs name shop.mock-legacy.example, at 203.0.113.90, where Shodan has seen Redis and a known vulnerability.
//  - The AWS account's Elastic IP, the origin of the proxied origin-api.mock.example, is listed on Shodan with that
//    hostname and PostgreSQL open.
//  - Amass (mocked: the real one never runs here) finds vpn.mock.example, which nothing else knows, at the staging address.

import { MOCK_AWS_IP } from "./aws.ts";
import { amass } from "../../src/providers/internet/amass.ts";

export const MOCK_SHODAN_KEY = "mockShodanKey0000000000000000000";
export const MOCK_LEGACY_DOMAIN = "mock-legacy.example";

interface MockOptions {
  onRequest?: (url: URL, init?: RequestInit) => void;
  /** Make crt.sh fail, as it often does. */
  crtshDown?: boolean;
  /** Amass isn't installed. */
  noAmass?: boolean;
  /** What the mock Amass is given to start from. */
  onAmass?: (input: { domains: string[] }) => void;
}

/** What the mock Amass finds: a name the logs and DNS already have, and one nothing else knows. */
const AMASS_FOUND: [string, string[]][] = [
  ["staging.mock.example", ["203.0.113.40"]],
  ["vpn.mock.example", ["203.0.113.40"]],
];

const ago = (days: number) => new Date(Date.now() - days * 86_400_000).toISOString().slice(0, 19);

const CERTS: Record<string, unknown[]> = {
  "mock.example": [
    {
      id: 9001,
      issuer_name: "C=US, O=Let's Encrypt, CN=R11",
      name_value: "mock.example\nwww.mock.example",
      serial_number: "01",
      not_before: ago(20),
      not_after: ago(-70),
      entry_timestamp: ago(20),
    },
    {
      id: 9002,
      issuer_name: "C=US, O=Google Trust Services, CN=WE1",
      name_value: "staging.mock.example",
      serial_number: "02",
      not_before: ago(3),
      not_after: ago(-87),
      entry_timestamp: ago(3),
    },
  ],
  [MOCK_LEGACY_DOMAIN]: [
    {
      id: 9003,
      issuer_name: "C=GB, O=Sectigo Limited, CN=Sectigo RSA Domain Validation Secure Server CA",
      name_value: `shop.${MOCK_LEGACY_DOMAIN}`,
      serial_number: "03",
      not_before: ago(100),
      not_after: ago(-265),
      entry_timestamp: ago(100),
    },
  ],
};

/** Public DNS answers for names the mock Cloudflare doesn't answer: [type, data]. */
const DNS: Record<string, Record<string, [number, string][]>> = {
  "mock.example": { CAA: [[257, '0 issue "letsencrypt.org"']] },
  "staging.mock.example": { A: [[1, "203.0.113.40"]] },
  "vpn.mock.example": { A: [[1, "203.0.113.40"]] },
  [MOCK_LEGACY_DOMAIN]: { NS: [[2, "ns1.registrar-dns.example."]] },
  [`shop.${MOCK_LEGACY_DOMAIN}`]: { A: [[1, "203.0.113.90"]] },
};

/** What Shodan has seen: InternetDB's shape, and the full API's extras. */
const HOSTS: Record<
  string,
  { ports: number[]; hostnames: string[]; vulns: string[]; products?: Record<number, [string, string]>; cvss?: Record<string, number> }
> = {
  [MOCK_AWS_IP]: {
    ports: [443, 5432],
    hostnames: ["origin-api.mock.example", "unrelated.other-company.example"],
    vulns: [],
    products: { 5432: ["PostgreSQL", "14.2"] },
  },
  "203.0.113.40": { ports: [22, 443], hostnames: ["staging.mock.example"], vulns: [], products: { 22: ["OpenSSH", "8.9p1"] } },
  "203.0.113.90": {
    ports: [80, 6379],
    hostnames: [`shop.${MOCK_LEGACY_DOMAIN}`],
    vulns: ["CVE-2022-0543"],
    products: { 6379: ["Redis key-value store", "5.0.7"] },
    cvss: { "CVE-2022-0543": 10 },
  },
};

export function installMockInternet(o: MockOptions = {}): () => void {
  const real = globalThis.fetch;
  const realAmass = { ...amass };
  amass.path = () => (o.noAmass ? null : "/mock/amass");
  amass.run = async (_bin, input) => {
    o.onAmass?.({ domains: input.domains });
    const found = new Map<string, string[]>();
    for (const [name, ips] of AMASS_FOUND) if (input.domains.some((d) => name.endsWith(`.${d}`))) found.set(name, ips);
    return found;
  };
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    const method = init?.method || "GET";

    if (url.hostname === "cloudflare-dns.com") {
      const name = (url.searchParams.get("name") || "").toLowerCase();
      const answers = DNS[name]?.[url.searchParams.get("type") || "A"];
      if (answers) return json({ Status: 0, Answer: answers.map(([type, data]) => ({ name, type, TTL: 300, data })) });
      if (name.endsWith(`.${MOCK_LEGACY_DOMAIN}`)) return json({ Status: 3, Answer: [] });
      return real(input as string, init);
    }
    if (!["crt.sh", "api.shodan.io", "internetdb.shodan.io"].includes(url.hostname)) return real(input as string, init);
    o.onRequest?.(url, init);
    if (method !== "GET") return json({ error: "The mock only reads" }, 405);

    if (url.hostname === "crt.sh") {
      if (o.crtshDown) return new Response("<html>502 Bad Gateway</html>", { status: 502 });
      const q = (url.searchParams.get("q") || "").replace(/^%\./, "");
      return json(CERTS[q] ?? []);
    }

    if (url.hostname === "internetdb.shodan.io") {
      const ip = decodeURIComponent(url.pathname.slice(1));
      const h = HOSTS[ip];
      return h ? json({ ip, ports: h.ports, hostnames: h.hostnames, cpes: [], tags: [], vulns: h.vulns }) : json({ detail: "No information available" }, 404);
    }

    // Shodan's API: every request carries the key.
    if (url.searchParams.get("key") !== MOCK_SHODAN_KEY) return json({ error: "Please provide a valid API key." }, 401);
    if (url.pathname === "/api-info") return json({ plan: "dev", query_credits: 100, scan_credits: 0 });
    const dns = /^\/dns\/domain\/(.+)$/.exec(url.pathname);
    if (dns) return json({ domain: dns[1], subdomains: dns[1] === MOCK_LEGACY_DOMAIN ? ["api", "shop"] : [], data: [] });
    const host = /^\/shodan\/host\/(.+)$/.exec(url.pathname);
    if (host) {
      const ip = decodeURIComponent(host[1]);
      const h = HOSTS[ip];
      if (!h) return json({ error: "No information available for that IP." }, 404);
      return json({
        ip_str: ip,
        ports: h.ports,
        hostnames: h.hostnames,
        domains: [],
        vulns: h.vulns,
        last_update: ago(2),
        data: h.ports.map((port) => ({
          port,
          transport: "tcp",
          product: h.products?.[port]?.[0],
          version: h.products?.[port]?.[1],
          // Banners are dropped by Keelson; this one proves it.
          data: "MOCK-BANNER-CONTENT",
          vulns: Object.fromEntries(h.vulns.map((id) => [id, { cvss: h.cvss?.[id] ?? null, verified: false }])),
        })),
      });
    }
    return json({ error: "Not found" }, 404);
  }) as typeof fetch;
  return () => {
    globalThis.fetch = real;
    Object.assign(amass, realAmass);
  };
}
