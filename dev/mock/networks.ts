// Mock networks for the dev server: a zero trust network that inspects TLS, a
// WARP proxy and a partner's VPN whose proxy is down. Requests "through" them
// are answered by the mocked platforms, and a test of one gets a made-up
// address from the documentation ranges, so the mock never opens a connection.

import { net, NetworkError, type Route } from "../../src/core/net.ts";
import type { TokenVault } from "../../src/config.ts";
import type { Repo } from "../../src/store/repo.ts";
import { PROVIDER_INFO, PROVIDERS } from "../../src/shared/providers.ts";
import { makeAuthority } from "./certificate.ts";

export const MOCK_NETWORK_PASSWORD = "mock-proxy-password";
/** The proxy nothing answers at, to show what a failed test looks like. */
const DOWN = "vpn-proxy.partner.example";
const CHECK_HOSTS = new Set<string>(PROVIDERS.flatMap((p) => PROVIDER_INFO[p].checkHost ?? []));

/** Sends every request on a mock network to the mocked platforms. Returns a function that puts the real sender back. */
export function installMockNetworks(): () => void {
  const real = net.send;
  net.send = async (route: Route, input: string | URL, init: RequestInit) => {
    const url = new URL(String(input));
    if (route.proxy?.host === DOWN)
      throw new NetworkError(`Couldn't use "${route.name}": the proxy at ${DOWN}:${route.proxy.port} didn't answer.`, "ETIMEDOUT");
    if (url.hostname === "www.cloudflare.com" && url.pathname === "/cdn-cgi/trace") {
      const warp = route.proxy?.port === 40000;
      return new Response(`fl=mock\nip=${warp ? "198.51.100.24" : "203.0.113.57"}\nwarp=${warp ? "on" : "off"}\ngateway=off\n`);
    }
    // A platform's own front page, asked for nothing and without a credential (a test, or the check before a scan):
    // any answer means it was reached. AWS's real requests go to "/" too, with a query and a signature.
    const bare = url.pathname === "/" && !url.search && !new Headers(init.headers).has("authorization");
    if (CHECK_HOSTS.has(url.hostname) && bare) return new Response("{}", { status: 401 });
    return fetch(input, init);
  };
  return () => {
    net.send = real;
  };
}

/** Adds the mock networks the way the Networks page would, with AWS, Gitea and GitHub sent through one. */
export function seedNetworks(repo: Repo, vault: TokenVault): void {
  const office = repo.networks.create({
    name: "Head office",
    kind: "netskope",
    proxy: null,
    secretId: null,
    ca: makeAuthority("Mock Group Inspection Root CA").ca,
  });
  const warp = repo.networks.create({
    name: "Build hosts",
    kind: "warp",
    proxy: { protocol: "socks5", host: "127.0.0.1", port: 40000, username: null },
    secretId: null,
    ca: null,
  });
  repo.networks.create({
    name: "Partner VPN",
    kind: "openvpn",
    proxy: { protocol: "http", host: DOWN, port: 8888, username: "keelson" },
    secretId: vault.put(MOCK_NETWORK_PASSWORD, null),
    ca: null,
  });
  repo.networks.setUse("aws", office.id);
  // The Gitea instance is on the office network and presents a certificate from the office's own authority.
  repo.networks.setUse("gitea", office.id);
  repo.networks.setUse("github", warp.id);
}
