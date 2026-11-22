// Networks: the ways Keelson's requests can leave the machine it runs on. Some
// platforms only answer from inside a company's network (an IP allowlist on a
// GitHub organization, an AWS policy tied to a source address, a registry with
// an access list), and that network is reached through a zero trust client or
// a VPN. A network here is the route into one: a proxy to send requests
// through, and the certificate to trust when it inspects TLS. Which network a
// platform's requests use is chosen per platform (src/networks.ts).
//
// Keelson never runs a VPN client itself: a tunnel changes the routes of the
// whole machine, so it couldn't be chosen per platform, and it needs privileges
// the Docker image doesn't have. Every product below can offer a proxy, or
// already steers the machine's traffic and only needs its certificate trusted.

import type { ProviderId } from "./providers.ts";

export const PROXY_PROTOCOLS = ["http", "https", "socks5"] as const;
export type ProxyProtocol = (typeof PROXY_PROTOCOLS)[number];

export const PROXY_PROTOCOL_LABEL: Record<ProxyProtocol, string> = {
  http: "HTTP proxy",
  https: "HTTP proxy over TLS",
  socks5: "SOCKS5 proxy",
};

/** The port each kind of proxy usually listens on, offered until one is typed. */
export const PROXY_DEFAULT_PORT: Record<ProxyProtocol, number> = { http: 8080, https: 443, socks5: 1080 };

export const NETWORK_KINDS = ["netskope", "warp", "zscaler", "openvpn", "wireguard", "tailscale", "proxy"] as const;
export type NetworkKind = (typeof NETWORK_KINDS)[number];

export interface NetworkKindInfo {
  label: string;
  /** What it is, in a line, for the kind picker. */
  summary: string;
  /** How Keelson gets a route into it: shown beside the form. Each entry is one step or fact. */
  setup: string[];
  /** The proxy it usually offers, pre-filled in the form. Absent when there is no usual one. */
  proxy?: { protocol: ProxyProtocol; host: string; port: number };
  /** It usually re-signs TLS with a certificate of its own, so the form asks for that certificate. */
  inspectsTls: boolean;
  /** Where its own documentation explains the step above. */
  docs?: string;
}

/**
 * What the app says about each kind of network. The kind only picks the wording and what the form starts with: every
 * network is sent to the same way (a proxy, a certificate, or both), so a new product needs an entry here and nothing else.
 */
export const NETWORK_KIND_INFO: Record<NetworkKind, NetworkKindInfo> = {
  netskope: {
    label: "Netskope",
    summary: "Traffic steered and inspected by Netskope",
    setup: [
      "Where the Netskope Client runs on the same machine as Keelson, it already steers Keelson's requests: leave the proxy empty.",
      "Without the client there, enter your tenant's explicit proxy address, from your Netskope administrator.",
      "Netskope re-signs the connections it inspects. Add your tenant's root certificate (and its intermediate, when it has one), which your administrator can download from the Netskope console.",
    ],
    inspectsTls: true,
    docs: "https://docs.netskope.com/",
  },
  warp: {
    label: "Cloudflare WARP",
    summary: "The Cloudflare One Client (WARP), in local proxy mode",
    setup: [
      "Put the client on the machine Keelson runs on in Local proxy mode: the service mode of its device profile in Zero Trust, or warp-cli mode proxy on a client no organization manages. It then listens on 127.0.0.1, port 40000 unless you changed it, as a SOCKS5 and HTTP proxy, and only what is sent there goes through Cloudflare.",
      "In a container, 127.0.0.1 is the container itself: run Keelson on the host's network, or run the client in a container beside it.",
      "Cloudflare drops a request that takes longer than 10 seconds in this mode. Keelson tries a failed request again, so a slow answer costs time rather than a gap.",
      "When your Zero Trust organization inspects TLS, add the root certificate it uses.",
    ],
    proxy: { protocol: "socks5", host: "127.0.0.1", port: 40000 },
    inspectsTls: false,
    docs: "https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/modes/",
  },
  zscaler: {
    label: "Zscaler",
    summary: "Traffic forwarded to and inspected by Zscaler",
    setup: [
      "Where Zscaler Client Connector runs on the same machine as Keelson, it already forwards Keelson's requests: leave the proxy empty.",
      "Without it there, enter the proxy address your Zscaler administrator gives for your cloud.",
      "With SSL inspection on, Zscaler re-signs connections. Add the Zscaler root certificate, or your organization's own if it uses one.",
    ],
    inspectsTls: true,
    docs: "https://help.zscaler.com/",
  },
  openvpn: {
    label: "OpenVPN",
    summary: "A VPN tunnel, reached through a proxy beside Keelson",
    setup: [
      "OpenVPN has no proxy of its own, and a tunnel on Keelson's machine would carry every platform's requests, not one platform's.",
      "Run an OpenVPN client beside Keelson that also offers an HTTP or SOCKS5 proxy into the tunnel (a VPN client container with a proxy built in, or a small proxy on a machine that is on the VPN), and enter that proxy here.",
      "If every platform should go through the VPN, connect the machine itself instead: no network is needed here.",
    ],
    inspectsTls: false,
  },
  wireguard: {
    label: "WireGuard",
    summary: "A VPN tunnel, reached through a proxy beside Keelson",
    setup: [
      "WireGuard has no proxy of its own, and a tunnel on Keelson's machine would carry every platform's requests, not one platform's.",
      "Run a WireGuard client beside Keelson that also offers an HTTP or SOCKS5 proxy into the tunnel (a VPN client container with a proxy built in, or a small proxy on a machine that is on the VPN), and enter that proxy here.",
      "If every platform should go through the VPN, connect the machine itself instead: no network is needed here.",
    ],
    inspectsTls: false,
  },
  tailscale: {
    label: "Tailscale",
    summary: "A tailnet, through Tailscale's userspace proxy",
    setup: [
      "Run tailscaled in userspace networking mode with its proxies on: --tun=userspace-networking --socks5-server=localhost:1055 --outbound-http-proxy-listen=localhost:1055.",
      "Enter that address here. To leave from one of your own machines, set it as the exit node.",
    ],
    proxy: { protocol: "socks5", host: "127.0.0.1", port: 1055 },
    inspectsTls: false,
    docs: "https://tailscale.com/docs/concepts/userspace-networking",
  },
  proxy: {
    label: "Proxy or other",
    summary: "Any HTTP or SOCKS5 proxy, or a certificate to trust",
    setup: [
      "Enter the proxy that leads into the network: an HTTP proxy (it must allow CONNECT), the same over TLS, or SOCKS5.",
      "When the network inspects TLS, add the certificate it signs with.",
    ],
    inspectsTls: false,
  },
};

export const isNetworkKind = (v: unknown): v is NetworkKind => typeof v === "string" && (NETWORK_KINDS as readonly string[]).includes(v);
export const isProxyProtocol = (v: unknown): v is ProxyProtocol => typeof v === "string" && (PROXY_PROTOCOLS as readonly string[]).includes(v);

/** One certificate a network trusts, as shown: never the certificate itself. */
export interface NetworkCertificate {
  subject: string;
  /** ISO date it stops being valid. */
  expires: string;
  expired: boolean;
  /** SHA-256, to compare with what the administrator handed over. */
  fingerprint: string;
}

/** What requests are sent through: everything that names no network of its own, or one platform. */
export type NetworkTarget = "default" | ProviderId;

export interface NetworkRow {
  id: number;
  name: string;
  kind: NetworkKind;
  /** Null when the network needs no proxy: the machine is already on it, and only its certificate is trusted. */
  proxy: { protocol: ProxyProtocol; host: string; port: number; username: string | null; hasPassword: boolean } | null;
  certificates: NetworkCertificate[];
  /** What is sent through it now. */
  usedBy: NetworkTarget[];
}

/**
 * Where each platform's requests go. `default` is a network, or null for the machine's own connection. A platform is
 * absent while it follows the default, "direct" to use the machine's own connection whatever the default is, or a network.
 */
export interface NetworkUse {
  default: number | null;
  providers: Partial<Record<ProviderId, number | "direct">>;
}

export interface NetworksResponse {
  networks: NetworkRow[];
  use: NetworkUse;
}

/** A network as the form sends it. `password` is left out to keep the stored one, and empty to remove it. */
export interface NetworkInput {
  name: string;
  kind: NetworkKind;
  proxy: { protocol: ProxyProtocol; host: string; port: number; username?: string | null; password?: string } | null;
  /** PEM certificates; left out to keep the stored ones, empty to remove them. */
  ca?: string;
}

export interface NetworkReach {
  provider: ProviderId;
  /** The platform's API host, or the instance a connected account of a self-hosted platform is on. */
  host: string;
  ok: boolean;
  /** How long the platform took to answer through the network. */
  ms: number | null;
  /** Why it couldn't be reached, fit to show. */
  error: string | null;
}

export interface NetworkTestResponse {
  /** The address the internet sees requests come from through this network, and whether Cloudflare saw WARP; null when it couldn't be told. */
  egress: { address: string; warp: boolean } | null;
  reached: NetworkReach[];
}

/** "socks5://127.0.0.1:40000", for lists. Never with a username or password. */
export const proxyAddress = (p: { protocol: ProxyProtocol; host: string; port: number }): string =>
  `${p.protocol}://${p.host.includes(":") ? `[${p.host}]` : p.host}:${p.port}`;

/**
 * The value a platform's network choice has in a picker: "inherit" (follow the default), "direct", or "net:<id>" for a
 * network. A network's value isn't its bare number: an object keeps numeric keys first, which would list networks
 * above "Default".
 */
export const networkChoice = (use: NetworkUse, target: NetworkTarget): string => {
  const value = target === "default" ? (use.default ?? "direct") : (use.providers[target] ?? "inherit");
  return typeof value === "number" ? `net:${value}` : value;
};

/** What a picker's value means to the API: a network's ID, "direct", or null to follow the default. */
export const choiceValue = (choice: string): number | "direct" | null =>
  choice.startsWith("net:") ? Number(choice.slice(4)) : choice === "direct" ? "direct" : null;
