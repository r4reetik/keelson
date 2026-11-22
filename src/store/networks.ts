// Networks (the ways requests can leave: a proxy, certificates to trust) and
// which one each platform's requests use. See src/shared/networks.ts for what a
// network is, and src/networks.ts for how a request finds its route.

import type { Store } from "./db.ts";
import { isNetworkKind, isProxyProtocol, type NetworkKind, type NetworkTarget, type NetworkUse, type ProxyProtocol } from "../shared/networks.ts";
import { isProvider } from "../shared/providers.ts";

export interface Network {
  id: number;
  name: string;
  kind: NetworkKind;
  proxy: { protocol: ProxyProtocol; host: string; port: number; username: string | null } | null;
  /** The proxy password's ID in the vault, when it has one. */
  secretId: string | null;
  /** PEM certificates trusted for requests through it. */
  ca: string | null;
  updatedAt: string;
}

export type NewNetwork = Omit<Network, "id" | "updatedAt">;

interface NetworkRecord {
  id: number;
  name: string;
  kind: string;
  proxy_protocol: string | null;
  proxy_host: string | null;
  proxy_port: number | null;
  proxy_username: string | null;
  secret_id: string | null;
  ca: string | null;
  updated_at: string;
}

const toNetwork = (r: NetworkRecord): Network => ({
  id: r.id,
  name: r.name,
  // A kind this version doesn't know (written by a newer one) is still a proxy and certificates.
  kind: isNetworkKind(r.kind) ? r.kind : "proxy",
  proxy:
    isProxyProtocol(r.proxy_protocol) && r.proxy_host && r.proxy_port
      ? { protocol: r.proxy_protocol, host: r.proxy_host, port: r.proxy_port, username: r.proxy_username }
      : null,
  secretId: r.secret_id,
  ca: r.ca,
  updatedAt: r.updated_at,
});

export class NetworkRepo {
  readonly #s: Store;
  constructor(store: Store) {
    this.#s = store;
  }

  list(): Network[] {
    return this.#s.all<NetworkRecord>("SELECT * FROM networks ORDER BY name COLLATE NOCASE").map(toNetwork);
  }

  get(id: number): Network | null {
    const r = this.#s.get<NetworkRecord>("SELECT * FROM networks WHERE id = ?", id);
    return r ? toNetwork(r) : null;
  }

  /** The network with this name, whatever its capitals. */
  byName(name: string): Network | null {
    const r = this.#s.get<NetworkRecord>("SELECT * FROM networks WHERE name = ? COLLATE NOCASE", name);
    return r ? toNetwork(r) : null;
  }

  create(n: NewNetwork): Network {
    const now = new Date().toISOString();
    const { lastInsertRowid } = this.#s.run(
      "INSERT INTO networks (name, kind, proxy_protocol, proxy_host, proxy_port, proxy_username, secret_id, ca, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      n.name,
      n.kind,
      n.proxy?.protocol ?? null,
      n.proxy?.host ?? null,
      n.proxy?.port ?? null,
      n.proxy?.username ?? null,
      n.secretId,
      n.ca,
      now,
      now,
    );
    return this.get(Number(lastInsertRowid))!;
  }

  update(id: number, n: NewNetwork): Network {
    this.#s.run(
      "UPDATE networks SET name = ?, kind = ?, proxy_protocol = ?, proxy_host = ?, proxy_port = ?, proxy_username = ?, secret_id = ?, ca = ?, updated_at = ? WHERE id = ?",
      n.name,
      n.kind,
      n.proxy?.protocol ?? null,
      n.proxy?.host ?? null,
      n.proxy?.port ?? null,
      n.proxy?.username ?? null,
      n.secretId,
      n.ca,
      new Date().toISOString(),
      id,
    );
    return this.get(id)!;
  }

  /** Removes a network. What was sent through it follows the default again. */
  remove(id: number): void {
    this.#s.run("DELETE FROM networks WHERE id = ?", id);
  }

  /** Vault IDs of every proxy password, so the vault keeps them. */
  secretIds(): string[] {
    return this.#s.all<{ secret_id: string }>("SELECT secret_id FROM networks WHERE secret_id IS NOT NULL").map((r) => r.secret_id);
  }

  use(): NetworkUse {
    const use: NetworkUse = { default: null, providers: {} };
    for (const r of this.#s.all<{ target: string; network_id: number | null }>("SELECT target, network_id FROM network_use")) {
      if (r.target === "default") use.default = r.network_id;
      else if (isProvider(r.target)) use.providers[r.target] = r.network_id ?? "direct";
    }
    return use;
  }

  /**
   * Sends a target's requests through a network, or over the machine's own connection ("direct"), or (null, platforms
   * only) wherever the default goes. For the default itself, "direct" and null are the same.
   */
  setUse(target: NetworkTarget, value: number | "direct" | null): void {
    if (value === null || (target === "default" && value === "direct")) this.#s.run("DELETE FROM network_use WHERE target = ?", target);
    else
      this.#s.run(
        "INSERT INTO network_use (target, network_id) VALUES (?, ?) ON CONFLICT(target) DO UPDATE SET network_id = excluded.network_id",
        target,
        value === "direct" ? null : value,
      );
  }
}
