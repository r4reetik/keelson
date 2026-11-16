// What a provider keeps for an account between scans, beyond the scan's own
// snapshot: GitHub's software bills of materials (rebuilt only when a
// repository's manifest and lock files change) and the dependency view the
// Repositories page reads. Values are gzipped JSON; rows go with their account.

import { gunzipSync, gzipSync } from "node:zlib";
import type { Store } from "./db.ts";

/** One account's cache, as a provider's scan sees it. */
export interface AccountCache {
  get<T>(key: string): T | null;
  put(key: string, value: unknown): void;
  /** Keys starting with `prefix`. */
  keys(prefix: string): string[];
  delete(key: string): void;
}

export class CacheRepo {
  readonly #s: Store;
  constructor(store: Store) {
    this.#s = store;
  }

  get<T>(accountId: string, key: string): T | null {
    const row = this.#s.db.prepare("SELECT data FROM provider_cache WHERE account_id = ? AND key = ?").get(accountId, key) as { data: Uint8Array } | undefined;
    if (!row) return null;
    try {
      return JSON.parse(gunzipSync(row.data).toString("utf8")) as T;
    } catch {
      return null;
    }
  }

  put(accountId: string, key: string, value: unknown): void {
    const data = gzipSync(Buffer.from(JSON.stringify(value)));
    this.#s.db
      .prepare(
        "INSERT INTO provider_cache (account_id, key, data, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT (account_id, key) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at",
      )
      .run(accountId, key, data, new Date().toISOString());
  }

  keys(accountId: string, prefix: string): string[] {
    return this.#s
      .all<{ key: string }>("SELECT key FROM provider_cache WHERE account_id = ? AND substr(key, 1, ?) = ?", accountId, prefix.length, prefix)
      .map((r) => r.key);
  }

  delete(accountId: string, key: string): void {
    this.#s.run("DELETE FROM provider_cache WHERE account_id = ? AND key = ?", accountId, key);
  }

  /** The cache of one account, for its provider's scan. */
  for(accountId: string): AccountCache {
    return {
      get: (key) => this.get(accountId, key),
      put: (key, value) => this.put(accountId, key, value),
      keys: (prefix) => this.keys(accountId, prefix),
      delete: (key) => this.delete(accountId, key),
    };
  }
}
