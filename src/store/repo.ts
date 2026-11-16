// The store's domain operations, one repository per concern:
//   repo.settings   instance settings and check overrides
//   repo.entities   companies or teams that own accounts
//   repo.accounts   Cloudflare accounts
//   repo.scans      scan lifecycle, trends and retention
//   repo.findings   findings with triage, and each finding's timeline
//   repo.users      the people who sign in, and their roles
//   repo.cache      what providers keep between scans (GitHub's SBOMs)

import type { Store } from "./db.ts";
import { SettingsRepo } from "./settings.ts";
import { AccountRepo, EntityRepo, type Account, type Entity } from "./accounts.ts";
import { ScanRepo } from "./scans.ts";
import { FindingRepo } from "./findings.ts";
import { UserRepo } from "./users.ts";
import { CacheRepo } from "./cache.ts";
import { resolveScope, type ResolvedScope } from "../shared/scope.ts";

export type { Account, Entity, EntityNotifications, EntityUpdate } from "./accounts.ts";
export { DEFAULT_NOTIFICATIONS } from "./accounts.ts";
export { DEFAULT_SETTINGS, type Overrides } from "./settings.ts";
export type { StoredFinding, TriagePatch } from "./findings.ts";
export type { DoneScan } from "./scans.ts";
export type { User } from "./users.ts";
export type { AccountCache } from "./cache.ts";
export type { Settings } from "../shared/api.ts";
export { displayName } from "../shared/scope.ts";

/** What the dashboard is looking at: every included account, one entity, or one account. */
export type Scope = ResolvedScope<Account, Entity>;

export class Repo {
  readonly store: Store;
  readonly settings: SettingsRepo;
  readonly entities: EntityRepo;
  readonly accounts: AccountRepo;
  readonly scans: ScanRepo;
  readonly findings: FindingRepo;
  readonly users: UserRepo;
  readonly cache: CacheRepo;

  constructor(store: Store) {
    this.store = store;
    this.settings = new SettingsRepo(store);
    this.entities = new EntityRepo(store);
    this.accounts = new AccountRepo(store);
    this.scans = new ScanRepo(store);
    this.findings = new FindingRepo(store);
    this.users = new UserRepo(store);
    this.cache = new CacheRepo(store);
  }

  /**
   * The entities and accounts someone limited to `limit` may see (src/store/users.ts), or every one with null.
   * Everything a user reads or changes is looked up here, so another entity's accounts are unknown to them.
   */
  view(limit: number[] | null): { entities: Entity[]; accounts: Account[] } {
    const entities = limit ? this.entities.list().filter((e) => limit.includes(e.id)) : this.entities.list();
    const ids = new Set(entities.map((e) => e.id));
    return { entities, accounts: this.accounts.list().filter((a) => ids.has(a.entityId)) };
  }

  /**
   * "all" (accounts whose entity is included in combined views), "e:<entity id>", "a:<account id>" or a set, among
   * the entities in `limit` (null for every entity); null if unknown there.
   */
  resolveScope(key: string, limit: number[] | null): Scope | null {
    const { accounts, entities } = this.view(limit);
    return resolveScope(accounts, entities, key);
  }
}
