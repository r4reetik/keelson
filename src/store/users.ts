// The people who sign in, with their roles and the entities they are limited to.
// Password hashes are read only to sign someone in, and never leave this module
// except to the code that checks them.

import type { Store } from "./db.ts";
import { isRole, type Role } from "../shared/roles.ts";

export interface User {
  id: number;
  /** Lowercase, unique. */
  username: string;
  name: string | null;
  role: Role;
  /** Signed in with a password an admin handed out, which must be replaced before anything else. */
  mustChangePassword: boolean;
  /** The entities this user is limited to, or null for every entity. Admins are never limited. */
  entities: number[] | null;
  createdAt: string;
  createdBy: string | null;
  lastLoginAt: string | null;
}

interface UserRecord {
  id: number;
  username: string;
  name: string | null;
  role: string;
  password_hash: string;
  must_change_password: number;
  limited: number;
  created_at: string;
  created_by: string | null;
  last_login_at: string | null;
}

const toUser = (r: UserRecord, entities: number[] | null): User => ({
  id: r.id,
  username: r.username,
  name: r.name,
  // A role this version doesn't know (written by a newer one) gets the least access.
  role: isRole(r.role) ? r.role : "viewer",
  mustChangePassword: !!r.must_change_password,
  entities: r.role === "admin" ? null : entities,
  createdAt: r.created_at,
  createdBy: r.created_by,
  lastLoginAt: r.last_login_at,
});

export interface NewUser {
  username: string;
  name: string | null;
  role: Role;
  /** The entities to limit the user to, or null (or absent) for every entity. Ignored for admins. */
  entities?: number[] | null;
  passwordHash: string;
  mustChangePassword: boolean;
  createdBy: string | null;
}

export class UserRepo {
  readonly #s: Store;
  constructor(store: Store) {
    this.#s = store;
  }

  #user(r: UserRecord): User {
    return toUser(r, r.limited ? this.#entities(r.id) : null);
  }

  #entities(id: number): number[] {
    return this.#s.all<{ entity_id: number }>("SELECT entity_id FROM user_entities WHERE user_id = ? ORDER BY entity_id", id).map((e) => e.entity_id);
  }

  list(): User[] {
    return this.#s.all<UserRecord>("SELECT * FROM users ORDER BY username").map((r) => this.#user(r));
  }

  count(): number {
    return this.#s.get<{ n: number }>("SELECT COUNT(*) AS n FROM users")!.n;
  }

  get(id: number): User | null {
    const r = this.#s.get<UserRecord>("SELECT * FROM users WHERE id = ?", id);
    return r ? this.#user(r) : null;
  }

  byUsername(username: string): User | null {
    const r = this.#s.get<UserRecord>("SELECT * FROM users WHERE username = ?", username.toLowerCase());
    return r ? this.#user(r) : null;
  }

  /** The stored hash, for checking a password. */
  passwordHash(id: number): string | null {
    return this.#s.get<{ password_hash: string }>("SELECT password_hash FROM users WHERE id = ?", id)?.password_hash ?? null;
  }

  create(u: NewUser): User {
    return this.#s.tx(() => {
      const r = this.#s.run(
        "INSERT INTO users (username, name, role, password_hash, must_change_password, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
        u.username.toLowerCase(),
        u.name,
        u.role,
        u.passwordHash,
        u.mustChangePassword ? 1 : 0,
        new Date().toISOString(),
        u.createdBy,
      );
      const id = Number(r.lastInsertRowid);
      this.setEntities(id, u.role === "admin" ? null : (u.entities ?? null));
      return this.get(id)!;
    });
  }

  /** Creates the first admin, unless someone already exists: two people opening a new instance at once get one admin. */
  createFirst(u: NewUser): User | null {
    return this.#s.tx(() => (this.count() ? null : this.create(u)));
  }

  update(id: number, patch: { name?: string | null; role?: Role; entities?: number[] | null }): void {
    this.#s.tx(() => {
      if (patch.name !== undefined) this.#s.run("UPDATE users SET name = ? WHERE id = ?", patch.name, id);
      if (patch.role !== undefined) this.#s.run("UPDATE users SET role = ? WHERE id = ?", patch.role, id);
      // An admin always sees every entity.
      if (patch.role === "admin") this.setEntities(id, null);
      else if (patch.entities !== undefined) this.setEntities(id, patch.entities);
    });
  }

  /** Limits a user to these entities, or lifts the limit with null. */
  setEntities(id: number, entities: number[] | null): void {
    this.#s.tx(() => {
      this.#s.run("DELETE FROM user_entities WHERE user_id = ?", id);
      this.#s.run("UPDATE users SET limited = ? WHERE id = ?", entities ? 1 : 0, id);
      for (const e of new Set(entities ?? [])) this.#s.run("INSERT INTO user_entities (user_id, entity_id) VALUES (?, ?)", id, e);
    });
  }

  setPassword(id: number, passwordHash: string, mustChange: boolean): void {
    this.#s.run("UPDATE users SET password_hash = ?, must_change_password = ? WHERE id = ?", passwordHash, mustChange ? 1 : 0, id);
  }

  signedIn(id: number): void {
    this.#s.run("UPDATE users SET last_login_at = ? WHERE id = ?", new Date().toISOString(), id);
  }

  delete(id: number): void {
    this.#s.run("DELETE FROM users WHERE id = ?", id);
  }

  admins(): number {
    return this.#s.get<{ n: number }>("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'")!.n;
  }
}
