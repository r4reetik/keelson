// The people who sign in, with their roles. Password hashes are read only to
// sign someone in, and never leave this module except to the code that checks them.

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
  created_at: string;
  created_by: string | null;
  last_login_at: string | null;
}

const toUser = (r: UserRecord): User => ({
  id: r.id,
  username: r.username,
  name: r.name,
  // A role this version doesn't know (written by a newer one) gets the least access.
  role: isRole(r.role) ? r.role : "viewer",
  mustChangePassword: !!r.must_change_password,
  createdAt: r.created_at,
  createdBy: r.created_by,
  lastLoginAt: r.last_login_at,
});

export interface NewUser {
  username: string;
  name: string | null;
  role: Role;
  passwordHash: string;
  mustChangePassword: boolean;
  createdBy: string | null;
}

export class UserRepo {
  readonly #s: Store;
  constructor(store: Store) {
    this.#s = store;
  }

  list(): User[] {
    return this.#s.all<UserRecord>("SELECT * FROM users ORDER BY username").map(toUser);
  }

  count(): number {
    return this.#s.get<{ n: number }>("SELECT COUNT(*) AS n FROM users")!.n;
  }

  get(id: number): User | null {
    const r = this.#s.get<UserRecord>("SELECT * FROM users WHERE id = ?", id);
    return r ? toUser(r) : null;
  }

  byUsername(username: string): User | null {
    const r = this.#s.get<UserRecord>("SELECT * FROM users WHERE username = ?", username.toLowerCase());
    return r ? toUser(r) : null;
  }

  /** The stored hash, for checking a password. */
  passwordHash(id: number): string | null {
    return this.#s.get<{ password_hash: string }>("SELECT password_hash FROM users WHERE id = ?", id)?.password_hash ?? null;
  }

  create(u: NewUser): User {
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
    return this.get(Number(r.lastInsertRowid))!;
  }

  /** Creates the first admin, unless someone already exists: two people opening a new instance at once get one admin. */
  createFirst(u: NewUser): User | null {
    return this.#s.tx(() => (this.count() ? null : this.create(u)));
  }

  update(id: number, patch: { name?: string | null; role?: Role }): void {
    if (patch.name !== undefined) this.#s.run("UPDATE users SET name = ? WHERE id = ?", patch.name, id);
    if (patch.role !== undefined) this.#s.run("UPDATE users SET role = ? WHERE id = ?", patch.role, id);
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
