// User management, for admins: add people with a role and a one-time password,
// change roles, reset passwords, remove people. Keelson always keeps one admin.

import type { Context } from "hono";
import type { AppContext, AppEnv } from "../env.ts";
import type { Routes } from "../router.ts";
import { requirePermission } from "../middleware.ts";
import { sessionUser } from "../security.ts";
import { param, personName, requireJson, role, username } from "../validate.ts";
import { badRequest, conflict, notFound } from "../errors.ts";
import { hashPassword, oneTimePassword } from "../passwords.ts";
import { log } from "../../log.ts";
import type { User } from "../../store/users.ts";
import { ROLE_INFO } from "../../shared/roles.ts";
import type { OneTimePasswordResponse, UserRow, UsersResponse } from "../../shared/api.ts";

const row = (u: User): UserRow => ({ ...sessionUser(u), createdAt: u.createdAt, createdBy: u.createdBy, lastLoginAt: u.lastLoginAt });

export function userRoutes(r: Routes, { repo, auth }: AppContext) {
  const admin = r.with(requirePermission("users"));
  const target = (c: Context<AppEnv>) =>
    repo.users.get(Number(param(c, "id"))) ??
    (() => {
      throw notFound("That user no longer exists.");
    })();
  const by = (c: Context<AppEnv>) => c.get("user").username || null;

  admin.get("/api/users", (c) => c.json({ users: repo.users.list().map(row) } satisfies UsersResponse));

  // Admins hand the one-time password to the person, who replaces it when they first sign in.
  admin.post("/api/users", async (c) => {
    const body = await requireJson(c);
    const name = username(body.username);
    if (repo.users.byUsername(name)) throw conflict(`${name} already has an account. Pick another username.`);
    const password = oneTimePassword();
    const user = repo.users.create({
      username: name,
      name: personName(body.name),
      role: role(body.role),
      passwordHash: await hashPassword(password),
      mustChangePassword: true,
      createdBy: by(c),
    });
    log.info(`${by(c) ?? "An admin"} added ${user.username} as ${ROLE_INFO[user.role].label}`);
    return c.json({ user: row(user), password } satisfies OneTimePasswordResponse);
  });

  admin.patch("/api/users/:id", async (c) => {
    const u = target(c);
    const body = await requireJson(c);
    const next = body.role === undefined ? u.role : role(body.role);
    if (u.role === "admin" && next !== "admin" && repo.users.admins() < 2)
      throw conflict("Keelson needs at least one admin. Make someone else an admin first.");
    repo.users.update(u.id, { role: next, ...(body.name !== undefined ? { name: personName(body.name) } : {}) });
    if (next !== u.role) log.info(`${by(c) ?? "An admin"} changed ${u.username} from ${ROLE_INFO[u.role].label} to ${ROLE_INFO[next].label}`);
    return c.json({ user: row(repo.users.get(u.id)!) });
  });

  // A new one-time password; the person is signed out everywhere until they use it.
  admin.post("/api/users/:id/password", async (c) => {
    const u = target(c);
    if (u.id === c.get("user").id) throw badRequest("Change your own password from your account menu.");
    const password = oneTimePassword();
    repo.users.setPassword(u.id, await hashPassword(password), true);
    auth.endSessions(u.id);
    log.info(`${by(c) ?? "An admin"} reset the password of ${u.username}`);
    return c.json({ user: row(repo.users.get(u.id)!), password } satisfies OneTimePasswordResponse);
  });

  admin.delete("/api/users/:id", (c) => {
    const u = target(c);
    if (u.id === c.get("user").id) throw badRequest("You can't remove yourself. Ask another admin.");
    if (u.role === "admin" && repo.users.admins() < 2) throw conflict("Keelson needs at least one admin.");
    repo.users.delete(u.id);
    auth.endSessions(u.id);
    log.info(`${by(c) ?? "An admin"} removed ${u.username}`);
    return c.json({ ok: true });
  });
}
