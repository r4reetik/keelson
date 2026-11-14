// Guards that routes carry (see router.ts). Reading needs a signed-in user; a
// change also names the permission it needs, and the router refuses to register
// a change that doesn't.

import type { MiddlewareHandler } from "hono";
import type { Repo } from "../store/repo.ts";
import type { AppEnv } from "./env.ts";
import type { Auth } from "./security.ts";
import { HttpError } from "./errors.ts";
import { readJson } from "./validate.ts";
import { can, refusal, type Permission } from "../shared/roles.ts";

/** Marks a guard that decides who may make a change; see `routes()` in router.ts. */
export const DECIDES_WHO = Symbol("decides who may make a change");
const decidesWho = (g: MiddlewareHandler<AppEnv>): MiddlewareHandler<AppEnv> => Object.assign(g, { [DECIDES_WHO]: true });

/**
 * Signed in (or sign-in is off). Someone signed in with a one-time password can do nothing but replace it,
 * unless `oneTimePassword` lets the route through (the session, changing the password, signing out).
 */
export const requireSession =
  (auth: Auth, { oneTimePassword = false } = {}): MiddlewareHandler<AppEnv> =>
  async (c, next) => {
    const user = auth.user(c);
    if (!user) throw new HttpError(401, "Sign in required", "auth");
    if (user.mustChangePassword && !oneTimePassword) throw new HttpError(403, "Choose a new password first.", "password");
    c.set("user", user);
    await next();
  };

/** The signed-in user's role has this permission (src/shared/roles.ts). Runs after requireSession. */
export const requirePermission = (permission: Permission): MiddlewareHandler<AppEnv> =>
  decidesWho(async (c, next) => {
    const user = c.get("user");
    if (!user || !can(user.role, permission)) throw new HttpError(403, refusal(user?.role ?? "viewer", permission), "role");
    await next();
  });

/** A change anyone who reaches the route may make: signing in or out, creating the first admin, their own password. */
export const anyone: MiddlewareHandler<AppEnv> = decidesWho(async (_c, next) => {
  await next();
});

/** At least one account is connected. */
export const requireConfigured =
  (repo: Repo): MiddlewareHandler<AppEnv> =>
  async (_c, next) => {
    if (!repo.accounts.list().length) throw new HttpError(409, "No account is connected yet.", "setup");
    await next();
  };

/** Resolves ?scope= (or the JSON body's `scope` on POST): all | e:<entity id> | a:<account id> | s:<account id>,<account id>… */
export const withScope =
  (repo: Repo): MiddlewareHandler<AppEnv> =>
  async (c, next) => {
    const key = c.req.method === "POST" ? String((await readJson(c))?.scope || "all") : c.req.query("scope") || "all";
    const scope = repo.resolveScope(key);
    if (!scope) throw new HttpError(404, "That account or entity no longer exists.", "scope");
    c.set("scope", scope);
    await next();
  };
