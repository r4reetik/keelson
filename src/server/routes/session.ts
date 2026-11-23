// Health, session state, creating the first admin, signing in and out, and the
// signed-in user's own name and password.

import type { AppContext } from "../env.ts";
import type { Routes } from "../router.ts";
import { anyone, requireSession } from "../middleware.ts";
import { publicAccount, sessionEntity } from "../present.ts";
import { password, personName, readJson, requireJson, username } from "../validate.ts";
import { HttpError, badRequest } from "../errors.ts";
import { hashPassword } from "../passwords.ts";
import { log } from "../../log.ts";
import { installKind } from "../../env.ts";
import type { Session, SessionUser } from "../../shared/api.ts";

export function sessionRoutes(r: Routes, { repo, auth, vault, version, updates }: AppContext) {
  const open = r.with(anyone);
  // Someone holding a one-time password may read the session, sign out, and replace it; nothing else.
  const self = r.with(requireSession(auth, { oneTimePassword: true }), anyone);

  r.get("/api/health", (c) => c.json({ ok: true, version }));

  r.get("/api/session", (c) => {
    const user = auth.user(c);
    const ready = !!user && !user.mustChangePassword;
    // Someone limited to some entities sees only theirs, and "configured" means one of them has an account.
    const { accounts, entities } = repo.view(user?.entities ?? null);
    return c.json({
      version,
      authRequired: auth.required,
      authenticated: !!user,
      setupRequired: auth.setupRequired,
      setupCodeRequired: auth.setupRequired && auth.setupCodeRequired(c),
      configured: accounts.length > 0,
      install: installKind(),
      ...(user ? { user } : {}),
      ...(ready ? { accounts: accounts.map((a) => publicAccount(vault, a)), entities: entities.map(sessionEntity), update: updates?.status() } : {}),
    } satisfies Session);
  });

  // The first admin. Only while nobody can sign in, and off this machine only with the setup code from the log.
  open.post("/api/setup", async (c) => {
    const body = await requireJson(c);
    const admin = { username: username(body.username), name: personName(body.name), password: password(body.password), code: String(body.code ?? "") };
    const err = await auth.setup(c, admin);
    if (err) throw new HttpError(err.startsWith("An admin") ? 409 : 401, err, err.startsWith("An admin") ? "auth" : undefined);
    log.info(`Admin ${admin.username} created`);
    return c.json({ ok: true });
  });

  open.post("/api/login", async (c) => {
    const body = await readJson(c);
    const err = await auth.login(c, String(body?.username ?? ""), String(body?.password ?? ""));
    if (err) throw new HttpError(401, err, "auth");
    return c.json({ ok: true });
  });

  open.post("/api/logout", (c) => {
    auth.logout(c);
    return c.json({ ok: true });
  });

  self.patch("/api/me", async (c) => {
    const me = signedInUser(c.get("user"));
    const body = await requireJson(c);
    repo.users.update(me.id, { name: personName(body.name) });
    return c.json({ ok: true });
  });

  // A new password, after the current one (or the one-time password) is confirmed. Other sessions end.
  self.put("/api/me/password", async (c) => {
    const me = signedInUser(c.get("user"));
    const body = await requireJson(c);
    const next = password(body.password);
    const err = await auth.checkPassword(c, me.id, String(body.current ?? ""));
    if (err) throw new HttpError(err.startsWith("Too many") ? 429 : 400, err);
    if (next === body.current) throw badRequest("Choose a password different from the current one.");
    repo.users.setPassword(me.id, await hashPassword(next), false);
    auth.endSessions(me.id, c);
    return c.json({ ok: true });
  });
}

/** With sign-in off there is no user to change. */
function signedInUser(u: SessionUser): SessionUser {
  if (!u.id) throw badRequest("Sign-in is turned off (KEELSON_AUTH=none), so there is no account to change.");
  return u;
}
