// HTTP API and the web app. Each route module registers its routes with the
// guards it needs (see router.ts), so access never depends on registration order.
// Every change also names the permission it needs (src/shared/roles.ts):
//   open       health, session, first admin, sign in/out, own password
//   authed     accounts, entities, settings, checks, triage, users
//   configured findings permalinks (needs a connected account)
//   scoped     dashboard data and exports (?scope=all | e:<id> | a:<id>)

import { Hono, type Context } from "hono";
import { bodyLimit } from "hono/body-limit";
import type { AppContext, AppEnv } from "./env.ts";
import { routes } from "./router.ts";
import { onError } from "./errors.ts";
import { requireConfigured, requireSession, withScope } from "./middleware.ts";
import { securityHeaders } from "./security.ts";
import { serveWeb } from "./static.ts";
import { sessionRoutes } from "./routes/session.ts";
import { accountRoutes } from "./routes/accounts.ts";
import { entityRoutes } from "./routes/entities.ts";
import { settingsRoutes } from "./routes/settings.ts";
import { dashboardRoutes, findingRoutes } from "./routes/dashboard.ts";
import { exportRoutes } from "./routes/exports.ts";
import { userRoutes } from "./routes/users.ts";
import { dependencyRoutes, sbomRoutes } from "./routes/dependencies.ts";
import { complianceRoutes } from "./routes/compliance.ts";

export type { AppContext } from "./env.ts";

/** Request bodies are small JSON: a cap stops a huge upload from exhausting memory before auth runs. */
const MAX_BODY = 1_000_000;
const MAX_LOGIN_BODY = 4096;
const tooLarge = (c: Context) => c.json({ error: "Request too large" }, 413);

export function createApp(ctx: AppContext) {
  const app = new Hono<AppEnv>();
  app.use("*", securityHeaders());
  for (const path of ["/api/login", "/api/setup"]) app.use(path, bodyLimit({ maxSize: MAX_LOGIN_BODY, onError: tooLarge }));
  app.use("/api/*", bodyLimit({ maxSize: MAX_BODY, onError: tooLarge }));
  app.use("*", ctx.auth.guard());
  app.onError(onError);

  const open = routes(app);
  const authed = open.with(requireSession(ctx.auth));
  const configured = authed.with(requireConfigured(ctx.repo));
  const scoped = configured.with(withScope(ctx.repo));

  sessionRoutes(open, ctx);
  accountRoutes(authed, ctx);
  entityRoutes(authed, ctx);
  settingsRoutes(authed, ctx);
  userRoutes(authed, ctx);
  findingRoutes(configured, ctx);
  dependencyRoutes(configured, ctx);
  dashboardRoutes(scoped, ctx);
  exportRoutes(scoped, ctx);
  sbomRoutes(scoped, ctx);
  complianceRoutes(scoped, ctx);

  app.all("/api/*", (c) => c.json({ error: "Not found" }, 404));
  app.get("*", (c) => serveWeb(c, ctx.webDir));
  return app;
}
