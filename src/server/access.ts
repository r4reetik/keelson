// What a user limited to some entities may reach (src/store/users.ts). Routes look
// accounts, entities and findings up through these helpers, so another entity's
// are unknown to that user (404), exactly as if they didn't exist.

import type { Context } from "hono";
import type { AppEnv } from "./env.ts";
import type { Account, Entity, Repo } from "../store/repo.ts";
import type { SessionUser } from "../shared/api.ts";
import { HttpError, notFound } from "./errors.ts";

/** The entities and accounts the signed-in user may see. */
export const viewOf = (repo: Repo, c: Context<AppEnv>) => repo.view(c.get("user").entities);

/** Whether the user may see this entity. */
export const reaches = (user: SessionUser, entityId: number): boolean => !user.entities || user.entities.includes(entityId);

/** An entity the user may see, or 404. */
export function ownEntity(repo: Repo, c: Context<AppEnv>, id: number): Entity {
  const e = repo.entities.get(id);
  if (!e || !reaches(c.get("user"), e.id)) throw notFound("Unknown entity");
  return e;
}

/** An account the user may see, or 404. */
export function ownAccount(repo: Repo, c: Context<AppEnv>, id: string): Account {
  const a = repo.accounts.get(id);
  if (!a || !reaches(c.get("user"), a.entityId)) throw notFound("Unknown account");
  return a;
}

/** Refuses something only an admin, or someone who sees every entity, may do. */
export const unlimitedOnly = (what: string) => new HttpError(403, `You can only see some entities, so you can't ${what}. Ask an admin.`, "role");
