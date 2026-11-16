// Connecting accounts from any provider: verify a credential (a token, an access
// key), add accounts, rename, move, replace the credential, remove. Available before any account is connected. The
// request names its provider (`provider`, Cloudflare when absent). Someone limited to some entities works only on
// those entities' accounts (src/server/access.ts) and can't create an entity.

import type { AppContext } from "../env.ts";
import type { Provider } from "../../providers/types.ts";
import type { Routes } from "../router.ts";
import { PROVIDER } from "../../providers/index.ts";
import { requirePermission } from "../middleware.ts";
import { ownAccount, reaches, unlimitedOnly, viewOf } from "../access.ts";
import { publicAccount, publicEntity } from "../present.ts";
import { ACCOUNT_ID_PATTERN, accountIdForEntity, entityOfAccountId } from "../../shared/providers.ts";
import { accountIds, bool, cleanName, direction, param, providerId, readJson, requireJson, token } from "../validate.ts";
import { badRequest, conflict } from "../errors.ts";
import {
  LINK_PROVIDER,
  type AccountRow,
  type AccountsResponse,
  type AddAccountsResponse,
  type ScanSnapshot,
  type TemplateResponse,
  type VerifyResponse,
} from "../../shared/api.ts";

/** Permissions are probed for the first few accounts a token can read; the rest are assumed alike. */
const PROBE_LIMIT = 10;

export function accountRoutes(r: Routes, { repo, scanner, vault }: AppContext) {
  const manage = r.with(requirePermission("accounts"));
  /** Drops tokens that no account references any more. */
  const pruneTokens = () => vault.retain(new Set(repo.accounts.list().map((a) => a.tokenId)));
  /**
   * What a credential can read. A per-entity provider (Sonar) has one account per entity instead, so its "accounts"
   * are the entities this person can add to, named after them.
   */
  const accountsFor = async (p: Provider, t: string, c: Parameters<typeof viewOf>[1]) =>
    p.info.perEntity
      ? viewOf(repo, c).entities.map((e) => ({ id: accountIdForEntity(e.id), name: e.name }))
      : p.listAccounts(t).catch(() => [] as { id: string; name: string }[]);

  r.get("/api/accounts/template", (c) => {
    const p = PROVIDER[providerId(c.req.query("provider"))];
    const acc = c.req.query("accountId");
    const help = p.tokenHelp(acc && ACCOUNT_ID_PATTERN[p.info.id].test(acc) ? acc : null);
    return c.json({ url: help.templateUrl ?? help.url, readAllUrl: help.url, template: !!help.templateUrl } satisfies TemplateResponse);
  });

  /**
   * The accounts a provider that starts from its siblings (Sonar, `reads`) needs scanned again: in the entities of
   * `ids`, the ones whose latest scan doesn't have a list their provider publishes, because it predates the list.
   * The scanner runs them first. A list left out because it couldn't be read only costs one more scan.
   */
  const staleFor = (p: Provider, ids: string[]): string[] => {
    if (!p.reads?.length) return [];
    const entities = new Set(ids.map((id) => repo.accounts.get(id)?.entityId));
    return repo.accounts
      .list()
      .filter((a) => entities.has(a.entityId) && !ids.includes(a.id))
      .filter((a) => {
        const latest = repo.scans.latest(a.id);
        if (!latest?.snapshot) return false;
        const links = (JSON.parse(latest.snapshot as string) as ScanSnapshot).links ?? {};
        return p.reads!.some((k) => LINK_PROVIDER[k] === a.provider && !(k in links));
      })
      .map((a) => a.id);
  };

  manage.post("/api/accounts/verify", async (c) => {
    const body = await requireJson(c);
    const p = PROVIDER[providerId(body.provider)];
    const t = token(body.token, p.info.id);
    const ids = accountIds(body.accountIds ?? (body.accountId ? [body.accountId] : []), p.info.id);
    const [info, visible] = await Promise.all([p.verify(t, ids), accountsFor(p, t, c)]);
    if (!info.valid) return c.json({ token: info, accounts: [], probes: {}, probeLimit: PROBE_LIMIT } satisfies VerifyResponse);
    const known = new Map(repo.accounts.list().map((a) => [a.id, a]));
    const user = c.get("user");
    // A per-entity provider's probe depends on the credential alone, so it is asked once.
    const once = p.info.perEntity && ids.length ? await p.probe(t, ids[0]) : null;
    const probes = Object.fromEntries(await Promise.all(ids.slice(0, PROBE_LIMIT).map(async (id) => [id, once ?? (await p.probe(t, id))] as const)));
    return c.json({
      token: info,
      probes,
      probeLimit: PROBE_LIMIT,
      templateUrl: p.tokenHelp(ids[0] || null).templateUrl ?? undefined,
      // An account already connected in an entity this user can't see says so, but not which entity.
      accounts: visible.map((a) => {
        const k = known.get(a.id);
        return { ...a, added: !!k, entityId: k && reaches(user, k.entityId) ? k.entityId : null };
      }),
    } satisfies VerifyResponse);
  });

  manage.post("/api/accounts", async (c) => {
    const body = await requireJson(c);
    const p = PROVIDER[providerId(body.provider)];
    const t = token(body.token, p.info.id);
    const ids = accountIds(body.accountIds, p.info.id);
    if (!ids.length) throw badRequest(`Choose at least one ${p.info.account}.`);
    const info = await p.verify(t, ids);
    if (!info.valid) throw badRequest(info.message || `The ${p.info.credential} is not valid.`);
    const visible = new Map((await accountsFor(p, t, c)).map((a) => [a.id, a.name]));
    const unseen = ids.find((id) => !visible.has(id));
    if (unseen) throw badRequest(`This ${p.info.credential} can't read ${p.info.account} ${unseen}.`);
    const other = ids.map((id) => repo.accounts.get(id)).find((a) => a && a.provider !== p.info.id);
    if (other) throw badRequest(`${other.id} is already connected as a ${PROVIDER[other.provider].info.label} account.`);
    const user = c.get("user");
    const elsewhere = ids.map((id) => repo.accounts.get(id)).find((a) => a && !reaches(user, a.entityId));
    if (elsewhere) throw unlimitedOnly(`change ${elsewhere.id}: it is connected in another entity`);

    // Accounts already here only get the new token and stay in their entity, so a new entity is
    // created only when at least one account is new; otherwise it would be left empty.
    const fresh = ids.filter((id) => !repo.accounts.get(id));
    let entityId: number;
    if (p.info.perEntity) {
      // Each account goes to the entity it watches (its ID names it); the response names the first.
      entityId = entityOfAccountId(ids[0])!;
    } else if (body.entityId != null) {
      const e = repo.entities.get(Number(body.entityId));
      if (!e || !reaches(user, e.id)) throw badRequest("That entity no longer exists.");
      entityId = e.id;
    } else if (!fresh.length) {
      entityId = repo.accounts.get(ids[0])!.entityId;
    } else if (user.entities) {
      // Someone limited to one entity adds to it without being asked; with several, they pick one.
      const own = viewOf(repo, c).entities;
      if (!own.length) throw unlimitedOnly("create an entity");
      if (own.length > 1) throw badRequest("Choose which of your entities to add these accounts to.");
      entityId = own[0].id;
    } else {
      const name = body.entityName != null ? cleanName(body.entityName) : visible.get(ids[0]) || "My organization";
      if (!name) throw badRequest("Give the entity a name.");
      entityId = repo.entities.create(name).id;
    }

    const tokenId = vault.put(t, info.kind);
    const added: string[] = [],
      updated: string[] = [];
    for (const id of ids) {
      if (repo.accounts.get(id)) {
        repo.accounts.update(id, { tokenId, tokenKind: info.kind, ...(p.info.perEntity ? {} : { name: visible.get(id) ?? null }) });
        updated.push(id);
      } else if (p.info.perEntity) {
        repo.accounts.add({ id, provider: p.info.id, name: p.info.label, entityId: entityOfAccountId(id)!, tokenId, tokenKind: info.kind });
        added.push(id);
      } else {
        repo.accounts.add({ id, provider: p.info.id, name: visible.get(id) ?? null, entityId, tokenId, tokenKind: info.kind });
        added.push(id);
      }
    }
    pruneTokens();
    scanner.start("setup", [...staleFor(p, ids), ...ids]);
    return c.json({ ok: true, added, updated, entityId } satisfies AddAccountsResponse);
  });

  r.get("/api/accounts", (c) => {
    const { accounts, entities } = viewOf(repo, c);
    return c.json({
      entities: entities.map((e) => ({
        ...publicEntity(e),
        accounts: accounts
          .filter((a) => a.entityId === e.id)
          .map((a): AccountRow => {
            const last = repo.scans.latestSummary(a.id);
            const failed = repo.scans.lastFailed(a.id);
            return {
              ...publicAccount(vault, a),
              busy: scanner.isBusy(a.id),
              lastScan: last ? { finishedAt: last.finished_at!, score: last.score, counts: JSON.parse(last.counts || "{}") } : null,
              lastFailed: failed && (!last || failed.id > last.id) ? { finishedAt: failed.finished_at!, error: failed.error || "" } : null,
            };
          }),
      })),
    } satisfies AccountsResponse);
  });

  manage.patch("/api/accounts/:id", async (c) => {
    const a = ownAccount(repo, c, param(c, "id"));
    const body = await requireJson(c);
    // Validate everything first, so a rejected request changes nothing.
    const alias = body.alias === undefined ? undefined : body.alias == null ? null : cleanName(body.alias) || null;
    const scheduled = body.scheduled === undefined ? undefined : bool(body.scheduled, "scheduled");
    const entity = body.entityId === undefined ? undefined : repo.entities.get(Number(body.entityId));
    if (body.entityId !== undefined && (!entity || !reaches(c.get("user"), entity.id))) throw badRequest("Unknown entity");
    if (entity && entity.id !== a.entityId && PROVIDER[a.provider].info.perEntity)
      throw badRequest(
        `This account watches ${repo.entities.get(a.entityId)?.name ?? "its entity"} from the internet, so it stays there. Add one to the other entity instead.`,
      );
    const move = body.move === undefined ? undefined : direction(body.move);
    repo.store.tx(() => {
      if (alias !== undefined) repo.accounts.update(a.id, { alias });
      if (scheduled !== undefined) repo.accounts.update(a.id, { scheduled });
      if (entity && entity.id !== a.entityId) repo.accounts.setEntity(a.id, entity.id);
      if (move) repo.accounts.move(a.id, move);
    });
    return c.json({ ok: true, account: publicAccount(vault, repo.accounts.get(a.id)!) });
  });

  manage.put("/api/accounts/:id/token", async (c) => {
    const a = ownAccount(repo, c, param(c, "id"));
    const p = PROVIDER[a.provider];
    const t = token((await readJson(c))?.token, a.provider);
    const info = await p.verify(t, [a.id]);
    if (!info.valid) throw badRequest(info.message || `The ${p.info.credential} is not valid.`);
    if (!(await accountsFor(p, t, c)).some((v) => v.id === a.id)) throw badRequest(`This ${p.info.credential} can't read this ${p.info.account}.`);
    repo.accounts.update(a.id, { tokenId: vault.put(t, info.kind), tokenKind: info.kind });
    pruneTokens();
    scanner.start("token", [a.id]);
    return c.json({ ok: true });
  });

  manage.delete("/api/accounts/:id", (c) => {
    const a = ownAccount(repo, c, param(c, "id"));
    if (scanner.isBusy(a.id)) throw conflict("Wait for this account's scan to finish.");
    repo.accounts.remove(a.id);
    pruneTokens();
    return c.json({ ok: true });
  });
}
