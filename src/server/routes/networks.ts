// Networks, for admins: the routes Keelson's requests can leave through (a proxy
// into a VPN or zero trust network, the certificates it signs with), which one
// each platform uses, and a test that says what a network reaches. Nothing
// here returns a proxy's password or a certificate's text: a row says whether a
// password is stored, and who each certificate names.

import type { Context } from "hono";
import type { AppContext, AppEnv } from "../env.ts";
import type { Routes } from "../router.ts";
import { requirePermission } from "../middleware.ts";
import { networkInput, networkTarget, param, requireJson, type CleanNetwork } from "../validate.ts";
import { badRequest, conflict, notFound } from "../errors.ts";
import { log } from "../../log.ts";
import { forgetRoute } from "../../core/net.ts";
import { describeCertificates, forgetNetwork, pruneVault, routeOf, testRoute, testTargets } from "../../networks.ts";
import type { Network, NewNetwork } from "../../store/repo.ts";
import { PROVIDER_INFO, PROVIDERS } from "../../shared/providers.ts";
import type { NetworkRow, NetworksResponse, NetworkTarget, NetworkTestResponse, NetworkUse } from "../../shared/networks.ts";

export function networkRoutes(r: Routes, { repo, vault }: AppContext) {
  const admin = r.with(requirePermission("networks"));
  const by = (c: Context<AppEnv>) => c.get("user").username || "An admin";
  const target = (c: Context<AppEnv>): Network =>
    repo.networks.get(Number(param(c, "id"))) ??
    (() => {
      throw notFound("That network no longer exists.");
    })();

  const usedBy = (use: NetworkUse, id: number): NetworkTarget[] => [
    ...(use.default === id ? (["default"] as const) : []),
    ...PROVIDERS.filter((p) => use.providers[p] === id),
  ];
  const row = (n: Network, use: NetworkUse): NetworkRow => ({
    id: n.id,
    name: n.name,
    kind: n.kind,
    proxy: n.proxy ? { ...n.proxy, hasPassword: !!n.secretId } : null,
    certificates: describeCertificates(n.ca),
    usedBy: usedBy(use, n.id),
  });
  const all = (): NetworksResponse => {
    const use = repo.networks.use();
    return { networks: repo.networks.list().map((n) => row(n, use)), use };
  };

  /** What to store for a request, given what is stored now: a field the request leaves alone keeps its value. */
  const stored = (clean: CleanNetwork, before: Network | null): NewNetwork => {
    if (!clean.proxy && (clean.ca === null || (clean.ca === undefined && !before?.ca)))
      throw badRequest("A network needs a proxy, a certificate to trust, or both. Without either it is this machine's own connection.");
    const clash = repo.networks.byName(clean.name);
    if (clash && clash.id !== before?.id) throw conflict(`${clash.name} already exists. Pick another name.`);
    const secretId =
      clean.password === undefined ? (clean.proxy?.username ? (before?.secretId ?? null) : null) : clean.password ? vault.put(clean.password, null) : null;
    return { name: clean.name, kind: clean.kind, proxy: clean.proxy, secretId, ca: clean.ca === undefined ? (before?.ca ?? null) : clean.ca };
  };

  admin.get("/api/networks", (c) => c.json(all() satisfies NetworksResponse));

  admin.post("/api/networks", async (c) => {
    const n = repo.networks.create(stored(networkInput(await requireJson(c)), null));
    log.info(`${by(c)} added the network ${n.name}`);
    return c.json(all() satisfies NetworksResponse);
  });

  admin.put("/api/networks/:id", async (c) => {
    const before = target(c);
    const next = stored(networkInput(await requireJson(c)), before);
    forgetNetwork(before, vault);
    const n = repo.networks.update(before.id, next);
    pruneVault(repo, vault);
    log.info(`${by(c)} changed the network ${n.name}`);
    return c.json(all() satisfies NetworksResponse);
  });

  admin.delete("/api/networks/:id", (c) => {
    const n = target(c);
    forgetNetwork(n, vault);
    repo.networks.remove(n.id);
    pruneVault(repo, vault);
    log.info(`${by(c)} removed the network ${n.name}`);
    return c.json(all() satisfies NetworksResponse);
  });

  // Which network a platform's requests use: { target: "default" | <platform>, network: <id> | "direct" | null }.
  admin.put("/api/network-use", async (c) => {
    const body = await requireJson(c);
    const what = networkTarget(body.target);
    const value = body.network === "direct" || body.network == null ? (body.network as "direct" | null) : Number(body.network);
    const network = typeof value === "number" ? repo.networks.get(value) : null;
    if (typeof value === "number" && !network) throw badRequest("That network no longer exists.");
    repo.networks.setUse(what, value);
    const through = network ? network.name : value === "direct" || what === "default" ? "this machine's own connection" : "the default network";
    log.info(`${by(c)} sent ${what === "default" ? "requests without a network of their own" : `${PROVIDER_INFO[what].label}'s requests`} through ${through}`);
    return c.json(all() satisfies NetworksResponse);
  });

  /**
   * Tests a stored network ({ id }), or settings not saved yet ({ network }, with `id` to use the stored password and
   * certificates where the form left them alone). Sends one GET per platform, and one per instance of a platform
   * people host themselves that an account is connected on, with no credential.
   */
  admin.post("/api/networks/test", async (c) => {
    const body = await requireJson(c);
    const before = body.id == null ? null : repo.networks.get(Number(body.id));
    if (body.id != null && !before) throw notFound("That network no longer exists.");
    if (!body.network) {
      if (!before) throw badRequest("Choose a network to test.");
      return c.json((await testRoute(routeOf(before, vault), testTargets(repo, vault))) satisfies NetworkTestResponse);
    }
    const clean = networkInput(body.network);
    if (!clean.proxy && (clean.ca === null || (clean.ca === undefined && !before?.ca))) throw badRequest("Enter a proxy or a certificate to test.");
    // Nothing is stored for a test: the password it types is used once.
    const password = clean.password === undefined ? (before?.secretId ? (vault.get(before.secretId)?.token ?? null) : null) : clean.password;
    const route = routeOf(
      { name: clean.name, kind: clean.kind, proxy: clean.proxy, secretId: null, ca: clean.ca === undefined ? (before?.ca ?? null) : clean.ca },
      vault,
      password,
    );
    try {
      return c.json((await testRoute(route, testTargets(repo, vault))) satisfies NetworkTestResponse);
    } finally {
      forgetRoute(route.key);
    }
  });
}
