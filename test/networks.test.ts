// Networks: a platform's requests leave through the network chosen for it. The
// transport is tried against real local proxies (HTTP with a sign-in, SOCKS5)
// and an HTTPS server whose certificate only the network's authority vouches
// for; the API, the scanner and the scanners Keelson runs are checked for where
// they send, and for never giving back a proxy's password or a certificate.

import { test, describe, before, after, afterEach } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { installMockCloudflare, MOCK_ACCOUNT, MOCK_TOKEN } from "../dev/mock/cloudflare.ts";
import { makeApp } from "./helpers/app.ts";
import { makeAuthority, makeHttpProxy, makeOrigin, makeSocksProxy } from "./helpers/proxy.ts";
import { runChild } from "../src/core/anchore.ts";
import { childProxyEnv, currentRoute, forgetNames, forgetRoute, net, NetworkError, own, ownRequest, request, through, type Route } from "../src/core/net.ts";
import { routeFor } from "../src/networks.ts";
import { NETWORK_KIND_INFO, NETWORK_KINDS } from "../src/shared/networks.ts";
import { PROVIDER_INFO, PROVIDERS } from "../src/shared/providers.ts";

const authority = makeAuthority();
const SRC = fileURLToPath(new URL("../src", import.meta.url));

let n = 0;
/** A route no other test used, so no connection is shared between tests. */
const route = (r: Partial<Route>): Route => ({ key: `test-${++n}`, name: "Office VPN", proxy: null, ca: authority.ca, ...r });
const used: Route[] = [];
const via = (r: Partial<Route>) => {
  const made = route(r);
  used.push(made);
  return made;
};
afterEach(() => {
  for (const r of used.splice(0)) forgetRoute(r.key);
});
const proxyAt = (port: number, protocol: "http" | "socks5" = "http", login?: { username: string; password: string }) => ({
  protocol,
  host: "127.0.0.1",
  port,
  username: login?.username ?? null,
  password: login?.password ?? null,
});
const failure = async (work: () => Promise<unknown>): Promise<NetworkError> => {
  try {
    await work();
  } catch (e) {
    return e as NetworkError;
  }
  throw new Error("the request went through");
};

describe("sending through a network", () => {
  test("an HTTP proxy tunnels the request, signs in, and the network's certificate is trusted", async () => {
    const origin = await makeOrigin(authority);
    const proxy = await makeHttpProxy({ login: "scan:s3cret" });
    try {
      const r = via({ proxy: proxyAt(proxy.port, "http", { username: "scan", password: "s3cret" }) });
      const res = await through(r, () =>
        request(`https://localhost:${origin.port}/v1/things?page=2`, {
          method: "POST",
          body: '{"a":1}',
          headers: { Authorization: "Bearer token", "X-Test": "yes" },
        }),
      );
      assert.equal(res.status, 200);
      assert.deepEqual(await res.json(), { ok: true, path: "/v1/things?page=2", method: "POST", body: '{"a":1}' });
      assert.equal(res.url, `https://localhost:${origin.port}/v1/things?page=2`);
      assert.deepEqual(proxy.connects, [{ target: `localhost:${origin.port}`, authorization: `Basic ${Buffer.from("scan:s3cret").toString("base64")}` }]);
      // The proxy only ever sees where the tunnel goes: the request's own credential stays inside TLS.
      assert.equal(origin.seen[0].headers.authorization, "Bearer token");
      assert.equal(origin.seen[0].headers["proxy-authorization"], undefined);

      // A second request reuses the tunnel.
      await (await through(r, () => request(`https://localhost:${origin.port}/again`))).text();
      assert.equal(proxy.connects.length, 1);
    } finally {
      await origin.close();
      await proxy.close();
    }
  });

  test("a SOCKS5 proxy is given the name, so names that exist only inside the network resolve there", async () => {
    const origin = await makeOrigin(authority);
    const proxy = await makeSocksProxy({ login: { username: "scan", password: "s3cret" }, map: { localhost: origin.port } });
    try {
      const r = via({ proxy: proxyAt(proxy.port, "socks5", { username: "scan", password: "s3cret" }) });
      // Port 443 goes nowhere on this machine: only the proxy knows where "localhost" is.
      const res = await through(r, () => request("https://localhost/inside"));
      assert.equal(((await res.json()) as { path: string }).path, "/inside");
      assert.deepEqual(proxy.asked, ["localhost:443"]);

      const wrong = await failure(() =>
        through(via({ proxy: proxyAt(proxy.port, "socks5", { username: "scan", password: "no" }) }), () => request("https://localhost/")),
      );
      assert.match(wrong.message, /refused the username or password/);
      const none = await failure(() => through(via({ proxy: proxyAt(proxy.port, "socks5") }), () => request("https://localhost/")));
      assert.match(none.message, /asks for a username and password/);
    } finally {
      await origin.close();
      await proxy.close();
    }
  });

  test("a network with only a certificate uses the machine's own connection and trusts it there, and nowhere else", async () => {
    const origin = await makeOrigin(authority);
    try {
      const res = await through(via({}), () => request(`https://localhost:${origin.port}/`));
      assert.equal(res.status, 200);
      await res.text();
      // The same host without the network: the certificate is nobody's the machine trusts.
      await assert.rejects(() => fetch(`https://localhost:${origin.port}/`));
      const other = makeAuthority("Another Root CA");
      const e = await failure(() => through(via({ ca: other.ca }), () => request(`https://localhost:${origin.port}/`)));
      assert.match(e.message, /isn't signed by an authority Keelson trusts.*add the certificate it signs with/);
    } finally {
      await origin.close();
    }
  });

  test("what went wrong is said in plain words, without the proxy's password", async () => {
    const origin = await makeOrigin(authority);
    const proxy = await makeHttpProxy({ login: "scan:s3cret" });
    const refusing = await makeHttpProxy({ refuse: 403 });
    try {
      const target = `https://localhost:${origin.port}/`;
      const wrong = await failure(() =>
        through(via({ proxy: proxyAt(proxy.port, "http", { username: "scan", password: "hunter2-wrong" }) }), () => request(target)),
      );
      assert.equal(wrong.message, `Couldn't use "Office VPN": the proxy at 127.0.0.1:${proxy.port} refused the username or password.`);
      assert.doesNotMatch(wrong.message + JSON.stringify(wrong), /hunter2/);
      const anonymous = await failure(() => through(via({ proxy: proxyAt(proxy.port) }), () => request(target)));
      assert.match(anonymous.message, /asks for a username and password/);
      const denied = await failure(() => through(via({ proxy: proxyAt(refusing.port) }), () => request(target)));
      assert.match(denied.message, /doesn't allow it \(it answered 403\)/);
      const untrusted = await failure(() =>
        through(via({ ca: null, proxy: proxyAt(proxy.port, "http", { username: "scan", password: "s3cret" }) }), () => request(target)),
      );
      assert.match(untrusted.message, /isn't signed by an authority Keelson trusts/);

      await proxy.close();
      const gone = await failure(() => through(via({ proxy: proxyAt(proxy.port) }), () => request(target)));
      assert.equal(gone.message, `Couldn't use "Office VPN": the proxy at 127.0.0.1:${proxy.port} refused the connection.`);
      // Not a proxy at all: the origin speaks TLS, not HTTP.
      const notProxy = await failure(() => through(via({ proxy: proxyAt(origin.port) }), () => request(target)));
      assert.match(notProxy.message, /stopped answering|doesn't answer as an HTTP proxy/);
    } finally {
      await origin.close();
      await proxy.close();
      await refusing.close();
    }
  });

  test("a host that doesn't exist is told apart from a proxy that failed, only when this machine's resolver can be believed", async () => {
    const proxy = await makeHttpProxy({ refuse: 502 });
    const real = net.lookup;
    try {
      const asked = () => through(via({ proxy: proxyAt(proxy.port) }), () => request("https://lambda.xx-nowhere-9.amazonaws.com/"));
      const missing = Object.assign(new Error("not found"), { code: "ENOTFOUND" });
      // The resolver knows public names, and says this one doesn't exist: the service isn't offered there.
      net.lookup = async (name) => {
        if (name !== "example.com") throw missing;
      };
      forgetNames();
      assert.equal((await failure(asked)).cause.code, "ENOTFOUND");
      // A resolver that knows nothing outside its own network can't say: it stays a failure to connect, never "doesn't exist".
      net.lookup = async () => {
        throw missing;
      };
      forgetNames();
      const e = await failure(asked);
      assert.equal(e.cause.code, "ECONNREFUSED");
      assert.match(e.message, /couldn't connect \(it answered 502\)/);
    } finally {
      net.lookup = real;
      forgetNames();
      await proxy.close();
    }
  });

  test("redirects, timeouts and plain HTTP behave as fetch does", async () => {
    const origin = await makeOrigin(authority, (req, res) => {
      if (req.url === "/moved") return res.writeHead(302, { location: "/here" }).end();
      if (req.url === "/slow") return void setTimeout(() => res.end("late"), 2000);
      if (req.url === "/empty") return res.writeHead(204).end();
      res.end(`at ${req.url} with ${req.headers.authorization ?? "nothing"}`);
    });
    const plain = await makeOrigin(null);
    const proxy = await makeHttpProxy();
    try {
      const r = via({ proxy: proxyAt(proxy.port) });
      const base = `https://localhost:${origin.port}`;
      const followed = await through(r, () => request(`${base}/moved`, { headers: { authorization: "Bearer t" } }));
      assert.equal(await followed.text(), "at /here with Bearer t");
      assert.equal(followed.redirected, true);
      const manual = await through(r, () => request(`${base}/moved`, { redirect: "manual" }));
      assert.equal(manual.status, 302);
      assert.equal(manual.headers.get("location"), "/here");
      await assert.rejects(() => through(r, () => request(`${base}/moved`, { redirect: "error" })), /redirect/);
      assert.equal((await through(r, () => request(`${base}/empty`))).status, 204);

      const late = await failure(() => through(r, () => request(`${base}/slow`, { signal: AbortSignal.timeout(100) })));
      assert.equal(late.name, "TimeoutError", "callers tell a timeout by the signal's own reason, as with fetch");

      // Plain HTTP is handed to an HTTP proxy whole, and tunnelled through a SOCKS5 one.
      const res = await through(r, () => request(`http://127.0.0.1:${plain.port}/plain`));
      assert.equal(((await res.json()) as { path: string }).path, "/plain");
      assert.deepEqual(proxy.relayed, [`http://127.0.0.1:${plain.port}/plain`]);
    } finally {
      await origin.close();
      await plain.close();
      await proxy.close();
    }
  });
});

describe("which route a request takes", () => {
  const real = { send: net.send, defaultRoute: net.defaultRoute, fetch: globalThis.fetch };
  afterEach(() => {
    net.send = real.send;
    net.defaultRoute = real.defaultRoute;
    globalThis.fetch = real.fetch;
  });

  test("a scan's route inside it, the default outside it and for Keelson's own lookups, and plain fetch with neither", async () => {
    const seen: string[] = [];
    net.send = async (r, input) => {
      seen.push(`${r.name} ${input}`);
      return new Response("ok");
    };
    globalThis.fetch = (async (input: string) => {
      seen.push(`direct ${input}`);
      return new Response("ok");
    }) as typeof fetch;
    const platform = route({ name: "Platform" });
    const fallback = route({ name: "Default" });

    await request("https://a.example/");
    await through(platform, async () => {
      await request("https://b.example/");
      // After an await, and from a nested call, the scan's route still applies.
      await new Promise((r) => setTimeout(r, 1));
      await (async () => request("https://c.example/"))();
      await ownRequest("https://d.example/");
      assert.equal(
        own(() => currentRoute()),
        null,
      );
      assert.equal(currentRoute(), platform);
    });
    net.defaultRoute = () => fallback;
    await request("https://e.example/");
    await through(platform, () => ownRequest("https://f.example/"));
    // A platform set to this machine's own connection goes direct, whatever the default is.
    await through(null, () => request("https://g.example/"));
    assert.deepEqual(seen, [
      "direct https://a.example/",
      "Platform https://b.example/",
      "Platform https://c.example/",
      "direct https://d.example/",
      "Default https://e.example/",
      "Default https://f.example/",
      "direct https://g.example/",
    ]);
  });

  test("nothing in src sends a request around the route", () => {
    const files = (dir: string): string[] => readdirSync(dir).flatMap((f) => (statSync(join(dir, f)).isDirectory() ? files(join(dir, f)) : [join(dir, f)]));
    // net.ts is the one caller of fetch; Amass's engine is asked on this machine's own port.
    const allowed = new Set(["core/net.ts", "providers/internet/amass.ts"]);
    for (const file of files(SRC).filter((f) => f.endsWith(".ts"))) {
      const name = file.slice(SRC.length + 1);
      if (allowed.has(name)) continue;
      const code = readFileSync(file, "utf8").replace(/\/\/.*|\/\*[\s\S]*?\*\//g, "");
      // A function's own parameter called fetch (a page reader) isn't the global one.
      if (/[(,]\s*fetch\s*:/.test(code)) continue;
      assert.doesNotMatch(
        code,
        /(?<![.\w$])fetch\(/,
        `${name} calls fetch itself: use request() or ownRequest() from src/core/net.ts, so a network chosen for a platform applies`,
      );
      assert.doesNotMatch(code, /from "node:https?"|undici/, `${name} opens connections of its own`);
    }
  });
});

describe("scanners Keelson runs", () => {
  test("get the route's proxy and certificates, and nothing when there is no network", async () => {
    assert.deepEqual(childProxyEnv(null, null), {});
    const env = childProxyEnv(
      route({ proxy: { protocol: "socks5", host: "10.1.2.3", port: 1080, username: "scan user", password: "p@ss:word" } }),
      "/tmp/ca.pem",
    );
    assert.equal(env.HTTPS_PROXY, "socks5://scan%20user:p%40ss%3Aword@10.1.2.3:1080");
    assert.equal(env.HTTP_PROXY, env.HTTPS_PROXY);
    assert.equal(env.NO_PROXY, "");
    assert.equal(env.SSL_CERT_FILE, "/tmp/ca.pem");
    assert.deepEqual(childProxyEnv(route({ ca: null, proxy: proxyAt(8080) }), null).SSL_CERT_FILE, undefined);

    const show = 'echo "proxy=$HTTPS_PROXY"; if [ -n "$SSL_CERT_FILE" ]; then grep -c BEGIN "$SSL_CERT_FILE"; else echo none; fi';
    const outside = await runChild("Test", "/bin/sh", ["-c", show], { seconds: 10 });
    assert.equal(outside.trim(), `proxy=${process.env.HTTPS_PROXY ?? ""}\nnone`);
    const inside = await through(route({ proxy: proxyAt(3128) }), () => runChild("Test", "/bin/sh", ["-c", show], { seconds: 10 }));
    const [proxy, certificates] = inside.trim().split("\n");
    assert.equal(proxy, "proxy=http://127.0.0.1:3128");
    assert.ok(Number(certificates) > 50, "the public authorities and the network's own, in one file");
    // A scanner's own database download takes the default route, even in the middle of a platform's scan.
    const mine = await through(route({ proxy: proxyAt(3128) }), () => own(() => runChild("Test", "/bin/sh", ["-c", show], { seconds: 10 })));
    assert.equal(mine.trim(), outside.trim());
  });
});

describe("the Networks page's API", () => {
  let restore: () => void;
  before(() => {
    restore = installMockCloudflare();
  });
  after(() => restore());
  const SECRET = "proxy-pass-9f3a";
  const office = { name: "Head office", kind: "netskope", proxy: null, ca: authority.ca };
  const vpn = {
    name: "Partner VPN",
    kind: "openvpn",
    proxy: { protocol: "http", host: "Proxy.Partner.Example", port: 8888, username: "keelson", password: SECRET },
  };

  test("networks are added, changed and removed, and never give back a password or a certificate", async () => {
    const t = makeApp({ configured: true });
    let all = await t.json("/api/networks", "POST", office);
    all = await t.json("/api/networks", "POST", vpn);
    assert.deepEqual(
      all.networks.map((x: any) => [x.name, x.kind, x.proxy, x.certificates.map((c: any) => c.subject)]),
      [
        ["Head office", "netskope", null, ["Mock Inspection Root CA"]],
        ["Partner VPN", "openvpn", { protocol: "http", host: "proxy.partner.example", port: 8888, username: "keelson", hasPassword: true }, []],
      ],
    );
    assert.deepEqual(all.use, { default: null, providers: {} });
    const [officeId, vpnId] = all.networks.map((x: any) => x.id);
    const everything = async () =>
      JSON.stringify([await t.json("/api/networks"), await t.json("/api/accounts"), await t.json("/api/session"), await t.json("/api/settings")]);
    assert.doesNotMatch(await everything(), new RegExp(`${SECRET}|BEGIN CERTIFICATE`));
    // The password is in the vault, beside the platforms' credentials, and the database holds only its ID.
    assert.match(readFileSync(join(t.dataDir, "credentials.json"), "utf8"), new RegExp(SECRET));
    assert.doesNotMatch(JSON.stringify(t.repo.store.all("SELECT * FROM networks")), new RegExp(SECRET));

    // An edit that leaves the password and certificate alone keeps them.
    all = await t.json(`/api/networks/${vpnId}`, "PUT", { ...vpn, name: "Partner VPN (Paris)", proxy: { ...vpn.proxy, port: 3128, password: undefined } });
    assert.equal(routeOf(t, vpnId).proxy!.password, SECRET);
    assert.equal(routeOf(t, vpnId).proxy!.port, 3128);
    all = await t.json(`/api/networks/${officeId}`, "PUT", { name: "Head office", kind: "zscaler", proxy: null });
    assert.equal(all.networks[0].certificates.length, 1);
    // Removing the username removes the password with it.
    await t.json(`/api/networks/${vpnId}`, "PUT", { ...vpn, proxy: { ...vpn.proxy, username: null, password: undefined } });
    assert.equal(routeOf(t, vpnId).proxy!.password, null);
    assert.doesNotMatch(readFileSync(join(t.dataDir, "credentials.json"), "utf8"), new RegExp(SECRET), "a password nothing uses is dropped from the vault");
    assert.match(readFileSync(join(t.dataDir, "credentials.json"), "utf8"), new RegExp(MOCK_TOKEN), "and the accounts' credentials stay");

    assert.equal((await t.call(`/api/networks/${vpnId}`, { method: "DELETE", body: "{}" })).status, 200);
    assert.equal((await t.call(`/api/networks/${vpnId}`, { method: "DELETE", body: "{}" })).status, 404);
    t.cleanup();
  });

  test("an account's credential isn't dropped when a network is, and a network's password isn't when an account is", async () => {
    const t = makeApp({ configured: true });
    const all = await t.json("/api/networks", "POST", vpn);
    assert.equal((await t.call(`/api/accounts/${MOCK_ACCOUNT}`, { method: "DELETE", body: "{}" })).status, 200);
    assert.equal(routeOf(t, all.networks[0].id).proxy!.password, SECRET);
    t.cleanup();
  });

  test("what can't work is refused with what to do instead", async () => {
    const t = makeApp();
    const refused = async (b: unknown) => {
      const res = await t.call("/api/networks", { method: "POST", body: JSON.stringify(b) });
      assert.ok(res.status === 400 || res.status === 409, `${res.status}`);
      return ((await res.json()) as any).error as string;
    };
    assert.match(await refused({ name: "Nothing", kind: "proxy", proxy: null }), /needs a proxy, a certificate to trust, or both/);
    assert.match(await refused({ ...vpn, kind: "ipsec" }), /what kind of network/);
    assert.match(await refused({ ...vpn, proxy: { ...vpn.proxy, host: "http://proxy.example:8080" } }), /only the proxy's host/);
    assert.match(await refused({ ...vpn, proxy: { ...vpn.proxy, port: 70000 } }), /from 1 to 65535/);
    assert.match(await refused({ ...vpn, proxy: { ...vpn.proxy, protocol: "socks4" } }), /HTTP, HTTP over TLS or SOCKS5/);
    assert.match(await refused({ ...office, ca: "not a certificate" }), /No certificate found/);
    assert.match(await refused({ ...office, ca: authority.ca.replace("MII", "!!!") }), /can't be read/);
    assert.match(await refused({ ...office, ca: `${authority.ca}\n${authority.key}` }), /contains a private key/);
    await t.json("/api/networks", "POST", office);
    assert.match(await refused({ ...office, name: "head OFFICE" }), /Head office already exists/);
    assert.match((await t.json("/api/network-use", "PUT", { target: "github", network: 999 })).error, /no longer exists/);
    assert.match((await t.json("/api/network-use", "PUT", { target: "bitbucket", network: "direct" })).error, /Unknown platform/);
    t.cleanup();
  });

  test("each platform follows the default, or names a network or this machine's own connection", async () => {
    const t = makeApp();
    let all = await t.json("/api/networks", "POST", office);
    all = await t.json("/api/networks", "POST", vpn);
    const [officeId, vpnId] = all.networks.map((x: any) => x.id);
    const name = (p: Parameters<typeof routeFor>[2]) => routeFor(t.repo, t.vault, p)?.name ?? null;
    assert.deepEqual([name(null), name("github"), name("aws")], [null, null, null]);

    await t.json("/api/network-use", "PUT", { target: "github", network: vpnId });
    assert.deepEqual([name(null), name("github"), name("aws")], [null, "Partner VPN", null]);
    all = await t.json("/api/network-use", "PUT", { target: "default", network: officeId });
    assert.deepEqual([name(null), name("github"), name("aws")], ["Head office", "Partner VPN", "Head office"]);
    all = await t.json("/api/network-use", "PUT", { target: "aws", network: "direct" });
    assert.deepEqual([name(null), name("github"), name("aws"), name("vercel")], ["Head office", "Partner VPN", null, "Head office"]);
    assert.deepEqual(all.use, { default: officeId, providers: { github: vpnId, aws: "direct" } });
    assert.deepEqual(
      all.networks.map((x: any) => x.usedBy),
      [["default"], ["github"]],
    );

    // A removed network's platforms follow the default again; a removed default is this machine's own connection.
    all = await t.json(`/api/networks/${vpnId}`, "DELETE", {});
    assert.deepEqual([name(null), name("github")], ["Head office", "Head office"]);
    await t.json("/api/network-use", "PUT", { target: "aws", network: null });
    assert.equal(name("aws"), "Head office");
    all = await t.json(`/api/networks/${officeId}`, "DELETE", {});
    assert.deepEqual(all.use, { default: null, providers: {} });
    assert.equal(name("aws"), null);
    t.cleanup();
  });

  test("only admins see or change networks, and someone limited to some entities never does", async () => {
    const t = makeApp({ configured: true });
    await t.json("/api/networks", "POST", vpn);
    const entity = t.repo.entities.list()[0].id;
    for (const as of [t.as("viewer"), t.as("analyst"), t.as("manager"), t.limitedAs("manager", [entity])]) {
      const read = await as.call("/api/networks");
      assert.equal(read.status, 403);
      assert.doesNotMatch(await read.text(), /partner/i);
      for (const [path, method] of [
        ["/api/networks", "POST"],
        ["/api/networks/1", "PUT"],
        ["/api/networks/1", "DELETE"],
        ["/api/network-use", "PUT"],
        ["/api/networks/test", "POST"],
      ])
        assert.equal((await as.call(path, { method, body: JSON.stringify(vpn) })).status, 403, `${method} ${path}`);
    }
    t.cleanup();
  });
});

describe("scans and the Add accounts flow", () => {
  let restore: () => void;
  const real = net.send;
  before(() => {
    restore = installMockCloudflare();
  });
  after(() => restore());
  afterEach(() => {
    net.send = real;
  });

  test("an account is scanned, and a credential verified, through its platform's network", async () => {
    const t = makeApp({ configured: true });
    const seen: { network: string; host: string; password: string | null }[] = [];
    net.send = async (r, input, init) => {
      seen.push({ network: r.name, host: new URL(String(input)).hostname, password: r.proxy?.password ?? null });
      return fetch(input, init);
    };
    const all = await t.json("/api/networks", "POST", {
      name: "Edge VPN",
      kind: "warp",
      proxy: { protocol: "socks5", host: "127.0.0.1", port: 40000, username: "scan", password: "s3cret" },
    });
    await t.scanner.start("manual", [MOCK_ACCOUNT]).done;
    assert.equal(seen.length, 0, "no network chosen: every request leaves over this machine's own connection");

    await t.json("/api/network-use", "PUT", { target: "cloudflare", network: all.networks[0].id });
    const result = await t.scanner.start("manual", [MOCK_ACCOUNT]).done;
    assert.ok(result[0].findings > 0);
    assert.ok(seen.length > 20, `${seen.length} requests`);
    assert.deepEqual([...new Set(seen.map((s) => `${s.network} ${s.host} ${s.password}`))], ["Edge VPN api.cloudflare.com s3cret"]);

    seen.length = 0;
    const verified = await t.json("/api/accounts/verify", "POST", { provider: "cloudflare", token: MOCK_TOKEN, accountIds: [MOCK_ACCOUNT] });
    assert.equal(verified.token.valid, true);
    assert.ok(seen.length > 0 && seen.every((s) => s.network === "Edge VPN"));

    // Another platform's requests don't take it.
    seen.length = 0;
    await t.json("/api/network-use", "PUT", { target: "cloudflare", network: null });
    await t.json("/api/network-use", "PUT", { target: "vercel", network: all.networks[0].id });
    await t.scanner.start("manual", [MOCK_ACCOUNT]).done;
    assert.equal(seen.length, 0);
    t.cleanup();
  });

  test("a scan through a network that is down fails with the network's name, and its password stays out of the error", async () => {
    const t = makeApp({ configured: true });
    const all = await t.json("/api/networks", "POST", {
      name: "Old VPN",
      kind: "proxy",
      proxy: { protocol: "http", host: "127.0.0.1", port: 9, username: "scan", password: "s3cret-word" },
    });
    await t.json("/api/network-use", "PUT", { target: "cloudflare", network: all.networks[0].id });
    await assert.rejects(() => t.scanner.start("manual", [MOCK_ACCOUNT]).done);
    const failed = t.repo.scans.lastFailed(MOCK_ACCOUNT)!;
    assert.match(failed.error!, /Couldn't use "Old VPN": the proxy at 127\.0\.0\.1:9 refused the connection/);
    assert.doesNotMatch(failed.error!, /s3cret/);
    t.cleanup();
  });

  test("testing a network says where requests come out and which platforms answered", async () => {
    const t = makeApp();
    net.send = async (r, input) => {
      const url = new URL(String(input));
      if (url.pathname === "/cdn-cgi/trace") return new Response("fl=1\nip=203.0.113.57\nwarp=on\n");
      if (url.hostname === PROVIDER_INFO.vercel.checkHost)
        throw new NetworkError(`Couldn't reach ${url.hostname} through "${r.name}": the proxy doesn't allow it.`, "ECONNREFUSED");
      return new Response("", { status: 401 });
    };
    const body = { network: { name: "Edge VPN", kind: "warp", proxy: { protocol: "socks5", host: "127.0.0.1", port: 40000 } } };
    const result = await t.json("/api/networks/test", "POST", body);
    assert.deepEqual(result.egress, { address: "203.0.113.57", warp: true });
    assert.deepEqual(
      result.reached.map((x: any) => [x.provider, x.host, x.ok]),
      // A platform people host themselves is asked at the instances its accounts are on: with none connected, nowhere.
      PROVIDERS.filter((p) => PROVIDER_INFO[p].checkHost).map((p) => [p, PROVIDER_INFO[p].checkHost, p !== "vercel"]),
    );
    assert.match(result.reached.find((x: any) => x.provider === "vercel").error, /doesn't allow it/);
    // Nothing was stored for it.
    assert.deepEqual((await t.json("/api/networks")).networks, []);
    assert.match((await t.json("/api/networks/test", "POST", {})).error, /Choose a network to test/);

    // A stored network is tested with its stored password.
    const all = await t.json("/api/networks", "POST", { ...body.network, proxy: { ...body.network.proxy, username: "scan", password: "s3cret" } });
    let password: string | null = null;
    net.send = async (r) => {
      password = r.proxy?.password ?? null;
      return new Response("", { status: 200 });
    };
    await t.json("/api/networks/test", "POST", { id: all.networks[0].id });
    assert.equal(password, "s3cret");
    t.cleanup();
  });
});

describe("kinds of network", () => {
  test("each says how Keelson gets a route in, and its usual proxy is one the form can hold", () => {
    for (const kind of NETWORK_KINDS) {
      const info = NETWORK_KIND_INFO[kind];
      assert.ok(info.label && info.summary && info.setup.length, kind);
      if (info.proxy) assert.ok(info.proxy.port > 0 && info.proxy.port < 65536 && info.proxy.host, kind);
      if (info.docs) assert.match(info.docs, /^https:\/\//, kind);
      // A network that inspects TLS needs its certificate: the steps must say so.
      if (info.inspectsTls) assert.match(info.setup.join(" "), /certificate/, kind);
    }
  });
});

function routeOf(t: ReturnType<typeof makeApp>, id: number): Route {
  const network = t.repo.networks.get(id)!;
  const secret = network.secretId ? (t.vault.get(network.secretId)?.token ?? null) : null;
  return { key: "", name: network.name, proxy: network.proxy ? { ...network.proxy, password: secret } : null, ca: network.ca };
}
