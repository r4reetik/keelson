// Every request Keelson sends goes through here, so a platform's requests can
// leave through the network chosen for it (Networks page, src/networks.ts): a
// proxy into a VPN or zero trust network, trusting the certificate that network
// signs with when it inspects TLS.
//
// A scan runs inside through(route, …), and request() anywhere below it uses
// that route. Outside a scan, and for Keelson's own lookups (ownRequest: CISA's
// catalog, support dates, AWS's address ranges), the default route applies.
// With no network chosen, request() is the global fetch, exactly as before.
//
// No dependency: an HTTP CONNECT or SOCKS5 tunnel is a few lines over node:net,
// and node:https does the rest. A network's certificate is trusted only for
// requests sent through that network, on top of the public authorities, never
// for the whole process. The proxy's password is in the vault and reaches only
// the proxy; no error names it.

import { AsyncLocalStorage } from "node:async_hooks";
import { lookup } from "node:dns/promises";
import http, { type IncomingMessage } from "node:http";
import https from "node:https";
import { connect as tcpConnect, isIP, type Socket } from "node:net";
import { Readable } from "node:stream";
import tls from "node:tls";
import { createBrotliDecompress, createGunzip, createInflate } from "node:zlib";
import type { ProxyProtocol } from "../shared/networks.ts";

/** How requests leave: through a proxy, trusting more certificates, or both. Null is the machine's own connection. */
export interface Route {
  /** Changes whenever the network's settings do: connections are reused while it stays the same. */
  key: string;
  /** The network's name, for errors and logs. */
  name: string;
  proxy: { protocol: ProxyProtocol; host: string; port: number; username: string | null; password: string | null } | null;
  /** PEM certificates trusted for requests on this route, besides the public authorities. */
  ca: string | null;
}

/** A request that failed on the way: the message says where and why in plain words, `cause.code` says what kind. */
export class NetworkError extends Error {
  override cause: { code: string };
  /**
   * The network itself is at fault, so every request through it fails the same way: its proxy can't be reached or
   * refuses the sign-in, or a certificate isn't trusted because the network's own is missing.
   */
  broken = false;
  constructor(message: string, code: string, broken = false) {
    super(message);
    this.name = "NetworkError";
    this.cause = { code };
    this.broken = broken;
  }
}

/** How long each step of setting up a connection may take: reaching the proxy, its answer, the TLS handshake. */
const STEP_MS = 20_000;
const MAX_REDIRECTS = 10;
/** Idle connections are kept this long, so a scan's thousands of requests don't each pay for a tunnel and a handshake. */
const KEEP_ALIVE_MS = 15_000;

const context = new AsyncLocalStorage<{ route: Route | null }>();

/** What tests and the mock dev server replace: how the default route is found, and how a request is sent on a route. */
export const net = {
  /** The route for everything outside a scan. Set at start-up to the Networks page's default. */
  defaultRoute: (): Route | null => null,
  /** Sends one request on a route. The mock answers here, so it never opens a connection. */
  send: (route: Route, input: string | URL, init: RequestInit): Promise<Response> => send(route, input, init),
  /** This machine's own resolver: rejects with code ENOTFOUND for a name that doesn't exist. */
  lookup: (name: string): Promise<unknown> => lookup(name),
};

/** The route requests use here: the scan's, else the default. */
export function currentRoute(): Route | null {
  const here = context.getStore();
  return here ? here.route : net.defaultRoute();
}

/** Runs `fn` with every request below it sent through `route` (null: the machine's own connection). */
export function through<T>(route: Route | null, fn: () => T): T {
  return context.run({ route }, fn);
}

/** Runs `fn` on the default route, whatever scan it is called from: for what Keelson reads for itself, not from a platform. */
export function own<T>(fn: () => T): T {
  return context.exit(fn);
}

/** `fetch`, through the network chosen for whatever is running. */
export function request(input: string | URL, init: RequestInit = {}): Promise<Response> {
  const route = currentRoute();
  return route ? net.send(route, input, init) : fetch(input, init);
}

/** `fetch` for Keelson's own lookups, on the default route even in the middle of a platform's scan. */
export const ownRequest = (input: string | URL, init: RequestInit = {}): Promise<Response> => own(() => request(input, init));

// ---- Certificates ----

const trusted = new Map<string, string[]>();
/** The public authorities Node trusts (with NODE_EXTRA_CA_CERTS), plus the route's own. */
function authorities(route: Route): string[] | undefined {
  if (!route.ca) return undefined;
  let list = trusted.get(route.key);
  if (!list) {
    list = [...tls.getCACertificates("default"), route.ca];
    trusted.set(route.key, list);
  }
  return list;
}

/** Every authority a route trusts as one PEM file, for scanners that read SSL_CERT_FILE; null when the route adds none. */
export const caBundle = (route: Route | null): string | null => (route?.ca ? `${authorities(route)!.join("\n")}\n` : null);

const UNTRUSTED = new Set([
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "UNABLE_TO_GET_ISSUER_CERT",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "CERT_UNTRUSTED",
]);

/** A failed TLS handshake, said so someone can act on it: an untrusted certificate is nearly always a network that inspects TLS. */
function tlsFailure(code: string, target: string, route: Route): NetworkError {
  const through = `Couldn't reach ${target} through ${where(route)}`;
  if (UNTRUSTED.has(code))
    return new NetworkError(
      `${through}: the certificate it was given isn't signed by an authority Keelson trusts. If this network inspects TLS, add the certificate it signs with to the network.`,
      code,
      true,
    );
  if (code === "CERT_HAS_EXPIRED") return new NetworkError(`${through}: the certificate it was given has expired.`, code);
  if (code === "ERR_TLS_CERT_ALTNAME_INVALID") return new NetworkError(`${through}: the certificate it was given is for another name.`, code);
  return new NetworkError(`${through}: the TLS handshake failed (${code}).`, code);
}
const TLS_CODES = new Set([...UNTRUSTED, "CERT_HAS_EXPIRED", "ERR_TLS_CERT_ALTNAME_INVALID"]);

// ---- Connections ----

const where = (route: Route) => `"${route.name}"`;
const proxyName = (p: NonNullable<Route["proxy"]>) => `${p.host}:${p.port}`;

/** Fails a step that takes too long, and cleans up after either way. */
function step<T>(socket: Socket, what: () => NetworkError, work: (done: (v: T) => void, fail: (e: Error) => void) => void): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => finish(() => reject(what())), STEP_MS);
    const onError = (e: Error) => finish(() => reject(e));
    const onClose = () => finish(() => reject(what()));
    const finish = (then: () => void) => {
      clearTimeout(timer);
      socket.off("error", onError);
      socket.off("close", onClose);
      then();
    };
    socket.once("error", onError);
    socket.once("close", onClose);
    work(
      (v) => finish(() => resolve(v)),
      (e) => finish(() => reject(e)),
    );
  });
}

/** Reads exactly `n` bytes from a socket that isn't flowing. */
function readBytes(socket: Socket, n: number, what: () => NetworkError): Promise<Buffer> {
  return step<Buffer>(socket, what, (done) => {
    const attempt = () => {
      const chunk = socket.read(n) as Buffer | null;
      if (!chunk) return false;
      socket.off("readable", attempt);
      done(chunk);
      return true;
    };
    if (!attempt()) socket.on("readable", attempt);
  });
}

function tcp(host: string, port: number, failed: (why: string, code: string) => NetworkError): Promise<Socket> {
  return new Promise<Socket>((resolve, reject) => {
    const socket = tcpConnect({ host, port });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(failed("didn't answer", "ETIMEDOUT"));
    }, STEP_MS);
    socket.once("connect", () => {
      clearTimeout(timer);
      socket.removeAllListeners("error");
      // An error after this belongs to whoever uses the socket; without a listener it would crash the process.
      socket.on("error", () => {});
      socket.setNoDelay(true);
      resolve(socket);
    });
    socket.once("error", (e: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      const code = e.code ?? "ECONNRESET";
      const why =
        code === "ECONNREFUSED"
          ? "refused the connection"
          : code === "ENOTFOUND" || code === "EAI_AGAIN"
            ? "has a name that doesn't resolve here"
            : code === "EHOSTUNREACH" || code === "ENETUNREACH"
              ? "can't be reached from here"
              : "couldn't be connected to";
      reject(failed(why, code));
    });
  });
}

function secure(socket: Socket, host: string, route: Route, target: string): Promise<Socket> {
  return new Promise<Socket>((resolve, reject) => {
    const s = tls.connect({ socket, servername: isIP(host) ? undefined : host, ca: authorities(route), ALPNProtocols: ["http/1.1"] });
    const timer = setTimeout(() => {
      s.destroy();
      reject(new NetworkError(`Couldn't reach ${target} through ${where(route)}: the TLS handshake timed out.`, "ETIMEDOUT"));
    }, STEP_MS);
    s.once("secureConnect", () => {
      clearTimeout(timer);
      s.removeAllListeners("error");
      s.on("error", () => {});
      resolve(s);
    });
    s.once("error", (e: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      socket.destroy();
      const code = e.code ?? "EPROTO";
      reject(tlsFailure(code, target, route));
    });
  });
}

/**
 * Whether a name the proxy couldn't connect to exists at all. AWS and Alibaba Cloud name a host per service and region,
 * and one that doesn't resolve means the service isn't offered there (not a gap). A proxy only says that it failed, so
 * Keelson asks its own resolver, and believes "no such name" only from a resolver that resolves public names: one
 * that knows nothing outside its own network would call every platform's host unknown.
 */
const known = new Map<string, { exists: boolean; at: number }>();
async function nameExists(host: string): Promise<boolean> {
  if (isIP(host)) return true;
  const resolves = async (name: string): Promise<boolean | null> => {
    const cached = known.get(name);
    if (cached && Date.now() - cached.at < 600_000) return cached.exists;
    try {
      await net.lookup(name);
      known.set(name, { exists: true, at: Date.now() });
      return true;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOTFOUND") return null;
      known.set(name, { exists: false, at: Date.now() });
      return false;
    }
  };
  if ((await resolves(host)) !== false) return true;
  // example.com is reserved by IANA and always resolves on the public internet.
  return (await resolves("example.com")) !== true;
}

const SOCKS_REPLY: Record<number, string> = {
  1: "the proxy couldn't connect",
  2: "the proxy's rules don't allow it",
  3: "the proxy has no route to its network",
  4: "the proxy couldn't reach the host",
  5: "the host refused the connection",
  6: "the connection timed out",
  7: "the proxy doesn't support the request",
  8: "the proxy doesn't support that kind of address",
};

async function socks5(socket: Socket, host: string, port: number, route: Route): Promise<void> {
  const p = route.proxy!;
  const target = `${host}:${port}`;
  const silent = () => new NetworkError(`Couldn't reach ${target} through ${where(route)}: the proxy at ${proxyName(p)} stopped answering.`, "ECONNRESET");
  const notSocks = () =>
    new NetworkError(`Couldn't use ${where(route)}: ${proxyName(p)} doesn't answer as a SOCKS5 proxy. Check its type and port.`, "EPROTO", true);
  const withLogin = p.username != null;
  socket.write(Buffer.from(withLogin ? [5, 2, 0, 2] : [5, 1, 0]));
  const [version, method] = await readBytes(socket, 2, silent);
  if (version !== 5) throw notSocks();
  if (method === 2 && withLogin) {
    const user = Buffer.from(p.username ?? "");
    const pass = Buffer.from(p.password ?? "");
    socket.write(Buffer.concat([Buffer.from([1, user.length]), user, Buffer.from([pass.length]), pass]));
    const [, status] = await readBytes(socket, 2, silent);
    if (status !== 0)
      throw new NetworkError(`Couldn't use ${where(route)}: the proxy at ${proxyName(p)} refused the username or password.`, "EPROXYAUTH", true);
  } else if (method !== 0) {
    throw new NetworkError(
      `Couldn't use ${where(route)}: the proxy at ${proxyName(p)} ${withLogin ? "accepts none of the ways Keelson can sign in" : "asks for a username and password"}.`,
      "EPROXYAUTH",
      true,
    );
  }
  // The name is sent as it is, so the proxy resolves it: names that exist only inside its network work.
  const family = isIP(host);
  const address =
    family === 4
      ? Buffer.from([1, ...host.split(".").map(Number)])
      : family === 6
        ? Buffer.concat([Buffer.from([4]), ipv6Bytes(host)])
        : Buffer.concat([Buffer.from([3, Buffer.byteLength(host)]), Buffer.from(host)]);
  socket.write(Buffer.concat([Buffer.from([5, 1, 0]), address, Buffer.from([port >> 8, port & 255])]));
  const [v, reply, , kind] = await readBytes(socket, 4, silent);
  if (v !== 5) throw notSocks();
  if (reply !== 0) {
    if ((reply === 1 || reply === 4) && !(await nameExists(host))) throw new NetworkError(`${host} doesn't exist`, "ENOTFOUND");
    throw new NetworkError(
      `Couldn't reach ${target} through ${where(route)}: ${SOCKS_REPLY[reply] ?? `the proxy answered with error ${reply}`}.`,
      "ECONNREFUSED",
    );
  }
  // The address the proxy connected from follows; its length depends on its kind.
  const rest = kind === 1 ? 6 : kind === 4 ? 18 : (await readBytes(socket, 1, silent))[0] + 2;
  await readBytes(socket, rest, silent);
}

function ipv6Bytes(address: string): Buffer {
  const [head, tail = ""] = address.split("::");
  const groups = (part: string) => (part ? part.split(":") : []);
  const h = groups(head);
  const t = address.includes("::") ? groups(tail) : [];
  const all = [...h, ...Array(8 - h.length - t.length).fill("0"), ...t];
  const out = Buffer.alloc(16);
  all.forEach((g, i) => out.writeUInt16BE(Number.parseInt(g, 16) || 0, i * 2));
  return out;
}

const basic = (p: NonNullable<Route["proxy"]>): string | null =>
  p.username != null ? `Basic ${Buffer.from(`${p.username}:${p.password ?? ""}`).toString("base64")}` : null;

async function httpConnect(socket: Socket, host: string, port: number, route: Route): Promise<void> {
  const p = route.proxy!;
  const target = `${host.includes(":") ? `[${host}]` : host}:${port}`;
  const auth = basic(p);
  socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n${auth ? `Proxy-Authorization: ${auth}\r\n` : ""}\r\n`);
  const silent = () => new NetworkError(`Couldn't reach ${target} through ${where(route)}: the proxy at ${proxyName(p)} stopped answering.`, "ECONNRESET");
  const head = await step<string>(socket, silent, (done, fail) => {
    let seen = Buffer.alloc(0);
    const attempt = () => {
      for (let chunk = socket.read() as Buffer | null; chunk; chunk = socket.read() as Buffer | null) {
        seen = Buffer.concat([seen, chunk]);
        const end = seen.indexOf("\r\n\r\n");
        if (end >= 0) {
          socket.off("readable", attempt);
          // Nothing should follow the proxy's answer before Keelson speaks; whatever does belongs to the connection.
          if (seen.length > end + 4) socket.unshift(seen.subarray(end + 4));
          return done(seen.subarray(0, end).toString("latin1"));
        }
        if (seen.length > 16_384) {
          socket.off("readable", attempt);
          return fail(
            new NetworkError(`Couldn't use ${where(route)}: ${proxyName(p)} doesn't answer as an HTTP proxy. Check its type and port.`, "EPROTO", true),
          );
        }
      }
    };
    socket.on("readable", attempt);
    attempt();
  });
  const status = Number(/^HTTP\/1\.[01] (\d{3})/.exec(head)?.[1]);
  if (!status)
    throw new NetworkError(`Couldn't use ${where(route)}: ${proxyName(p)} doesn't answer as an HTTP proxy. Check its type and port.`, "EPROTO", true);
  if (status >= 200 && status < 300) return;
  if (status === 407)
    throw new NetworkError(
      `Couldn't use ${where(route)}: the proxy at ${proxyName(p)} ${auth ? "refused the username or password" : "asks for a username and password"}.`,
      "EPROXYAUTH",
      true,
    );
  if (status !== 403 && !(await nameExists(host))) throw new NetworkError(`${host} doesn't exist`, "ENOTFOUND");
  throw new NetworkError(
    `Couldn't reach ${target} through ${where(route)}: the proxy at ${proxyName(p)} ${status === 403 ? "doesn't allow it" : "couldn't connect"} (it answered ${status}).`,
    "ECONNREFUSED",
  );
}

/** A connection to the proxy itself, over TLS when the proxy takes it. */
async function toProxy(route: Route): Promise<Socket> {
  const p = route.proxy!;
  const socket = await tcp(p.host, p.port, (why, code) => new NetworkError(`Couldn't use ${where(route)}: the proxy at ${proxyName(p)} ${why}.`, code, true));
  return p.protocol === "https" ? secure(socket, p.host, route, `the proxy at ${proxyName(p)}`) : socket;
}

/** A connection to host:port on the route: through the proxy's tunnel when it has one. */
async function open(route: Route, host: string, port: number): Promise<Socket> {
  const target = `${host}:${port}`;
  if (!route.proxy) return tcp(host, port, (why, code) => new NetworkError(code === "ENOTFOUND" ? `${host} doesn't exist` : `${target} ${why}.`, code));
  const socket = await toProxy(route);
  try {
    if (route.proxy.protocol === "socks5") await socks5(socket, host, port, route);
    else await httpConnect(socket, host, port, route);
    return socket;
  } catch (e) {
    socket.destroy();
    throw e;
  }
}

interface Agents {
  https: https.Agent;
  http: http.Agent;
  /** For plain-HTTP requests handed to an HTTP proxy as they are (no tunnel); null when the route has no such proxy. */
  relay: http.Agent | null;
}
const agents = new Map<string, Agents>();

type Created = (err: Error | null, socket: Socket) => void;
/** Hands a connection (or why there is none) to the agent that asked for it. */
const hand = (made: Promise<Socket>, created?: Created): undefined => {
  made.then(
    (socket) => created?.(null, socket),
    (e: Error) => created?.(e, undefined as never),
  );
  return undefined;
};
type Target = { host?: string | null; hostname?: string | null; port?: number | string | null; servername?: string };

function agentsFor(route: Route): Agents {
  const made = agents.get(route.key);
  if (made) return made;
  const options = { keepAlive: true, keepAliveMsecs: KEEP_ALIVE_MS, maxSockets: 64, timeout: KEEP_ALIVE_MS * 4 };
  const hostOf = (o: Target) => String(o.hostname ?? o.host ?? "").replace(/^\[|\]$/g, "");

  class Secure extends https.Agent {
    override createConnection(o: Target, created?: Created) {
      const host = hostOf(o);
      const port = Number(o.port) || 443;
      return hand(
        open(route, host, port).then((socket) => secure(socket, o.servername || host, route, host)),
        created,
      );
    }
  }
  class Plain extends http.Agent {
    override createConnection(o: Target, created?: Created) {
      return hand(open(route, hostOf(o), Number(o.port) || 80), created);
    }
  }
  class Relay extends http.Agent {
    override createConnection(_o: Target, created?: Created) {
      return hand(toProxy(route), created);
    }
  }
  // Without a proxy only the certificates differ, and Node's own connections take those.
  const next: Agents = route.proxy
    ? { https: new Secure(options), http: new Plain(options), relay: route.proxy.protocol === "socks5" ? null : new Relay(options) }
    : { https: new https.Agent({ ...options, ca: authorities(route) }), http: new http.Agent(options), relay: null };
  agents.set(route.key, next);
  return next;
}

/** Forgets which names resolve here. For tests, which change the resolver. */
export const forgetNames = (): void => known.clear();

/** Closes a route's idle connections and forgets it: called when its network changes or is removed. */
export function forgetRoute(key: string): void {
  const a = agents.get(key);
  if (a) for (const agent of [a.https, a.http, a.relay]) agent?.destroy();
  agents.delete(key);
  trusted.delete(key);
}

// ---- Requests ----

const NO_BODY = new Set([101, 204, 205, 304]);
const REDIRECT = new Set([301, 302, 303, 307, 308]);

function bodyOf(body: RequestInit["body"]): Buffer | undefined {
  if (body == null) return undefined;
  if (typeof body === "string") return Buffer.from(body);
  if (body instanceof URLSearchParams) return Buffer.from(body.toString());
  if (body instanceof ArrayBuffer) return Buffer.from(body);
  if (ArrayBuffer.isView(body)) return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  throw new TypeError("A request sent through a network needs its body as text or bytes.");
}

function once(route: Route, url: URL, method: string, headers: Headers, body: Buffer | undefined, signal: AbortSignal | null): Promise<IncomingMessage> {
  return new Promise<IncomingMessage>((resolve, reject) => {
    const a = agentsFor(route);
    const secureTarget = url.protocol === "https:";
    const out: Record<string, string> = {};
    headers.forEach((v, k) => {
      out[k] = v;
    });
    if (body) out["content-length"] = String(body.length);
    else if (method === "POST" || method === "PUT") out["content-length"] = "0";
    // Plain HTTP through an HTTP proxy is handed over whole: most proxies refuse a tunnel to port 80.
    const relayed = !secureTarget && a.relay && route.proxy;
    if (relayed && basic(relayed)) out["proxy-authorization"] = basic(relayed)!;
    const req = (secureTarget ? https : http).request({
      protocol: url.protocol,
      hostname: url.hostname.replace(/^\[|\]$/g, ""),
      port: url.port || (secureTarget ? 443 : 80),
      path: relayed ? url.href : `${url.pathname}${url.search}`,
      method,
      headers: out,
      agent: secureTarget ? a.https : relayed ? a.relay! : a.http,
      ...(signal ? { signal } : {}),
    });
    req.once("response", resolve);
    req.once("error", (e: NodeJS.ErrnoException) => {
      // fetch rejects with the signal's own reason (a TimeoutError), and callers tell a timeout by it.
      if (signal?.aborted) return reject(signal.reason);
      if (e instanceof NetworkError) return reject(e);
      const code = e.code ?? "ECONNRESET";
      if (TLS_CODES.has(code)) return reject(tlsFailure(code, url.hostname, route));
      reject(
        new NetworkError(
          code === "ENOTFOUND" ? `${url.hostname} doesn't exist` : `Couldn't reach ${url.host} through ${where(route)}: the connection failed (${code}).`,
          code,
        ),
      );
    });
    req.end(body);
  });
}

function toResponse(res: IncomingMessage, url: URL, method: string, redirected: boolean): Response {
  const headers = new Headers();
  for (const [k, v] of Object.entries(res.headers)) {
    if (Array.isArray(v)) for (const one of v) headers.append(k, one);
    else if (v != null) headers.set(k, v);
  }
  const status = res.statusCode ?? 502;
  const empty = method === "HEAD" || NO_BODY.has(status);
  let stream: Readable = res;
  if (!empty) {
    // Keelson asks for no compression, but a proxy or a server may compress anyway.
    const encoding = (headers.get("content-encoding") ?? "").trim().toLowerCase();
    const unpack =
      encoding === "gzip" || encoding === "x-gzip"
        ? createGunzip()
        : encoding === "deflate"
          ? createInflate()
          : encoding === "br"
            ? createBrotliDecompress()
            : null;
    if (unpack) {
      res.once("error", (e) => unpack.destroy(e));
      stream = res.pipe(unpack);
      headers.delete("content-encoding");
      headers.delete("content-length");
    }
  } else res.resume();
  const out = new Response(empty ? null : (Readable.toWeb(stream) as ReadableStream<Uint8Array>), { status, statusText: res.statusMessage ?? "", headers });
  Object.defineProperty(out, "url", { value: url.href });
  Object.defineProperty(out, "redirected", { value: redirected });
  return out;
}

/** One request on a route, with fetch's behaviour for what Keelson's clients use: method, headers, a body, a signal, redirects. */
async function send(route: Route, input: string | URL, init: RequestInit): Promise<Response> {
  let url = new URL(String(input));
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new TypeError(`Keelson only sends HTTP requests, not ${url.protocol}`);
  let method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  let body = bodyOf(init.body);
  const signal = init.signal ?? null;
  const mode = init.redirect ?? "follow";
  if (signal?.aborted) throw signal.reason;
  for (let hop = 0; ; hop++) {
    const res = await once(route, url, method, headers, body, signal);
    const status = res.statusCode ?? 0;
    const location = res.headers.location;
    if (!REDIRECT.has(status) || !location || mode === "manual") return toResponse(res, url, method, hop > 0);
    res.resume();
    if (mode === "error") throw new NetworkError(`${url.host} answered with a redirect, which this request doesn't follow.`, "EREDIRECT");
    if (hop >= MAX_REDIRECTS) throw new NetworkError(`${url.host} redirected too many times.`, "EREDIRECT");
    const next = new URL(location, url);
    if (next.protocol !== "https:" && next.protocol !== "http:")
      throw new NetworkError(`${url.host} redirected somewhere Keelson doesn't follow.`, "EREDIRECT");
    if (status === 303 || ((status === 301 || status === 302) && method === "POST")) {
      method = method === "HEAD" ? "HEAD" : "GET";
      body = undefined;
      for (const h of ["content-type", "content-length", "content-encoding"]) headers.delete(h);
    }
    // A credential meant for one host isn't handed to the host it redirects to.
    if (next.origin !== url.origin) for (const h of ["authorization", "cookie", "proxy-authorization"]) headers.delete(h);
    url = next;
  }
}

// ---- Scanners ----

/**
 * The variables that send a scanner Keelson runs (Trivy, Grype) the same way: Go's HTTP client reads the proxy from
 * them. `caFile` is where the caller wrote caBundle(route), when the route has certificates of its own.
 */
export function childProxyEnv(route: Route | null, caFile: string | null): Record<string, string> {
  if (!route) return {};
  const out: Record<string, string> = {};
  if (route.proxy) {
    const p = route.proxy;
    const login = p.username != null ? `${encodeURIComponent(p.username)}${p.password ? `:${encodeURIComponent(p.password)}` : ""}@` : "";
    const address = `${p.protocol}://${login}${p.host.includes(":") ? `[${p.host}]` : p.host}:${p.port}`;
    for (const k of ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"]) out[k] = address;
    out.NO_PROXY = "";
    out.no_proxy = "";
  }
  if (caFile) out.SSL_CERT_FILE = caFile;
  return out;
}
