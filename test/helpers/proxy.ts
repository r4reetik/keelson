// What the network tests send through: an HTTPS server that uses a certificate
// from an authority made on the spot (dev/mock/certificate.ts), an HTTP proxy
// that tunnels (CONNECT) and relays, and a SOCKS5 proxy. Everything listens on
// 127.0.0.1 and is closed by the test that made it.

import http from "node:http";
import https from "node:https";
import net, { type AddressInfo, type Server, type Socket } from "node:net";

export { makeAuthority } from "../../dev/mock/certificate.ts";

const listening = (server: Server): Promise<number> =>
  new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve((server.address() as AddressInfo).port)));

const closer = (server: Server, sockets: Set<Socket>) => () =>
  new Promise<void>((resolve) => {
    for (const s of sockets) s.destroy();
    server.close(() => resolve());
  });

function track(server: Server): Set<Socket> {
  const sockets = new Set<Socket>();
  server.on("connection", (s: Socket) => {
    sockets.add(s);
    s.on("close", () => sockets.delete(s));
    s.on("error", () => {});
  });
  return sockets;
}

/** An HTTPS (or plain HTTP) server that answers with what it was asked. */
export async function makeOrigin(tlsWith: { cert: string; key: string } | null, handler?: http.RequestListener) {
  const seen: { method: string; url: string; headers: http.IncomingHttpHeaders; body: string }[] = [];
  const listener: http.RequestListener = (req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      seen.push({ method: req.method!, url: req.url!, headers: req.headers, body });
      if (handler) return handler(req, res);
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ ok: true, path: req.url, method: req.method, body }));
    });
  };
  const server = tlsWith ? https.createServer(tlsWith, listener) : http.createServer(listener);
  const sockets = track(server);
  const port = await listening(server);
  return { port, seen, close: closer(server, sockets) };
}

/** An HTTP proxy: tunnels with CONNECT, relays plain HTTP, and asks for `login` ("user:password") when given. */
export async function makeHttpProxy(o: { login?: string; refuse?: number } = {}) {
  const connects: { target: string; authorization: string | null }[] = [];
  const relayed: string[] = [];
  const allowed = (h: http.IncomingHttpHeaders) => !o.login || h["proxy-authorization"] === `Basic ${Buffer.from(o.login).toString("base64")}`;
  const server = http.createServer((req, res) => {
    // A request with a whole address: plain HTTP handed over to relay.
    relayed.push(req.url!);
    if (!allowed(req.headers)) return res.writeHead(407).end();
    const to = new URL(req.url!);
    const out = http.request(
      { host: to.hostname, port: to.port, path: `${to.pathname}${to.search}`, method: req.method, headers: { ...req.headers, host: to.host } },
      (r) => {
        res.writeHead(r.statusCode!, r.headers);
        r.pipe(res);
      },
    );
    out.on("error", () => res.writeHead(502).end());
    req.pipe(out);
  });
  server.on("connect", (req, client: Socket, head) => {
    connects.push({ target: req.url!, authorization: req.headers["proxy-authorization"] ?? null });
    if (!allowed(req.headers)) return client.end("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");
    if (o.refuse) return client.end(`HTTP/1.1 ${o.refuse} Refused\r\n\r\n`);
    const [host, port] = req.url!.split(":");
    const upstream = net.connect(Number(port), host, () => {
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      upstream.write(head);
      upstream.pipe(client);
      client.pipe(upstream);
    });
    upstream.on("error", () => client.end("HTTP/1.1 502 Bad Gateway\r\n\r\n"));
    client.on("error", () => upstream.destroy());
  });
  const sockets = track(server);
  const port = await listening(server);
  return { port, connects, relayed, close: closer(server, sockets) };
}

/** A SOCKS5 proxy (RFC 1928), with username and password (RFC 1929) when `login` is given. `map` sends a name somewhere else, as a network's own DNS would. */
export async function makeSocksProxy(o: { login?: { username: string; password: string }; map?: Record<string, number> } = {}) {
  const asked: string[] = [];
  const server = net.createServer((client) => {
    let buffer = Buffer.alloc(0);
    let stage: "hello" | "login" | "request" | "open" = "hello";
    const onData = (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (stage === "hello" && buffer.length >= 2 && buffer.length >= 2 + buffer[1]) {
        const methods = [...buffer.subarray(2, 2 + buffer[1])];
        buffer = buffer.subarray(2 + buffer[1]);
        const want = o.login ? 2 : 0;
        if (!methods.includes(want)) return client.end(Buffer.from([5, 0xff]));
        client.write(Buffer.from([5, want]));
        stage = o.login ? "login" : "request";
      }
      if (stage === "login" && buffer.length >= 2) {
        const ulen = buffer[1];
        if (buffer.length < 3 + ulen) return;
        const plen = buffer[2 + ulen];
        if (buffer.length < 3 + ulen + plen) return;
        const username = buffer.subarray(2, 2 + ulen).toString();
        const password = buffer.subarray(3 + ulen, 3 + ulen + plen).toString();
        buffer = buffer.subarray(3 + ulen + plen);
        const ok = username === o.login!.username && password === o.login!.password;
        client.write(Buffer.from([1, ok ? 0 : 1]));
        if (!ok) return client.end();
        stage = "request";
      }
      if (stage === "request" && buffer.length >= 5) {
        const kind = buffer[3];
        const length = kind === 1 ? 4 : kind === 4 ? 16 : buffer[4] + 1;
        if (buffer.length < 4 + length + 2) return;
        const host = kind === 3 ? buffer.subarray(5, 4 + length).toString() : [...buffer.subarray(4, 8)].join(".");
        const port = buffer.readUInt16BE(4 + length);
        const rest = buffer.subarray(4 + length + 2);
        asked.push(`${host}:${port}`);
        stage = "open";
        client.off("data", onData);
        const upstream = net.connect(o.map?.[host] ?? port, "127.0.0.1", () => {
          client.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
          if (rest.length) upstream.write(rest);
          upstream.pipe(client);
          client.pipe(upstream);
        });
        upstream.on("error", () => client.end(Buffer.from([5, 5, 0, 1, 0, 0, 0, 0, 0, 0])));
        client.on("error", () => upstream.destroy());
      }
    };
    client.on("data", onData);
  });
  const sockets = track(server);
  const port = await listening(server);
  return { port, asked, close: closer(server, sockets) };
}
