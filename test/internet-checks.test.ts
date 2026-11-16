// The rules every internet (Sonar) check follows, as for the other providers: each
// fails on its case, the well-watched entity passes everything, an unreadable source
// skips its checks instead of passing them; and the pieces discovery is built from
// (CAA, issuers, registrable names) read what the services send.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { evaluateInternet } from "../src/providers/internet/engine.ts";
import { INTERNET_CHECKS } from "../src/providers/internet/catalog.ts";
import { INTERNET_MODULES } from "../src/providers/internet/checks/index.ts";
import { caaAllows } from "../src/providers/internet/checks/certificates.ts";
import {
  caaOfIssuer,
  certificatesOf,
  followChains,
  issuerName,
  parseCaa,
  registrable,
  serviceName,
  sharedPlatformName,
} from "../src/providers/internet/discover.ts";
import { hostMatches, routesFor } from "../src/providers/internet/checks/routing.ts";
import { parseSubs } from "../src/providers/internet/amass.ts";
import { CATEGORIES } from "../src/core/categories.ts";
import { INTERNET_CASES, INTERNET_OPTS, address, domain, host, internetInventory, loadBalancer, route, target } from "./internet-cases.ts";
import { opts } from "./fixtures/inventory.ts";

const judge = (inv: ReturnType<typeof internetInventory>) => evaluateInternet(inv, opts(INTERNET_OPTS));

test("every internet check fails on its case", () => {
  const silent = INTERNET_CHECKS.filter((c) => !judge(INTERNET_CASES[c.id]()).findings.some((f) => f.checkId === c.id && !f.pass)).map((c) => c.id);
  assert.deepEqual(silent, [], "these cases don't make their check fail");
});

test("the well-watched entity passes every check it evaluates", () => {
  const ev = judge(internetInventory());
  assert.deepEqual(
    ev.findings.filter((f) => !f.pass).map((f) => `${f.checkId} ${f.resource}`),
    [],
  );
  const evaluated = new Set(ev.results.map((r) => r.checkId));
  assert.deepEqual(
    INTERNET_CHECKS.filter((c) => !evaluated.has(c.id)).map((c) => c.id),
    [],
    "the fixture gives every check something to pass",
  );
});

test("an internet check whose source was unreadable reports nothing, even on its failing case", () => {
  const leaked: string[] = [];
  for (const c of INTERNET_CHECKS)
    for (const source of c.requires ?? []) {
      const inv = { ...INTERNET_CASES[c.id](), unreadable: [source] };
      if (judge(inv).results.some((r) => r.checkId === c.id)) leaked.push(`${c.id} (${source})`);
    }
  assert.deepEqual(leaked, []);
});

test("an address Shodan couldn't be asked about is neither passed nor failed", () => {
  const ev = judge(internetInventory({ addresses: [address({ shodan: null })] }));
  assert.deepEqual(
    ev.results.filter((r) => r.resource.startsWith("203.0.113.10") || r.checkId === "XP-012").map((r) => r.checkId),
    [],
  );
});

test("internet checks use the shared categories, start with N (or XP- when they compare platforms), and every module file is registered", () => {
  const ids = INTERNET_CHECKS.map((c) => c.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const c of INTERNET_CHECKS) {
    assert.match(c.id, c.spans ? /^XP-\d{3}$/ : /^N[A-Z]{2}-\d{3}$/, c.id);
    assert.ok((CATEGORIES as readonly string[]).includes(c.category), c.id);
    assert.ok(c.title && c.why && c.fix && c.docs, c.id);
    assert.ok(c.requires?.length, `${c.id} names the sources it reads`);
  }
  const dir = new URL("../src/providers/internet/checks/", import.meta.url);
  const files = readdirSync(dir).filter((f) => /^export default defineChecks\(/m.test(readFileSync(new URL(f, dir), "utf8")));
  assert.equal(files.length, INTERNET_MODULES.length, `modules on disk: ${files.join(", ")}`);
});

test("severity follows what is open: Redis is critical, SSH medium, a CVSS 9 vulnerability high", () => {
  const sev = (ports: number[], id: string) =>
    judge(
      internetInventory({ addresses: [address({ shodan: { seen: true, ports, services: [], vulns: [], hostnames: [], lastSeen: null, via: "internetdb" } })] }),
    ).findings.find((f) => f.checkId === id && !f.pass)?.severity;
  assert.equal(sev([6379], "NSV-001"), "critical");
  assert.equal(sev([5432], "NSV-001"), "high");
  assert.equal(sev([22], "NSV-002"), "medium");
  assert.equal(judge(INTERNET_CASES["NSV-003"]()).findings.find((f) => f.checkId === "NSV-003")?.severity, "high");
});

test("vulnerabilities are listed by score, or newest first without one, and say when InternetDB can't score them", () => {
  const vulns = ["CVE-2016-8670", "CVE-2025-23419", "CVE-2021-23017"].map((id) => ({ id, cvss: null }));
  const inv = internetInventory({
    addresses: [address({ shodan: { seen: true, ports: [443], services: [], vulns, hostnames: [], lastSeen: null, via: "internetdb" } })],
  });
  const f = judge(inv).findings.find((x) => x.checkId === "NSV-003")!;
  assert.equal(f.detail, "CVE-2025-23419, CVE-2021-23017, CVE-2016-8670");
  assert.equal(f.severity, "medium");
  assert.ok(f.evidence?.chain?.some((s) => s.label === "Scores"));
  const api = internetInventory({
    addresses: [
      address({ shodan: { seen: true, ports: [443], services: [], vulns: [{ id: "CVE-2024-0001", cvss: 7.5 }], hostnames: [], lastSeen: null, via: "api" } }),
    ],
  });
  const scored = judge(api).findings.find((x) => x.checkId === "NSV-003")!;
  assert.ok(!scored.evidence?.chain?.some((s) => s.label === "Scores"), "only InternetDB's answer lacks scores");
});

test("an origin Shodan lists is high when AWS says its security groups let anyone in", () => {
  const inv = INTERNET_CASES["XP-012"]();
  const ev = evaluateInternet(
    inv,
    opts({
      related: {
        ...INTERNET_OPTS.related!,
        awsOrigins: [{ kind: "ip", name: "203.0.113.10", region: "eu-west-1", resource: "instance web-1", web: "open", groups: [] }],
      },
    }),
  );
  assert.equal(ev.findings.find((f) => f.checkId === "XP-012")?.severity, "high");
  assert.equal(judge(inv).findings.find((f) => f.checkId === "XP-012")?.severity, "medium");
});

test("CAA is judged only on recent certificates from authorities Keelson knows, with issuewild for wildcards", () => {
  const old = domain({
    certificates: [{ ...domain().certificates![0], issuer: "Google Trust Services", caa: ["pki.goog"], notBefore: "2026-01-01T00:00:00Z" }],
  });
  assert.ok(!judge(internetInventory({ domains: [old] })).findings.some((f) => f.checkId === "NCT-001" && !f.pass), "issued before the last 30 days");
  const unknown = domain({ certificates: [{ ...domain().certificates![0], issuer: "Some CA", caa: null }] });
  assert.ok(!judge(internetInventory({ domains: [unknown] })).findings.some((f) => f.checkId === "NCT-001" && !f.pass), "an unknown issuer isn't judged");
  const caa = { issue: ["letsencrypt.org"], issuewild: ["pki.goog"] };
  const c = domain().certificates![0];
  assert.equal(caaAllows(caa, { ...c, names: ["*.example.com"], caa: ["pki.goog"] }), true);
  assert.equal(caaAllows(caa, { ...c, names: ["*.example.com"], caa: ["letsencrypt.org"] }), false);
  assert.equal(caaAllows({ issue: [""], issuewild: [] }, c), false, '";" allows no one');
  assert.equal(caaAllows({ issue: [], issuewild: [] }, c), true, "no CAA allows anyone");
});

test("CAA is read in presentation form and in RFC 3597's generic form", () => {
  const generic = (tag: string, value: string) => {
    const bytes = [0, tag.length, ...Buffer.from(tag), ...Buffer.from(value)];
    return `\\# ${bytes.length} ${bytes.map((b) => b.toString(16).padStart(2, "0")).join(" ")}`;
  };
  assert.deepEqual(
    parseCaa({
      status: 0,
      answers: [
        { type: 257, data: '0 issue "letsencrypt.org"' },
        { type: 257, data: generic("issue", "pki.goog; cansignhttpexchanges=yes") },
        { type: 257, data: generic("issuewild", ";") },
        { type: 257, data: '0 iodef "mailto:security@example.com"' },
        { type: 5, data: "other.example." },
      ],
    }),
    { issue: ["letsencrypt.org", "pki.goog"], issuewild: [""] },
  );
});

test("issuers are named by their organisation and matched to their CAA identifiers", () => {
  assert.equal(issuerName("C=US, O=Let's Encrypt, CN=R11"), "Let's Encrypt");
  assert.equal(issuerName('C=US, O="Cloudflare, Inc.", CN=Cloudflare Inc ECC CA-3'), "Cloudflare, Inc.");
  assert.equal(issuerName("CN=Only A Name"), "Only A Name");
  assert.deepEqual(caaOfIssuer("Let's Encrypt"), ["letsencrypt.org"]);
  assert.ok(caaOfIssuer("Cloudflare, Inc.")?.includes("digicert.com"), "Cloudflare's certificates come from DigiCert");
  assert.equal(caaOfIssuer("Some Private CA"), null);
});

test("certificates from the logs keep one entry per serial and only the domain's own names", () => {
  const entry = (id: number, serial: string, names: string) => ({
    id,
    issuer_name: "C=US, O=Let's Encrypt, CN=R11",
    name_value: names,
    serial_number: serial,
    not_before: "2026-05-30T10:00:00",
    not_after: "2026-08-28T10:00:00",
    entry_timestamp: "2026-05-30T10:05:00.123",
  });
  const certs = certificatesOf(
    [entry(1, "aa", "example.com\nwww.example.com"), entry(2, "aa", "www.example.com"), entry(3, "bb", "other.example\napi.example.com")],
    "example.com",
  );
  assert.equal(certs.length, 2, "the precertificate and the certificate are one");
  assert.deepEqual(certs[1].names, ["api.example.com"], "a name under another company's domain is dropped");
  assert.equal(certs[0].notBefore, "2026-05-30T10:00:00Z", "crt.sh's times are UTC");
});

test("a registrable name is guessed without a public suffix list", () => {
  assert.equal(registrable("a.b.example.com"), "example.com");
  assert.equal(registrable("shop.example.co.uk"), "example.co.uk");
  assert.equal(registrable("example.io"), "example.io");
  assert.equal(registrable("WWW.Example.COM."), "example.com");
  assert.ok(sharedPlatformName("mock-web.vercel.app") && sharedPlatformName("org.github.io"), "platforms' shared domains aren't the entity's");
  assert.ok(!sharedPlatformName("app.example.com"));
});

test("validation, DKIM and service records aren't hostnames", () => {
  for (const name of ["_abc123.example.com", "selector1._domainkey.example.com", "_sip._tls.example.com"]) assert.ok(serviceName(name), name);
  assert.ok(!serviceName("www.example.com"));
});

test("load balancer host conditions match with AWS's wildcards, and a hostname takes the rules that can match it", () => {
  assert.ok(hostMatches("*.example.com", "api.example.com"));
  assert.ok(hostMatches("API.example.com", "api.example.com"), "host conditions ignore case");
  assert.ok(hostMatches("api-?.example.com", "api-1.example.com"));
  assert.ok(!hostMatches("*.example.com", "example.org"));
  const l = {
    port: 443,
    protocol: "HTTPS",
    routes: [
      route({ rule: "1", hosts: ["admin.example.com"] }),
      route({ rule: "2", hosts: ["*.example.com"], paths: ["/api/*"] }),
      route({ rule: "3", hosts: ["*.example.com"] }),
      route({ rule: "4" }),
      route(),
    ],
  };
  assert.deepEqual(
    routesFor(l, "www.example.com").map((r) => r.rule),
    ["2", "3"],
    "a path rule may take some requests; the first rule without other conditions takes the rest",
  );
  assert.deepEqual(
    routesFor(l, "other.org").map((r) => r.rule),
    ["4"],
  );
});

test("a bypassable target is high, and critical when the rule it serves signs visitors in", () => {
  const behind = (authenticates: boolean) =>
    judge(
      internetInventory({
        loadBalancers: [
          loadBalancer({ listeners: [{ port: 443, protocol: "HTTPS", routes: [route({ authenticates, targets: [target({ openOnPort: true })] })] }] }),
        ],
      }),
    ).findings.find((f) => f.checkId === "XP-013" && !f.pass);
  assert.equal(behind(false)?.severity, "high");
  assert.equal(behind(true)?.severity, "critical");
  const internal = judge(
    internetInventory({
      loadBalancers: [
        loadBalancer({ internetFacing: false, listeners: [{ port: 443, protocol: "HTTPS", routes: [route({ targets: [target({ openOnPort: true })] })] }] }),
      ],
    }),
  ).findings.filter((f) => f.checkId === "XP-013");
  assert.deepEqual(internal, [], "an internal load balancer adds nothing a direct request skips");
});

test("Amass's names are read with their IPv4 addresses", () => {
  const out = parseSubs("www.example.com 192.0.2.1,192.0.2.2\nmail.example.com\nnot a name\n");
  assert.deepEqual(out.get("www.example.com"), ["192.0.2.1", "192.0.2.2"]);
  assert.deepEqual(out.get("mail.example.com"), []);
  assert.equal(out.size, 2);
});

test("a hostname that CNAMEs to another of the entity's hostnames reaches what that one reaches", () => {
  const lbName = loadBalancer().dnsName;
  const cname = (name: string, target: string, proxied = false) => ({ host: name, zone: "example.com", type: "CNAME", target, proxied });
  const hosts = [
    host({ name: "app.example.com", records: [cname("app.example.com", "app-origin.example.com", true)], servedBy: "Cloudflare (proxied)" }),
    host({ name: "app-origin.example.com", records: [cname("app-origin.example.com", lbName)], servedBy: "AWS load balancer", loadBalancer: lbName }),
    host({ name: "loop-a.example.com", records: [cname("loop-a.example.com", "loop-b.example.com")], servedBy: "CNAME to example.com" }),
    host({ name: "loop-b.example.com", records: [cname("loop-b.example.com", "loop-a.example.com")], servedBy: "CNAME to example.com" }),
  ];
  followChains(hosts);
  assert.equal(hosts[0].loadBalancer, lbName);
  assert.equal(hosts[0].servedBy, "Cloudflare (proxied)", "a proxied hostname is still served by Cloudflare");
  assert.equal(hosts[2].loadBalancer, null, "a loop ends");
});

test("a routed hostname isn't judged behind CloudFront, and one on another load balancer says which", () => {
  const routed = (h: ReturnType<typeof host>, others: ReturnType<typeof loadBalancer>[] = []) =>
    judge(
      internetInventory({
        hosts: [host({ name: "www.example.com", loadBalancer: loadBalancer().dnsName }), h],
        loadBalancers: [
          loadBalancer({ listeners: [{ port: 443, protocol: "HTTPS", routes: [route({ rule: "1", hosts: ["shop.example.com"] }), route()] }] }),
          ...others,
        ],
      }),
    ).findings.filter((f) => f.checkId === "XP-015" && f.resource === "shop.example.com");
  const viaCloudFront = host({
    name: "shop.example.com",
    records: [{ host: "shop.example.com", zone: "example.com", type: "CNAME", target: "d111111abcdef8.cloudfront.net", proxied: false }],
    servedBy: "AWS",
  });
  assert.deepEqual(routed(viaCloudFront), [], "CloudFront may forward it to the load balancer");
  const other = loadBalancer({ name: "new-web", dnsName: "new-web-1.eu-west-1.elb.amazonaws.com" });
  const [moved] = routed(host({ name: "shop.example.com", loadBalancer: other.dnsName, servedBy: "AWS load balancer" }), [other]);
  assert.equal(moved.pass, false);
  assert.match(moved.detail, /another load balancer, new-web/);
});

test("a network load balancer in front of an application one: the hostname reaches the application one's rules and targets", () => {
  const alb = loadBalancer({
    name: "app",
    dnsName: "app-1.eu-west-1.elb.amazonaws.com",
    listeners: [
      {
        port: 443,
        protocol: "HTTPS",
        routes: [
          route({ rule: "1", hosts: ["www.example.com"], authenticates: true, targets: [target({ openOnPort: true })] }),
          route({ action: "fixed-response", detail: "404", targets: [] }),
        ],
      },
    ],
  });
  const nlb = loadBalancer({
    name: "edge",
    type: "network",
    dnsName: "edge-0123.elb.eu-west-1.amazonaws.com",
    listeners: [
      { port: 443, protocol: "TCP", routes: [route({ targets: [target({ kind: "alb", id: "app", name: null, publicIp: null, openOnPort: null })] })] },
    ],
  });
  const ev = judge(internetInventory({ hosts: [host({ loadBalancer: nlb.dnsName })], loadBalancers: [nlb, alb] }));
  const failed = ev.findings.filter((f) => !f.pass).map((f) => `${f.checkId} ${f.severity}`);
  assert.ok(failed.includes("XP-013 critical"), `the application load balancer's target is judged: ${failed.join(", ")}`);
  assert.ok(!failed.some((f) => f.startsWith("XP-015")), "the rule's hostname does reach it, through the network load balancer");
});
