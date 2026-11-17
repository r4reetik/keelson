// Where a finding's addresses and hostnames are in the entity's other accounts
// (src/server/locate.ts): followed through DNS to what holds them, released or
// outside the entity when nothing does, and a finding about a port checked against
// the holder's security groups. Fixtures are made-up names and documentation
// addresses (203.0.113.0/24, 198.51.100.0/24).

import { test } from "node:test";
import assert from "node:assert/strict";
import { locate, portsOf, type EntityScan, type LocateInput } from "../src/server/locate.ts";
import type { ScanSnapshot } from "../src/shared/api.ts";

const HELD = "203.0.113.10";
const OUTSIDER = "198.51.100.20";
const RELEASED = "203.0.113.99";

const cloudflare: EntityScan = {
  provider: "cloudflare",
  accountId: "cf1",
  account: "Example",
  snap: {
    links: {
      cloudflareDns: [
        { host: "rdp.example.com", zone: "example.com", type: "A", target: HELD, proxied: false },
        { host: "other.example.com", zone: "example.com", type: "A", target: OUTSIDER, proxied: false },
        { host: "old.example.com", zone: "example.com", type: "A", target: RELEASED, proxied: false },
        { host: "app.example.com", zone: "example.com", type: "CNAME", target: "nlb-1.ap-southeast-1.nlb.aliyuncsslbintl.com", proxied: false },
        { host: "mail.example.com", zone: "example.com", type: "CNAME", target: "mx.vendor.example", proxied: false },
        { host: "app.example.com", zone: "example.com", type: "AAAA", target: "100::", proxied: true },
      ],
    },
  },
};

const route53: EntityScan = {
  provider: "aws",
  accountId: "111122223333",
  account: "Example AWS",
  snap: {
    links: {
      awsAddresses: [],
      route53Dns: [{ host: "rdp.example.com", zone: "example.com", type: "A", target: HELD, proxied: false }],
    },
  },
};

const alibaba: EntityScan = {
  provider: "alibaba",
  accountId: "5000000000000001",
  account: "Example Alibaba",
  snap: {
    resources: {
      rows: [
        {
          kind: "ECS instance",
          group: "Compute",
          id: "i-win1",
          name: "win-1",
          region: "ap-southeast-1",
          exposure: `Public address ${HELD}`,
          facts: [],
          link: "https://ecs.console.alibabacloud.com/server/i-win1/detail",
          findings: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        },
      ],
      regions: [{ name: "ap-southeast-1", label: "Singapore", resources: 1 }],
      emptyRegions: 0,
      skippedRegions: [],
    } satisfies ScanSnapshot["resources"],
    links: {
      alibabaAddresses: [HELD],
      alibabaReleased: [{ ip: RELEASED, at: "2026-11-01T00:00:00.000Z" }],
      alibabaExposure: [
        {
          ip: HELD,
          account: "Example Alibaba",
          region: "ap-southeast-1",
          resource: "instance win-1 (i-win1)",
          open: [{ protocol: "tcp", from: 3389, to: 3389, groups: ["remote"] }],
        },
      ],
      alibabaLoadBalancers: [
        {
          provider: "alibaba",
          name: "app-nlb",
          dnsName: "nlb-1.ap-southeast-1.nlb.aliyuncsslbintl.com",
          account: "Example Alibaba",
          region: "ap-southeast-1",
          type: "network",
          internetFacing: true,
          web: null,
          waf: null,
          listeners: [{ port: 443, protocol: "TCP", routes: null }],
        },
      ],
    },
  },
};

const SCANS = [cloudflare, route53, alibaba];
const finding = (o: Partial<LocateInput>): LocateInput => ({
  accountId: "cf1",
  zone: "example.com",
  title: "Rdp server exposed",
  checkId: "SC:rdp_server_exposed",
  resource: "rdp.example.com",
  detail: `Points to ${HELD}.`,
  evidence: null,
  ...o,
});

test("a hostname is followed through DNS to the instance that holds its address, and the port is checked", () => {
  const { items } = locate(finding({}), SCANS);
  assert.equal(items.length, 1, "the address the hostname led to isn't repeated");
  const [item] = items;
  assert.equal(item.status, "found");
  assert.equal(item.summary, "Alibaba Cloud: ECS instance win-1 (i-win1) in Singapore");
  assert.equal(item.steps[0].label, "Cloudflare DNS and Route 53", "the same record in two DNS services is one step");
  assert.equal(item.steps.length, 2);
  assert.match(item.steps[1].value, /holds 203\.0\.113\.10/);
  assert.equal(item.steps[1].link, "https://ecs.console.alibabacloud.com/server/i-win1/detail");
  assert.deepEqual(
    item.ports.map((p) => [p.port, p.open]),
    [[3389, true]],
  );
  assert.match(item.ports[0].detail, /remote let anyone reach tcp 3389: this confirms the finding/);
});

test("a port no security group opens contradicts the finding", () => {
  const closed = {
    ...alibaba,
    snap: { ...alibaba.snap, links: { ...alibaba.snap.links, alibabaExposure: [{ ...alibaba.snap.links!.alibabaExposure![0], open: [] }] } },
  };
  const [item] = locate(finding({}), [cloudflare, closed]).items;
  assert.equal(item.ports[0].open, false);
});

test("an address no connected account holds is outside the entity, and one an account let go is released", () => {
  const outside = locate(finding({ resource: "other.example.com", detail: `Points to ${OUTSIDER}.` }), SCANS).items[0];
  assert.equal(outside.status, "outside");
  assert.match(outside.summary, /None of the entity's AWS and Alibaba Cloud accounts holds 198\.51\.100\.20/);
  const released = locate(finding({ resource: "old.example.com", detail: "" }), SCANS).items[0];
  assert.equal(released.status, "released");
  assert.match(released.steps[1].value, /released, around 2026-11-01/);
  const unknown = locate(finding({ resource: "x", detail: `Points to ${OUTSIDER}.` }), [cloudflare]).items;
  assert.deepEqual(unknown, [], "with no cloud listing its addresses, there is nothing to conclude");
});

test("a CNAME goes to the load balancer it names, and one to another company's service is outside", () => {
  const [app] = locate(finding({ resource: "app.example.com", title: "CNAME not proxied", checkId: "SC:cname_record_not_proxied", detail: "" }), SCANS).items;
  assert.equal(app.status, "found");
  assert.match(app.summary, /network load balancer app-nlb in Singapore/);
  assert.ok(!app.steps.some((s) => s.value.includes("100::")), "Cloudflare's placeholder AAAA leads nowhere");
  const [mail] = locate(finding({ resource: "mail.example.com", detail: "" }), SCANS).items;
  assert.equal(mail.status, "outside");
  assert.match(mail.summary, /mx\.vendor\.example isn't served by any of the entity's connected accounts/);
});

test("what isn't an address or host in the finding is left alone", () => {
  const items = locate(
    finding({
      accountId: "5000000000000001",
      zone: "example.com",
      resource: "sg-1",
      detail: "tcp 22 from 0.0.0.0/0, owned by ops@example.com, in example.com, 10.0.0.5",
    }),
    SCANS,
  ).items;
  assert.deepEqual(items, [], "0.0.0.0/0, a private address, an email's domain and the finding's own zone aren't looked up");
  const own = locate(finding({ accountId: "5000000000000001", resource: "i-win1", detail: `reachable at ${HELD}` }), SCANS).items;
  assert.deepEqual(own, [], "an address the finding's own account holds, it already names");
});

test("the ports a finding is about come from its title, check and detail", () => {
  assert.deepEqual(portsOf({ checkId: "SC:rdp_server_exposed", title: "Rdp server exposed", detail: "" }), [{ port: 3389, service: "RDP" }]);
  assert.deepEqual(portsOf({ checkId: "NSV-001", title: "Database open", detail: "MongoDB answers on port 27017" }), [{ port: 27017, service: "MongoDB" }]);
  assert.deepEqual(portsOf({ checkId: "TLS-001", title: "Old TLS", detail: "" }), []);
});
