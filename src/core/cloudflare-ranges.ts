// Cloudflare's published address ranges (cloudflare.com/ips), which proxied traffic
// comes from. An AWS scan uses them to tell an origin whose security group admits
// only Cloudflare from one that admits anyone, so Cloudflare's origin-exposure
// check can rate an exposed address by whether it can really be reached. The list
// changes rarely; a range Cloudflare adds later only makes a group look less locked
// than it is, never more.

export const CLOUDFLARE_RANGES = [
  "173.245.48.0/20",
  "103.21.244.0/22",
  "103.22.200.0/22",
  "103.31.4.0/22",
  "141.101.64.0/18",
  "108.162.192.0/18",
  "190.93.240.0/20",
  "188.114.96.0/20",
  "197.234.240.0/22",
  "198.41.128.0/17",
  "162.158.0.0/15",
  "104.16.0.0/13",
  "104.24.0.0/14",
  "172.64.0.0/13",
  "131.0.72.0/22",
  "2400:cb00::/32",
  "2606:4700::/32",
  "2803:f800::/32",
  "2405:b500::/32",
  "2405:8100::/32",
  "2a06:98c0::/29",
  "2c0f:f248::/32",
];

// Addresses that can't come from the internet: private, shared, loopback and link-local ranges.
const INTERNAL_RANGES = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128"];

type Range = { v6: boolean; start: bigint; end: bigint };

function ipToBig(ip: string): { v6: boolean; n: bigint } | null {
  if (ip.includes(":")) {
    const [head, tail, ...rest] = ip.toLowerCase().split("::");
    if (rest.length) return null;
    const parse = (s: string | undefined) => (s ? s.split(":") : []);
    const a = parse(head),
      b = parse(tail);
    const groups = tail === undefined ? a : [...a, ...Array(8 - a.length - b.length).fill("0"), ...b];
    if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null;
    return { v6: true, n: groups.reduce((n, g) => (n << 16n) | BigInt(Number.parseInt(g, 16)), 0n) };
  }
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m || m.slice(1).some((p) => Number(p) > 255)) return null;
  return { v6: false, n: m.slice(1).reduce((n, p) => (n << 8n) | BigInt(p), 0n) };
}

function toRange(cidr: string): Range | null {
  const [ip, bits] = cidr.trim().split("/");
  const addr = ipToBig(ip ?? "");
  if (!addr) return null;
  const width = addr.v6 ? 128 : 32;
  const len = bits === undefined ? width : Number(bits);
  if (!Number.isInteger(len) || len < 0 || len > width) return null;
  const size = 1n << BigInt(width - len);
  const start = (addr.n / size) * size;
  return { v6: addr.v6, start, end: start + size - 1n };
}

const ranges = (cidrs: string[]) => cidrs.flatMap((c) => toRange(c) ?? []);
const CLOUDFLARE = ranges(CLOUDFLARE_RANGES);
const INTERNAL = ranges(INTERNAL_RANGES);

const within = (cidr: string, list: Range[]) => {
  const r = toRange(cidr);
  return !!r && list.some((x) => x.v6 === r.v6 && x.start <= r.start && r.end <= x.end);
};

/** Whether every address in a CIDR is one of Cloudflare's. */
export const inCloudflare = (cidr: string): boolean => within(cidr, CLOUDFLARE);

/** Whether every address in a CIDR is private or otherwise unreachable from the internet. */
export const isInternal = (cidr: string): boolean => within(cidr, INTERNAL);
