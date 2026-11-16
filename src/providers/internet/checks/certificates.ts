// Certificate transparency: every public certificate is logged, so a certificate for
// the entity's names from a certificate authority its CAA records don't allow is
// visible within minutes. Recent ones only: CAA is checked when a certificate is
// issued, and Keelson can't see what the CAA records said before today.

import { defineChecks } from "./define.ts";
import type { Caa, CtCertificate } from "../types.ts";

/** Certificates issued in this many days are judged against today's CAA records. */
const RECENT_DAYS = 30;

/** Whether today's CAA lets the issuer issue for every name on the certificate; null when it can't be told. */
export function caaAllows(caa: Caa, cert: CtCertificate): boolean | null {
  if (!cert.caa) return null;
  const allowed = (wild: boolean) => (wild && caa.issuewild.length ? caa.issuewild : caa.issue);
  for (const name of cert.names) {
    const list = allowed(name.startsWith("*."));
    // No CAA for this kind of name: any authority may issue.
    if (!list.length) continue;
    if (!list.some((id) => id && cert.caa!.includes(id))) return false;
  }
  return true;
}

export default defineChecks(
  {
    "NCT-001": {
      category: "TLS & HTTPS",
      severity: "medium",
      docs: "https://developers.cloudflare.com/ssl/edge-certificates/caa-records/",
      requires: ["certificates", "dns"],
      title: "Certificate issued by an authority the domain's CAA records don't allow",
      why: "CAA records name the only certificate authorities that may issue for a domain. A recent certificate from another one means the records changed, an authority ignored them, or someone got a certificate for your name who shouldn't have, and could use it to impersonate the site.",
      fix: "1. Open the certificate in the logs and find who requested it. 2. If it's yours, add its authority to the domain's CAA records. 3. If it isn't, ask the authority to revoke it and find how the name was validated (a dangling record, a compromised account, a hijacked email).",
    },
  },
  ({ inv }, report) => {
    const since = Date.parse(inv.now) - RECENT_DAYS * 86_400_000;
    for (const d of inv.domains) {
      if (!d.certificates || !d.caa) continue;
      if (!d.caa.issue.length && !d.caa.issuewild.length) continue;
      let failed = false;
      for (const c of d.certificates) {
        if (Date.parse(c.notBefore) < since || caaAllows(d.caa, c) !== false) continue;
        failed = true;
        report("NCT-001", {
          zone: d.name,
          resource: c.names[0],
          pass: false,
          detail: `${c.issuer}, issued ${c.notBefore.slice(0, 10)}; CAA allows ${[...new Set([...d.caa.issue, ...d.caa.issuewild])].map((x) => x || "no one").join(", ")}`,
          confidence: "likely",
          evidence: {
            chain: [
              { label: "Certificate transparency log", value: `${c.names.slice(0, 5).join(", ")} by ${c.issuer} on ${c.notBefore.slice(0, 10)}` },
              {
                label: `CAA on ${d.name}`,
                value: [...d.caa.issue.map((x) => `issue ${x || ";"}`), ...d.caa.issuewild.map((x) => `issuewild ${x || ";"}`)].join(", "),
              },
            ],
          },
          link: `https://crt.sh/?id=${c.id}`,
        });
      }
      if (!failed) report("NCT-001", { zone: d.name, resource: d.name, pass: true });
    }
  },
);
