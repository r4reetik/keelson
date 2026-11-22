// A certificate authority made when it is asked for, and a certificate it signs:
// what a network that inspects TLS presents. The mock dev server's networks
// trust one, and the network tests serve HTTPS with one. Nothing here is a real
// organization's certificate, and no key is kept in the repository.

import { createHash, createSign, generateKeyPairSync, type KeyObject } from "node:crypto";
import { isIP } from "node:net";

// Written as DER by hand: node:crypto signs but doesn't issue certificates.

const der = (tag: number, ...parts: Buffer[]): Buffer => {
  const body = Buffer.concat(parts);
  const length = body.length < 128 ? [body.length] : body.length < 256 ? [0x81, body.length] : [0x82, body.length >> 8, body.length & 255];
  return Buffer.concat([Buffer.from([tag, ...length]), body]);
};
const seq = (...parts: Buffer[]) => der(0x30, ...parts);
const oid = (hex: string) => der(0x06, Buffer.from(hex, "hex"));
const int = (n: number) => der(0x02, Buffer.from([n]));
const time = (d: Date) => der(0x17, Buffer.from(`${d.toISOString().replace(/[-:T]/g, "").slice(2, 14)}Z`));
const name = (cn: string) => seq(der(0x31, seq(oid("550403"), der(0x0c, Buffer.from(cn)))));
const ECDSA_SHA256 = seq(oid("2a8648ce3d040302"));

function certificate(subject: string, issuer: string, key: KeyObject, signer: KeyObject, o: { ca: boolean; names?: string[]; notAfter?: Date }): string {
  const extensions = [
    // basicConstraints, critical
    seq(oid("551d13"), der(0x01, Buffer.from([0xff])), der(0x04, seq(...(o.ca ? [der(0x01, Buffer.from([0xff]))] : [])))),
    ...(o.names?.length
      ? [seq(oid("551d11"), der(0x04, seq(...o.names.map((n) => (isIP(n) ? der(0x87, Buffer.from(n.split(".").map(Number))) : der(0x82, Buffer.from(n)))))))]
      : []),
  ];
  const tbs = seq(
    der(0xa0, int(2)),
    // A serial number from the name: positive, and never zero.
    der(
      0x02,
      Buffer.from(
        createHash("sha256")
          .update(subject)
          .digest()
          .subarray(0, 8)
          .map((b, i) => (i ? b : b & 0x7f || 1)),
      ),
    ),
    ECDSA_SHA256,
    name(issuer),
    seq(time(new Date(Date.now() - 86_400_000)), time(o.notAfter ?? new Date(Date.now() + 365 * 86_400_000))),
    name(subject),
    key.export({ type: "spki", format: "der" }),
    der(0xa3, seq(...extensions)),
  );
  const signature = createSign("sha256").update(tbs).sign(signer);
  const body = seq(tbs, ECDSA_SHA256, der(0x03, Buffer.from([0]), signature)).toString("base64");
  return `-----BEGIN CERTIFICATE-----\n${body.match(/.{1,64}/g)!.join("\n")}\n-----END CERTIFICATE-----\n`;
}

/** An authority no machine trusts, as a network that inspects TLS has, and a certificate it signed for 127.0.0.1 and localhost. */
export function makeAuthority(cn = "Mock Inspection Root CA", o: { notAfter?: Date } = {}) {
  const pair = () => generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const ca = pair();
  const leaf = pair();
  return {
    ca: certificate(cn, cn, ca.publicKey, ca.privateKey, { ca: true, notAfter: o.notAfter }),
    cert: certificate("localhost", cn, leaf.publicKey, ca.privateKey, { ca: false, names: ["localhost", "127.0.0.1"] }),
    key: leaf.privateKey.export({ type: "pkcs8", format: "pem" }) as string,
  };
}
