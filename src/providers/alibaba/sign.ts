// Alibaba Cloud's request signatures, with node:crypto and nothing else: V3
// (ACS3-HMAC-SHA256) for the RPC and ROA APIs, and OSS's own V4
// (OSS4-HMAC-SHA256) for buckets. Keelson only sends GET, so the payload is always
// empty. test/alibaba.test.ts checks both against the examples Alibaba Cloud
// publishes in its signature documentation.

import { createHash, createHmac, randomUUID } from "node:crypto";

export interface AlibabaCredentials {
  accessKeyId: string;
  accessKeySecret: string;
}

const sha256 = (data: string) => createHash("sha256").update(data).digest("hex");
const hmac = (key: string | Buffer, data: string) => createHmac("sha256", key).update(data).digest();
export const EMPTY_SHA256 = sha256("");

/** RFC 3986 encoding, as both signatures want it: everything but letters, digits and -_.~ is escaped; a space is %20. */
export const acsEncode = (s: string) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

/** The query string in canonical form (sorted by key, strictly encoded), which is also how it is sent. */
export const canonicalQuery = (query: Record<string, string>) =>
  Object.keys(query)
    .sort()
    .map((k) => `${acsEncode(k)}=${acsEncode(query[k])}`)
    .join("&");

/** "2026-11-17T08:00:00Z": V3's x-acs-date. */
const isoSeconds = (d: Date) => `${d.toISOString().slice(0, 19)}Z`;

export interface AcsRequest {
  /** GET for everything Keelson sends; tests sign Alibaba Cloud's published example, which is a POST with an empty body. */
  method?: string;
  host: string;
  /** "/" for RPC APIs; the resource path for ROA APIs, already percent-encoded. */
  path: string;
  query: Record<string, string>;
  /** The API's action name and version (x-acs-action, x-acs-version). */
  action: string;
  version: string;
  now?: Date;
  nonce?: string;
}

/**
 * The headers for a V3-signed GET: Host, the x-acs-* headers and Authorization. Every x-acs- header and Host is
 * signed; the payload is empty.
 */
export function signAcs3(creds: AlibabaCredentials, req: AcsRequest): Record<string, string> {
  const headers: Record<string, string> = {
    host: req.host,
    "x-acs-action": req.action,
    "x-acs-content-sha256": EMPTY_SHA256,
    "x-acs-date": isoSeconds(req.now ?? new Date()),
    "x-acs-signature-nonce": req.nonce ?? randomUUID(),
    "x-acs-version": req.version,
  };
  const names = Object.keys(headers).sort();
  const canonical = [
    req.method ?? "GET",
    req.path,
    canonicalQuery(req.query),
    names.map((n) => `${n}:${headers[n].trim()}\n`).join(""),
    names.join(";"),
    EMPTY_SHA256,
  ].join("\n");
  const signature = createHmac("sha256", creds.accessKeySecret)
    .update(`ACS3-HMAC-SHA256\n${sha256(canonical)}`)
    .digest("hex");
  return { ...headers, authorization: `ACS3-HMAC-SHA256 Credential=${creds.accessKeyId},SignedHeaders=${names.join(";")},Signature=${signature}` };
}

export interface OssRequest {
  /** GET for everything Keelson sends; tests sign Alibaba Cloud's published examples with other methods. */
  method?: string;
  /** The bucket the request is for; none for ListBuckets. */
  bucket: string | null;
  /** The object key after the bucket, or "" for a bucket's own subresources. */
  key?: string;
  /** Query parameters, unencoded. A subresource such as `?acl` is a key with an empty value. */
  query: Record<string, string>;
  /** Headers besides x-oss-date and x-oss-content-sha256. x-oss-*, Content-Type and Content-MD5 are always signed. */
  headers?: Record<string, string>;
  /** Other headers to sign, named in AdditionalHeaders. */
  additionalHeaders?: string[];
  /** The region in the signing scope, without "oss-": "cn-hangzhou". */
  region: string;
  now?: Date;
}

/** OSS's canonical query: encoded, then sorted, and a parameter without a value is its key alone ("acl", not "acl="). */
export const ossQuery = (query: Record<string, string>) =>
  Object.entries(query)
    .map(([k, v]) => [acsEncode(k), v === "" ? null : acsEncode(v)] as const)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => (v == null ? k : `${k}=${v}`))
    .join("&");

const SIGNED_BY_DEFAULT = (name: string) => name.startsWith("x-oss-") || name === "content-type" || name === "content-md5";

/** The headers for an OSS V4-signed request: Date, x-oss-date, x-oss-content-sha256 and Authorization. */
export function signOss4(creds: AlibabaCredentials, req: OssRequest): Record<string, string> {
  const now = req.now ?? new Date();
  const stamp = now
    .toISOString()
    .replace(/[-:]/g, "")
    .replace(/\.\d{3}/, "");
  const day = stamp.slice(0, 8);
  const headers: Record<string, string> = { ...req.headers, "x-oss-content-sha256": "UNSIGNED-PAYLOAD", "x-oss-date": stamp };
  const lower = new Map(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  const additional = [...new Set((req.additionalHeaders ?? []).map((h) => h.toLowerCase()))].filter((h) => lower.has(h) && !SIGNED_BY_DEFAULT(h)).sort();
  const signed = [...lower.keys()].filter((h) => SIGNED_BY_DEFAULT(h) || additional.includes(h)).sort();
  // The canonical URI names the bucket even when the bucket is in the host name.
  const uri = req.bucket ? `/${req.bucket}/${(req.key ?? "").split("/").map(acsEncode).join("/")}` : "/";
  const canonical = [
    req.method ?? "GET",
    uri,
    ossQuery(req.query),
    signed.map((n) => `${n}:${lower.get(n)!.trim()}\n`).join(""),
    additional.join(";"),
    "UNSIGNED-PAYLOAD",
  ].join("\n");
  const scope = `${day}/${req.region}/oss/aliyun_v4_request`;
  const toSign = ["OSS4-HMAC-SHA256", stamp, scope, sha256(canonical)].join("\n");
  const key = hmac(hmac(hmac(hmac(`aliyun_v4${creds.accessKeySecret}`, day), req.region), "oss"), "aliyun_v4_request");
  const signature = createHmac("sha256", key).update(toSign).digest("hex");
  return {
    date: now.toUTCString(),
    "x-oss-content-sha256": "UNSIGNED-PAYLOAD",
    "x-oss-date": stamp,
    authorization: `OSS4-HMAC-SHA256 Credential=${creds.accessKeyId}/${scope}${additional.length ? `,AdditionalHeaders=${additional.join(";")}` : ""},Signature=${signature}`,
  };
}
