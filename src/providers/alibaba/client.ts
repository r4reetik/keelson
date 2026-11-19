// Read-only Alibaba Cloud client. Every request is a signed GET: the RPC APIs (RAM,
// ECS, VPC, the load balancers, RDS, KMS…) take their action and parameters in the
// query string, the ROA APIs (Container Service, Function Compute) are read with
// GET by design, and OSS is read with GET on a bucket's subresources. Alibaba
// Cloud's RPC APIs answer GET for writes too, so GET alone proves nothing: rpc()
// and roa() send only actions whose name starts with Describe, List or Get and
// that the policy in src/shared/alibaba.ts names, and test/alibaba.test.ts fails on
// any other. Every call is recorded under a coverage label, like the other
// providers' clients.
//
// Limits: at most 8 requests in flight. Throttling answers and 5xx are retried
// with a growing pause; network errors are retried twice.

import { ALIBABA_SOURCES, type AlibabaSourceKey } from "./sources.ts";
import { acsEncode, canonicalQuery, ossQuery, signAcs3, signOss4, type AlibabaCredentials } from "./sign.ts";
import { find, parseXml, text, type XmlNode } from "../../core/xml.ts";
import { ALIBABA_POLICY_ACTIONS } from "../../shared/alibaba.ts";
import { CREDENTIAL_SEPARATOR } from "../../shared/providers.ts";
import type { Coverage } from "../../shared/api.ts";

const MAX_IN_FLIGHT = 8;
/** The first pause before a retry, doubled each time. Tests set it to 0. */
export const retry = { pauseMs: 500 };
const TIMEOUT_MS = 30_000;
/** A raw JSON payload; inventory.ts turns it into the typed shapes in types.ts. */
export type Json = any;

interface Product {
  version: string;
  /** Takes the region as a RegionId parameter, so its central endpoint can answer for any region. */
  regionParam?: boolean;
  /** The product's code in RAM actions, when it differs from its own ("yundun-sas" for Security Center). */
  ram?: string;
  /** One endpoint for every region. */
  global?: string;
  /** The endpoint's first label, when it isn't the product's code ("r-kvstore" for Tair and Redis, "mongodb"). */
  host?: string;
}

/** Each API Keelson reads: its version, and its endpoint when it isn't `<product>.<region>.aliyuncs.com`. */
export const PRODUCTS: Record<string, Product> = {
  sts: { version: "2015-04-01", global: "sts.aliyuncs.com" },
  ram: { version: "2015-05-01", global: "ram.aliyuncs.com" },
  ims: { version: "2019-08-15", ram: "ram", global: "ims.aliyuncs.com" },
  ecs: { regionParam: true, version: "2014-05-26" },
  vpc: { regionParam: true, version: "2016-04-28" },
  slb: { regionParam: true, version: "2014-05-15" },
  alb: { version: "2020-06-16" },
  nlb: { version: "2022-04-30" },
  rds: { regionParam: true, version: "2014-08-15" },
  kvstore: { regionParam: true, version: "2015-01-01", host: "r-kvstore" },
  dds: { regionParam: true, version: "2015-12-01", host: "mongodb" },
  kms: { version: "2016-01-20" },
  actiontrail: { version: "2020-07-06" },
  cs: { version: "2015-12-15" },
  fc: { version: "2023-03-30" },
  cr: { version: "2018-12-01" },
  eci: { regionParam: true, version: "2018-08-08" },
  // Security Center answers in two places: Shanghai for accounts on the China site, Singapore for the international one.
  sas: { version: "2018-12-03", ram: "yundun-sas", global: "tds.cn-shanghai.aliyuncs.com" },
  cdn: { version: "2018-05-10", global: "cdn.aliyuncs.com" },
  alidns: { version: "2015-01-09", global: "alidns.aliyuncs.com" },
};

/** The product an endpoint belongs to: "r-kvstore.cn-hangzhou.aliyuncs.com" is kvstore, tds is Security Center, fcv3 is Function Compute. */
export function productOfHost(host: string): string {
  const first = host.split(".")[0];
  if (first === "tds") return "sas";
  if (first === "fcv3") return "fc";
  return Object.entries(PRODUCTS).find(([, p]) => p.host === first)?.[0] ?? first;
}

/** What every read action's name starts with. */
export const READ_ACTION = /^(Describe|List|Get|BatchGet)[A-Z]/;
/** Actions that need no permission and so aren't in the policy. */
const UNGATED = new Set(["sts:GetCallerIdentity"]);
const ALLOWED = new Set(ALIBABA_POLICY_ACTIONS);

/** APIs whose RAM action has another name than the API itself. */
const RAM_NAME: Record<string, string> = { "cs:DescribeClustersV1": "cs:GetClusters", "cr:ListRepoTag": "cr:ListRepositoryTag" };

/** The RAM action an API call is, as the policy names it ("yundun-sas:DescribeCloudCenterInstances"). */
export const ramAction = (product: string, action: string) => {
  const name = `${PRODUCTS[product]?.ram ?? product}:${action}`;
  return RAM_NAME[name] ?? name;
};

/** Whether Keelson sends this action: a read, and named in its policy. */
export const isReadAction = (product: string, action: string) =>
  READ_ACTION.test(action) && (ALLOWED.has(ramAction(product, action)) || UNGATED.has(ramAction(product, action)));

const THROTTLED = /^(Throttling(\..+)?|ServiceUnavailable|Busy\w*|SlowDown|TooManyRequests|RequestLimitExceeded)$/i;
const DENIED =
  /^(Forbidden(\..+)?|NoPermission|NotAuthorized|AccessDenied|UnauthorizedOperation|InvalidAccessKeyId(\..+)?|SignatureDoesNotMatch|IncompleteSignature|InvalidSecurityToken(\..+)?)$/i;
/** A product the account never opened, or that isn't offered in the region: nothing to read, not a missing permission. */
const NOT_OPENED =
  /(NotOpen|Unopened|NotActivated|NotEnabled|NotSubscribed|ServiceNotFound|NotBuy|ServiceNotExist|UserDisable|RegionNotSupport)|^(UnsupportedRegion|InvalidRegion(Id)?(\.NotFound)?)$/i;
/**
 * The same, said only in the message. In local regions (cn-fuzhou, cn-nanjing, cn-wuhan-lr) the ALB and NLB endpoints
 * resolve to a shared gateway that answers 403 "The specified region of  is not authorized." for a product that isn't
 * offered there; a missing permission names the action or resource instead. Elastic Container Instance answers 400 "The
 * specified parameter RegionId:cn-fuzhou is not valid" in a region it isn't offered in (seen on a real account, 2026-11-19).
 */
const NOT_OFFERED =
  /specified region (of .*)?is not (authorized|supported)|not (supported|available) in (this|the specified) region|specified parameter RegionId:\s*[a-z0-9-]+ is not valid/i;

export class AlibabaError extends Error {
  status: number;
  code: string;
  /** The endpoint that answered, so a coverage gap says which region and product failed. */
  host?: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
  /** The thing asked for isn't set up: no policy, no login profile. */
  get notFound(): boolean {
    return this.status === 404 || /NotFound|NoSuch|NotExist|EntityNotExist/i.test(this.code);
  }
  /** The product has no endpoint in this region, or the account never opened it: there is nothing to read. */
  get noEndpoint(): boolean {
    return this.code === "NoEndpoint" || NOT_OPENED.test(this.code) || NOT_OFFERED.test(this.message);
  }
  /** The AccessKey isn't allowed to read it, or isn't valid. */
  get denied(): boolean {
    return this.status === 401 || this.status === 403 || DENIED.test(this.code);
  }
}

/**
 * The AccessKey as the vault stores it: "<AccessKey ID>:<AccessKey secret>". Null when it isn't a long-lived
 * pair; STS tokens (STS.…) need a security token and expire within hours.
 */
export function parseCredentials(token: string): AlibabaCredentials | null {
  const at = token.indexOf(CREDENTIAL_SEPARATOR);
  if (at < 0) return null;
  const accessKeyId = token.slice(0, at).trim();
  const accessKeySecret = token.slice(at + 1).trim();
  return /^LTAI[A-Za-z0-9]{12,30}$/.test(accessKeyId) && /^[A-Za-z0-9]{20,64}$/.test(accessKeySecret) ? { accessKeyId, accessKeySecret } : null;
}

export class AlibabaClient {
  calls = 0;
  readonly coverage = new Map<AlibabaSourceKey, Coverage & { key: AlibabaSourceKey }>();
  /** The account's UID. */
  accountId: string;
  readonly #creds: AlibabaCredentials;
  #inFlight = 0;
  #queue: (() => void)[] = [];
  /** Products whose regional endpoint doesn't resolve, so the central one is used with RegionId. */
  readonly #central = new Set<string>();

  constructor(creds: AlibabaCredentials, accountId = "") {
    this.#creds = creds;
    this.accountId = accountId;
  }

  /**
   * An RPC API action: GET, its parameters in the query string. `region` null uses the product's global endpoint, or
   * `host` when given. Refuses any action that isn't a read named in Keelson's policy.
   */
  async rpc(product: string, region: string | null, action: string, params: Record<string, string> = {}, host?: string): Promise<Json> {
    const p = PRODUCTS[product];
    if (!p || !isReadAction(product, action)) throw new Error(`${ramAction(product, action)} isn't a read action Keelson sends`);
    const query = region && p.regionParam ? { RegionId: region, ...params } : params;
    const send = (host: string) =>
      this.#send(host, {
        path: "/",
        query,
        sign: (now) => signAcs3(this.#creds, { host, path: "/", query, action, version: p.version, now }),
      });
    const body = host ? await send(host) : await this.#regional(product, region, send);
    return body ? JSON.parse(body) : null;
  }

  /** An ROA API's GET: Container Service, Function Compute. The action is named for the signature and the policy. */
  async roa(product: string, region: string, action: string, path: string, query: Record<string, string> = {}): Promise<Json> {
    const p = PRODUCTS[product];
    if (!p || !isReadAction(product, action)) throw new Error(`${ramAction(product, action)} isn't a read action Keelson sends`);
    const encoded = path.split("/").map(acsEncode).join("/");
    // Function Compute 3.0 answers at fcv3.<region>.
    const host = product === "fc" ? `fcv3.${region}.aliyuncs.com` : `${product}.${region}.aliyuncs.com`;
    const body = await this.#send(host, {
      path: encoded,
      query,
      sign: (now) => signAcs3(this.#creds, { host, path: encoded, query, action, version: p.version, now }),
    });
    return body ? JSON.parse(body) : null;
  }

  /**
   * An OSS GET: ListBuckets when `bucket` is null, else a bucket's subresource (`{ acl: "" }`). Returns the parsed
   * XML, or the raw text for subresources that answer JSON (a bucket policy).
   */
  async oss(bucket: { name: string; region: string } | null, query: Record<string, string>): Promise<XmlNode>;
  async oss(bucket: { name: string; region: string } | null, query: Record<string, string>, raw: true): Promise<string>;
  async oss(bucket: { name: string; region: string } | null, query: Record<string, string>, raw?: true): Promise<XmlNode | string> {
    const region = bucket?.region ?? "cn-hangzhou";
    const host = bucket ? `${bucket.name}.oss-${region}.aliyuncs.com` : `oss-${region}.aliyuncs.com`;
    const qs = ossQuery(query);
    const body = await this.#send(host, {
      path: "/",
      query,
      queryString: qs,
      sign: (now) => signOss4(this.#creds, { bucket: bucket?.name ?? null, query, region, now }),
    });
    return raw ? body : parseXml(body);
  }

  /** Runs a read; null when the thing isn't set up (404, NoSuch…). Other errors are thrown. */
  async optional<T>(fn: () => Promise<T>): Promise<T | null> {
    try {
      return await fn();
    } catch (e) {
      if (e instanceof AlibabaError && e.notFound) return null;
      throw e;
    }
  }

  /** Runs a read with coverage: null when the AccessKey can't read it. */
  async read<T>(source: AlibabaSourceKey, fn: () => Promise<T>): Promise<T | null> {
    try {
      const out = await fn();
      this.note(source, true);
      return out;
    } catch (e) {
      this.note(source, false, e);
      return null;
    }
  }

  /** Like read(), but a product with no endpoint in the region, or one the account never opened, gives `empty` and isn't a gap. */
  async readIn<T>(source: AlibabaSourceKey, empty: T, fn: () => Promise<T>): Promise<T | null> {
    try {
      const out = await fn();
      this.note(source, true);
      return out;
    } catch (e) {
      if (e instanceof AlibabaError && e.noEndpoint) return empty;
      this.note(source, false, e);
      return null;
    }
  }

  /** Like read(), but "not set up" is null and unreadable is undefined, and only the latter is a coverage gap. */
  async readOptional<T>(source: AlibabaSourceKey, fn: () => Promise<T>): Promise<T | null | undefined> {
    try {
      const out = await this.optional(fn);
      this.note(source, true);
      return out;
    } catch (e) {
      this.note(source, false, e);
      return undefined;
    }
  }

  /** Records whether a source was readable. The first failure sticks, as in the other clients. */
  note(source: AlibabaSourceKey, ok: boolean, err?: unknown): void {
    const prev = this.coverage.get(source);
    if (prev && !prev.ok) return;
    const { label, permission } = ALIBABA_SOURCES[source];
    this.coverage.set(
      source,
      ok
        ? { key: source, label, permission, ok: true }
        : {
            key: source,
            label,
            permission,
            ok: false,
            status: (err as AlibabaError)?.status || 0,
            message: `${(err as AlibabaError)?.host ? `${(err as AlibabaError).host}: ` : ""}${String((err as Error)?.message || err)}`.slice(0, 240),
          },
    );
  }

  /** A regional product's endpoint, falling back to its central one (with RegionId) where the regional one doesn't resolve. */
  async #regional(product: string, region: string | null, send: (host: string) => Promise<string>): Promise<string> {
    const p = PRODUCTS[product];
    if (p.global) return send(p.global);
    const prefix = p.host ?? product;
    if (!region) return send(`${prefix}.aliyuncs.com`);
    const key = `${product}/${region}`;
    // Products addressed only by endpoint can't fall back to a central one.
    if (!p.regionParam) return send(`${prefix}.${region}.aliyuncs.com`);
    if (this.#central.has(key)) return send(`${prefix}.aliyuncs.com`);
    try {
      return await send(`${prefix}.${region}.aliyuncs.com`);
    } catch (e) {
      if (!(e instanceof AlibabaError) || e.code !== "NoEndpoint") throw e;
      this.#central.add(key);
      return send(`${prefix}.aliyuncs.com`);
    }
  }

  /** Sends one signed GET and returns the body. Throws AlibabaError. */
  async #send(
    host: string,
    req: { path: string; query: Record<string, string>; queryString?: string; sign: (now: Date) => Record<string, string> },
  ): Promise<string> {
    await this.#acquire();
    try {
      for (let attempt = 0; ; attempt++) {
        this.calls++;
        const qs = req.queryString ?? canonicalQuery(req.query);
        let res: Response;
        try {
          const { host: _host, ...headers } = req.sign(new Date());
          res = await fetch(`https://${host}${req.path}${qs ? `?${qs}` : ""}`, { method: "GET", signal: AbortSignal.timeout(TIMEOUT_MS), headers });
        } catch (e) {
          // A host that doesn't resolve is a product Alibaba Cloud doesn't offer at that endpoint.
          const cause = (e as { cause?: { code?: string } }).cause?.code;
          if (cause === "ENOTFOUND") throw Object.assign(new AlibabaError(0, "NoEndpoint", `${host} doesn't exist`), { host });
          if (attempt < 2) {
            await sleep(retry.pauseMs * 2 * (attempt + 1));
            continue;
          }
          throw Object.assign(new AlibabaError(0, "NetworkError", `Network error: ${(e as Error).message}`), { host });
        }
        const body = await res.text();
        if (res.ok) return body;
        const err = errorOf(res, body);
        err.host = host;
        if ((THROTTLED.test(err.code) || res.status === 429 || res.status >= 500) && attempt < 4) {
          await sleep(retry.pauseMs * 2 ** attempt);
          continue;
        }
        throw err;
      }
    } finally {
      this.#release();
    }
  }

  async #acquire(): Promise<void> {
    while (this.#inFlight >= MAX_IN_FLIGHT) await new Promise<void>((r) => this.#queue.push(r));
    this.#inFlight++;
  }

  #release(): void {
    this.#inFlight--;
    this.#queue.shift()?.();
  }
}

/** Errors come as JSON (Code, Message; ROA APIs lowercase) or, from OSS, as XML. */
function errorOf(res: Response, body: string): AlibabaError {
  let code = "";
  let message = "";
  try {
    if (body.trimStart().startsWith("<")) {
      const doc = parseXml(body);
      const err = find(doc, "Error") ?? doc;
      code = text(err, "Code") ?? "";
      message = text(err, "Message") ?? "";
    } else if (body) {
      const j = JSON.parse(body);
      code = String(j.Code ?? j.code ?? j.ErrorCode ?? "");
      message = String(j.Message ?? j.message ?? j.ErrorMessage ?? "");
    }
  } catch {
    /* an unparseable error body: fall back to the status */
  }
  return new AlibabaError(res.status, code || String(res.status), message || code || res.statusText || "Request failed");
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, Math.max(0, ms)));
