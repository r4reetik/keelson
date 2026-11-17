// The reads of one region beyond its network, instances and databases: CloudTrail,
// Config, KMS, ACM, Secrets Manager, ECR, ECS, EKS, DynamoDB, Cognito, WAF, Systems
// Manager documents, CodeBuild, EventBridge, SageMaker, OpenSearch, ElastiCache,
// Redshift, SNS, SQS, MQ, MSK and EFS, plus EC2 launch templates, volumes, sharing
// blocks and transit gateways, and RDS snapshots and TLS parameters.
//
// Each source is read on its own: one the key can't read is a coverage gap for its
// checks only, and a service AWS doesn't offer in the region reads as empty. Lists
// that cost a request per item stop at MAX_ITEMS. Secrets never enter the
// inventory: policies are reduced to conclusions, environment variables and
// start-up scripts are scanned in memory and only the kind found is kept, and SNS
// endpoints keep only their host.

import type { AwsClient, Json } from "./client.ts";
import { secretInUserData } from "./inventory.ts";
import { allowsAnyone } from "./policy.ts";
import { HOME_REGION } from "./sources.ts";
import { at, bool, find, items, text, type XmlNode } from "../../core/xml.ts";
import { secretInVariables, secretKindIn } from "../../core/secret-patterns.ts";
import type { AwsDatabase, AwsKafka, AwsKey, AwsKubernetes, AwsRegion, AwsSearchDomain, AwsTaskDefinition, AwsTrail, AwsWebAcl, FoundSecret } from "./types.ts";

/** Items read one request each (keys, secrets, tables, repositories…) stop here in a region. */
const MAX_ITEMS = 200;
const MAX_PAGES = 50;
const CONCURRENCY = 6;

type Fields = Partial<AwsRegion>;

/** Everything this file reads in one region. `databases` are the region's RDS instances, for their TLS parameters. */
export async function readServices(client: AwsClient, region: string, databases: AwsDatabase[] | null): Promise<Fields> {
  const [
    trails,
    configRecording,
    keys,
    certificates,
    secrets,
    repositories,
    taskDefinitions,
    kubernetes,
    tables,
    cognito,
    webAcls,
    documents,
    buildProjects,
    eventBuses,
    notebooks,
    searchDomains,
    caches,
    warehouses,
    sns,
    queues,
    brokers,
    kafka,
    fileSystems,
    launchTemplates,
    unencryptedVolumes,
    sharingBlocks,
    transitGateways,
    dbSnapshots,
  ] = await Promise.all([
    client.readIn("cloudtrail", [], () => readTrails(client, region)),
    client.readIn("config", null, async () => {
      const body = await client.rpc("config", region, "DescribeConfigurationRecorderStatus");
      return arr(body?.ConfigurationRecordersStatus).some((r: Json) => r?.recording === true);
    }),
    client.readIn("kms", [], () => readKeys(client, region)),
    client.readIn("acm", [], () => readCertificates(client, region)),
    client.readIn("secrets", [], () => readSecrets(client, region)),
    client.readIn("ecr", [], () => readRepositories(client, region)),
    client.readIn("ecs", [], () => readTaskDefinitions(client, region)),
    client.readIn("eks", [], () => readKubernetes(client, region)),
    client.readIn("dynamodb", [], () => readTables(client, region)),
    client.readIn("cognito", { userPools: [], identityPools: [] }, () => readCognito(client, region)),
    client.readIn("waf", [], () => readWebAcls(client, region)),
    client.readIn("ssmDocuments", [], () => readDocuments(client, region)),
    client.readIn("codebuild", [], () => readBuildProjects(client, region)),
    client.readIn("eventBuses", [], async () =>
      (await rpcAll(client, "events", region, "ListEventBuses", { Limit: 100 }, "EventBuses")).map((b) => ({
        name: String(b.Name ?? ""),
        public: allowsAnyone(b.Policy),
      })),
    ),
    client.readIn("sagemaker", [], () => readNotebooks(client, region)),
    client.readIn("opensearch", [], () => readSearchDomains(client, region)),
    client.readIn("elasticache", [], () => readCaches(client, region)),
    client.readIn("redshift", [], async () =>
      (await queryAll(client, "redshift", region, "DescribeClusters", "Clusters", { MaxRecords: "100" })).map((c) => ({
        id: text(c, "ClusterIdentifier") ?? "",
        public: bool(c, "PubliclyAccessible") === true,
        encrypted: bool(c, "Encrypted") === true,
      })),
    ),
    client.readIn("sns", { topics: [], httpSubscriptions: [] }, () => readSns(client, region)),
    client.readIn("sqs", [], () => readQueues(client, region)),
    client.readIn("mq", [], () => readBrokers(client, region)),
    client.readIn("msk", [], () => readKafka(client, region)),
    client.readIn("efs", [], () => readFileSystems(client, region)),
    client.readIn("launchTemplates", [], () => readLaunchTemplates(client, region)),
    client.readIn("volumes", [], async () =>
      (
        await ec2All(client, region, "DescribeVolumes", "volumeSet", {
          MaxResults: "500",
          "Filter.1.Name": "encrypted",
          "Filter.1.Value.1": "false",
          "Filter.2.Name": "status",
          "Filter.2.Value.1": "in-use",
        })
      )
        .filter((v) => bool(v, "encrypted") !== true)
        .map((v) => ({ id: text(v, "volumeId") ?? "", instance: text(items(v, "attachmentSet")[0], "instanceId") })),
    ),
    client.readIn("sharingBlocks", null, async () => {
      const [snaps, images] = await Promise.all([
        client.query("ec2", region, "GetSnapshotBlockPublicAccessState"),
        client.query("ec2", region, "GetImageBlockPublicAccessState"),
      ]);
      return { snapshots: text(find(snaps, "state")) ?? "unblocked", images: text(find(images, "imageBlockPublicAccessState")) ?? "unblocked" };
    }),
    client.readIn("transitGateways", [], async () =>
      (await ec2All(client, region, "DescribeTransitGateways", "transitGatewaySet"))
        // A transit gateway shared from another account is that account's to configure.
        .filter((t) => text(t, "ownerId") === client.accountId && text(t, "state") !== "deleted")
        .map((t) => ({ id: text(t, "transitGatewayId") ?? "", autoAccept: text(t, "options", "autoAcceptSharedAttachments") === "enable" })),
    ),
    client.readIn("dbSnapshots", [], () => readDbSnapshots(client, region)),
    databases?.length ? client.readIn("dbParameters", undefined, () => readTlsParameters(client, region, databases)) : Promise.resolve(undefined),
  ]);

  return {
    trails,
    configRecording,
    keys,
    certificates,
    secrets,
    repositories,
    taskDefinitions,
    kubernetes,
    tables,
    userPools: cognito ? cognito.userPools : null,
    identityPools: cognito ? cognito.identityPools : null,
    webAcls,
    documents,
    buildProjects,
    eventBuses,
    notebooks,
    searchDomains,
    caches,
    warehouses,
    topics: sns ? sns.topics : null,
    httpSubscriptions: sns ? sns.httpSubscriptions : null,
    queues,
    brokers,
    kafka,
    fileSystems,
    launchTemplates,
    unencryptedVolumes,
    sharingBlocks,
    transitGateways,
    dbSnapshots,
  };
}

// ---- helpers

const arr = (v: unknown): Json[] => (Array.isArray(v) ? v : []);
const str = (v: unknown): string | null => (typeof v === "string" && v ? v : null);
const ms = (v: unknown): number | null => {
  // JSON APIs send epoch seconds; REST ones send ISO dates.
  if (typeof v === "number") return v * 1000;
  const t = typeof v === "string" ? Date.parse(v) : Number.NaN;
  return Number.isFinite(t) ? t : null;
};
/** The last part of an ARN or path: a name. */
const tail = (arn: string) => arn.split(/[/:]/).pop() ?? arn;

/** Every item of a paged rpc() list. `token` names the answer's token field and the request's, which most APIs share. */
async function rpcAll(
  client: AwsClient,
  service: string,
  region: string,
  action: string,
  params: Json,
  listKey: string,
  token: [string, string] = ["NextToken", "NextToken"],
): Promise<Json[]> {
  const out: Json[] = [];
  let next: string | null = null;
  for (let page = 0; page < MAX_PAGES; page++) {
    const body: Json = await client.rpc(service, region, action, next ? { ...params, [token[1]]: next } : params);
    out.push(...arr(body?.[listKey]));
    next = str(body?.[token[0]]);
    if (!next) break;
  }
  return out;
}

/** Every item of a paged REST-JSON list. */
async function restAll(
  client: AwsClient,
  service: string,
  region: string,
  path: string,
  query: Record<string, string>,
  listKey: string,
  token: [string, string],
): Promise<Json[]> {
  const out: Json[] = [];
  let next: string | null = null;
  for (let page = 0; page < MAX_PAGES; page++) {
    const body: Json = await client.json(service, region, path, next ? { ...query, [token[1]]: next } : query);
    out.push(...arr(body?.[listKey]));
    next = str(body?.[token[0]]);
    if (!next) break;
  }
  return out;
}

/** Every element of a paged Query list (Marker paging). */
async function queryAll(
  client: AwsClient,
  service: string,
  region: string,
  action: string,
  list: string,
  params: Record<string, string> = {},
): Promise<XmlNode[]> {
  const out: XmlNode[] = [];
  let marker: string | null = null;
  for (let page = 0; page < MAX_PAGES; page++) {
    const doc: XmlNode = await client.query(service, region, action, marker ? { ...params, Marker: marker } : params);
    out.push(...items(find(doc, list)));
    marker = text(find(doc, "Marker")) ?? text(find(doc, "NextMarker"));
    if (!marker) break;
  }
  return out;
}

/** Every element of a paged EC2 list (NextToken paging). */
async function ec2All(client: AwsClient, region: string, action: string, list: string, params: Record<string, string> = {}): Promise<XmlNode[]> {
  const out: XmlNode[] = [];
  let next: string | null = null;
  for (let page = 0; page < MAX_PAGES; page++) {
    const doc: XmlNode = await client.query("ec2", region, action, next ? { ...params, NextToken: next } : params);
    out.push(...items(find(doc, list)));
    next = text(find(doc, "nextToken"));
    if (!next) break;
  }
  return out;
}

/** Runs `fn` over the first MAX_ITEMS items, a few at a time. */
async function each<T, R>(list: T[], fn: (item: T) => Promise<R>): Promise<R[]> {
  const todo = list.slice(0, MAX_ITEMS);
  const out: R[] = new Array(todo.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(CONCURRENCY, todo.length) }, async () => {
      while (next < todo.length) {
        const i = next++;
        out[i] = await fn(todo[i]);
      }
    }),
  );
  return out;
}

/** A read of one item's detail that may be refused on its own (a key policy that doesn't trust the account): null then. */
async function maybe<T>(fn: () => Promise<T>): Promise<T | null> {
  try {
    return await fn();
  } catch {
    return null;
  }
}

// ---- CloudTrail

/** Each trail's status is read once per scan, in its home region, however many regions list it. */
const trailStatus = new WeakMap<AwsClient, Map<string, Promise<boolean | null>>>();

async function readTrails(client: AwsClient, region: string): Promise<AwsTrail[]> {
  const body = await client.rpc("cloudtrail", region, "DescribeTrails", { includeShadowTrails: true });
  let cache = trailStatus.get(client);
  if (!cache) trailStatus.set(client, (cache = new Map()));
  return Promise.all(
    arr(body?.trailList).map(async (t): Promise<AwsTrail> => {
      const arn = String(t.TrailARN ?? "");
      const home = String(t.HomeRegion ?? region);
      if (!cache!.has(arn))
        cache!.set(
          arn,
          // An organization's trail seen from a member account may not answer: unknown, never assumed on.
          maybe(() => client.rpc("cloudtrail", home, "GetTrailStatus", { Name: arn })).then((s) => (typeof s?.IsLogging === "boolean" ? s.IsLogging : null)),
        );
      return {
        arn,
        name: String(t.Name ?? tail(arn)),
        homeRegion: home,
        multiRegion: t.IsMultiRegionTrail === true,
        organization: t.IsOrganizationTrail === true,
        own: arn.split(":")[4] === client.accountId,
        logging: await cache!.get(arn)!,
        validation: t.LogFileValidationEnabled === true,
      };
    }),
  );
}

// ---- KMS, ACM, Secrets Manager

async function readKeys(client: AwsClient, region: string): Promise<AwsKey[]> {
  const listed = await rpcAll(client, "kms", region, "ListKeys", { Limit: 1000 }, "Keys", ["NextMarker", "Marker"]);
  const keys = await each(listed, async (k): Promise<AwsKey | null> => {
    const id = String(k.KeyId ?? "");
    const meta = (await client.rpc("kms", region, "DescribeKey", { KeyId: id }))?.KeyMetadata;
    // AWS managed keys rotate every year on their own, and their policies are AWS's.
    if (meta?.KeyManager !== "CUSTOMER") return null;
    const enabled = meta.KeyState === "Enabled";
    const rotatable = meta.KeySpec === "SYMMETRIC_DEFAULT" && meta.Origin === "AWS_KMS";
    const [rotation, policy] = await Promise.all([
      rotatable && enabled ? maybe(() => client.rpc("kms", region, "GetKeyRotationStatus", { KeyId: id })) : Promise.resolve(null),
      maybe(() => client.rpc("kms", region, "GetKeyPolicy", { KeyId: id, PolicyName: "default" })),
    ]);
    return {
      id,
      description: str(meta.Description),
      enabled,
      rotatable,
      rotation: typeof rotation?.KeyRotationEnabled === "boolean" ? rotation.KeyRotationEnabled : null,
      deletionDate: meta.KeyState === "PendingDeletion" ? ms(meta.DeletionDate) : null,
      publicPolicy: policy ? allowsAnyone(policy.Policy) : null,
    };
  });
  return keys.filter((k): k is AwsKey => !!k);
}

const KEY_TYPES = ["RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096", "EC_prime256v1", "EC_secp384r1", "EC_secp521r1"];

async function readCertificates(client: AwsClient, region: string) {
  // Without the key types, ACM lists RSA 2048 certificates only.
  const list = await rpcAll(client, "acm", region, "ListCertificates", { MaxItems: 1000, Includes: { keyTypes: KEY_TYPES } }, "CertificateSummaryList");
  return list
    .filter((c) => c.Status === "ISSUED" || c.Status === "EXPIRED")
    .map((c) => ({
      id: tail(String(c.CertificateArn ?? "")),
      domain: String(c.DomainName ?? ""),
      type: String(c.Type ?? ""),
      inUse: c.InUse === true,
      notAfter: ms(c.NotAfter),
      renews: c.Type === "AMAZON_ISSUED" && c.RenewalEligibility === "ELIGIBLE",
    }));
}

async function readSecrets(client: AwsClient, region: string) {
  const list = await rpcAll(client, "secretsmanager", region, "ListSecrets", { MaxResults: 100 }, "SecretList");
  return each(list, async (s) => {
    const policy = await maybe(() => client.rpc("secretsmanager", region, "GetResourcePolicy", { SecretId: s.ARN }));
    return {
      name: String(s.Name ?? ""),
      createdAt: ms(s.CreatedDate),
      changedAt: ms(s.LastChangedDate),
      accessedAt: ms(s.LastAccessedDate),
      rotation: s.RotationEnabled === true,
      publicPolicy: policy ? allowsAnyone(policy.ResourcePolicy) : null,
    };
  });
}

// ---- containers

const wildcard = (pattern: string, name: string) => new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")}$`).test(name);

async function readRepositories(client: AwsClient, region: string) {
  const [repos, registry] = await Promise.all([
    rpcAll(client, "ecr", region, "DescribeRepositories", { maxResults: 1000 }, "repositories", ["nextToken", "nextToken"]),
    maybe(() => client.rpc("ecr", region, "GetRegistryScanningConfiguration")),
  ]);
  // Registry rules scan matching repositories on push or continuously, whatever each repository says.
  const rules = arr(registry?.scanningConfiguration?.rules).filter((r) => r?.scanFrequency === "SCAN_ON_PUSH" || r?.scanFrequency === "CONTINUOUS_SCAN");
  return each(repos, async (r) => {
    const name = String(r.repositoryName ?? "");
    let publicPolicy: boolean | null = false;
    try {
      publicPolicy = allowsAnyone((await client.rpc("ecr", region, "GetRepositoryPolicy", { repositoryName: name }))?.policyText);
    } catch (e) {
      // No policy is the usual case: nothing public.
      publicPolicy = (e as { notFound?: boolean }).notFound ? false : null;
    }
    return {
      name,
      scanned:
        r.imageScanningConfiguration?.scanOnPush === true ||
        rules.some((rule) => arr(rule.repositoryFilters).some((f) => wildcard(String(f?.filter ?? ""), name))),
      immutableTags: String(r.imageTagMutability ?? "").startsWith("IMMUTABLE"),
      publicPolicy,
    };
  });
}

/** The task definitions that ECS services run: what is really running, not every revision ever registered. */
async function readTaskDefinitions(client: AwsClient, region: string): Promise<AwsTaskDefinition[]> {
  const clusters = await rpcAll(client, "ecs", region, "ListClusters", { maxResults: 100 }, "clusterArns", ["nextToken", "nextToken"]);
  const usedBy = new Map<string, string[]>();
  for (const cluster of clusters.slice(0, MAX_ITEMS)) {
    const arns = await rpcAll(client, "ecs", region, "ListServices", { cluster, maxResults: 100 }, "serviceArns", ["nextToken", "nextToken"]);
    for (let i = 0; i < arns.length && i < MAX_ITEMS; i += 10) {
      const body = await client.rpc("ecs", region, "DescribeServices", { cluster, services: arns.slice(i, i + 10) });
      for (const s of arr(body?.services)) {
        const td = String(s.taskDefinition ?? "");
        if (td) usedBy.set(td, [...(usedBy.get(td) ?? []), String(s.serviceName ?? "")]);
      }
    }
  }
  const defs = await each([...usedBy.keys()], async (arn): Promise<AwsTaskDefinition> => {
    const td = (await client.rpc("ecs", region, "DescribeTaskDefinition", { taskDefinition: arn }))?.taskDefinition ?? {};
    const containers = arr(td.containerDefinitions);
    let secret: FoundSecret | null = null;
    for (const c of containers) {
      // Only the variable's name and the kind leave this function; the values are dropped with the payload.
      const found = secretInVariables(Object.fromEntries(arr(c.environment).map((e) => [String(e?.name ?? ""), e?.value])));
      if (found && (!secret || (secret.likely && !found.likely))) secret = { ...found, where: `${c.name}: ${found.where}` };
    }
    return {
      name: `${td.family ?? tail(arn)}:${td.revision ?? ""}`,
      services: usedBy.get(arn) ?? [],
      privileged: containers.filter((c) => c.privileged === true).map((c) => String(c.name ?? "")),
      hostNamespaces: [td.networkMode === "host" && "network", td.pidMode === "host" && "process", td.ipcMode === "host" && "IPC"].filter(
        (x): x is string => !!x,
      ),
      secret,
    };
  });
  return defs.sort((a, b) => a.name.localeCompare(b.name));
}

async function readKubernetes(client: AwsClient, region: string): Promise<AwsKubernetes[]> {
  const names = await restAll(client, "eks", region, "/clusters", { maxResults: "100" }, "clusters", ["nextToken", "nextToken"]);
  const clusters = await each(names, async (name: string) => (await client.json("eks", region, `/clusters/${encodeURIComponent(name)}`))?.cluster ?? {});
  // AWS says which versions are in standard or extended support, so no table of dates goes stale here.
  const versions = new Map<string, string | null>();
  for (const v of new Set(clusters.map((c) => str(c.version)).filter((v): v is string => !!v))) {
    const body = await maybe(() => client.json("eks", region, "/cluster-versions", { clusterVersions: v }));
    const hit = arr(body?.clusterVersions).find((x) => x?.clusterVersion === v);
    versions.set(v, str(hit?.versionStatus) ?? (hit?.status ? String(hit.status).toUpperCase().replace(/-/g, "_") : null));
  }
  return clusters.map((c) => {
    const vpc = c.resourcesVpcConfig ?? {};
    const cidrs = arr(vpc.publicAccessCidrs).map(String);
    return {
      name: String(c.name ?? ""),
      version: str(c.version),
      publicEndpoint: vpc.endpointPublicAccess === true,
      openToAll: vpc.endpointPublicAccess === true && (cidrs.length === 0 || cidrs.includes("0.0.0.0/0")),
      secretsEncrypted: arr(c.encryptionConfig).some((e) => arr(e?.resources).includes("secrets")),
      auditLogs: arr(c.logging?.clusterLogging).some((l) => l?.enabled === true && arr(l?.types).includes("audit")),
      versionStatus: c.version ? (versions.get(c.version) ?? null) : null,
    };
  });
}

// ---- data

async function readTables(client: AwsClient, region: string) {
  const names = await rpcAll(client, "dynamodb", region, "ListTables", { Limit: 100 }, "TableNames", ["LastEvaluatedTableName", "ExclusiveStartTableName"]);
  return each(names, async (name: string) => {
    const body = await maybe(() => client.rpc("dynamodb", region, "DescribeContinuousBackups", { TableName: name }));
    const status = body?.ContinuousBackupsDescription?.PointInTimeRecoveryDescription?.PointInTimeRecoveryStatus;
    return { name: String(name), pitr: status ? status === "ENABLED" : null };
  });
}

async function readSearchDomains(client: AwsClient, region: string): Promise<AwsSearchDomain[]> {
  const names = arr((await client.json("es", region, "/2021-01-01/domain"))?.DomainNames).map((d) => String(d?.DomainName ?? ""));
  return each(names, async (name) => {
    const d = (await client.json("es", region, `/2021-01-01/opensearch/domain/${encodeURIComponent(name)}`))?.DomainStatus ?? {};
    const tls = String(d.DomainEndpointOptions?.TLSSecurityPolicy ?? "");
    return {
      name,
      vpc: !!str(d.VPCOptions?.VPCId),
      openPolicy: allowsAnyone(d.AccessPolicies),
      fineGrained: d.AdvancedSecurityOptions?.Enabled === true,
      encryptedAtRest: d.EncryptionAtRestOptions?.Enabled === true,
      nodeToNode: d.NodeToNodeEncryptionOptions?.Enabled === true,
      enforceHttps: d.DomainEndpointOptions?.EnforceHTTPS === true,
      tls12: tls !== "" && !tls.includes("TLS-1-0"),
    };
  });
}

async function readCaches(client: AwsClient, region: string) {
  const [groups, standalone] = await Promise.all([
    queryAll(client, "elasticache", region, "DescribeReplicationGroups", "ReplicationGroups", { MaxRecords: "100" }),
    queryAll(client, "elasticache", region, "DescribeCacheClusters", "CacheClusters", { MaxRecords: "100", ShowCacheClustersNotInReplicationGroups: "true" }),
  ]);
  return [
    ...groups.map((g) => ({
      id: text(g, "ReplicationGroupId") ?? "",
      engine: text(g, "Engine") ?? "redis",
      transit: bool(g, "TransitEncryptionEnabled") === true,
      atRest: bool(g, "AtRestEncryptionEnabled") === true,
    })),
    ...standalone.map((c) => ({
      id: text(c, "CacheClusterId") ?? "",
      engine: text(c, "Engine") ?? "",
      transit: bool(c, "TransitEncryptionEnabled") === true,
      atRest: bool(c, "AtRestEncryptionEnabled") === true,
    })),
  ];
}

async function readFileSystems(client: AwsClient, region: string) {
  const list = await restAll(client, "elasticfilesystem", region, "/2015-02-01/file-systems", { MaxItems: "100" }, "FileSystems", ["NextMarker", "Marker"]);
  return list
    .filter((f) => f.LifeCycleState !== "deleted" && f.LifeCycleState !== "deleting")
    .map((f) => ({ id: String(f.FileSystemId ?? ""), name: str(f.Name), encrypted: f.Encrypted === true }));
}

/** Manual snapshots only: automated ones can't be shared. */
async function readDbSnapshots(client: AwsClient, region: string) {
  const [instances, clusters] = await Promise.all([
    queryAll(client, "rds", region, "DescribeDBSnapshots", "DBSnapshots", { SnapshotType: "manual", MaxRecords: "100" }),
    queryAll(client, "rds", region, "DescribeDBClusterSnapshots", "DBClusterSnapshots", { SnapshotType: "manual", MaxRecords: "100" }),
  ]);
  const restorableByAll = (doc: XmlNode) =>
    items(find(doc, "DBSnapshotAttributes") ?? find(doc, "DBClusterSnapshotAttributes")).some(
      (a) => text(a, "AttributeName") === "restore" && items(a, "AttributeValues").some((v) => v.text.trim() === "all"),
    );
  const [a, b] = await Promise.all([
    each(instances, async (s) => {
      const id = text(s, "DBSnapshotIdentifier") ?? "";
      return { id, cluster: false, public: restorableByAll(await client.query("rds", region, "DescribeDBSnapshotAttributes", { DBSnapshotIdentifier: id })) };
    }),
    each(clusters, async (s) => {
      const id = text(s, "DBClusterSnapshotIdentifier") ?? "";
      return {
        id,
        cluster: true,
        public: restorableByAll(await client.query("rds", region, "DescribeDBClusterSnapshotAttributes", { DBClusterSnapshotIdentifier: id })),
      };
    }),
  ]);
  return [...a, ...b];
}

/** The parameter that makes each engine require TLS. Others (Oracle, SQL Server) do it differently and aren't judged. */
const TLS_PARAMETER: [RegExp, string][] = [
  [/postgres/, "rds.force_ssl"],
  [/mysql|mariadb/, "require_secure_transport"],
];

/** Sets `tlsRequired` on each database whose engine has a TLS parameter, from its parameter group (or its cluster's). */
async function readTlsParameters(client: AwsClient, region: string, databases: AwsDatabase[]): Promise<undefined> {
  const clusters = databases.some((d) => d.cluster)
    ? new Map(
        (await queryAll(client, "rds", region, "DescribeDBClusters", "DBClusters", { MaxRecords: "100" })).map((c) => [
          text(c, "DBClusterIdentifier") ?? "",
          text(c, "DBClusterParameterGroup"),
        ]),
      )
    : new Map<string, string | null>();
  const values = new Map<string, Promise<Map<string, string>>>();
  const paramsOf = (group: string, cluster: boolean) => {
    const key = `${cluster ? "cluster" : "instance"}:${group}`;
    if (!values.has(key))
      values.set(
        key,
        queryAll(
          client,
          "rds",
          region,
          cluster ? "DescribeDBClusterParameters" : "DescribeDBParameters",
          "Parameters",
          cluster ? { DBClusterParameterGroupName: group, MaxRecords: "100" } : { DBParameterGroupName: group, MaxRecords: "100" },
        ).then((ps) => new Map(ps.map((p) => [text(p, "ParameterName") ?? "", text(p, "ParameterValue") ?? ""]))),
      );
    return values.get(key)!;
  };
  await each(databases, async (db) => {
    const param = TLS_PARAMETER.find(([re]) => re.test(db.engine))?.[1];
    if (!param) return;
    const clusterGroup = db.cluster ? clusters.get(db.cluster) : null;
    const group = clusterGroup ?? db.parameterGroup;
    if (!group) return;
    const value = (await paramsOf(group, !!clusterGroup)).get(param);
    // No value set means the engine's default: off for MySQL and MariaDB; unknown for PostgreSQL, whose default changed in 15.
    db.tlsRequired = value ? /^(1|on|true)$/i.test(value) : /mysql|mariadb/.test(db.engine) ? false : null;
  });
  return undefined;
}

// ---- identity, edge and messaging

async function readCognito(client: AwsClient, region: string) {
  const [pools, identities] = await Promise.all([
    rpcAll(client, "cognito-idp", region, "ListUserPools", { MaxResults: 60 }, "UserPools"),
    rpcAll(client, "cognito-identity", region, "ListIdentityPools", { MaxResults: 60 }, "IdentityPools"),
  ]);
  const [userPools, identityPools] = await Promise.all([
    each(pools, async (p) => {
      const pool = (await client.rpc("cognito-idp", region, "DescribeUserPool", { UserPoolId: p.Id }))?.UserPool ?? {};
      return { id: String(p.Id ?? ""), name: String(p.Name ?? ""), mfa: String(pool.MfaConfiguration ?? "OFF") };
    }),
    each(identities, async (p) => {
      const pool = await client.rpc("cognito-identity", region, "DescribeIdentityPool", { IdentityPoolId: p.IdentityPoolId });
      const guest = pool?.AllowUnauthenticatedIdentities === true;
      const roles = guest ? await maybe(() => client.rpc("cognito-identity", region, "GetIdentityPoolRoles", { IdentityPoolId: p.IdentityPoolId })) : null;
      const arn = str(roles?.Roles?.unauthenticated);
      return { id: String(p.IdentityPoolId ?? ""), name: String(p.IdentityPoolName ?? ""), guest, guestRole: arn ? tail(arn) : null };
    }),
  ]);
  return { userPools, identityPools };
}

async function readWebAcls(client: AwsClient, region: string): Promise<AwsWebAcl[]> {
  // Web ACLs for CloudFront live in us-east-1 under their own scope.
  const scopes: AwsWebAcl["scope"][] = region === HOME_REGION ? ["REGIONAL", "CLOUDFRONT"] : ["REGIONAL"];
  const out: AwsWebAcl[] = [];
  for (const scope of scopes) {
    const acls = await rpcAll(client, "wafv2", region, "ListWebACLs", { Scope: scope, Limit: 100 }, "WebACLs", ["NextMarker", "NextMarker"]);
    out.push(
      ...(await each(acls, async (a) => {
        const arn = String(a.ARN ?? "");
        const [acl, logging, resources] = await Promise.all([
          client.rpc("wafv2", region, "GetWebACL", { Name: a.Name, Scope: scope, Id: a.Id }),
          client.optional(() => client.rpc("wafv2", region, "GetLoggingConfiguration", { ResourceArn: arn })).catch(() => undefined),
          scope === "REGIONAL" ? client.rpc("wafv2", region, "ListResourcesForWebACL", { WebACLArn: arn, ResourceType: "APPLICATION_LOAD_BALANCER" }) : null,
        ]);
        return {
          name: String(a.Name ?? ""),
          arn,
          scope,
          rules: arr(acl?.WebACL?.Rules).length,
          logging: logging === undefined ? null : !!logging?.LoggingConfiguration,
          loadBalancers: arr(resources?.ResourceArns).map(String),
        };
      })),
    );
  }
  return out;
}

async function readDocuments(client: AwsClient, region: string) {
  const docs = await rpcAll(client, "ssm", region, "ListDocuments", { Filters: [{ Key: "Owner", Values: ["Self"] }], MaxResults: 50 }, "DocumentIdentifiers");
  return each(docs, async (d) => {
    const name = String(d.Name ?? "");
    const perms = await client.rpc("ssm", region, "DescribeDocumentPermission", { Name: name, PermissionType: "Share" });
    return { name, public: arr(perms?.AccountIds).includes("all") };
  });
}

async function readBuildProjects(client: AwsClient, region: string) {
  const names = await rpcAll(client, "codebuild", region, "ListProjects", {}, "projects", ["nextToken", "nextToken"]);
  const out: { name: string; public: boolean; secret: FoundSecret | null }[] = [];
  for (let i = 0; i < names.length && i < MAX_ITEMS; i += 100) {
    const body = await client.rpc("codebuild", region, "BatchGetProjects", { names: names.slice(i, i + 100) });
    for (const p of arr(body?.projects)) {
      // Parameter Store and Secrets Manager variables hold a reference; only plain-text ones can hold the secret itself.
      const plain = arr(p.environment?.environmentVariables).filter((v) => (v?.type ?? "PLAINTEXT") === "PLAINTEXT");
      const inSource = secretKindIn(String(p.source?.location ?? ""));
      out.push({
        name: String(p.name ?? ""),
        public: p.projectVisibility === "PUBLIC_READ",
        secret: inSource
          ? { where: "source location", kind: inSource, likely: false }
          : secretInVariables(Object.fromEntries(plain.map((v) => [String(v.name ?? ""), v.value]))),
      });
    }
  }
  return out;
}

async function readNotebooks(client: AwsClient, region: string) {
  const list = await rpcAll(client, "sagemaker", region, "ListNotebookInstances", { MaxResults: 100 }, "NotebookInstances");
  return each(list, async (n) => {
    const name = String(n.NotebookInstanceName ?? "");
    const d = await client.rpc("sagemaker", region, "DescribeNotebookInstance", { NotebookInstanceName: name });
    return { name, internet: d?.DirectInternetAccess === "Enabled" };
  });
}

async function readSns(client: AwsClient, region: string) {
  const topicNodes = await queryAllToken(client, "sns", region, "ListTopics", "Topics");
  const topics = await each(topicNodes, async (t) => {
    const arn = text(t, "TopicArn") ?? "";
    const attrs = await client.query("sns", region, "GetTopicAttributes", { TopicArn: arn });
    const policy = items(find(attrs, "Attributes")).find((e) => text(e, "key") === "Policy");
    return { name: tail(arn), public: allowsAnyone(text(policy, "value")) };
  });
  const subs = await queryAllToken(client, "sns", region, "ListSubscriptions", "Subscriptions");
  const httpSubscriptions = subs
    .filter((s) => text(s, "Protocol") === "http")
    .map((s) => {
      let host = "";
      try {
        host = new URL(text(s, "Endpoint") ?? "").host;
      } catch {
        /* an endpoint that isn't a URL: no host to keep */
      }
      return { topic: tail(text(s, "TopicArn") ?? ""), host };
    });
  return { topics, httpSubscriptions };
}

/** A Query list paged with NextToken (SNS). */
async function queryAllToken(client: AwsClient, service: string, region: string, action: string, list: string): Promise<XmlNode[]> {
  const out: XmlNode[] = [];
  let next: string | null = null;
  for (let page = 0; page < MAX_PAGES; page++) {
    const doc: XmlNode = await client.query(service, region, action, next ? { NextToken: next } : {});
    out.push(...items(find(doc, list)));
    next = text(find(doc, "NextToken"));
    if (!next) break;
  }
  return out;
}

async function readQueues(client: AwsClient, region: string) {
  const urls = await rpcAll(client, "sqs", region, "ListQueues", { MaxResults: 1000 }, "QueueUrls");
  return each(urls, async (url: string) => {
    const body = await client.rpc("sqs", region, "GetQueueAttributes", { QueueUrl: url, AttributeNames: ["Policy"] });
    return { name: tail(String(url)), public: allowsAnyone(body?.Attributes?.Policy) };
  });
}

async function readBrokers(client: AwsClient, region: string) {
  const list = await restAll(client, "mq", region, "/v1/brokers", { maxResults: "100" }, "brokerSummaries", ["nextToken", "nextToken"]);
  return each(list, async (b) => {
    const d = await client.json("mq", region, `/v1/brokers/${encodeURIComponent(String(b.brokerId ?? ""))}`);
    return { name: String(d?.brokerName ?? b.brokerName ?? ""), engine: String(d?.engineType ?? b.engineType ?? ""), public: d?.publiclyAccessible === true };
  });
}

async function readKafka(client: AwsClient, region: string): Promise<AwsKafka[]> {
  const list = await restAll(client, "kafka", region, "/api/v2/clusters", { maxResults: "100" }, "clusterInfoList", ["nextToken", "nextToken"]);
  return list.map((c) => {
    const p = c.provisioned ?? {};
    const s = c.serverless ?? {};
    return {
      name: String(c.clusterName ?? ""),
      public: (p.brokerNodeGroupInfo?.connectivityInfo?.publicAccess?.type ?? "DISABLED") !== "DISABLED",
      // Serverless clusters always require IAM authentication and TLS.
      unauthenticated: !c.serverless && p.clientAuthentication?.unauthenticated?.enabled === true,
      plaintext: !s.clientAuthentication && /PLAINTEXT/.test(String(p.encryptionInfo?.encryptionInTransit?.clientBroker ?? "")),
    };
  });
}

// ---- EC2 launch templates

async function readLaunchTemplates(client: AwsClient, region: string) {
  // "$Default" with no template named describes the default version of every launch template in one list.
  const versions = await ec2All(client, region, "DescribeLaunchTemplateVersions", "launchTemplateVersionSet", {
    "LaunchTemplateVersion.1": "$Default",
    MaxResults: "200",
  });
  return versions.map((v) => {
    const data = at(v, "launchTemplateData");
    const meta = at(data, "metadataOptions");
    const tokens = text(meta, "httpTokens");
    return {
      id: text(v, "launchTemplateId") ?? "",
      name: text(v, "launchTemplateName") ?? "",
      imdsV2: text(meta, "httpEndpoint") === "disabled" ? null : tokens ? tokens === "required" : null,
      // The script is decoded, scanned and dropped here; only the kind found is kept.
      userDataSecret: secretInUserData(text(data, "userData")),
    };
  });
}
