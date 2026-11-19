// Container images on Alibaba Cloud: the images in Container Registry (ACR)
// Enterprise Edition instances, the workloads that run images (Elastic Container
// Instance groups and Function Compute functions built from an image), and
// Trivy's scan of the images that matter.
//
// The registry login comes from cr:GetAuthorizationToken: a temporary user name
// and password for one instance, valid for an hour, able to do only what the
// AccessKey's RAM user can. Pulling also needs cr:PullRepository, the one action
// in Keelson's policy that reads data (an image's layers) rather than
// configuration; without it the images are listed and the pull is a coverage gap.
// Container Registry Personal Edition has no API (Alibaba Cloud's documentation,
// November 2026), so its images are known only from the workloads that run them
// and aren't scanned. Container groups' environment variables come back with
// their values and are dropped as they're read; ACK's own workloads live in the
// Kubernetes API, which Keelson doesn't read.

import { AlibabaError, type AlibabaClient, type Json } from "./client.ts";
import { ruleText } from "./checks/define.ts";
import type { AlibabaInventory } from "./types.ts";
import { pickImages, scanImages, type Foreign, type RegistryImage } from "../../core/images.ts";
import type { RegistryLogin } from "../../core/trivy.ts";
import type { ProgressEvent, Related } from "../../core/types.ts";
import type { AccountCache } from "../../store/repo.ts";
import { canonicalRegistry, ecrHost, registryKind, type ImageRef, type ImagesSnapshot, type WorkloadLink } from "../../shared/images.ts";

/** Repositories read one request each for their tags, per registry instance. */
const MAX_REPOSITORIES = 300;
const MAX_GROUP_PAGES = 25;
const list = (v: unknown): Json[] => (Array.isArray(v) ? v : []);

/** A registry instance: the hosts that serve it, and its images. */
export interface AlibabaRegistry {
  id: string;
  name: string;
  region: string;
  /** The host Keelson pulls from: the public one when the instance has it on, else the VPC one. */
  host: string;
  /** Every host that serves the instance, lowercase. */
  hosts: string[];
  repositories: number;
  images: RegistryImage[];
}

/** An Elastic Container Instance group, without its containers' variables. */
export interface AlibabaContainerGroup {
  id: string;
  name: string;
  region: string;
  running: boolean;
  publicIp: string | null;
  securityGroup: string | null;
  containers: { name: string; image: string }[];
}

async function pages(fetch: (page: number) => Promise<Json>, items: (body: Json) => Json[], size: number, max = 20): Promise<Json[]> {
  const out: Json[] = [];
  for (let n = 1; n <= max; n++) {
    const got = items(await fetch(n));
    out.push(...got);
    if (got.length < size) break;
  }
  return out;
}

/** Runs a regional read; a region where the product isn't offered or was never opened is empty, not a gap. */
async function inRegion<T>(client: AlibabaClient, source: "registries" | "containerGroups", empty: T, fn: () => Promise<T>): Promise<T | null> {
  try {
    const out = await fn();
    client.note(source, true);
    return out;
  } catch (e) {
    if (e instanceof AlibabaError && e.noEndpoint) return empty;
    client.note(source, false, e);
    return null;
  }
}

/** Every Enterprise Edition registry instance in the regions read, with its tagged images. Null when one couldn't be read. */
export async function readRegistries(client: AlibabaClient, regions: string[]): Promise<AlibabaRegistry[] | null> {
  const out: AlibabaRegistry[] = [];
  let complete = true;
  for (const region of regions) {
    const got = await inRegion(client, "registries", [] as AlibabaRegistry[], async () => {
      const cr = (action: string, params: Record<string, string>) => client.rpc("cr", region, action, params);
      const instances = await pages(
        (n) => cr("ListInstance", { PageNo: String(n), PageSize: "30" }),
        (b) => list(b?.Instances),
        30,
      );
      const found: AlibabaRegistry[] = [];
      for (const inst of instances) {
        const id = String(inst.InstanceId ?? "");
        if (!id || (inst.RegionId && inst.RegionId !== region)) continue;
        const endpoints = list((await cr("ListInstanceEndpoint", { InstanceId: id, ModuleName: "Registry" }))?.Endpoints);
        const hostsOf = (e: Json) =>
          list(e?.Domains)
            .map((d) => String(d?.Domain ?? "").toLowerCase())
            .filter(Boolean);
        const open = endpoints.filter((e) => e?.Enable === true && /internet/i.test(String(e?.EndpointType)));
        const hosts = [...new Set(endpoints.flatMap(hostsOf))];
        const host = open.flatMap(hostsOf)[0] ?? hosts[0];
        if (!host) continue;
        const repos = await pages(
          (n) => cr("ListRepository", { InstanceId: id, RepoStatus: "NORMAL", PageNo: String(n), PageSize: "100" }),
          (b) => list(b?.Repositories),
          100,
        );
        const images: RegistryImage[] = [];
        for (const r of repos.slice(0, MAX_REPOSITORIES)) {
          // One entry per tag: tags of the same image are put together.
          const tags = list((await cr("ListRepoTag", { InstanceId: id, RepoId: String(r.RepoId), PageNo: "1", PageSize: "100" }))?.Images);
          const byDigest = new Map<string, RegistryImage>();
          for (const t of tags) {
            const raw = String(t?.Digest ?? "");
            const digest = /^[a-f0-9]{64}$/.test(raw) ? `sha256:${raw}` : raw;
            if (!/^sha256:[a-f0-9]{64}$/.test(digest) || !t?.Tag) continue;
            const pushed = Number(t.ImageUpdate ?? t.ImageCreate);
            const prev = byDigest.get(digest);
            if (prev) prev.tags.push(String(t.Tag));
            else
              byDigest.set(digest, {
                registry: canonicalRegistry(host),
                repository: `${r.RepoNamespaceName}/${r.RepoName}`.toLowerCase(),
                region,
                digest,
                tags: [String(t.Tag)],
                pushedAt: Number.isFinite(pushed) && pushed > 0 ? new Date(pushed).toISOString() : null,
                pulledAt: null,
                public: String(r.RepoType).toUpperCase() === "PUBLIC",
              });
          }
          images.push(...byDigest.values());
        }
        found.push({ id, name: String(inst.InstanceName ?? id), region, host, hosts, repositories: repos.length, images });
      }
      return found;
    });
    if (got) out.push(...got);
    else complete = false;
  }
  return complete ? out : null;
}

/** Elastic Container Instance groups that are running, in the regions read. Null when one couldn't be read. */
export async function readContainerGroups(client: AlibabaClient, regions: string[]): Promise<AlibabaContainerGroup[] | null> {
  const out: AlibabaContainerGroup[] = [];
  let complete = true;
  for (const region of regions) {
    const got = await inRegion(client, "containerGroups", [] as AlibabaContainerGroup[], async () => {
      const groups: Json[] = [];
      let token: string | null = null;
      for (let n = 0; n < MAX_GROUP_PAGES; n++) {
        const body: Json = await client.rpc("eci", region, "DescribeContainerGroups", {
          RegionId: region,
          Limit: "20",
          ...(token ? { NextToken: token } : {}),
        });
        groups.push(...list(body?.ContainerGroups));
        token = typeof body?.NextToken === "string" && body.NextToken ? body.NextToken : null;
        if (!token) break;
      }
      // Only names and images leave this function: each container's environment variables come with their values.
      return groups.map((g) => ({
        id: String(g.ContainerGroupId ?? ""),
        name: String(g.ContainerGroupName ?? g.ContainerGroupId ?? ""),
        region,
        running: String(g.Status) === "Running",
        publicIp: typeof g.InternetIp === "string" && g.InternetIp ? g.InternetIp : null,
        securityGroup: typeof g.SecurityGroupId === "string" && g.SecurityGroupId ? g.SecurityGroupId : null,
        containers: list(g.Containers)
          .map((c) => ({ name: String(c?.Name ?? ""), image: String(c?.Image ?? "") }))
          .filter((c) => c.image),
      }));
    });
    if (got) out.push(...got);
    else complete = false;
  }
  return complete ? out : null;
}

/**
 * The account's workloads that run images: container groups (the same image run many times, as a Kubernetes cluster's
 * virtual nodes do, is one workload with a count) and functions built from an image. Null when either couldn't be read.
 */
export function workloadLinks(inv: AlibabaInventory): WorkloadLink[] | null {
  if (!inv.containerGroups || inv.regions.some((r) => r.functions === null)) return null;
  const account = inv.accountName ?? inv.accountId;
  const out = new Map<string, WorkloadLink>();
  for (const g of inv.containerGroups) {
    if (!g.running || !g.containers.length) continue;
    const region = inv.regions.find((r) => r.name === g.region);
    const group = region?.securityGroups?.find((s) => s.id === g.securityGroup);
    const via = g.publicIp && group?.open.length ? [`a public address, with ${ruleText(group.open[0])} in ${group.name || group.id}`] : [];
    const internet = via.length ? true : g.publicIp && !group ? null : false;
    // Pods of one deployment differ only in their generated suffix.
    const base = g.name.replace(/-[a-z0-9]{8,10}-[a-z0-9]{5}$|-[a-z0-9]{5}$|-\d+$/, "");
    const key = `${g.region}|${base}|${g.containers.map((c) => c.image).join(",")}|${internet}`;
    const prev = out.get(key);
    if (prev) prev.running = (prev.running ?? 1) + 1;
    else
      out.set(key, {
        provider: "alibaba",
        kind: "ECI container group",
        name: base || g.name,
        group: null,
        account,
        region: g.region,
        link: `https://eci.console.alibabacloud.com/#/eci/${g.region}/detail/${encodeURIComponent(g.id)}/containers`,
        containers: g.containers,
        running: 1,
        internet,
        via,
        loadBalancers: [],
      });
  }
  for (const r of inv.regions)
    for (const f of r.functions ?? []) {
      if (!f.image) continue;
      const open = f.anonymousTriggers?.length ? [`an HTTP trigger anyone can call (${f.anonymousTriggers[0]})`] : [];
      out.set(`fc|${r.name}|${f.name}`, {
        provider: "alibaba",
        kind: "Function Compute function",
        name: f.name,
        group: null,
        account,
        region: r.name,
        link: `https://fcnext.console.alibabacloud.com/${r.name}/functions/${encodeURIComponent(f.name)}`,
        containers: [{ name: f.name, image: f.image }],
        running: null,
        internet: open.length ? true : f.anonymousTriggers ? false : null,
        via: open,
        loadBalancers: [],
      });
    }
  return [...out.values()];
}

/** Whose registry an image is in, as this account sees it. */
function foreignFor(registries: AlibabaRegistry[], related: Partial<Related>): (ref: ImageRef) => Foreign {
  const own = new Set(registries.flatMap((r) => r.hosts.map(canonicalRegistry)));
  return (ref) => {
    const kind = registryKind(ref.registry);
    // The account's own images come from its instances' lists. Any other Alibaba Cloud registry is private to its owner:
    // another account's instance, or a Personal Edition registry, which has no API to list or sign in to.
    if (kind === "acr") return own.has(canonicalRegistry(ref.registry)) || (related.alibabaAccounts?.length ?? 0) > 0 ? "entity" : "private";
    if (kind === "ecr") return related.awsAccounts?.includes(ecrHost(ref.registry)?.account ?? "") ? "entity" : "private";
    if (kind === "ghcr") return related.githubOrgs?.includes(ref.repository.split("/")[0]) ? "entity" : "public";
    return "public";
  };
}

/** Reads the registries and container groups, picks and scans the images, and records the result on the inventory. */
export async function scanAlibabaImages(
  client: AlibabaClient,
  inv: AlibabaInventory,
  o: { cache: AccountCache; toolDir: string | null; related: Partial<Related>; onProgress: (p: ProgressEvent) => void; previous?: ImagesSnapshot | null },
): Promise<void> {
  o.onProgress({ phase: "Reading container registries and workloads" });
  const regions = inv.regions.map((r) => r.name);
  const [registries, groups] = await Promise.all([readRegistries(client, regions), readContainerGroups(client, regions)]);
  inv.registries = registries;
  inv.containerGroups = groups;
  const own = workloadLinks(inv) ?? [];
  const workloads = [...own, ...(o.related.alibabaWorkloads ?? []), ...(o.related.awsWorkloads ?? [])];
  // One login per registry instance, asked for only when an image in it is scanned.
  const logins = new Map<string, () => Promise<RegistryLogin | null>>();
  const loginFor = (r: AlibabaRegistry) => {
    if (!logins.has(r.id))
      logins.set(r.id, async () => {
        const body = await client.rpc("cr", r.region, "GetAuthorizationToken", { InstanceId: r.id });
        if (!body?.TempUsername || !body?.AuthorizationToken) throw new Error("Container Registry didn't return a registry login.");
        return { username: String(body.TempUsername), password: String(body.AuthorizationToken) };
      });
    return logins.get(r.id)!;
  };
  const all = registries ?? [];
  const targets = pickImages({
    registry: all.flatMap((r) => r.images),
    workloads,
    ownWorkloads: own,
    login: (img) => {
      const r = all.find((x) => canonicalRegistry(x.host) === img.registry && x.region === img.region);
      return r ? loginFor(r) : null;
    },
    foreign: foreignFor(all, o.related),
    now: inv.now,
  });
  const { snapshot, scans, later } = await scanImages(targets, {
    repositories: all.reduce((n, r) => n + r.repositories, 0),
    cache: o.cache,
    toolDir: o.toolDir,
    onProgress: o.onProgress,
    note: (source, ok, err) => client.note(source === "pull" ? "imagePull" : source, ok, err),
    now: inv.now,
    previous: o.previous,
  });
  inv.images = { snapshot, scans, workloads, later };
  inv.unreadable = [...client.coverage.values()].filter((c) => !c.ok).map((c) => c.key);
}
