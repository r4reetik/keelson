// How Alibaba Cloud check modules are written: the same shape as the other
// providers' (see src/core/checks/define.ts), over an Alibaba Cloud inventory.
//
//   export default defineChecks({
//     "LID-001": { category: "Identity & access", severity: "critical", title: "…", why: "…", fix: "…", requires: ["identity"] },
//   }, ({ inv, d }, report) => {
//     report("LID-001", { zone: GLOBAL, resource: "main account", pass: !inv.rootKey, link: d.accessKeys });
//   });
//
// A finding's `zone` is its region, or "Global" for RAM, OSS settings, CDN and DNS.
// Check IDs start with L (aLibaba): A… is AWS's.

import { checksFor } from "../../../core/checks/define.ts";
import type { EngineOptions, Related } from "../../../core/types.ts";
import type { AlibabaSourceKey } from "../sources.ts";
import type { AlibabaInterface, AlibabaInventory, AlibabaRegion, AlibabaSecurityGroup, AlibabaSecurityRule } from "../types.ts";

export interface AlibabaContext {
  inv: AlibabaInventory;
  opts: EngineOptions;
  /** Links into the Alibaba Cloud console. */
  d: typeof dash;
  /** What the entity's other accounts share, for checks that span providers. */
  related: Related;
}

export const defineChecks = checksFor<AlibabaContext, AlibabaSourceKey>();

const CONSOLE = "https://console.alibabacloud.com";
const ram = (hash: string) => `https://ram.console.alibabacloud.com/${hash}`;
const ecs = (region: string, hash: string) => `https://ecs.console.alibabacloud.com/${hash}?regionId=${region}`;

export const dash = {
  accessKeys: ram("manage/ak"),
  securitySettings: ram("settings"),
  user: (name: string) => ram(`users/detail?userId=${encodeURIComponent(name)}`),
  role: (name: string) => ram(`roles/detail?roleName=${encodeURIComponent(name)}`),
  policies: ram("policies"),
  ossOverview: "https://oss.console.alibabacloud.com/overview",
  bucket: (name: string, region: string) => `https://oss.console.alibabacloud.com/bucket/oss-${region}/${encodeURIComponent(name)}/permission`,
  securityGroup: (region: string, id: string) => ecs(region, `securityGroupDetail/region/${region}/groupId/${id}/detail/intranetIngress`),
  instance: (region: string, id: string) => ecs(region, `server/${id}/detail`),
  disks: (region: string) => ecs(region, "disk"),
  images: (region: string) => ecs(region, "image"),
  launchTemplates: (region: string) => ecs(region, "launchTemplate"),
  vpc: (region: string, id: string) => `https://vpc.console.alibabacloud.com/vpc/${region}/vpcs/${id}`,
  flowLogs: (region: string) => `https://vpc.console.alibabacloud.com/sflowlog/${region}/flowlogs`,
  database: (region: string, id: string, service: "rds" | "redis" | "mongodb" = "rds") =>
    service === "redis"
      ? `https://kvstore.console.alibabacloud.com/Redis/instance/${region}/${id}/info`
      : service === "mongodb"
        ? `https://mongodb.console.alibabacloud.com/replicate/${region}/instances/${id}/basicInfo`
        : `https://rdsnext.console.alibabacloud.com/detail/${id}/basicInfo?region=${region}`,
  loadBalancer: (region: string, type: string, id: string) =>
    type === "clb" ? `https://slb.console.alibabacloud.com/slb/${region}/slbs/${id}` : `https://slb.console.alibabacloud.com/${type}/${region}/${type}s/${id}`,
  function: (region: string, name: string) => `https://fcnext.console.alibabacloud.com/${region}/functions/${encodeURIComponent(name)}`,
  kms: (region: string) => `https://yundun.console.alibabacloud.com/?p=kms#/key/list?region=${region}`,
  secrets: (region: string) => `https://yundun.console.alibabacloud.com/?p=kms#/secret/list?region=${region}`,
  cluster: (region: string, id: string) => `https://cs.console.alibabacloud.com/#/k8s/cluster/${id}/v2/info/overview?region=${region}`,
  actiontrail: "https://actiontrail.console.alibabacloud.com/#/trail/list",
  securityCenter: "https://yundun.console.alibabacloud.com/?p=sas#/assetsManage",
  cdnDomain: (name: string) => `https://cdn.console.alibabacloud.com/domain/detail/${encodeURIComponent(name)}/https`,
  dnsDomain: (name: string) => `https://dns.console.alibabacloud.com/#/dns/setting/${encodeURIComponent(name)}`,
  home: CONSOLE,
};

/** A region that runs something: instances, databases, load balancers or functions. Per-region settings only matter there. */
export const inUse = (r: AlibabaRegion): boolean =>
  !!(r.instances?.some((i) => i.running) || r.databases?.length || r.loadBalancers?.length || r.functions?.length);

/** Whether an open rule covers a port. "all" is every port of every protocol. */
export const ruleOpens = (r: AlibabaSecurityRule, port: number): boolean =>
  r.protocol === "all" || (r.protocol === "tcp" && r.from != null && r.to != null && r.from <= port && port <= r.to);

/** Whether an open rule of a security group covers a port. */
export const opens = (g: AlibabaSecurityGroup, port: number): boolean => g.open.some((r) => ruleOpens(r, port));

/** Whether a group lets the internet reach the web ports. */
export const opensWeb = (g: AlibabaSecurityGroup): boolean => opens(g, 443) || opens(g, 80);

/** The interfaces a security group is attached to: what its rules really expose. */
export const usedBy = (region: AlibabaRegion, groupId: string): AlibabaInterface[] =>
  (region.interfaces ?? []).filter((i) => i.securityGroups.includes(groupId));

/**
 * Whether an interface is the account's own server: an instance or an interface it attached. Load balancers and the
 * interfaces Alibaba Cloud manages for its services (an ALB's or NLB's zone addresses, ALB_SYSTEM_SECURITY_GROUP…)
 * answer only on their listeners, so a wide group there opens nothing more; the listeners are judged on their own.
 */
export const isServer = (i: AlibabaInterface): boolean => i.kind === "instance" || i.kind === "network interface";

/** "tcp 22" or "tcp 8000-8100" or "all traffic", with where from. */
export const ruleText = (r: AlibabaSecurityRule): string =>
  `${r.protocol === "all" ? "all traffic" : `${r.protocol} ${r.from === r.to ? r.from : `${r.from}-${r.to}`}`} from ${r.cidr}`;

/** The 16-digit account in a trust policy's principal: an account ID, or the ARN of its root, a user or a role. */
export const accountOf = (principal: string): string | null =>
  /^(\d{16})(@|$)|^acs:ram::(\d{16}):/
    .exec(principal)
    ?.slice(1)
    .find((x) => x && /^\d/.test(x)) ?? null;

export const days = (from: number | null, now: number): number | null => (from == null ? null : Math.floor((now - from) / 86_400_000));
export const date = (t: number | null): string => (t ? new Date(t).toISOString().slice(0, 10) : "unknown");
export const list = (items: string[]) => `${items.slice(0, 3).join(", ")}${items.length > 3 ? ` and ${items.length - 3} more` : ""}`;
