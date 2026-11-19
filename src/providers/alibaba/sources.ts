// Every Alibaba Cloud data source a scan reads. Like the other providers'
// registries, each source has a coverage label, the RAM actions that grant it (from
// src/shared/alibaba.ts, which is also the policy Keelson asks for), and an optional
// probe for the Add accounts flow.

import { ALIBABA_ACTIONS } from "../../shared/alibaba.ts";
import type { AlibabaClient } from "./client.ts";

export interface AlibabaSource {
  label: string;
  /** The RAM actions that read it. */
  permission: string;
  /** A cheap request that proves the AccessKey can read this source (Add accounts). */
  probe?: (c: AlibabaClient) => Promise<unknown>;
  /** Read in every enabled region. A region that refuses is left out rather than failing the source. */
  regional?: boolean;
}

/** Where global APIs and probes are asked: every account can call Hangzhou's endpoints, wherever its resources are. */
export const HOME_REGION = "cn-hangzhou";

type Key = keyof typeof ALIBABA_ACTIONS | "registryNetwork" | "trivy" | "kev";
const LABELS: Record<Key, { label: string; probe?: AlibabaSource["probe"]; regional?: boolean; permission?: string }> = {
  identity: { label: "Account identity and alias", probe: (c) => c.rpc("sts", null, "GetCallerIdentity") },
  accountSecurity: {
    label: "Main account's AccessKeys and MFA (RAM's security practice report)",
    probe: (c) => c.optional(() => c.rpc("ims", null, "GetAccountSecurityPracticeReport")),
  },
  ramUsers: {
    label: "RAM users, their AccessKeys, MFA and console access",
    probe: (c) => c.rpc("ims", null, "ListUsers", { MaxItems: "1" }),
  },
  passwordPolicy: { label: "RAM password policy", probe: (c) => c.rpc("ram", null, "GetPasswordPolicy") },
  securityPreference: {
    label: "RAM security settings: MFA at sign-in, and whether users manage their own AccessKeys",
    probe: (c) => c.rpc("ims", null, "GetSecurityPreference"),
  },
  ramPolicies: {
    label: "RAM policies and who they're attached to (documents reduced to what they allow, never stored)",
    probe: (c) => c.rpc("ram", null, "ListPolicies", { PolicyType: "Custom", MaxItems: "1" }),
  },
  ramRoles: { label: "RAM roles and their trust policies", probe: (c) => c.rpc("ram", null, "ListRoles", { MaxItems: "1" }) },
  ossAccount: { label: "OSS Block Public Access for the account", probe: (c) => c.optional(() => c.oss(null, { publicAccessBlock: "" })) },
  ossBuckets: { label: "OSS buckets", probe: (c) => c.oss(null, { "max-keys": "1" }) },
  ossBucketAccess: { label: "OSS bucket ACLs and Block Public Access" },
  bucketPolicies: { label: "OSS bucket policies (reduced to who they allow, never stored)" },
  regions: { label: "Enabled regions", probe: (c) => c.rpc("ecs", HOME_REGION, "DescribeRegions") },
  securityGroups: {
    label: "Security groups and their rules",
    probe: (c) => c.rpc("ecs", HOME_REGION, "DescribeSecurityGroups", { PageSize: "1" }),
    regional: true,
  },
  instances: { label: "ECS instances", probe: (c) => c.rpc("ecs", HOME_REGION, "DescribeInstances", { PageSize: "1" }), regional: true },
  networkInterfaces: {
    label: "Network interfaces and EIPs",
    probe: (c) => c.rpc("vpc", HOME_REGION, "DescribeEipAddresses", { PageSize: "1" }),
    regional: true,
  },
  userData: { label: "Instance start-up scripts (scanned for credentials, never stored)", regional: true },
  launchTemplates: {
    label: "ECS launch templates (start-up scripts scanned for credentials, never stored)",
    probe: (c) => c.rpc("ecs", HOME_REGION, "DescribeLaunchTemplates", { PageSize: "1" }),
    regional: true,
  },
  disks: { label: "Cloud disks and encryption by default", probe: (c) => c.rpc("ecs", HOME_REGION, "DescribeDisks", { PageSize: "1" }), regional: true },
  images: { label: "Custom images and who they're shared with", regional: true },
  vpcs: { label: "VPCs and flow logs", probe: (c) => c.rpc("vpc", HOME_REGION, "DescribeVpcs", { PageSize: "1" }), regional: true },
  loadBalancers: {
    label: "Load balancers (ALB, NLB, CLB) and listeners",
    probe: (c) => c.rpc("alb", HOME_REGION, "ListLoadBalancers", { MaxResults: "1" }),
    regional: true,
  },
  lbAccess: { label: "CLB listeners' ports and access control lists", regional: true },
  lbRouting: { label: "Load balancer rules, server groups and their servers", regional: true },
  databases: {
    label: "ApsaraDB RDS instances, their whitelists, TLS and encryption",
    probe: (c) => c.rpc("rds", HOME_REGION, "DescribeDBInstances", { PageSize: "30" }),
    regional: true,
  },
  redis: {
    label: "Tair (Redis) instances: endpoints, whitelists, password-free access and TLS",
    probe: (c) => c.rpc("kvstore", HOME_REGION, "DescribeInstances", { PageSize: "1" }),
    regional: true,
  },
  mongodb: {
    label: "ApsaraDB for MongoDB instances: endpoints, whitelists, password-free access and TLS",
    probe: (c) => c.rpc("dds", HOME_REGION, "DescribeDBInstances", { PageSize: "1" }),
    regional: true,
  },
  functions: { label: "Function Compute functions and triggers (environment variables scanned for credentials, never stored)", regional: true },
  registries: {
    label: "Container Registry Enterprise Edition instances, their repositories and image tags",
    probe: (c) => c.rpc("cr", HOME_REGION, "ListInstance", { PageNo: "1", PageSize: "1" }),
    regional: true,
  },
  imagePull: {
    label: "Pulling images from Container Registry, for Trivy to scan",
    permission: "cr:GetAuthorizationToken, cr:PullRepository",
  },
  registryNetwork: {
    label: "Connecting to Container Registry from where Keelson runs, to pull images",
    permission:
      "A connection to each instance's registry host. An instance whose internet access is off, or admits only an allowlist, refuses others: add the address Keelson connects from to the allowlist (Container Registry console, the instance's Access Control, Internet), or run Keelson in a VPC linked to the instance",
  },
  containerGroups: {
    label: "Elastic Container Instance groups and their images (environment variables dropped)",
    probe: (c) => c.rpc("eci", HOME_REGION, "DescribeContainerGroups", { RegionId: HOME_REGION, Limit: "1" }),
    regional: true,
  },
  trivy: {
    label: "Packages, vulnerabilities and stored credentials in container images (Aqua Trivy)",
    permission:
      "Trivy installed where Keelson runs: on the PATH, or its path in KEELSON_TRIVY (not in the Docker image yet). Its database, about 1.6 GB, is downloaded into the data folder",
  },
  kev: {
    label: "CISA's catalog of known exploited vulnerabilities",
    permission: "None: a public file, read from www.cisa.gov without a credential",
  },
  kms: {
    label: "KMS keys and secrets (names and dates, never values)",
    probe: (c) => c.rpc("kms", HOME_REGION, "ListKeys", { PageSize: "1" }),
    regional: true,
  },
  clusters: { label: "Container Service (ACK) clusters", probe: (c) => c.roa("cs", HOME_REGION, "DescribeClustersV1", "/api/v1/clusters", { page_size: "1" }) },
  actiontrail: {
    label: "ActionTrail trails",
    probe: (c) => c.rpc("actiontrail", HOME_REGION, "DescribeTrails"),
  },
  securityCenter: {
    label: "Security Center agents",
    probe: (c) => c.rpc("sas", null, "DescribeCloudCenterInstances", { PageSize: "1", CurrentPage: "1" }),
  },
  cdn: { label: "CDN domains", probe: (c) => c.rpc("cdn", null, "DescribeUserDomains", { PageSize: "1" }) },
  dns: { label: "Alibaba Cloud DNS domains and records", probe: (c) => c.rpc("alidns", null, "DescribeDomains", { PageSize: "1" }) },
};

export type AlibabaSourceKey = Key;
export const ALIBABA_SOURCES = Object.fromEntries(
  Object.entries(LABELS).map(([k, v]) => [
    k,
    { ...v, permission: v.permission ?? ((ALIBABA_ACTIONS as Record<string, readonly string[]>)[k] ?? []).join(", ") },
  ]),
) as Record<AlibabaSourceKey, AlibabaSource>;
export const ALIBABA_SOURCE_KEYS = Object.keys(LABELS) as AlibabaSourceKey[];
