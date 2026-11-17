// Every Alibaba Cloud check module, in the order they run. Adding one: write it
// with defineChecks (./define.ts), list it here, and add a failing case to
// test/alibaba-cases.ts.

import identity from "./identity.ts";
import access from "./access.ts";
import storage from "./storage.ts";
import network from "./network.ts";
import compute from "./compute.ts";
import data from "./data.ts";
import workloads from "./workloads.ts";
import secrets from "./secrets.ts";
import edge from "./edge.ts";
import dns from "./dns.ts";
import monitoring from "./monitoring.ts";
import cloudflareLinks from "./cloudflare-links.ts";
import type { CheckModule } from "../../../core/checks/define.ts";

export const ALIBABA_MODULES = [identity, access, storage, network, compute, data, workloads, secrets, edge, dns, monitoring, cloudflareLinks] as const;

type IdsOf<M> = M extends CheckModule<infer Id, infer _C, infer _S> ? Id : never;
export type AlibabaCheckId = IdsOf<(typeof ALIBABA_MODULES)[number]>;
