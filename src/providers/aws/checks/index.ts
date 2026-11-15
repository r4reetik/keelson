// Every AWS check module, in the order they run. Adding one: write it with
// defineChecks (./define.ts), list it here, and add a failing case to
// test/aws-cases.ts.

import identity from "./identity.ts";
import storage from "./storage.ts";
import network from "./network.ts";
import compute from "./compute.ts";
import data from "./data.ts";
import edge from "./edge.ts";
import dns from "./dns.ts";
import monitoring from "./monitoring.ts";
import cloudflareLinks from "./cloudflare-links.ts";
import githubActions from "./github-actions.ts";
import access from "./access.ts";
import workloads from "./workloads.ts";
import datastores from "./datastores.ts";
import containers from "./containers.ts";
import secrets from "./secrets.ts";
import messaging from "./messaging.ts";
import logging from "./logging.ts";
import web from "./web.ts";
import type { CheckModule } from "../../../core/checks/define.ts";

export const AWS_MODULES = [
  identity,
  access,
  storage,
  network,
  compute,
  workloads,
  containers,
  data,
  datastores,
  secrets,
  messaging,
  edge,
  web,
  dns,
  monitoring,
  logging,
  cloudflareLinks,
  githubActions,
] as const;

type IdsOf<M> = M extends CheckModule<infer Id, infer _C, infer _S> ? Id : never;
export type AwsCheckId = IdsOf<(typeof AWS_MODULES)[number]>;
