// Every internet (Sonar) check module, in the order they run. Adding one: write it
// with defineChecks (./define.ts), list it here, and add a failing case to
// test/internet-cases.ts.

import dns from "./dns.ts";
import certificates from "./certificates.ts";
import services from "./services.ts";
import origins from "./origins.ts";
import routing from "./routing.ts";
import type { CheckModule } from "../../../core/checks/define.ts";

export const INTERNET_MODULES = [dns, certificates, services, origins, routing] as const;

type IdsOf<M> = M extends CheckModule<infer Id, infer _C, infer _S> ? Id : never;
export type InternetCheckId = IdsOf<(typeof INTERNET_MODULES)[number]>;
