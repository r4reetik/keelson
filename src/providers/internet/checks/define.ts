// How internet (Sonar) check modules are written: the same shape as the other
// providers' (see src/core/checks/define.ts), over an entity's outside view. A
// finding's `zone` is the entity's domain it is under, or null for an address no
// hostname of the entity points at.
//
//   export default defineChecks({
//     "NDS-001": { category: "DNS", severity: "low", title: "…", why: "…", fix: "…", requires: ["related"] },
//   }, ({ inv }, report) => {
//     for (const d of inv.domains) report("NDS-001", { zone: d.name, resource: d.name, pass: !!d.dnsAt });
//   });

import { checksFor } from "../../../core/checks/define.ts";
import type { EngineOptions } from "../../../core/types.ts";
import type { InternetSourceKey } from "../sources.ts";
import type { Address, InternetInventory, Related } from "../types.ts";

export interface InternetContext {
  inv: InternetInventory;
  opts: EngineOptions;
  related: Related;
}

export const defineChecks = checksFor<InternetContext, InternetSourceKey>();

/** Shodan's page for an address. */
export const shodanLink = (ip: string) => `https://www.shodan.io/host/${encodeURIComponent(ip)}`;

/** The domain a finding about an address belongs to: the first of the entity's hostnames that point at it. */
export const zoneOf = (inv: InternetInventory, a: Address): string | null =>
  a.hosts.map((h) => inv.hosts.find((x) => x.name === h.name)?.domain).find(Boolean) ?? null;

/** Who has the address, in a sentence for evidence. */
export const ownerOf = (a: Address): string =>
  a.heldBy
    ? "An AWS account in this entity holds it"
    : `Not held by a connected account; the entity's DNS points ${
        a.hosts.length
          ? a.hosts
              .map((h) => h.name)
              .slice(0, 3)
              .join(", ")
          : "a hostname"
      } at it`;

/** When Shodan last saw something, for evidence. */
export const seenWhen = (a: Address): string => (a.shodan?.seen && a.shodan.lastSeen ? `, last seen ${a.shodan.lastSeen.slice(0, 10)}` : "");
