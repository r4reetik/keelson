// ActionTrail, VPC flow logs and Security Center's agent. Like AWS's CloudTrail and
// flow log checks, per-region settings are judged only where something runs.
// Prowler's checks for Log Service alert rules and Security Center's paid editions
// are left out: they test compliance wording or a purchase, not exposure.

import { defineChecks, inUse } from "./define.ts";
import { GLOBAL } from "../types.ts";

export default defineChecks(
  {
    "LMO-001": {
      category: "Monitoring",
      severity: "high",
      docs: "https://www.alibabacloud.com/help/en/actiontrail/user-guide/create-a-single-account-trail",
      requires: ["actiontrail"],
      title: "ActionTrail doesn't record every region",
      why: "Without a trail that records reads and writes in every region and delivers them to OSS or Log Service, the account keeps only 90 days of events in the console, and nothing at all an investigator can query after that. A break-in would leave no lasting record of what was done.",
      fix: "In the ActionTrail console → Trails → Create Trail, choose All Regions and All event types (Read and Write), and deliver the events to a private OSS bucket or a Log Service project. Keep the trail turned on.",
    },
    "LMO-002": {
      category: "Monitoring",
      severity: "low",
      docs: "https://www.alibabacloud.com/help/en/vpc/user-guide/flow-logs",
      requires: ["vpcs", "instances", "databases", "loadBalancers"],
      title: "VPC with running resources has no flow logs",
      why: "Without flow logs, nobody can tell after the fact which addresses talked to what in the VPC: an investigation has no record of connections in or out.",
      fix: "In the VPC console → Flow Logs, create a flow log for the VPC (or its vSwitches) that delivers to Log Service.",
    },
    "LMO-003": {
      category: "Monitoring",
      severity: "low",
      docs: "https://www.alibabacloud.com/help/en/security-center/user-guide/install-the-security-center-agent",
      requires: ["securityCenter", "instances"],
      title: "Running instance isn't protected by Security Center's agent",
      why: "Security Center's agent, included for free, detects brute-force logins, web shells and known vulnerabilities on the instance. Without it, a compromise of this server raises no alert.",
      fix: "In the Security Center console → Assets → Servers, install the agent on the instance (one click for ECS), or with Cloud Assistant across many instances.",
    },
  },
  ({ inv, d }, report) => {
    if (inv.trails) {
      const good = inv.trails.filter((t) => t.allRegions && t.allEvents && t.logging && t.delivers);
      const best = inv.trails.find((t) => t.allRegions) ?? inv.trails[0];
      report("LMO-001", {
        zone: GLOBAL,
        resource: good[0]?.name ?? best?.name ?? "account",
        pass: good.length > 0,
        detail: good.length
          ? ""
          : !inv.trails.length
            ? "No trail"
            : best && !best.logging
              ? `Trail ${best.name} is turned off`
              : best && !best.allRegions
                ? `Trail ${best.name} records only ${best.homeRegion}`
                : best && !best.allEvents
                  ? `Trail ${best.name} records only some events`
                  : `Trail ${best?.name} delivers its events nowhere`,
        link: d.actiontrail,
      });
    }

    for (const r of inv.regions) {
      if (!inUse(r)) continue;
      // A VPC is judged when something that runs in a VPC is there.
      const running = new Set([
        ...(r.instances ?? []).filter((i) => i.running).flatMap((i) => i.vpcId ?? []),
        ...(r.loadBalancers ?? []).flatMap((l) => l.vpcId ?? []),
      ]);
      for (const v of r.vpcs ?? [])
        if (v.flowLogs != null && running.has(v.id))
          report("LMO-002", { zone: r.name, resource: v.id, pass: v.flowLogs, detail: v.flowLogs ? "" : "No active flow log", link: d.flowLogs(r.name) });
      if (inv.protectedInstances)
        for (const i of (r.instances ?? []).filter((x) => x.running))
          report("LMO-003", {
            zone: r.name,
            resource: i.name ? `${i.name} (${i.id})` : i.id,
            pass: inv.protectedInstances.has(i.id),
            detail: inv.protectedInstances.has(i.id) ? "" : "The Security Center agent isn't installed or isn't online",
            link: d.securityCenter,
          });
    }
  },
);
