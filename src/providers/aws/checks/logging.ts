// The account's record of what happened: CloudTrail in every region with log files
// that can be checked for tampering, AWS Config where workloads run, and logs of
// the requests a WAF web ACL sees.

import { defineChecks, inUse } from "./define.ts";
import { GLOBAL } from "../types.ts";

export default defineChecks(
  {
    "AMO-004": {
      category: "Monitoring",
      severity: "high",
      docs: "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html",
      requires: ["cloudtrail"],
      title: "CloudTrail doesn't record every region",
      why: "API calls in the regions no trail covers aren't kept anywhere beyond 90 days of event history. Attackers often work in regions nobody uses, to start instances or create keys, precisely because nobody looks there.",
      fix: "In CloudTrail → Trails → Create trail, create one trail that applies to all regions and logs management events, or an organization trail from the management account. Make sure it is logging.",
    },
    "AMO-005": {
      category: "Monitoring",
      severity: "low",
      docs: "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html",
      requires: ["cloudtrail"],
      title: "CloudTrail log files can't be checked for tampering",
      why: "Without log file validation, someone who reaches the log bucket can change or delete entries, and nothing shows that the record of their activity was altered.",
      fix: "In CloudTrail → the trail → General details → Edit, turn on Log file validation.",
    },
    "AMO-006": {
      category: "Monitoring",
      severity: "low",
      docs: "https://docs.aws.amazon.com/config/latest/developerguide/gs-console.html",
      requires: ["config", "instances", "databases", "loadBalancers", "functions"],
      title: "AWS Config isn't recording in a region that runs workloads",
      why: "There is no history of how resources were configured. After an incident you can't tell when a security group opened, a bucket became public or a role changed.",
      fix: "In AWS Config → Settings, turn on recording for the region (all resource types, or the ones you care about), or deploy it to every account and region with a conformance pack or Control Tower.",
    },
    "AMO-007": {
      category: "Monitoring",
      severity: "low",
      docs: "https://docs.aws.amazon.com/waf/latest/developerguide/logging.html",
      requires: ["waf"],
      title: "WAF web ACL doesn't log requests",
      why: "There is no record of which requests the web ACL blocked or let through, so an attack it missed, or a rule that blocks real users, goes unnoticed.",
      fix: "In WAF & Shield → Web ACLs → the web ACL → Logging and metrics, enable logging to CloudWatch Logs, S3 or Firehose. Redact headers that carry credentials.",
    },
  },
  ({ inv, d }, report) => {
    // A region is recorded when a trail that covers it is logging; one whose trails can't be told (an organization's,
    // from a member account) isn't judged.
    const known = inv.regions.filter((r) => r.trails && !(r.trails.length && r.trails.every((t) => t.logging == null)));
    if (known.length) {
      const missing = known.filter((r) => !r.trails!.some((t) => t.logging === true)).map((r) => r.name);
      report("AMO-004", {
        zone: GLOBAL,
        resource: "CloudTrail",
        pass: !missing.length,
        detail: missing.length
          ? missing.length === known.length
            ? "No trail is logging in any region"
            : `No logging trail covers ${missing.slice(0, 6).join(", ")}${missing.length > 6 ? ` and ${missing.length - 6} more` : ""}`
          : "",
        link: "https://console.aws.amazon.com/cloudtrail/home#/trails",
      });
    }
    const seen = new Set<string>();
    for (const r of inv.regions)
      for (const t of r.trails ?? []) {
        // Each trail once, and only the account's own: an organization's trail is configured in its management account.
        if (!t.own || seen.has(t.arn)) continue;
        seen.add(t.arn);
        report("AMO-005", {
          zone: t.multiRegion ? GLOBAL : t.homeRegion,
          resource: t.name,
          pass: t.validation,
          detail: t.validation ? "" : "Log file validation is off",
          link: `https://${t.homeRegion}.console.aws.amazon.com/cloudtrail/home?region=${t.homeRegion}#/trails/${encodeURIComponent(t.arn)}`,
        });
      }
    for (const r of inv.regions) {
      if (r.configRecording != null && inUse(r))
        report("AMO-006", {
          zone: r.name,
          resource: r.name,
          pass: r.configRecording,
          detail: r.configRecording ? "" : "No configuration recorder is recording",
          link: d.console(r.name, "config", "/settings"),
        });
      for (const acl of r.webAcls ?? [])
        if (acl.logging != null)
          report("AMO-007", {
            zone: acl.scope === "CLOUDFRONT" ? GLOBAL : r.name,
            resource: acl.name,
            pass: acl.logging,
            detail: acl.logging ? "" : "Logging is off",
            link: d.console(r.name, "wafv2", `/webacls?region=${acl.scope === "CLOUDFRONT" ? "global" : r.name}`),
          });
    }
  },
);
