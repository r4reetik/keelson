// OSS: whether the account blocks public access, buckets that are public through
// their ACL or policy once the bucket's and the account's blocks are taken into
// account, and bucket policies that let other accounts in. A bucket anyone can
// write to is worse than one anyone can read, and so is one ActionTrail delivers
// the account's audit log to. A public bucket that Alibaba Cloud CDN serves can
// usually be private: the CDN reads private buckets with its own role.

import { defineChecks, accountOf, list } from "./define.ts";
import { GLOBAL, type AlibabaBucket } from "../types.ts";

/** Buckets Container Registry (ACR) creates and manages for its own images: not the account's to configure. */
export const serviceBucket = (name: string) => /^cri-[a-z0-9]+-registry$/.test(name);

/** Whether anyone can write to a public bucket: a public-read-write ACL, or a policy that lets anyone upload or delete. */
const writable = (b: AlibabaBucket) => b.acl === "public-read-write" || !!b.policy?.publicWrite;

/** How a bucket is open to the internet after both blocks apply, or [] when it isn't. */
export function publicThrough(b: AlibabaBucket, accountBlock: boolean | null): string[] {
  if (b.blockPublicAccess || accountBlock) return [];
  return [
    b.acl === "public-read-write" ? "its ACL, which lets anyone read and write" : b.acl === "public-read" ? "its ACL, which lets anyone read" : null,
    b.policy?.public ? (b.policy.publicWrite ? "its bucket policy, which lets anyone write" : "its bucket policy") : null,
  ].flatMap((x) => x ?? []);
}

export default defineChecks(
  {
    "LOS-001": {
      category: "Attack surface",
      severity: "medium",
      docs: "https://www.alibabacloud.com/help/en/oss/user-guide/block-public-access",
      requires: ["ossAccount", "ossBuckets"],
      title: "OSS Block Public Access is off for the account",
      why: "Without the account-wide block, any bucket can be made public by one ACL or policy change, now or later. With it on, a mistake on a single bucket can't expose data.",
      fix: "In the OSS console → Block Public Access (on the overview page), turn it on for the account. Buckets that must be public (a static site, for example) are better served through CDN with origin fetch from a private bucket.",
    },
    "LOS-002": {
      category: "Attack surface",
      severity: "high",
      docs: "https://www.alibabacloud.com/help/en/oss/user-guide/oss-bucket-acl",
      requires: ["ossAccount", "ossBuckets", "ossBucketAccess", "bucketPolicies"],
      attackPath: true,
      title: "OSS bucket is public",
      why: "Anyone on the internet can list and download the bucket's objects, with no record of who did. Public buckets are the most common source of leaked data in object storage, because whatever is uploaded later is public too. A bucket anyone can also write to can be filled with malware served from your name, overwritten or emptied, and runs up your bill.",
      fix: '1. If the bucket shouldn\'t be public, open it in OSS → Permission Control and turn on Block Public Access. 2. Set its ACL to private and remove statements that allow "*" from its bucket policy. 3. If it serves a website, put CDN in front with private origin fetch, then make the bucket private.',
    },
    "LOS-003": {
      category: "Attack surface",
      severity: "low",
      docs: "https://www.alibabacloud.com/help/en/oss/user-guide/block-public-access",
      requires: ["ossAccount", "ossBuckets", "ossBucketAccess"],
      title: "OSS bucket has no Block Public Access of its own",
      why: "The bucket is private today, but neither it nor the account blocks public access, so one ACL or policy change makes it public.",
      fix: '1. If the bucket serves a website or downloads through Alibaba Cloud CDN, turn on access to private OSS buckets in the CDN domain\'s origin settings, then make the bucket private. 2. Otherwise set its ACL to private and remove the policy statement for "*". 3. Then turn on Block Public Access for the bucket, in OSS → the bucket → Permission Control.',
    },
    "LOS-004": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://www.alibabacloud.com/help/en/oss/user-guide/oss-bucket-policy",
      requires: ["bucketPolicies"],
      title: "Bucket policy lets an Alibaba Cloud account outside the entity in",
      why: "The bucket's policy grants another Alibaba Cloud account access. If it isn't one of yours, that company, and anyone who gets into its account, can reach the bucket.",
      fix: "1. If the account is yours, add it to this entity in Keelson. 2. Otherwise edit the bucket's policy in OSS → Permission Control → Bucket Policy and remove the account, or limit it to the paths and actions it needs.",
    },
  },
  ({ inv, d, related }, report) => {
    if (inv.ossBlock !== undefined && inv.buckets) {
      const account = inv.ossBlock;
      if (inv.buckets.length)
        report("LOS-001", { zone: GLOBAL, resource: "account", pass: !!account, detail: account ? "" : "Off for the account", link: d.ossOverview });
      const trails = new Set((inv.trails ?? []).flatMap((t) => (t.ossBucket ? [t.ossBucket] : [])));
      // CDN domains whose origin is a bucket's endpoint ("<bucket>.oss-<region>.aliyuncs.com").
      const cdnOf = (b: string) => (inv.cdnDomains ?? []).filter((c) => c.origins.some((o) => o.startsWith(`${b}.oss-`))).map((c) => c.name);
      for (const b of inv.buckets) {
        // A bucket whose settings couldn't be read is left out, not passed.
        if (b.acl === undefined || b.blockPublicAccess === undefined || b.policy === undefined) continue;
        const through = publicThrough(b, account);
        const audit = trails.has(b.name);
        const cdn = through.length ? cdnOf(b.name) : [];
        report("LOS-002", {
          zone: b.region,
          resource: b.name,
          pass: !through.length,
          severity: through.length && (writable(b) || audit) ? "critical" : undefined,
          detail: through.length
            ? `Public through ${through.join(" and ")}${audit ? ". ActionTrail delivers the account's audit log to it, so anyone can read it" : ""}${cdn.length ? `. Served through the CDN domain${cdn.length === 1 ? "" : "s"} ${list(cdn)}, which can read a private bucket` : ""}`
            : "",
          evidence: through.length
            ? {
                chain: [
                  ...through.map((t) => ({ label: "Public access", value: t })),
                  ...(audit ? [{ label: "ActionTrail", value: "delivers the account's audit log to this bucket" }] : []),
                  ...cdn.map((c) => ({ label: "Alibaba Cloud CDN", value: `${c} fetches from this bucket` })),
                  { label: "Bucket's Block Public Access", value: b.blockPublicAccess ? "On" : "Off" },
                  { label: "Account's Block Public Access", value: account ? "On" : "Off" },
                ],
              }
            : null,
          link: d.bucket(b.name, b.region),
        });
        if (!account && !through.length && !serviceBucket(b.name))
          report("LOS-003", {
            zone: b.region,
            resource: b.name,
            pass: !!b.blockPublicAccess,
            detail: b.blockPublicAccess ? "" : "Off",
            link: d.bucket(b.name, b.region),
          });
      }
    }

    // Which accounts belong to the entity is only known once every Alibaba Cloud account in it has been scanned.
    if (inv.buckets && !related.unknown.includes("alibabaAccounts")) {
      const ours = new Set([inv.accountId, ...(related.alibabaAccounts ?? [])]);
      for (const b of inv.buckets) {
        if (!b.policy) continue;
        const outside = [...new Set(b.policy.otherAccounts.map((a) => accountOf(a) ?? a))].filter((a) => !ours.has(a));
        report("LOS-004", {
          zone: b.region,
          resource: b.name,
          pass: !outside.length,
          detail: outside.length ? `Allows account${outside.length === 1 ? "" : "s"} ${outside.join(", ")}` : "",
          link: d.bucket(b.name, b.region),
        });
      }
      report.passIfNone("LOS-004", "account", GLOBAL);
    }
  },
);
