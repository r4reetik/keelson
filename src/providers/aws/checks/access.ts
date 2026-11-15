// Access that IAM's own lists don't show at a glance: identities whose policies let
// them make themselves administrators, Cognito identity pools that hand AWS
// credentials to anyone, user pools without multi-factor sign-in, buckets that let
// accounts outside the entity in, and transit gateways that join any shared VPC.

import { defineChecks } from "./define.ts";
import { GLOBAL } from "../types.ts";

/**
 * AWS's own accounts that write load balancer access logs into a bucket, by region. Their account IDs appear in the
 * bucket policies AWS documents, so they aren't another company's.
 */
const ELB_LOG_ACCOUNTS = new Set([
  "127311923021",
  "033677994240",
  "027434742980",
  "797873946194",
  "098369216593",
  "754344448648",
  "589379963580",
  "718504428378",
  "383597477331",
  "600734575887",
  "114774131450",
  "783225319266",
  "582318560864",
  "985666609251",
  "054676820928",
  "156460612806",
  "652711504416",
  "635631232127",
  "009996457667",
  "897822967062",
  "076674570225",
  "507241528517",
  "048591011584",
  "190560391635",
]);

export default defineChecks(
  {
    "AID-013": {
      category: "Identity & access",
      severity: "high",
      docs: "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_manage-edit.html",
      requires: ["iamDetails"],
      attackPath: true,
      title: "IAM identity can give itself more access",
      why: "Its policies aren't administrator access, but they let it get there: change or attach a policy, create keys or passwords for other users, or hand a stronger role to an instance or function it starts. Whoever holds its credentials can take over the account.",
      fix: '1. Open the policy named in the finding. 2. Remove the IAM actions listed, or limit them to named resources (Resource with an ARN, not "*"). 3. For iam:PassRole, name the roles it may pass and add an iam:PassedToService condition.',
    },
    "AID-014": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/cognito/latest/developerguide/identity-pools.html#authenticated-and-unauthenticated-identities",
      requires: ["cognito"],
      title: "Cognito identity pool gives AWS credentials to anyone",
      why: "Guest access is on, so anyone on the internet can get temporary AWS credentials for the pool's guest role, without signing in. Whatever that role may do, they can do.",
      fix: "In Cognito → Identity pools → the pool → User access, turn off Guest access. If guests need it, give the guest role only the few actions they need, on named resources.",
    },
    "AID-015": {
      category: "Identity & access",
      severity: "low",
      docs: "https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-mfa.html",
      requires: ["cognito"],
      title: "Cognito user pool doesn't offer multi-factor sign-in",
      why: "Users can only sign in with a password, so a reused or phished password is enough to take over their account in your application.",
      fix: "In Cognito → User pools → the pool → Authentication methods → Multi-factor authentication, choose Optional MFA (or Require MFA for staff-only pools) and turn on authenticator apps.",
    },
    "AS3-004": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-walkthroughs-managing-access-example2.html",
      requires: ["bucketPolicies"],
      title: "Bucket policy lets an AWS account outside the entity in",
      why: "Another AWS account can read or write the bucket with its own credentials. If it belongs to a former vendor or partner, or was never yours, it keeps that access, and you see none of its activity in your own logs.",
      fix: "1. Open the bucket → Permissions → Bucket policy. 2. If the account is one of yours, add it to this entity in Keelson. 3. Otherwise remove the statement that names it, or narrow it to the objects and actions it needs.",
    },
    "ANW-004": {
      category: "Attack surface",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/vpc/latest/tgw/tgw-transit-gateways.html#tgw-modifying",
      requires: ["transitGateways"],
      title: "Transit gateway joins shared VPCs without approval",
      why: "Any account the transit gateway is shared with can attach a VPC and reach the networks behind it, without anyone in this account accepting it.",
      fix: "In VPC → Transit gateways → the gateway → Modify, untick Auto accept shared attachments, and accept each attachment by hand.",
    },
  },
  ({ inv, d, related }, report) => {
    const link = { user: d.user, group: d.group, role: d.roleDetails };
    for (const e of inv.escalations ?? [])
      report("AID-013", {
        zone: GLOBAL,
        resource: e.name,
        pass: false,
        detail: `The ${e.kind} can use ${e.paths.join(", ")}, through ${e.via}`,
        link: link[e.kind](e.name),
      });
    if (inv.escalations) report.passIfNone("AID-013", "account", GLOBAL);

    // Accounts in the entity are ours; AWS's log-delivery accounts are AWS's.
    const ours = related.unknown.includes("awsAccounts") ? null : new Set([inv.accountId, ...(related.awsAccounts ?? [])]);
    if (ours)
      for (const b of inv.buckets ?? []) {
        if (!b.policy) continue;
        const outside = b.policy.otherAccounts.filter((a) => !ours.has(a) && !ELB_LOG_ACCOUNTS.has(a));
        report("AS3-004", {
          zone: b.region,
          resource: b.name,
          pass: !outside.length,
          confidence: "likely",
          detail: outside.length ? `The policy allows account${outside.length === 1 ? "" : "s"} ${outside.join(", ")}` : "",
          link: d.bucket(b.name),
        });
      }

    for (const r of inv.regions) {
      for (const p of r.identityPools ?? []) {
        const role = p.guestRole ? inv.roles?.find((x) => x.name === p.guestRole) : undefined;
        report("AID-014", {
          zone: r.name,
          resource: p.name,
          pass: !p.guest,
          // Guest credentials with administrator access are the whole account for anyone who asks.
          severity: p.guest && role?.admin ? "critical" : undefined,
          detail: p.guest
            ? `Guest access is on${p.guestRole ? `, as the role ${p.guestRole}${role?.admin ? ", which has administrator access" : ""}` : ""}`
            : "",
          link: d.console(r.name, "cognito/v2", `/identity/identity-pools/${encodeURIComponent(p.id)}`),
        });
      }
      for (const p of r.userPools ?? [])
        report("AID-015", {
          zone: r.name,
          resource: p.name,
          pass: p.mfa !== "OFF",
          detail: p.mfa === "OFF" ? "MFA is off" : "",
          link: d.console(r.name, "cognito/v2", `/idp/user-pools/${encodeURIComponent(p.id)}`),
        });
      for (const t of r.transitGateways ?? [])
        report("ANW-004", {
          zone: r.name,
          resource: t.id,
          pass: !t.autoAccept,
          detail: t.autoAccept ? "Auto accept shared attachments is on" : "",
          link: d.console(r.name, "vpcconsole", `TransitGatewayDetails:transitGatewayId=${t.id}`),
        });
    }
  },
);
