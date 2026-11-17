// ECS: the metadata service, start-up scripts and launch templates, disk
// encryption, custom images shared outside the entity, an internet-facing
// instance that runs as an administrator, and one that takes SSH passwords from
// the internet. The metadata service is judged by what it
// would give away: an instance's RAM role.

import { defineChecks, list, opens } from "./define.ts";
import { GLOBAL } from "../types.ts";

export default defineChecks(
  {
    "LEC-001": {
      category: "Platform",
      severity: "medium",
      docs: "https://www.alibabacloud.com/help/en/ecs/user-guide/view-instance-metadata",
      requires: ["instances"],
      title: "Instance's metadata service answers without a token",
      why: "In normal mode the metadata service answers any request from the instance, so a server-side request forgery in the application is enough to read the temporary credentials of the instance's RAM role. Security hardening mode requires a token that such a request can't get.",
      fix: "In the ECS console, open the instance → Modify Instance Metadata Access Mode and choose Security Hardening Mode (tokens required), after checking that the software on it uses a current SDK or Cloud Assistant.",
    },
    "LEC-002": {
      category: "Platform",
      severity: "low",
      docs: "https://www.alibabacloud.com/help/en/ecs/user-guide/encryption-overview",
      requires: ["disks", "instances"],
      title: "Cloud disks aren't encrypted by default",
      why: "Unlike some clouds, Alibaba Cloud doesn't encrypt ECS disks unless asked. New disks, and every snapshot and image made from them, are stored unencrypted unless whoever creates them remembers to ask, and a snapshot shared or copied by mistake carries the data in the clear. Encryption by default makes every new disk encrypted with no change to how instances use it.",
      fix: "1. In the ECS console → Block Storage → Cloud Disks, turn on Account-level Encryption by Default for the region. 2. Existing disks stay as they are: re-create the ones holding sensitive data from an encrypted snapshot copy during a maintenance window.",
    },
    "LEC-004": {
      category: "Secrets",
      severity: "high",
      docs: "https://www.alibabacloud.com/help/en/ecs/user-guide/customize-the-initialization-configuration-for-an-instance",
      requires: ["userData", "instances"],
      title: "Credential in an instance's start-up script",
      why: "User data is readable by anyone who can describe the instance, and from inside the instance through the metadata service. A token or key written into it is shared with everyone who has either.",
      fix: "1. Rotate the credential. 2. Store it in KMS Secrets Manager and have the script fetch it at boot with the instance's RAM role. 3. Replace the user data (the instance must be stopped to change it).",
    },
    "LEC-005": {
      category: "Platform",
      severity: "medium",
      docs: "https://www.alibabacloud.com/help/en/ecs/user-guide/view-instance-metadata",
      requires: ["launchTemplates"],
      title: "Launch template lets instances answer metadata requests without a token",
      why: "Every instance launched from this template, by a scaling group or by hand, starts in normal mode, where a server-side request forgery can read its RAM role's credentials.",
      fix: "Create a new version of the template with Security Hardening Mode for the metadata service, and make it the default version.",
    },
    "LEC-006": {
      category: "Secrets",
      severity: "high",
      docs: "https://www.alibabacloud.com/help/en/ecs/user-guide/customize-the-initialization-configuration-for-an-instance",
      requires: ["launchTemplates"],
      title: "Credential in a launch template's start-up script",
      why: "The template's user data is readable by anyone who can describe launch templates, and every instance launched from it carries the credential in its metadata.",
      fix: "1. Rotate the credential. 2. Store it in KMS Secrets Manager and fetch it at boot with the instance's RAM role. 3. Create a new template version without it, make that the default, and delete the old versions.",
    },
    "LEC-007": {
      category: "Identity & access",
      severity: "high",
      docs: "https://www.alibabacloud.com/help/en/ecs/user-guide/attach-an-instance-ram-role-to-an-ecs-instance",
      requires: ["instances", "securityGroups", "ramRoles", "ramPolicies"],
      attackPath: true,
      title: "Internet-facing instance runs with administrator access",
      why: "The instance has a public address, its security group lets the internet in, and its RAM role is an administrator. A vulnerability in anything it serves can be turned into the role's credentials, and so into the whole account.",
      fix: "1. Give the instance a role with only the permissions its software needs. 2. Require tokens for its metadata service (Security Hardening Mode). 3. Put it behind a load balancer and remove its public address.",
    },
    "LEC-009": {
      category: "Attack surface",
      severity: "medium",
      docs: "https://www.alibabacloud.com/help/en/ecs/user-guide/ssh-key-pairs",
      requires: ["instances", "securityGroups", "networkInterfaces"],
      attackPath: true,
      title: "Internet-facing Linux instance signs in with a password over SSH",
      why: "The instance has no SSH key pair, so it was set up to sign in with a password, which Alibaba Cloud's public Linux images accept over SSH. Its security group lets the whole internet reach port 22, where passwords are guessed around the clock, and one weak or reused password is a shell on the server.",
      fix: "1. In the ECS console → the instance → Bind Key Pair, attach an SSH key pair: Alibaba Cloud then turns password sign-in off on its Linux images. 2. Restrict port 22 to your office or VPN range, or remove it and connect with Workbench or Cloud Assistant, which need no inbound port.",
    },
    "LEC-008": {
      category: "Attack surface",
      severity: "medium",
      docs: "https://www.alibabacloud.com/help/en/ecs/user-guide/share-a-custom-image",
      requires: ["images"],
      title: "Custom image is shared outside the entity",
      why: "Whoever the image is shared with can start an instance from it and read everything on its disks: application code, configuration, and any credential that was on the server when the image was made.",
      fix: "1. If the account is yours, add it to this entity in Keelson. 2. Otherwise open the image in ECS → Images → Share Image and remove the account, or stop sharing it with everyone.",
    },
  },
  ({ inv, d, related }, report) => {
    const roles = new Map((inv.roles ?? []).map((r) => [r.name, r]));
    const ours = related.unknown.includes("alibabaAccounts") ? null : new Set([inv.accountId, ...(related.alibabaAccounts ?? [])]);
    for (const r of inv.regions) {
      const zone = r.name;
      for (const i of (r.instances ?? []).filter((x) => x.running)) {
        const resource = i.name ? `${i.name} (${i.id})` : i.id;
        const link = d.instance(zone, i.id);
        if (i.metadataTokens != null) {
          // What normal mode gives away is the instance's role: high when the internet reaches the instance, low when it has no role.
          const runsAs = i.role ? roles.get(i.role) : undefined;
          report("LEC-001", {
            zone,
            resource,
            pass: i.metadataTokens,
            severity: i.metadataTokens ? undefined : !i.role ? "low" : i.publicIp ? "high" : undefined,
            detail: i.metadataTokens
              ? ""
              : `Normal mode${i.publicIp ? `, the instance has the public address ${i.publicIp}` : ""}${
                  i.role
                    ? `, and it runs as the RAM role ${i.role}${runsAs?.admin ? ", which has administrator access" : ""}`
                    : ". It has no RAM role, so there are no credentials to take"
                }`,
            link,
          });
        }
        if (i.userDataSecret !== undefined)
          report("LEC-004", {
            zone,
            resource,
            pass: !i.userDataSecret,
            detail: i.userDataSecret ? `The user data contains ${i.userDataSecret}` : "",
            confidence: i.userDataSecret ? "likely" : undefined,
            link,
          });
        // Reachable: a public address, and a security group that lets the internet in on something.
        const open = (r.securityGroups ?? []).filter((g) => i.securityGroups.includes(g.id) && g.open.length);
        const role = i.role ? roles.get(i.role) : undefined;
        if (!i.publicIp || !open.length || !role || !inv.roles || !inv.admins || !r.securityGroups) continue;
        report("LEC-007", {
          zone,
          resource,
          pass: !role.admin,
          // In normal mode, a single forged request to the metadata service is enough to take the role's credentials.
          severity: role.admin && i.metadataTokens === false ? "critical" : undefined,
          detail: role.admin
            ? `Public at ${i.publicIp} through ${open.map((g) => g.name).join(", ")}, running as ${role.name}, which has administrator access${i.metadataTokens === false ? ". The metadata service answers without a token" : ""}`
            : "",
          evidence: role.admin
            ? {
                chain: [
                  { label: "Reachable from the internet", value: `${i.publicIp}, through ${open.map((g) => `${g.name} (${g.id})`).join(", ")}` },
                  { label: "Instance RAM role", value: role.name },
                  { label: "Role", value: `${role.name} has administrator access` },
                  {
                    label: "Metadata service",
                    value: i.metadataTokens === false ? "Normal mode: one request forgery reads the credentials" : "Security hardening mode",
                  },
                ],
              }
            : null,
          link,
        });
      }
      // The setting only matters where disks are created. One finding for the region rather than one per disk: the fix is
      // the same setting, and a disk-by-disk list buried the rest on a real account.
      if (r.diskEncryptionByDefault != null && r.instances?.length) {
        const used = (r.disks ?? []).filter((k) => k.inUse);
        const plain = used.filter((k) => !k.encrypted).length;
        report("LEC-002", {
          zone,
          resource: zone,
          pass: r.diskEncryptionByDefault,
          detail: r.diskEncryptionByDefault
            ? ""
            : `Off${used.length ? `, and ${plain} of the ${used.length} disk${used.length === 1 ? "" : "s"} in use ${plain === 1 ? "isn't" : "aren't"} encrypted` : ""}`,
          link: d.disks(zone),
        });
      }
      // A Linux instance without a key pair, on a public address that a group opens port 22 to.
      if (r.instances && r.securityGroups && r.interfaces)
        for (const i of r.instances) {
          if (!i.running || i.os !== "linux") continue;
          const nics = r.interfaces.filter((n) => n.owner === i.id);
          const address = i.publicIp ?? nics.find((n) => n.publicIp)?.publicIp ?? null;
          if (!address) continue;
          const groups = r.securityGroups.filter((g) => [...i.securityGroups, ...nics.flatMap((n) => n.securityGroups)].includes(g.id));
          const ssh = groups.filter((g) => opens(g, 22));
          if (!ssh.length) continue;
          const resource = i.name ? `${i.name} (${i.id})` : i.id;
          report("LEC-009", {
            zone,
            resource,
            pass: i.keyPair,
            detail: i.keyPair ? "" : `No SSH key pair, at ${address}, and ${ssh.map((g) => g.name).join(", ")} allows port 22 from anywhere`,
            // The image may have password sign-in turned off in sshd itself, which the API can't see.
            confidence: i.keyPair ? undefined : "likely",
            evidence: i.keyPair
              ? null
              : {
                  chain: [
                    { label: "Public address", value: `${resource} at ${address}` },
                    ...ssh.map((g) => ({ label: "Security group", value: `${g.name} (${g.id}) allows tcp 22 from 0.0.0.0/0` })),
                    { label: "Sign-in", value: "No SSH key pair is bound, so the instance was set up with a password" },
                  ],
                },
            link: d.instance(zone, i.id),
          });
        }
      for (const t of r.launchTemplates ?? []) {
        const resource = `${t.name} (${t.id})`;
        if (t.metadataTokens != null)
          report("LEC-005", {
            zone,
            resource,
            pass: t.metadataTokens,
            detail: t.metadataTokens ? "" : "The default version starts instances in normal mode",
            link: d.launchTemplates(zone),
          });
        report("LEC-006", {
          zone,
          resource,
          pass: !t.userDataSecret,
          detail: t.userDataSecret ? `The default version's user data contains ${t.userDataSecret}` : "",
          confidence: t.userDataSecret ? "likely" : undefined,
          link: d.launchTemplates(zone),
        });
      }
      if (ours)
        for (const img of r.images ?? []) {
          const everyone = img.sharedWith.includes("all");
          const outside = img.sharedWith.filter((a) => a !== "all" && !ours.has(a));
          report("LEC-008", {
            zone,
            resource: img.name ? `${img.name} (${img.id})` : img.id,
            pass: !everyone && !outside.length,
            // A community image anyone can start is the AWS counterpart of a public AMI.
            severity: everyone ? "high" : undefined,
            detail: everyone
              ? "Shared with every Alibaba Cloud account"
              : outside.length
                ? `Shared with account${outside.length === 1 ? "" : "s"} ${list(outside)}`
                : "",
            link: d.images(zone),
          });
        }
    }
    if (ours && inv.regions.some((r) => r.images)) report.passIfNone("LEC-008", "images", GLOBAL);
  },
);
