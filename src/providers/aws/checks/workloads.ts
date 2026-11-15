// What runs workloads, beyond the instances themselves: launch templates (which
// every Auto Scaling group starts from), volumes, the region's blocks on public
// sharing, Lambda functions' resource policies and environment variables, and
// SageMaker notebooks. Credentials are found by kind; their values are never kept.

import { defineChecks, inUse } from "./define.ts";

export default defineChecks(
  {
    "AEC-009": {
      category: "Platform",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-IMDS-new-instances.html",
      requires: ["launchTemplates"],
      title: "Launch template allows IMDSv1",
      why: "Every instance started from it, by an Auto Scaling group or by hand, answers the old metadata service, so a server-side request forgery in its software can read the instance role's credentials.",
      fix: "Create a new version of the launch template with Metadata version set to V2 only (token required), make it the default, and start an instance refresh on the Auto Scaling groups that use it.",
    },
    "AEC-010": {
      category: "Secrets",
      severity: "high",
      docs: "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html",
      requires: ["launchTemplates"],
      title: "Credential in a launch template's start-up script",
      why: "Anyone who can describe launch templates or reach an instance's metadata can read the start-up script, and the credential written into it. It also lands on every instance started from the template.",
      fix: "1. Rotate the credential. 2. Create a new template version that reads it at start-up from Secrets Manager or Parameter Store through the instance role. 3. Make that version the default and delete the old ones.",
    },
    "AEC-011": {
      category: "Platform",
      severity: "low",
      docs: "https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html",
      requires: ["volumes"],
      title: "EBS volume isn't encrypted",
      why: "The volume, and every snapshot taken of it, is stored in the clear. An unencrypted snapshot can be shared or copied to another account as it is.",
      fix: "Volumes can't be encrypted in place. Snapshot the volume, copy the snapshot with encryption on, create a volume from the copy and swap it in. Turn on EBS encryption by default so new volumes are encrypted.",
    },
    "AEC-012": {
      category: "Attack surface",
      severity: "low",
      docs: "https://docs.aws.amazon.com/ebs/latest/userguide/block-public-access-snapshots.html",
      requires: ["sharingBlocks"],
      title: "Snapshots and machine images can still be made public",
      why: "Anyone in the account who can change a snapshot's or image's permissions can share it with everyone, and with it the data on its disks. A block on public sharing stops that for the whole region.",
      fix: "In EC2 → Settings → Data protection and security, turn on Block public access for EBS snapshots (Block all public sharing) and for AMIs.",
    },
    "AEC-013": {
      category: "Attack surface",
      severity: "critical",
      docs: "https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html",
      requires: ["functions", "functionPolicies"],
      attackPath: true,
      title: "Lambda function's policy lets anyone invoke it",
      why: "Its resource policy allows any AWS account, or anyone, to call it without a condition. They can run it with whatever input they choose, as its role, and on your bill.",
      fix: 'In Lambda → the function → Configuration → Permissions → Resource-based policy statements, remove the statement for "*", or add a condition that names the source (aws:SourceArn or aws:SourceAccount).',
    },
    "AEC-014": {
      category: "Secrets",
      severity: "high",
      docs: "https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html#configuration-envvars-encryption",
      requires: ["functions"],
      title: "Credential in a Lambda function's environment variables",
      why: "Anyone who can read the function's configuration, including read-only roles and tools like this one, sees the value in clear text. It's also copied into every version of the function.",
      fix: "1. Rotate the credential. 2. Store it in Secrets Manager or Parameter Store and read it at start-up through the function's role. 3. Remove the variable and publish a new version.",
    },
    "AEC-015": {
      category: "Attack surface",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/sagemaker/latest/dg/appendix-notebook-and-internet-access.html",
      requires: ["sagemaker"],
      title: "SageMaker notebook has direct internet access",
      why: "The notebook can reach anywhere on the internet outside your VPC's controls, so code or data in it can leave without passing any firewall or log you run.",
      fix: "Notebook instances can't change this in place: create a new one in a VPC subnet with Direct internet access disabled, give it a NAT gateway or VPC endpoints for what it needs, and move the work over.",
    },
  },
  ({ inv, d }, report) => {
    for (const r of inv.regions) {
      for (const t of r.launchTemplates ?? []) {
        const where = { zone: r.name, resource: t.name, link: d.console(r.name, "ec2", `LaunchTemplateDetails:launchTemplateId=${t.id}`) };
        // Not set means the AMI's default applies, which can't be told from here.
        if (t.imdsV2 != null) report("AEC-009", { ...where, pass: t.imdsV2, detail: t.imdsV2 ? "" : "The default version sets HttpTokens to optional" });
        report("AEC-010", {
          ...where,
          pass: !t.userDataSecret,
          detail: t.userDataSecret ? `The default version's start-up script contains ${t.userDataSecret}` : "",
        });
      }
      for (const v of r.unencryptedVolumes ?? [])
        report("AEC-011", {
          zone: r.name,
          resource: v.id,
          pass: false,
          detail: v.instance ? `Attached to ${v.instance}` : "",
          link: d.console(r.name, "ec2", `VolumeDetails:volumeId=${v.id}`),
        });
      if (r.unencryptedVolumes && inUse(r)) report.passIfNone("AEC-011", "volumes", r.name);
      const b = r.sharingBlocks;
      // Only where something runs: an empty region has nothing to share.
      if (b && inUse(r)) {
        const open = [b.snapshots === "unblocked" && "EBS snapshots", b.images === "unblocked" && "AMIs"].filter(Boolean);
        report("AEC-012", {
          zone: r.name,
          resource: r.name,
          pass: !open.length,
          detail: open.length ? `Public sharing isn't blocked for ${open.join(" or ")}` : "",
          link: d.ebsSettings(r.name),
        });
      }
      for (const f of r.functions ?? []) {
        const where = { zone: r.name, resource: f.name, link: d.lambda(r.name, f.name) };
        if (f.publicPolicy != null)
          report("AEC-013", { ...where, pass: !f.publicPolicy, detail: f.publicPolicy ? 'Its resource policy allows "*" without a condition' : "" });
        if (f.envSecret !== undefined)
          report("AEC-014", {
            ...where,
            pass: !f.envSecret,
            severity: f.envSecret?.likely ? "medium" : undefined,
            confidence: f.envSecret?.likely ? "likely" : undefined,
            detail: f.envSecret ? `${f.envSecret.where} holds ${f.envSecret.kind}` : "",
          });
      }
      for (const n of r.notebooks ?? [])
        report("AEC-015", {
          zone: r.name,
          resource: n.name,
          pass: !n.internet,
          detail: n.internet ? "Direct internet access is enabled" : "",
          link: d.console(r.name, "sagemaker", `/notebook-instances/${encodeURIComponent(n.name)}`),
        });
    }
  },
);
