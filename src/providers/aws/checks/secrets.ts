// Where secrets live and who can reach them: Secrets Manager secrets (open
// policies, ones never changed or no longer used), KMS keys (open policies,
// rotation, deletion scheduled), Systems Manager documents shared with everyone,
// and CodeBuild projects with credentials in them or public builds.

import { date, days, defineChecks } from "./define.ts";

const YEAR = 365;
const UNUSED_DAYS = 90;

export default defineChecks(
  {
    "ASC-001": {
      category: "Secrets",
      severity: "critical",
      docs: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_resource-policies.html",
      requires: ["secrets"],
      attackPath: true,
      title: "Secret's resource policy lets anyone read it",
      why: 'Its resource policy allows "*" without a condition, so any AWS account can read the secret\'s value.',
      fix: '1. Rotate the secret now. 2. In Secrets Manager → the secret → Resource permissions, remove the statement for "*", or name the accounts and roles that need it. Secrets Manager\'s Block public policy option refuses such statements in future.',
    },
    "ASC-002": {
      category: "Secrets",
      severity: "low",
      docs: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html",
      requires: ["secrets"],
      title: "Secret hasn't changed in over a year",
      why: "The same value has been in use for more than a year, so anyone who copied it at any point in that time, a former employee or a leaked log, can still use it.",
      fix: "Turn on rotation in Secrets Manager → the secret → Rotation, with a rotation function for databases and AWS services. For a third party's API key, issue a new key, store it, and revoke the old one.",
    },
    "ASC-003": {
      category: "Secrets",
      severity: "low",
      docs: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/manage_delete-secret.html",
      requires: ["secrets"],
      title: "Secret unused for 90 days",
      why: "Nothing has read the secret in three months, so it most likely guards something no longer in use, while the credential itself still works.",
      fix: "Find out what it was for. Revoke the credential at its source, then delete the secret in Secrets Manager (it can be restored during the recovery window).",
    },
    "ASC-004": {
      category: "Secrets",
      severity: "high",
      docs: "https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html",
      requires: ["kms"],
      attackPath: true,
      title: "KMS key policy lets anyone use the key",
      why: 'The key policy allows "*" without a condition, so other AWS accounts can decrypt data encrypted with it, or use it to encrypt yours.',
      fix: 'In KMS → the key → Key policy → Edit, replace the "*" principal with your account and the roles that use the key, or add a condition (aws:PrincipalOrgID, kms:CallerAccount).',
    },
    "ASC-005": {
      category: "Secrets",
      severity: "low",
      docs: "https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html",
      requires: ["kms"],
      title: "KMS key doesn't rotate automatically",
      why: "The same key material encrypts everything for as long as the key exists. Yearly rotation limits how much data any one version of the key protects, at no cost to existing data.",
      fix: "In KMS → the key → Key rotation, turn on Automatically rotate this KMS key (every 365 days, or a shorter period).",
    },
    "ASC-006": {
      category: "Change risk",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html",
      requires: ["kms"],
      title: "KMS key is scheduled for deletion",
      why: "When the waiting period ends, the key is gone and every piece of data encrypted with it (volumes, snapshots, objects, database storage) can never be decrypted again.",
      fix: "If anything may still use the key, cancel the deletion in KMS → the key → Key actions → Cancel key deletion, and disable it instead while you check its CloudTrail usage.",
    },
    "ASC-007": {
      category: "Attack surface",
      severity: "high",
      docs: "https://docs.aws.amazon.com/systems-manager/latest/userguide/documents-ssm-sharing.html",
      requires: ["ssmDocuments"],
      title: "Systems Manager document is shared with everyone",
      why: "Any AWS account can read the document, and with it the commands, script paths, hostnames and sometimes credentials it holds.",
      fix: "In Systems Manager → Documents → Owned by me → the document → Permissions, choose Private, and share with named accounts only. The account setting Block public sharing stops it happening again.",
    },
    "ASC-008": {
      category: "Secrets",
      severity: "high",
      docs: "https://docs.aws.amazon.com/codebuild/latest/userguide/build-env-ref-env-vars.html",
      requires: ["codebuild"],
      title: "Credential in a CodeBuild project",
      why: "A plain-text environment variable or a source URL with a password in it is readable by anyone who can view the project, and shows in build logs.",
      fix: "1. Rotate the credential. 2. Store it in Secrets Manager or Parameter Store and reference it with the SECRETS_MANAGER or PARAMETER_STORE variable type. 3. Connect the source with a CodeConnections connection instead of a URL with a password.",
    },
    "ASC-009": {
      category: "Attack surface",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/codebuild/latest/userguide/public-builds.html",
      requires: ["codebuild"],
      title: "CodeBuild project's builds are public",
      why: "Anyone on the internet can read the project's build logs and artifacts, which often show paths, versions, hostnames and the output of every command.",
      fix: "In CodeBuild → the project → Edit → Project configuration, set Public build access off.",
    },
  },
  ({ inv, d }, report) => {
    for (const r of inv.regions) {
      for (const s of r.secrets ?? []) {
        const where = { zone: r.name, resource: s.name, link: d.console(r.name, "secretsmanager", `secret?name=${encodeURIComponent(s.name)}`) };
        if (s.publicPolicy != null) report("ASC-001", { ...where, pass: !s.publicPolicy, detail: s.publicPolicy ? 'The resource policy allows "*"' : "" });
        const changed = s.changedAt ?? s.createdAt;
        const age = days(changed, inv.now);
        if (age != null)
          report("ASC-002", {
            ...where,
            pass: s.rotation || age <= YEAR,
            detail: !s.rotation && age > YEAR ? `Last changed ${date(changed)}, ${age} days ago` : "",
          });
        const created = days(s.createdAt, inv.now);
        if (created != null && created > UNUSED_DAYS) {
          const idle = days(s.accessedAt, inv.now);
          const unused = idle == null || idle > UNUSED_DAYS;
          report("ASC-003", { ...where, pass: !unused, detail: unused ? (s.accessedAt ? `Last read ${date(s.accessedAt)}` : "Never read") : "" });
        }
      }
      for (const k of r.keys ?? []) {
        const label = k.description ? `${k.description} (${k.id})` : k.id;
        const where = { zone: r.name, resource: label, link: d.console(r.name, "kms", `/kms/keys/${k.id}`) };
        if (k.publicPolicy != null) report("ASC-004", { ...where, pass: !k.publicPolicy, detail: k.publicPolicy ? 'The key policy allows "*"' : "" });
        if (k.rotatable && k.enabled && k.rotation != null)
          report("ASC-005", { ...where, pass: k.rotation, detail: k.rotation ? "" : "Automatic rotation is off" });
        report("ASC-006", { ...where, pass: k.deletionDate == null, detail: k.deletionDate != null ? `Deleted on ${date(k.deletionDate)}` : "" });
      }
      for (const doc of r.documents ?? [])
        report("ASC-007", {
          zone: r.name,
          resource: doc.name,
          pass: !doc.public,
          detail: doc.public ? "Shared with all AWS accounts" : "",
          link: d.console(r.name, "systems-manager", `/documents/${encodeURIComponent(doc.name)}/permissions`),
        });
      for (const p of r.buildProjects ?? []) {
        const where = { zone: r.name, resource: p.name, link: d.console(r.name, "codesuite/codebuild", `/projects/${encodeURIComponent(p.name)}`) };
        report("ASC-008", {
          ...where,
          pass: !p.secret,
          severity: p.secret?.likely ? "medium" : undefined,
          confidence: p.secret?.likely ? "likely" : undefined,
          detail: p.secret ? `${p.secret.where} holds ${p.secret.kind}` : "",
        });
        report("ASC-009", { ...where, pass: !p.public, detail: p.public ? "Public build access is on" : "" });
      }
    }
  },
);
