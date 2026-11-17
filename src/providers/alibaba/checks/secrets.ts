// KMS keys and secrets: rotation, keys scheduled for deletion, and secrets that
// haven't changed in over a year. Secret values are never asked for: only names,
// dates and rotation settings are read.

import { defineChecks, date, days } from "./define.ts";

const YEAR = 365;

export default defineChecks(
  {
    "LKM-001": {
      category: "Secrets",
      severity: "low",
      docs: "https://www.alibabacloud.com/help/en/kms/key-management-service/user-guide/configure-key-rotation",
      requires: ["kms"],
      title: "KMS key doesn't rotate automatically",
      why: "A key that never rotates protects everything encrypted with it with the same material for as long as it lives. Automatic rotation limits how much data one compromised version can expose.",
      fix: "In the KMS console → Keys → the key → Configure Rotation, turn on automatic rotation (every 365 days or sooner).",
    },
    "LKM-002": {
      category: "Change risk",
      severity: "medium",
      docs: "https://www.alibabacloud.com/help/en/kms/key-management-service/user-guide/manage-keys-2",
      requires: ["kms"],
      title: "KMS key is scheduled for deletion",
      why: "Once the waiting period ends, data encrypted with the key can never be decrypted again: disks, databases, OSS objects and secrets that use it are lost.",
      fix: "If anything still uses the key, cancel the deletion in the KMS console → Keys → the key → Cancel Deletion. Otherwise let it go, and note who scheduled it.",
    },
    "LKM-003": {
      category: "Secrets",
      severity: "low",
      docs: "https://www.alibabacloud.com/help/en/kms/user-guide/overview-9",
      requires: ["kms"],
      title: "Secret hasn't changed in over a year",
      why: "A credential that never changes stays useful to anyone who copied it, from a log, a laptop or a former colleague, for as long as it lives.",
      fix: "Turn on automatic rotation for the secret in KMS → Secrets (RAM, RDS and ECS secrets rotate on their own), or rotate it by hand and put a date on the next rotation.",
    },
  },
  ({ inv, d }, report) => {
    for (const r of inv.regions) {
      for (const k of r.keys ?? []) {
        const where = { zone: r.name, resource: k.description ? `${k.description} (${k.id})` : k.id, link: d.kms(r.name) };
        if (k.rotatable && k.enabled && k.rotation != null)
          report("LKM-001", { ...where, pass: k.rotation, detail: k.rotation ? "" : "Automatic rotation is off" });
        report("LKM-002", { ...where, pass: k.deletionDate == null, detail: k.deletionDate != null ? `Deleted on ${date(k.deletionDate)}` : "" });
      }
      for (const s of r.secrets ?? []) {
        const changed = s.rotatedAt ?? s.createdAt;
        const age = days(changed, inv.now);
        if (age != null)
          report("LKM-003", {
            zone: r.name,
            resource: s.name,
            pass: s.rotation || age <= YEAR,
            detail: !s.rotation && age > YEAR ? `Last changed ${date(changed)}, ${age} days ago` : "",
            link: d.secrets(r.name),
          });
      }
    }
  },
);
