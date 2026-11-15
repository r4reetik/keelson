// Data stores beyond the database instances in data.ts: RDS snapshots anyone can
// restore and databases that accept connections without TLS, OpenSearch domains,
// ElastiCache, Redshift, DynamoDB point-in-time recovery and EFS encryption.

import { defineChecks } from "./define.ts";

export default defineChecks(
  {
    "ADB-004": {
      category: "Attack surface",
      severity: "critical",
      docs: "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.html",
      requires: ["dbSnapshots"],
      attackPath: true,
      title: "Database snapshot is public",
      why: "Any AWS account can restore the snapshot and read the whole database as it was, with no password and nothing in your logs.",
      fix: "In RDS → Snapshots → Manual → the snapshot → Actions → Share snapshot, set DB snapshot visibility to Private. If it may already have been copied, treat its data and credentials as exposed.",
    },
    "ADB-005": {
      category: "TLS & HTTPS",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html",
      requires: ["databases", "dbParameters"],
      title: "Database accepts connections without TLS",
      why: "Clients may connect in plain text, so passwords and query results cross the network unencrypted, and anyone on that path can read or change them.",
      fix: "In the database's parameter group (its cluster parameter group for Aurora), set rds.force_ssl to 1 for PostgreSQL, or require_secure_transport to ON for MySQL and MariaDB, after checking that every client connects with TLS.",
    },
    "ADB-006": {
      category: "Attack surface",
      severity: "critical",
      docs: "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/ac.html",
      requires: ["opensearch"],
      attackPath: true,
      title: "OpenSearch domain is open to anyone",
      why: "The domain has a public endpoint and an access policy that lets anyone in, so anyone who finds it can search, change and delete its indexes.",
      fix: "1. Replace the access policy with one that names your IAM roles or address ranges. 2. Turn on fine-grained access control. 3. Better, move the domain into a VPC: create a new one with VPC access and restore a snapshot into it.",
    },
    "ADB-007": {
      category: "Platform",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/encryption-at-rest.html",
      requires: ["opensearch"],
      title: "OpenSearch domain doesn't encrypt its data",
      why: "Its indexes are stored, or passed between its nodes, in the clear. Fine-grained access control also can't be turned on without both.",
      fix: "In OpenSearch → the domain → Actions → Edit security configuration, turn on Encryption of data at rest and Node-to-node encryption (on older domains, create a new domain and restore a snapshot).",
    },
    "ADB-008": {
      category: "TLS & HTTPS",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/infrastructure-security.html",
      requires: ["opensearch"],
      title: "OpenSearch domain accepts plain HTTP or TLS 1.0",
      why: "Clients can send queries and credentials in plain text or over an old TLS version that can be broken.",
      fix: "In OpenSearch → the domain → Actions → Edit, under Encryption, turn on Require HTTPS for all traffic and choose a TLS security policy with TLS 1.2 as the minimum.",
    },
    "ADB-009": {
      category: "TLS & HTTPS",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/in-transit-encryption.html",
      requires: ["elasticache"],
      title: "Cache accepts unencrypted connections",
      why: "Whatever the cache holds (sessions, tokens, cached query results) crosses the network in plain text.",
      fix: "Modify the cluster to turn on encryption in transit, first in preferred mode while clients move to TLS, then in required mode.",
    },
    "ADB-010": {
      category: "Platform",
      severity: "low",
      docs: "https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/at-rest-encryption.html",
      requires: ["elasticache"],
      title: "Cache stores data unencrypted",
      why: "Its disk and its backups are stored in the clear.",
      fix: "Encryption at rest can't be turned on in place: take a backup, create a new cluster with encryption at rest from it, and switch clients over.",
    },
    "ADB-011": {
      category: "Attack surface",
      severity: "high",
      docs: "https://docs.aws.amazon.com/redshift/latest/mgmt/managing-clusters-vpc.html",
      requires: ["redshift"],
      attackPath: true,
      title: "Redshift cluster is publicly accessible",
      why: "The data warehouse has a public address. Only its security group and passwords stand between the internet and your data.",
      fix: "In Redshift → the cluster → Actions → Modify publicly accessible setting, turn it off, and reach the cluster from inside the VPC or through a VPN.",
    },
    "ADB-012": {
      category: "Platform",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html",
      requires: ["redshift"],
      title: "Redshift cluster isn't encrypted",
      why: "The warehouse's data and its snapshots are stored in the clear.",
      fix: "In Redshift → the cluster → Properties → Database configurations → Edit encryption, choose AWS KMS. Redshift migrates the data in place.",
    },
    "ADB-013": {
      category: "Platform",
      severity: "low",
      docs: "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery.html",
      requires: ["dynamodb"],
      title: "DynamoDB table can't be restored to a point in time",
      why: "A bad deployment, a script that deletes the wrong items or a compromised credential can wipe the table, and there is nothing to restore it from.",
      fix: "In DynamoDB → the table → Backups → Point-in-time recovery, choose Edit and turn it on.",
    },
    "ADB-014": {
      category: "Platform",
      severity: "low",
      docs: "https://docs.aws.amazon.com/efs/latest/ug/encryption.html",
      requires: ["efs"],
      title: "EFS file system isn't encrypted",
      why: "Its files and backups are stored in the clear.",
      fix: "Encryption can't be turned on in place: create an encrypted file system, copy the data with AWS DataSync, and move the mount targets over.",
    },
  },
  ({ inv, d }, report) => {
    for (const r of inv.regions) {
      const rds = (id: string) => d.database(r.name, id);
      for (const s of r.dbSnapshots ?? [])
        report("ADB-004", {
          zone: r.name,
          resource: s.id,
          pass: !s.public,
          detail: s.public ? `${s.cluster ? "Cluster snapshot" : "Snapshot"} anyone can restore` : "",
          link: d.console(r.name, "rds", s.cluster ? `db-snapshot:engine=aurora;id=${encodeURIComponent(s.id)}` : `db-snapshot:id=${encodeURIComponent(s.id)}`),
        });
      for (const db of r.databases ?? []) {
        if (db.tlsRequired == null) continue;
        report("ADB-005", {
          zone: r.name,
          resource: db.id,
          pass: db.tlsRequired,
          // A public database without TLS sends credentials across the internet.
          severity: !db.tlsRequired && db.public ? "high" : undefined,
          detail: db.tlsRequired ? "" : `${db.parameterGroup ?? "Its parameter group"} doesn't require TLS for ${db.engine}`,
          link: rds(db.id),
        });
      }
      for (const s of r.searchDomains ?? []) {
        const where = { zone: r.name, resource: s.name, link: d.console(r.name, "aos", `opensearch/domains/${encodeURIComponent(s.name)}`) };
        const open = !s.vpc && s.openPolicy;
        report("ADB-006", {
          ...where,
          pass: !open,
          // With fine-grained access control a user still has to sign in.
          severity: open && s.fineGrained ? "high" : undefined,
          detail: open
            ? `Public endpoint, and the access policy allows "*"${s.fineGrained ? "; fine-grained access control still asks for a sign-in" : ""}`
            : "",
        });
        const plain = [!s.encryptedAtRest && "at rest", !s.nodeToNode && "between nodes"].filter(Boolean);
        report("ADB-007", { ...where, pass: !plain.length, detail: plain.length ? `Not encrypted ${plain.join(" or ")}` : "" });
        const weak = [!s.enforceHttps && "HTTPS isn't required", !s.tls12 && "TLS 1.0 is allowed"].filter(Boolean);
        report("ADB-008", { ...where, pass: !weak.length, detail: weak.join("; ") });
      }
      for (const c of r.caches ?? []) {
        const where = {
          zone: r.name,
          resource: c.id,
          link: d.console(r.name, "elasticache", `/${c.engine === "memcached" ? "memcached" : "redis"}-cluster-details/${c.id}`),
        };
        report("ADB-009", { ...where, pass: c.transit, detail: c.transit ? "" : `${c.engine} without encryption in transit` });
        // Memcached keeps nothing on disk to encrypt.
        if (c.engine !== "memcached") report("ADB-010", { ...where, pass: c.atRest, detail: c.atRest ? "" : "No encryption at rest" });
      }
      for (const w of r.warehouses ?? []) {
        const where = { zone: r.name, resource: w.id, link: d.console(r.name, "redshiftv2", `cluster-details?cluster=${encodeURIComponent(w.id)}`) };
        report("ADB-011", { ...where, pass: !w.public, detail: w.public ? "Publicly accessible" : "" });
        report("ADB-012", { ...where, pass: w.encrypted, detail: w.encrypted ? "" : "Not encrypted" });
      }
      for (const t of r.tables ?? [])
        if (t.pitr != null)
          report("ADB-013", {
            zone: r.name,
            resource: t.name,
            pass: t.pitr,
            detail: t.pitr ? "" : "Point-in-time recovery is off",
            link: d.console(r.name, "dynamodbv2", `table?name=${encodeURIComponent(t.name)}&tab=backups`),
          });
      for (const f of r.fileSystems ?? [])
        report("ADB-014", {
          zone: r.name,
          resource: f.name ? `${f.name} (${f.id})` : f.id,
          pass: f.encrypted,
          detail: f.encrypted ? "" : "Not encrypted at rest",
          link: d.console(r.name, "efs", `/file-systems/${f.id}`),
        });
    }
  },
);
