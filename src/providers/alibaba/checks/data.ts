// ApsaraDB RDS, Tair (Redis) and ApsaraDB for MongoDB. On Alibaba Cloud an IP
// whitelist, not a security group, decides who can connect, so a whitelist that
// admits every address is judged with the instance's endpoints: open to the
// internet when it also has a public connection string, open to the whole network
// when it doesn't. Tair and MongoDB can also let clients in the VPC connect without
// a password ("password-free access"), which turns any foothold in the VPC into the
// data. Then TLS, judged by where its traffic travels, and encryption at rest.

import { defineChecks } from "./define.ts";

export default defineChecks(
  {
    "LDB-001": {
      category: "Attack surface",
      severity: "critical",
      docs: "https://www.alibabacloud.com/help/en/rds/apsaradb-rds-for-mysql/configure-an-ip-address-whitelist-for-an-apsaradb-rds-for-mysql-instance",
      requires: ["databases"],
      attackPath: true,
      title: "Database whitelist admits every address",
      why: "ApsaraDB instances (RDS, Tair and MongoDB) accept connections only from the addresses in their whitelist. This one admits 0.0.0.0/0, so with a public endpoint anyone on the internet can try its passwords and its protocol's bugs; without one, every host that can reach the network can.",
      fix: "1. In the instance's console → Whitelist Settings, replace 0.0.0.0/0 with the addresses or security groups of the applications that connect. 2. Release the public endpoint if nothing outside Alibaba Cloud needs it.",
    },
    "LDB-002": {
      category: "TLS & HTTPS",
      severity: "medium",
      docs: "https://www.alibabacloud.com/help/en/rds/apsaradb-rds-for-mysql/configure-ssl-encryption-for-an-apsaradb-rds-for-mysql-instance",
      requires: ["databases"],
      title: "Database accepts connections without TLS",
      why: "Without TLS, credentials and query results cross the network in plain text. Over a public endpoint that is the internet; inside a VPC it is readable by anything on the path between the application and the database.",
      fix: "In the instance's console → Data Security (RDS) or TLS Settings (Tair, MongoDB), turn on TLS for the endpoint the applications use, then have the clients connect with TLS.",
    },
    "LDB-003": {
      category: "Platform",
      severity: "low",
      docs: "https://www.alibabacloud.com/help/en/rds/apsaradb-rds-for-mysql/configure-tde-for-an-apsaradb-rds-for-mysql-instance",
      requires: ["databases"],
      title: "Database storage isn't encrypted",
      why: "Transparent data encryption is off, so the database's files and backups are stored unencrypted, and a copied backup carries the data in the clear. Access to the instance itself matters more: this is the last line, not the first.",
      fix: "In the RDS console → the instance → Data Security → TDE, turn on TDE with a KMS key. It can't be turned off again, so check the engine version's notes first.",
    },
    "LDB-004": {
      category: "Identity & access",
      severity: "high",
      docs: "https://www.alibabacloud.com/help/en/redis/user-guide/enable-password-free-access",
      requires: ["redis", "mongodb"],
      attackPath: true,
      title: "Tair or MongoDB lets clients in the VPC connect without a password",
      why: "Password-free access is on: any client in the VPC whose address the whitelist admits can read and change every key or document without credentials. One compromised instance, container or function in the VPC is then the whole data store, with nothing in its logs to tell an attacker from the application.",
      fix: "In the instance's console → Instance Information (Tair) or Database Connections (MongoDB), turn password-free access off and give each application its own account with only the permissions it needs. Narrow the whitelist to the applications' addresses.",
    },
  },
  ({ inv, d }, report) => {
    for (const r of inv.regions)
      for (const db of r.databases ?? []) {
        const resource = db.name && db.name !== db.id ? `${db.name} (${db.id})` : db.id;
        const link = d.database(r.name, db.id, db.service);
        // "RDS MySQL", "Redis 7.0", "MongoDB 6.0": Tair and MongoDB name their engine after the product already.
        const what = db.service === "rds" ? `RDS ${db.engine}` : db.engine;
        const open = db.openWhitelist.length > 0;
        report("LDB-001", {
          zone: r.name,
          resource,
          pass: !open,
          severity: open && !db.publicEndpoint ? "medium" : undefined,
          detail: open
            ? `${what} whitelist allows ${db.openWhitelist.join(", ")}${db.publicEndpoint ? ", and it has a public endpoint" : ", with no public endpoint: every host on the network can connect"}`
            : "",
          evidence:
            open && db.publicEndpoint
              ? {
                  chain: [
                    { label: "Public endpoint", value: `${what} instance ${resource} has a connection string on the internet` },
                    { label: "Whitelist", value: db.openWhitelist.join(", ") },
                    ...(db.passwordFree ? [{ label: "Password-free access", value: "On for clients in the VPC" }] : []),
                  ],
                }
              : null,
          link,
        });
        if (db.ssl != null)
          report("LDB-002", {
            zone: r.name,
            resource,
            pass: db.ssl,
            // Plain text over the internet is worse than plain text inside the VPC.
            severity: db.ssl || db.publicEndpoint ? undefined : "low",
            detail: db.ssl ? "" : `TLS is off (${what})${db.publicEndpoint ? ", and it has a public endpoint" : ", reached only inside the VPC"}`,
            link,
          });
        if (db.tde != null) report("LDB-003", { zone: r.name, resource, pass: db.tde, detail: db.tde ? "" : `TDE is off (${what})`, link });
        if (db.passwordFree != null)
          report("LDB-004", {
            zone: r.name,
            resource,
            pass: !db.passwordFree,
            severity: db.passwordFree && open ? "critical" : undefined,
            detail: db.passwordFree
              ? `${what} accepts clients in the VPC without a password${open ? `, and its whitelist allows ${db.openWhitelist.join(", ")}` : ""}`
              : "",
            evidence: db.passwordFree
              ? {
                  chain: [
                    { label: "Password-free access", value: `${what} instance ${resource}: clients in the VPC need no password` },
                    { label: "Whitelist", value: open ? `${db.openWhitelist.join(", ")}: every address` : "Limited to the listed addresses" },
                  ],
                }
              : null,
            link,
          });
      }
  },
);
