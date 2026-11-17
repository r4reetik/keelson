// Container Service (ACK) clusters and Function Compute: an API server on the
// internet, credentials in a function's environment, and HTTP triggers anyone can
// call.

import { defineChecks } from "./define.ts";

export default defineChecks(
  {
    "LCN-001": {
      category: "Attack surface",
      severity: "medium",
      docs: "https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/user-guide/control-public-access-to-the-api-server-of-a-cluster",
      requires: ["clusters"],
      title: "ACK cluster's API server has a public endpoint",
      why: "The Kubernetes API server answers on the internet. Its authentication is all that stands between anyone and the cluster, and a leaked kubeconfig or a vulnerability in the API server is exploitable from anywhere.",
      fix: "In the ACK console → the cluster → Basic Information, unbind the EIP from the API server and reach it through the VPC (a bastion, VPN or Cloud Shell). If it must stay public, restrict its SLB with an access control list.",
    },
    "LCN-002": {
      category: "Secrets",
      severity: "high",
      docs: "https://www.alibabacloud.com/help/en/functioncompute/fc-3-0/user-guide/environment-variables",
      requires: ["functions"],
      title: "Credential in a function's environment variables",
      why: "Environment variables are readable by anyone who can view the function's configuration, and travel with every copy of it. A token or key there is shared with all of them.",
      fix: "1. Rotate the credential. 2. Store it in KMS Secrets Manager and read it at run time with the function's RAM role. 3. Remove the variable from the function.",
    },
    "LCN-003": {
      category: "Attack surface",
      severity: "medium",
      docs: "https://www.alibabacloud.com/help/en/functioncompute/fc-3-0/user-guide/http-triggers-overview",
      requires: ["functions"],
      title: "Function's HTTP trigger needs no authentication",
      why: "Anyone who finds the trigger's URL can call the function as often as they like, and every bug in it is reachable from the internet.",
      fix: "If the function isn't meant to be public, set the HTTP trigger's authentication to Signature or JWT. If it is, make sure it checks its callers itself and limit what its RAM role can do.",
    },
  },
  ({ inv, d }, report) => {
    const roles = new Map((inv.roles ?? []).map((r) => [r.name, r]));
    for (const r of inv.regions) {
      for (const c of r.clusters ?? [])
        report("LCN-001", {
          zone: r.name,
          resource: `${c.name} (${c.id})`,
          pass: !c.publicEndpoint,
          detail: c.publicEndpoint ? `Kubernetes ${c.version ?? ""} API server is on the internet`.replace("  ", " ") : "",
          link: d.cluster(r.name, c.id),
        });
      for (const f of r.functions ?? []) {
        const link = d.function(r.name, f.name);
        report("LCN-002", {
          zone: r.name,
          resource: f.name,
          pass: !f.envSecret,
          detail: f.envSecret ? `${f.envSecret.where} holds ${f.envSecret.kind}` : "",
          confidence: f.envSecret?.likely ? "likely" : undefined,
          link,
        });
        if (f.anonymousTriggers) {
          const open = f.anonymousTriggers.length > 0;
          // Anyone can run a public function; when its role is an administrator, a bug in it is a bug in the account.
          const admin = open && !!f.role && !!roles.get(f.role)?.admin;
          report("LCN-003", {
            zone: r.name,
            resource: f.name,
            pass: !open,
            severity: admin ? "high" : undefined,
            detail: open ? `Anonymous HTTP trigger ${f.anonymousTriggers.join(", ")}${admin ? `, and its role ${f.role} has administrator access` : ""}` : "",
            confidence: open ? "likely" : undefined,
            link,
          });
        }
      }
    }
  },
);
