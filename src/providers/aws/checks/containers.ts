// Containers: EKS clusters' API endpoints, audit logs and Kubernetes versions; the
// ECS task definitions that services run (privileged containers, the host's
// namespaces, credentials in environment variables); and ECR repositories (public
// policies, image scanning, tags that can be overwritten).

import { defineChecks } from "./define.ts";

export default defineChecks(
  {
    "ACN-001": {
      category: "Attack surface",
      severity: "high",
      docs: "https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html",
      requires: ["eks"],
      attackPath: true,
      title: "EKS API endpoint is open to the whole internet",
      why: "Anyone can reach the cluster's Kubernetes API. One leaked kubeconfig, token or API vulnerability is then enough to control the workloads, without being on your network.",
      fix: "In EKS → the cluster → Networking → Manage endpoint access, turn on private access, and either turn public access off or limit it to your offices' and CI's address ranges.",
    },
    "ACN-002": {
      category: "Monitoring",
      severity: "low",
      docs: "https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html",
      requires: ["eks"],
      title: "EKS cluster keeps no audit log",
      why: "There is no record of who called the Kubernetes API: who read a secret, started a pod or changed a role binding. After an incident you can't tell what happened.",
      fix: "In EKS → the cluster → Observability → Control plane logging → Manage, turn on Audit (and Authenticator). The logs go to CloudWatch Logs; set a retention period on the log group.",
    },
    "ACN-003": {
      category: "Platform",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html",
      requires: ["eks"],
      title: "EKS cluster runs a Kubernetes version past standard support",
      why: "The version gets security fixes only under extended support, which costs more per cluster hour and ends on a date, after which AWS upgrades the cluster for you. An unsupported version gets no fixes at all.",
      fix: "Plan the upgrade: check deprecated APIs, upgrade the control plane one minor version at a time in EKS → the cluster → Upgrade version, then the node groups and add-ons.",
    },
    "ACN-004": {
      category: "Platform",
      severity: "high",
      docs: "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html#container_definition_security",
      requires: ["ecs"],
      title: "ECS task runs a privileged container or shares the host",
      why: "A privileged container, or one in the host's network or process namespace, can reach the host it runs on and every other container there. A compromise of the application becomes a compromise of the host.",
      fix: "Register a new revision of the task definition without Privileged, and with awsvpc or bridge networking and no host PID or IPC mode. Grant the specific Linux capabilities it needs instead, then update the service to the new revision.",
    },
    "ACN-005": {
      category: "Secrets",
      severity: "high",
      docs: "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/secrets-envvar-secrets-manager.html",
      requires: ["ecs"],
      title: "Credential in an ECS task definition's environment variables",
      why: "Task definitions are readable by anyone who can describe them, in every revision ever registered, so the credential is in clear text for every read-only role and tool.",
      fix: "1. Rotate the credential. 2. Store it in Secrets Manager or Parameter Store. 3. Register a revision that passes it under secrets (valueFrom) instead of environment, and deregister the old revisions.",
    },
    "ACN-006": {
      category: "Attack surface",
      severity: "critical",
      docs: "https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policies.html",
      requires: ["ecr"],
      attackPath: true,
      title: "ECR repository is public",
      why: "Its repository policy lets anyone pull images, and with them any code, configuration or secrets built into them. If it also allows pushing, anyone can replace the images your services run.",
      fix: 'In ECR → the repository → Permissions, remove the statement for "*" or name the accounts and roles that need access. Use ECR Public for images meant to be public.',
    },
    "ACN-007": {
      category: "Platform",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html",
      requires: ["ecr"],
      title: "ECR images aren't scanned for vulnerabilities",
      why: "Images are pushed and run without anyone being told they contain packages with known vulnerabilities.",
      fix: "In ECR → Private registry → Feature & Settings → Scanning, add a rule that scans on push for all repositories (filter *), or turn on enhanced scanning with Amazon Inspector.",
    },
    "ACN-008": {
      category: "Change risk",
      severity: "low",
      docs: "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html",
      requires: ["ecr"],
      title: "ECR image tags can be overwritten",
      why: "Anyone who can push can replace the image behind a tag a service already runs, such as a release tag, and the next deployment or restart picks it up with no change anyone reviewed.",
      fix: "In ECR → the repository → Edit, set Tag immutability to Immutable (with exclusions for tags like latest if you need them), and deploy by digest or by release tag.",
    },
  },
  ({ inv, d }, report) => {
    for (const r of inv.regions) {
      for (const k of r.kubernetes ?? []) {
        const where = { zone: r.name, resource: k.name, link: d.console(r.name, "eks", `/clusters/${encodeURIComponent(k.name)}`) };
        report("ACN-001", { ...where, pass: !k.openToAll, detail: k.openToAll ? "The public endpoint accepts any address (0.0.0.0/0)" : "" });
        report("ACN-002", { ...where, pass: k.auditLogs, detail: k.auditLogs ? "" : "Audit logging is off" });
        if (k.versionStatus)
          report("ACN-003", {
            ...where,
            pass: k.versionStatus === "STANDARD_SUPPORT",
            severity: k.versionStatus === "UNSUPPORTED" ? "high" : undefined,
            detail:
              k.versionStatus === "STANDARD_SUPPORT"
                ? ""
                : `Kubernetes ${k.version} is in ${k.versionStatus === "UNSUPPORTED" ? "no support" : "extended support"}`,
          });
      }
      for (const t of r.taskDefinitions ?? []) {
        const where = {
          zone: r.name,
          resource: t.name,
          link: d.console(r.name, "ecs", `/v2/task-definitions/${encodeURIComponent(t.name.replace(":", "/"))}`),
        };
        const used = t.services.length ? ` (used by ${t.services.slice(0, 3).join(", ")}${t.services.length > 3 ? "…" : ""})` : "";
        const risky = [
          t.privileged.length && `privileged container${t.privileged.length === 1 ? "" : "s"} ${t.privileged.join(", ")}`,
          t.hostNamespaces.length && `the host's ${t.hostNamespaces.join(" and ")} namespace${t.hostNamespaces.length === 1 ? "" : "s"}`,
        ].filter(Boolean);
        report("ACN-004", { ...where, pass: !risky.length, detail: risky.length ? `Runs ${risky.join(" and ")}${used}` : "" });
        report("ACN-005", {
          ...where,
          pass: !t.secret,
          severity: t.secret?.likely ? "medium" : undefined,
          confidence: t.secret?.likely ? "likely" : undefined,
          detail: t.secret ? `${t.secret.where} holds ${t.secret.kind}${used}` : "",
        });
      }
      for (const repo of r.repositories ?? []) {
        const where = {
          zone: r.name,
          resource: repo.name,
          link: d.console(r.name, "ecr", `/repositories/private/${inv.accountId}/${encodeURIComponent(repo.name)}`),
        };
        if (repo.publicPolicy != null)
          report("ACN-006", { ...where, pass: !repo.publicPolicy, detail: repo.publicPolicy ? 'The repository policy allows "*"' : "" });
        report("ACN-007", { ...where, pass: repo.scanned, detail: repo.scanned ? "" : "Neither the repository nor a registry rule scans its images" });
        report("ACN-008", { ...where, pass: repo.immutableTags, detail: repo.immutableTags ? "" : "Tags are mutable" });
      }
    }
  },
);
