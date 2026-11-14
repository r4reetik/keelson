// What GitHub's own code security finds and whether it's switched on: leaked
// secrets still open, secret scanning and push protection on public repositories,
// open critical and high Dependabot and code scanning alerts, and Dependabot
// security updates. A secret's value is never read; GitHub's name for its kind is.

import { active, defineChecks } from "./define.ts";
import type { GithubContext } from "./define.ts";
import type { Severity } from "../../../core/types.ts";

const SERIOUS = new Set(["critical", "high"]);

/** Per active repository: how many open alerts are critical and how many high. */
function serious(ctx: GithubContext, alerts: { repo: string; severity: string }[]) {
  const by = new Map<string, { critical: number; high: number }>();
  for (const a of alerts) {
    if (!SERIOUS.has(a.severity)) continue;
    const n = by.get(a.repo) ?? { critical: 0, high: 0 };
    n[a.severity as "critical" | "high"]++;
    by.set(a.repo, n);
  }
  return active(ctx.inv).map((r) => ({ repo: r, count: by.get(r.name) ?? { critical: 0, high: 0 } }));
}

const summary = (n: { critical: number; high: number }) =>
  [n.critical && `${n.critical} critical`, n.high && `${n.high} high`].filter(Boolean).join(" and ") + " open";

export default defineChecks(
  {
    "GSC-001": {
      category: "Secrets",
      severity: "high",
      docs: "https://docs.github.com/en/code-security/secret-scanning/enabling-secret-scanning-features/enabling-secret-scanning-for-your-repository",
      requires: ["codeSecurity"],
      title: "Public repository doesn't scan for leaked secrets",
      why: "Anyone can read a public repository and its whole history. Secret scanning is free there and tells you when a key or token is committed, often before someone else finds it.",
      fix: "In the repository's Settings → Code security, enable Secret scanning. To cover every public repository, apply a security configuration under the organization's Settings → Code security → Configurations.",
    },
    "GSC-002": {
      category: "Secrets",
      severity: "medium",
      docs: "https://docs.github.com/en/code-security/secret-scanning/protecting-pushes-with-secret-scanning",
      requires: ["codeSecurity"],
      title: "Push protection is off",
      why: "Secret scanning only reports a secret after it's pushed, when it's already in the history. Push protection stops the push instead.",
      fix: "In the repository's Settings → Code security, enable Push protection under Secret scanning, or turn it on in the organization's security configuration.",
    },
    "GSC-003": {
      category: "Secrets",
      severity: "critical",
      docs: "https://docs.github.com/en/code-security/secret-scanning/managing-alerts-from-secret-scanning/resolving-alerts-from-secret-scanning",
      requires: ["secretScanning"],
      attackPath: true,
      title: "Leaked secret found in a repository and not resolved",
      why: "GitHub found a credential in the code or its history. Anyone who can read the repository, or who cloned it before, can use it until it's revoked.",
      fix: "1. Revoke or rotate the credential where it was issued. Deleting the commit doesn't help: the value stays in clones and forks. 2. Close the alert in the repository's Security → Secret scanning as Revoked.",
    },
    "GSC-004": {
      category: "Platform",
      severity: "high",
      docs: "https://docs.github.com/en/code-security/dependabot/dependabot-alerts/viewing-and-updating-dependabot-alerts",
      requires: ["dependabot"],
      title: "Dependency with a critical or high vulnerability",
      why: "A package the repository depends on has a published vulnerability rated critical or high, so how to exploit it is public.",
      fix: "Open the repository's Security → Dependabot alerts, update the packages, or dismiss an alert with the reason when the vulnerable code isn't reachable.",
    },
    "GSC-005": {
      category: "Platform",
      severity: "high",
      docs: "https://docs.github.com/en/code-security/code-scanning/managing-code-scanning-alerts/assessing-code-scanning-alerts-for-your-repository",
      requires: ["codeScanning"],
      title: "Code scanning found a critical or high vulnerability",
      why: "Code scanning found a weakness in the repository's own code rated critical or high, such as an injection or a path traversal.",
      fix: "Open the repository's Security → Code scanning, fix the code it points at, or dismiss the alert with the reason when it's a false positive.",
    },
    "GSC-006": {
      category: "Platform",
      severity: "low",
      docs: "https://docs.github.com/en/code-security/dependabot/dependabot-security-updates/configuring-dependabot-security-updates",
      requires: ["codeSecurity"],
      title: "Dependabot security updates are off",
      why: "Without them, a fix for a vulnerable dependency waits for someone to notice the alert and make the change by hand.",
      fix: "In the repository's Settings → Code security, enable Dependabot security updates, or turn it on in the organization's security configuration.",
    },
  },
  (ctx, report) => {
    const { inv, d } = ctx;
    for (const r of active(inv)) {
      const s = r.security;
      if (!s) continue;
      const link = d.repo(r.name, "settings/security_analysis");
      if (!r.private && s.secretScanning != null)
        report("GSC-001", { zone: r.name, resource: r.name, pass: s.secretScanning, detail: s.secretScanning ? "" : "Secret scanning is off", link });
      if (s.secretScanning && s.pushProtection != null)
        report("GSC-002", {
          zone: r.name,
          resource: r.name,
          pass: s.pushProtection,
          detail: s.pushProtection ? "" : "Secret scanning is on, push protection is off",
          link,
        });
      if (s.dependabotUpdates != null)
        report("GSC-006", {
          zone: r.name,
          resource: r.name,
          pass: s.dependabotUpdates,
          detail: s.dependabotUpdates ? "" : "Dependabot security updates are off",
          link,
        });
    }

    if (inv.secretScanning) {
      for (const a of inv.secretScanning) {
        const severity: Severity | undefined = a.validity === "inactive" ? "medium" : undefined;
        report("GSC-003", {
          zone: a.repo,
          resource: `${a.repo} alert ${a.number}`,
          pass: false,
          severity,
          confidence: a.validity === "active" ? "confirmed" : undefined,
          detail: [
            `${a.kind}`,
            a.validity === "active" ? "GitHub checked it still works" : a.validity === "inactive" ? "GitHub reports it no longer works" : null,
            a.pushProtectionBypassed ? "pushed past push protection" : null,
          ]
            .filter(Boolean)
            .join(", "),
          link: d.repo(a.repo, `security/secret-scanning/${a.number}`),
        });
      }
      report.passIfNone("GSC-003", inv.login);
    }

    const alerts = [
      ["GSC-004", inv.dependabot, "security/dependabot"],
      ["GSC-005", inv.codeScanning, "security/code-scanning"],
    ] as const;
    for (const [id, list, page] of alerts) {
      if (!list) continue;
      for (const { repo, count } of serious(ctx, list)) {
        const found = count.critical + count.high > 0;
        report(id, {
          zone: repo.name,
          resource: repo.name,
          pass: !found,
          severity: found && !count.critical ? "medium" : undefined,
          detail: found ? summary(count) : "",
          link: d.repo(repo.name, page),
        });
      }
    }
  },
);
