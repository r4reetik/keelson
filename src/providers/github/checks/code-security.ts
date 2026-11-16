// What GitHub's own code security finds and whether it's switched on: leaked
// secrets still open, secret scanning and push protection on public repositories,
// Dependabot alerts and code scanning, their open critical and high alerts, and
// Dependabot security updates. A secret's value is never read; GitHub's name for
// its kind is.
//
// A repository only passes an alert check when the feature runs there: no alerts
// from a scanner that's off proves nothing.

import { active, defineChecks } from "./define.ts";
import type { GithubContext } from "./define.ts";
import type { Severity } from "../../../core/types.ts";
import type { GithubRepo } from "../types.ts";

const SERIOUS = new Set(["critical", "high"]);

/** Per active repository where the scanner runs (`on`): how many open alerts are critical and how many high. */
function serious(ctx: GithubContext, alerts: { repo: string; severity: string }[], on: (r: GithubRepo) => boolean) {
  const by = new Map<string, { critical: number; high: number }>();
  for (const a of alerts) {
    if (!SERIOUS.has(a.severity)) continue;
    const n = by.get(a.repo) ?? { critical: 0, high: 0 };
    n[a.severity as "critical" | "high"]++;
    by.set(a.repo, n);
  }
  // An alert from a repository that has since turned the scanner off still counts.
  return active(ctx.inv)
    .filter((r) => on(r) || by.has(r.name))
    .map((r) => ({ repo: r, count: by.get(r.name) ?? { critical: 0, high: 0 } }));
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
      // Not codeSecurity: a leaked secret is reported even when the repository's settings can't be read; only its passes need them.
      requires: ["secretScanning"],
      attackPath: true,
      title: "Leaked secret found in a repository and not resolved",
      why: "GitHub found a credential in the code or its history. Anyone who can read the repository, or who cloned it before, can use it until it's revoked.",
      fix: "1. Revoke or rotate the credential where it was issued. Deleting the commit doesn't help: the value stays in clones and forks. 2. Close the alert in the repository's Security → Secret scanning as Revoked.",
    },
    "GSC-004": {
      category: "Supply chain",
      severity: "high",
      docs: "https://docs.github.com/en/code-security/dependabot/dependabot-alerts/viewing-and-updating-dependabot-alerts",
      requires: ["dependabot", "dependabotSetup"],
      title: "Dependency with a critical or high vulnerability",
      why: "A package the repository depends on has a published vulnerability rated critical or high, so how to exploit it is public.",
      fix: "Open the repository's Security → Dependabot alerts, update the packages, or dismiss an alert with the reason when the vulnerable code isn't reachable.",
    },
    "GSC-005": {
      category: "Platform",
      severity: "high",
      docs: "https://docs.github.com/en/code-security/code-scanning/managing-code-scanning-alerts/assessing-code-scanning-alerts-for-your-repository",
      requires: ["codeScanning", "codeScanningSetup"],
      title: "Code scanning found a critical or high vulnerability",
      why: "Code scanning found a weakness in the repository's own code rated critical or high, such as an injection or a path traversal.",
      fix: "Open the repository's Security → Code scanning, fix the code it points at, or dismiss the alert with the reason when it's a false positive.",
    },
    "GSC-006": {
      category: "Platform",
      severity: "low",
      docs: "https://docs.github.com/en/code-security/dependabot/dependabot-security-updates/configuring-dependabot-security-updates",
      requires: ["codeSecurity", "dependabot"],
      title: "Dependabot security updates are off where Dependabot has found something",
      why: "The repository has open Dependabot alerts, and without security updates each fix waits for someone to notice the alert and make the change by hand.",
      fix: "In the repository's Settings → Code security, enable Dependabot security updates, or turn it on in the organization's security configuration. Dependabot then opens a pull request for each fix.",
    },
    "GSC-007": {
      category: "Platform",
      severity: "medium",
      docs: "https://docs.github.com/en/code-security/dependabot/dependabot-alerts/configuring-dependabot-alerts",
      requires: ["dependabotSetup"],
      title: "Dependabot alerts are off",
      why: "GitHub doesn't tell anyone when a dependency of this repository has a published vulnerability. Dependabot alerts are free on every repository, private ones included.",
      fix: "In the repository's Settings → Code security, enable Dependabot alerts. To cover every repository, apply a security configuration under the organization's Settings → Code security → Configurations.",
    },
    "GSC-008": {
      category: "Platform",
      severity: "medium",
      docs: "https://docs.github.com/en/code-security/code-scanning/enabling-code-scanning/configuring-default-setup-for-code-scanning",
      requires: ["codeScanningSetup"],
      title: "Public repository isn't scanned for vulnerabilities in its code",
      why: "Anyone can read this code and look for injections and other weaknesses in it. Code scanning is free on public repositories and finds many of them first.",
      fix: "In the repository's Settings → Code security, choose Set up → Default under Code scanning, or turn it on for every public repository in the organization's security configuration.",
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
      // Only where Dependabot has something to fix: an empty repository, or one without alerts, gains nothing from it.
      const open = inv.dependabot?.filter((a) => a.repo === r.name).length ?? 0;
      if (s.dependabotUpdates != null && open)
        report("GSC-006", {
          zone: r.name,
          resource: r.name,
          pass: s.dependabotUpdates,
          detail: s.dependabotUpdates ? "" : `Security updates are off, with ${open} open Dependabot alert${open === 1 ? "" : "s"}`,
          link,
        });
    }
    for (const r of active(inv)) {
      const link = d.repo(r.name, "settings/security_analysis");
      if (r.dependabotAlerts != null)
        report("GSC-007", { zone: r.name, resource: r.name, pass: r.dependabotAlerts, detail: r.dependabotAlerts ? "" : "Dependabot alerts are off", link });
      if (!r.private && r.codeScanning != null)
        report("GSC-008", { zone: r.name, resource: r.name, pass: r.codeScanning, detail: r.codeScanning ? "" : "Code scanning has never run", link });
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
      // No alert only means something where secret scanning runs.
      const alerted = new Set(inv.secretScanning.map((a) => a.repo));
      for (const r of active(inv)) if (r.security?.secretScanning && !alerted.has(r.name)) report("GSC-003", { zone: r.name, resource: r.name, pass: true });
    }

    const alerts = [
      ["GSC-004", inv.dependabot, "security/dependabot", (r: GithubRepo) => r.dependabotAlerts === true],
      ["GSC-005", inv.codeScanning, "security/code-scanning", (r: GithubRepo) => r.codeScanning === true],
    ] as const;
    for (const [id, list, page, on] of alerts) {
      if (!list) continue;
      for (const { repo, count } of serious(ctx, list, on)) {
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
