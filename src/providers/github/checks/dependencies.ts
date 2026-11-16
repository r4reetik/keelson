// What each repository depends on, from its software bill of materials (Anchore
// Syft over its manifest and lock files): packages with vulnerabilities attackers
// are known to exploit, packages with critical or high vulnerabilities, packages
// known to be malicious, actions used by a tag that can be moved, projects that
// install dependencies without a lock file, and strong copyleft licenses.
//
// One finding per package and repository, whatever its version: upgrading to a
// version that's still vulnerable keeps the same finding (and its triage), and a
// package used by several parts of a monorepo is one thing to fix. Its evidence
// says which parts use it, directly or through another package, and the smallest
// upgrade that fixes each vulnerability.

import { defineChecks, type GithubContext } from "./define.ts";
import type { Confidence, Evidence, Severity } from "../../../core/types.ts";
import type { DepPackage, DepVuln, GithubRepo, RepoDependencies } from "../types.ts";
import type { ActionsEvidence, DependencyEvidence, LicenseEvidence, LockEvidence } from "../../../shared/dependencies.ts";
import { compareVersions, MAX_VULNS } from "../sbom/index.ts";

/** A vulnerability this likely to be exploited in the next 30 days (FIRST's EPSS) is reported whatever its severity. */
export const EPSS_REPORTED = 0.1;
/** Below this EPSS, a vulnerability in a package only another package uses is rated one step lower. */
export const EPSS_LIKELY = 0.01;
const LOWER: Record<Severity, Severity> = { critical: "high", high: "medium", medium: "low", low: "low", info: "info" };

/** The same package at every version a repository uses. */
interface Group {
  name: string;
  ecosystem: string;
  versions: DepPackage[];
}

const isMalicious = (v: DepVuln) => [v.id, ...v.aliases].some((id) => id.startsWith("MAL-"));
const serious = (v: DepVuln) => v.kev || v.severity === "critical" || v.severity === "high" || (v.epss ?? 0) >= EPSS_REPORTED;

function groups(packages: DepPackage[]): Group[] {
  const by = new Map<string, Group>();
  for (const p of packages) {
    const k = `${p.ecosystem}|${p.name}`;
    const g = by.get(k) ?? { name: p.name, ecosystem: p.ecosystem, versions: [] };
    g.versions.push(p);
    by.set(k, g);
  }
  return [...by.values()];
}

/** Every use of the package, at every version, is through another package. */
const isTransitive = (g: Group) => {
  const uses = g.versions.flatMap((p) => p.usedBy);
  return uses.length > 0 && uses.every((u) => !u.direct);
};

/** "lodash (npm)": the finding's resource, the same whatever the version. */
const resourceOf = (g: { name: string; ecosystem: string }) => `${g.name} (${g.ecosystem})`;

const partName = (deps: RepoDependencies, path: string) => {
  const p = deps.parts.find((x) => x.path === path);
  return p?.workflows ? "workflows" : path || (p?.name ? `root (${p.name})` : "root");
};

const listed = (items: string[], max = 3) => (items.length <= max ? joinAnd(items) : `${items.slice(0, max).join(", ")} and ${items.length - max} more`);
const joinAnd = (items: string[]) => (items.length < 2 ? (items[0] ?? "") : `${items.slice(0, -1).join(", ")} and ${items.at(-1)}`);

/** The smallest version that fixes every listed vulnerability that has a fix. */
export function upgradeFor(vulns: DepVuln[]): string | null {
  const fixes = vulns.map((v) => v.fixedIn).filter((f): f is string => !!f);
  return fixes.length ? fixes.sort(compareVersions).at(-1)! : null;
}

/** What the finding dialog shows for a vulnerable package: each version, where it's used, and its vulnerabilities. */
function evidenceOf(ctx: GithubContext, r: GithubRepo, deps: RepoDependencies, g: Group, picked: (v: DepVuln) => boolean): Evidence {
  const dependabot = ctx.inv.dependabot?.filter((a) => a.repo === r.name && a.pkg === g.name) ?? null;
  const vulnerabilities = g.versions
    .flatMap((p) => p.vulns.filter(picked).map((v) => ({ ...v, version: p.version })))
    .sort((a, b) => Number(b.kev) - Number(a.kev) || b.risk - a.risk);
  const dependabotIds = new Set(dependabot?.map((a) => a.advisory));
  const dependency: DependencyEvidence = {
    name: g.name,
    ecosystem: g.ecosystem,
    versions: g.versions.map((p) => ({
      version: p.version,
      upgrade: upgradeFor(p.vulns.filter(picked)),
      upgradeAll: upgradeFor(p.vulns),
      devOnly: p.devOnly,
      locations: p.locations,
      usedBy: p.usedBy.map((u) => ({ ...u, label: partName(deps, u.part) })),
      vulns: p.vulns.length,
    })),
    vulnerabilities: vulnerabilities.slice(0, MAX_VULNS).map((v) => ({
      id: v.id,
      aliases: v.aliases,
      version: v.version,
      severity: v.severity,
      cvss: v.cvss,
      epss: v.epss,
      percentile: v.percentile,
      kev: v.kev,
      ransomware: v.ransomware,
      fixedIn: v.fixedIn,
      state: v.state,
      summary: v.summary,
      url: v.url,
      cpeOnly: v.cpeOnly,
      dependabot: [v.id, ...v.aliases].some((id) => dependabotIds.has(id)),
    })),
    more: Math.max(0, vulnerabilities.length - MAX_VULNS),
    // Whether GitHub's own Dependabot tells anyone about it: off, on and alerting, or on and silent.
    dependabot: r.dependabotAlerts === false ? "off" : dependabot?.length ? "alerting" : r.dependabotAlerts ? "silent" : null,
  };
  return { dependency };
}

/** Where a package is used, in a sentence: "used directly by apps/web and packages/ui". */
function usedByText(deps: RepoDependencies, g: Group): string {
  const usages = g.versions.flatMap((p) => p.usedBy);
  const direct = [...new Set(usages.filter((u) => u.direct).map((u) => partName(deps, u.part)))];
  const through = [...new Set(usages.filter((u) => !u.direct).map((u) => partName(deps, u.part)))].filter((p) => !direct.includes(p));
  const multi = deps.parts.filter((p) => !p.workflows).length > 1;
  if (!multi) return direct.length ? "a direct dependency" : through.length ? "pulled in by another package" : "";
  return [direct.length && `used directly by ${listed(direct)}`, through.length && `pulled in by other packages in ${listed(through)}`]
    .filter(Boolean)
    .join("; ");
}

/** A vulnerability's CVE when it has one, else its own ID: the name people search for. */
const cveOf = (v: DepVuln) => [v.id, ...v.aliases].find((id) => id.startsWith("CVE-")) ?? v.id;

/** "mock-router 1.4.0: 2 vulnerabilities, 1 critical and 1 high". */
function summary(g: Group, vulns: DepVuln[], exploited = false): string {
  const versions = listed([...new Set(g.versions.map((p) => p.version))], 2);
  if (exploited) {
    const ids = [...new Set(vulns.filter((v) => v.kev).map(cveOf))];
    return `${g.name} ${versions}: ${listed(ids, 2)} ${ids.length === 1 ? "is" : "are"} known to be exploited`;
  }
  const counts = (["critical", "high", "medium", "low"] as const).map((s) => [s, vulns.filter((v) => v.severity === s).length] as const).filter(([, n]) => n);
  const what =
    vulns.length === 1
      ? `1 ${vulns[0].severity} vulnerability (${cveOf(vulns[0])})`
      : `${vulns.length} vulnerabilities, ${joinAnd(counts.map(([s, n]) => `${n} ${s}`))}`;
  // Reported for how likely its exploitation is rather than its severity: say so.
  const likely = vulns.filter((v) => v.severity !== "critical" && v.severity !== "high" && (v.epss ?? 0) >= EPSS_REPORTED);
  const epss = likely.length ? `, ${Math.round(100 * Math.max(...likely.map((v) => v.epss ?? 0)))}% likely to be exploited within 30 days` : "";
  return `${g.name} ${versions}: ${what}${epss}`;
}

export default defineChecks(
  {
    "GDP-001": {
      category: "Supply chain",
      severity: "critical",
      docs: "https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-supply-chain-security",
      requires: ["manifests", "syft", "grype"],
      attackPath: true,
      title: "Dependency has a vulnerability attackers are exploiting",
      why: "A package this repository uses has a vulnerability in CISA's catalog of known exploited vulnerabilities: attackers are using it now, with tools that are already public. Anything built from this code that runs the package is exposed.",
      fix: "1. Upgrade the package to the version the evidence names, in every part that uses it, and deploy. 2. If it comes in through another package, upgrade that one, or override the version (npm overrides, Yarn resolutions, a Go replace or a constraint). 3. Check what ran it before the upgrade for signs of compromise.",
    },
    "GDP-002": {
      category: "Supply chain",
      severity: "high",
      docs: "https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-supply-chain-security",
      requires: ["manifests", "syft", "grype"],
      title: "Dependency has a critical or high vulnerability",
      why: "A package this repository uses has a published vulnerability rated critical or high, or one that FIRST's EPSS rates likely to be exploited soon. How to exploit it is public, so whatever is built from this code inherits it until the package is upgraded.",
      fix: "1. Upgrade the package to the version the evidence names; it fixes every listed vulnerability that has a fix. 2. If it comes in through another package, upgrade that one, or override the version (npm overrides, Yarn resolutions, a Go replace or a constraint). 3. If the vulnerable code can't be reached from how you use it, mark the finding as accepted with the reason.",
    },
    "GDP-003": {
      category: "Supply chain",
      severity: "critical",
      docs: "https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database",
      requires: ["manifests", "syft", "grype"],
      attackPath: true,
      title: "Dependency is a known malicious package",
      why: "The package is listed as malware: published to steal credentials, open a backdoor or run code when it's installed. Installing it is enough, so every developer machine and CI runner that installed this version may be compromised.",
      fix: "1. Remove the package, or move to a version that isn't listed, and regenerate the lock file. 2. Treat every machine and CI runner that installed it as compromised: rotate the credentials they held. 3. Check how it got in: a typo in the name, or a dependency that pulled it.",
    },
    "GDP-004": {
      category: "Supply chain",
      severity: "low",
      docs: "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
      requires: ["manifests"],
      title: "Workflows run third-party actions by a tag that can be moved",
      why: "A tag such as v4 can be pointed at different code at any time, by the action's owner or by whoever takes over their account. Workflows run that code with the repository's token and secrets, as happened with tj-actions/changed-files in 2025. A commit SHA can't be moved.",
      fix: "Pin each third-party action to the full commit SHA of the release you use, with the tag in a comment (uses: owner/action@<sha> # v4). Dependabot or Renovate keep pinned actions up to date. Actions owned by GitHub (actions/*, github/*) and your own organization aren't counted.",
    },
    "GDP-005": {
      category: "Supply chain",
      severity: "low",
      docs: "https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/dependency-graph-supported-package-ecosystems",
      requires: ["manifests"],
      title: "Project installs dependencies without a lock file",
      why: "Without a lock file, or with version ranges in a requirements file, every install takes whatever version is newest at that moment. A malicious or broken release reaches your builds without anyone changing the code, and Keelson can't check those versions for vulnerabilities.",
      fix: "Commit the lock file your package manager writes (package-lock.json, yarn.lock, pnpm-lock.yaml, go.sum, Gemfile.lock, composer.lock, poetry.lock, Pipfile.lock), and install from it in CI (npm ci, pip install with pinned == versions or a lock).",
    },
    "GLI-001": {
      category: "Supply chain",
      severity: "low",
      docs: "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository",
      requires: ["manifests", "syft", "grant"],
      title: "Dependency under a strong copyleft license",
      why: "The package's license (such as GPL or AGPL) requires software that includes it to be released under the same terms when it's distributed, or for AGPL and SSPL when it's offered over a network. A repository that isn't under a compatible license may have to release its own code, or remove the package.",
      fix: "Check with whoever looks after licensing whether this use is allowed: it depends on how the software is distributed or offered. Otherwise replace the package with one under a permissive license. Mark the finding as accepted when the use is cleared.",
    },
  },
  (ctx, report) => {
    const { inv, d } = ctx;
    const deps = inv.dependencies;
    if (!deps) return;
    const repos = new Map(inv.repos.map((r) => [r.name, r]));
    const own = inv.login.toLowerCase();

    for (const rd of deps.repos) {
      const r = repos.get(rd.repo);
      if (!r) continue;
      const zone = r.name;
      const link = d.repo(r.name, r.dependabotAlerts ? "security/dependabot" : "network/dependencies");

      // Actions by a tag: everything but GitHub's own and the organization's.
      const moving = rd.actions.filter((a) => {
        const owner = a.action.split("/")[0].toLowerCase();
        return owner !== "actions" && owner !== "github" && owner !== own && !/^[0-9a-f]{40}$/i.test(a.ref);
      });
      if (rd.actions.length) {
        const names = [...new Set(moving.map((a) => `${a.action}@${a.ref}`))];
        report("GDP-004", {
          zone,
          resource: r.name,
          pass: !moving.length,
          detail: moving.length ? `${listed(names)} ${names.length === 1 ? "is" : "are"} used by a tag` : "",
          evidence: moving.length ? { actions: moving.map((a): ActionsEvidence => ({ uses: `${a.action}@${a.ref}`, workflow: a.workflow })) } : null,
          link: d.repo(r.name, `blob/${encodeURIComponent(r.defaultBranch)}/${moving[0]?.workflow ?? ".github/workflows"}`),
        });
      }

      for (const p of rd.parts) {
        if (p.workflows || p.devOnly) continue;
        const needsLock = p.unpinned.length > 0;
        if (!needsLock && !p.lockfile) continue;
        report("GDP-005", {
          zone,
          resource: p.path ? `${r.name}/${p.path}` : r.name,
          pass: !needsLock,
          detail: needsLock ? `${p.path || "The repository's root"} installs ${listed(p.unpinned)} without a pinned version` : "",
          evidence: needsLock ? { lock: { part: p.path, files: p.files, unpinned: p.unpinned } satisfies LockEvidence } : null,
          link: d.repo(r.name, `tree/${encodeURIComponent(r.defaultBranch)}/${p.path}`),
        });
      }

      if (!rd.packages) continue;
      const found = { "GDP-001": false, "GDP-002": false, "GDP-003": false, "GLI-001": false };
      for (const g of groups(rd.packages)) {
        const all = g.versions.flatMap((p) => p.vulns);
        const devOnly = g.versions.every((p) => p.devOnly);
        const where = usedByText(rd, g);
        const malicious = all.filter(isMalicious);
        const kev = all.filter((v) => v.kev && !isMalicious(v));
        const bad = all.filter((v) => serious(v) && !v.kev && !isMalicious(v));
        if (malicious.length) {
          found["GDP-003"] = true;
          report("GDP-003", {
            zone,
            resource: resourceOf(g),
            pass: false,
            detail: [`${g.name} ${[...new Set(g.versions.map((p) => p.version))].join(", ")} is listed as malicious (${malicious[0].id})`, where]
              .filter(Boolean)
              .join("; "),
            evidence: evidenceOf(ctx, r, rd, g, isMalicious),
            link,
          });
          continue;
        }
        if (kev.length) {
          found["GDP-001"] = true;
          report("GDP-001", {
            zone,
            resource: resourceOf(g),
            pass: false,
            severity: devOnly ? "high" : undefined,
            confidence: kev.every((v) => v.cpeOnly) ? "likely" : undefined,
            detail: [summary(g, kev, true), upgradeText(kev), where, devOnly ? "development only" : null].filter(Boolean).join("; "),
            evidence: evidenceOf(ctx, r, rd, g, (v) => v.kev || serious(v)),
            link,
          });
          continue;
        }
        if (bad.length) {
          found["GDP-002"] = true;
          const worst: Severity = bad.some((v) => v.severity === "critical") ? "critical" : bad.some((v) => v.severity === "high") ? "high" : "medium";
          const confidence: Confidence | undefined = bad.every((v) => v.cpeOnly) ? "likely" : undefined;
          // Only another package uses it, and nothing says it's about to be exploited: its vulnerable code is often never called.
          const remote = isTransitive(g) && bad.every((v) => (v.epss ?? 0) < EPSS_LIKELY);
          let severity: Severity = devOnly ? LOWER[worst] : worst;
          if (remote) severity = LOWER[severity];
          report("GDP-002", {
            zone,
            resource: resourceOf(g),
            pass: false,
            severity,
            confidence,
            detail: [summary(g, bad), upgradeText(bad), where, devOnly ? "development only" : null, remote ? "unlikely to be exploited soon" : null]
              .filter(Boolean)
              .join("; "),
            evidence: evidenceOf(ctx, r, rd, g, serious),
            link,
          });
        }
      }
      for (const id of ["GDP-001", "GDP-002", "GDP-003"] as const) if (!found[id]) report(id, { zone, resource: r.name, pass: true });

      // Licenses: only where the repository's own license isn't a copyleft one that allows them.
      if (copyleft(r.license)) continue;
      // A product split into many packages under one npm scope (@ckeditor/*) is one licensing decision, so one finding.
      const scoped = (p: DepPackage): DepPackage & { original: string } => ({
        ...p,
        name: p.name.startsWith("@") ? `${p.name.split("/")[0]}/*` : p.name,
        original: p.name,
      });
      const strong = groups(rd.packages.filter((p) => p.licenseRisk === "strong" && !p.devOnly).map(scoped));
      for (const g of strong) {
        const license = [...new Set(g.versions.flatMap((p) => p.licenses))].join(", ") || "a strong copyleft license";
        const nameOf = (p: DepPackage) => (p as DepPackage & { original?: string }).original ?? p.name;
        const count = new Set(g.versions.map(nameOf)).size;
        const network = /\b(AGPL|SSPL)/i.test(license);
        report("GLI-001", {
          zone,
          resource: resourceOf(g),
          pass: false,
          severity: network ? "medium" : undefined,
          confidence: "likely",
          detail: [
            `${count > 1 ? `${count} ${g.name} packages are` : `${nameOf(g.versions[0])} is`} under ${license}`,
            usedByText(rd, g),
            r.license ? `the repository is under ${r.license}` : "the repository has no license",
          ]
            .filter(Boolean)
            .join("; "),
          evidence: {
            license: {
              licenses: g.versions.map((p) => ({
                name: nameOf(p),
                version: p.version,
                licenses: p.licenses,
                usedBy: p.usedBy.map((u) => partName(rd, u.part)),
              })),
              repositoryLicense: r.license,
            } satisfies LicenseEvidence,
          },
          link: d.repo(r.name, "network/dependencies"),
        });
      }
      if (!strong.length && rd.packages.some((p) => p.licenseRisk)) report("GLI-001", { zone, resource: r.name, pass: true });
    }
  },
);

const copyleft = (spdx: string | null) => !!spdx && /^(A?GPL|LGPL|SSPL|EUPL|OSL)/i.test(spdx);

function upgradeText(vulns: DepVuln[]): string | null {
  const to = upgradeFor(vulns);
  const unfixed = vulns.filter((v) => !v.fixedIn).length;
  if (!to) return "no fixed version yet";
  return `upgrade to ${to}${unfixed ? ` (${unfixed} without a fix yet)` : ""}`;
}
