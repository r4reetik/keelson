// The checks on what a repository depends on, from its software bill of
// materials (src/core/sbom): packages with vulnerabilities attackers are known
// to exploit, packages with critical or high vulnerabilities, packages known to
// be malicious, actions used by a tag that can be moved, projects that install
// dependencies without a lock file, and strong copyleft licenses. Defined once
// here and given each platform's IDs and words (GitHub's GDP- and GLI-, Gitea's
// TED-), like the image checks (./image-checks.ts).
//
// One finding per package and repository, whatever its version: upgrading to a
// version that's still vulnerable keeps the same finding (and its triage), and a
// package used by several parts of a monorepo is one thing to fix. Its evidence
// says which parts use it, directly or through another package, and the smallest
// upgrade that fixes each vulnerability.

import type { CheckMeta, EvalInput } from "./checks/define.ts";
import type { Confidence, Evidence, Severity } from "./types.ts";
import type { ActionsEvidence, DependencyEvidence, DepPackage, DepVuln, LicenseEvidence, LockEvidence, RepoDependencies } from "../shared/dependencies.ts";
import { compareVersions, MAX_VULNS, type DependencyInventory } from "./sbom/index.ts";

/** The six checks, by what each is about: a platform gives each one its own ID. */
export interface DependencyCheckIds<I extends string> {
  exploited: I;
  vulnerable: I;
  malicious: I;
  actions: I;
  lock: I;
  license: I;
}

/** What differs in the checks' words from one platform to the next. */
export interface DependencyWording {
  /** The platform's own page for each subject, where it has one. */
  docs: { supplyChain?: string; advisories?: string; actions?: string; lock?: string; license?: string };
  /** What keeps pinned actions up to date there: a sentence. */
  pinning: string;
  /** The check about code a pipeline takes from elsewhere, in the platform's own words, where it has no actions (GitLab CI includes). */
  actions?: { title: string; why: string; fix: string };
}

/** One repository as the checks need it. */
export interface DependencyTarget {
  name: string;
  defaultBranch: string;
  /** The repository's own license as an SPDX ID; null without one. */
  license: string | null;
  /** Whether GitHub's Dependabot alerts are on; absent on a platform without them. */
  dependabotAlerts?: boolean | null;
}

export interface DependencyInput {
  dependencies: DependencyInventory | null;
  /** The organization's name: its own actions aren't third parties'. */
  org: string;
  repos: DependencyTarget[];
  /** GitHub's own Dependabot alerts, to say in the evidence whether it tells anyone; absent elsewhere. */
  dependabot?: { repo: string; pkg: string; advisory: string }[] | null;
  /** Where a finding sends people on the platform. */
  links: {
    dependencies(r: DependencyTarget): string;
    licenses(r: DependencyTarget): string;
    file(r: DependencyTarget, path: string): string;
    folder(r: DependencyTarget, path: string): string;
  };
  /** The folder workflows are in, linked when no one workflow is named. */
  workflowsDir: string;
  /** How a finding says something can move: "used by a tag" unless the platform says it another way. */
  movable?: string;
}

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
function evidenceOf(input: DependencyInput, r: DependencyTarget, deps: RepoDependencies, g: Group, picked: (v: DepVuln) => boolean): Evidence {
  const dependabot = input.dependabot?.filter((a) => a.repo === r.name && a.pkg === g.name) ?? null;
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

/** The dependency checks' metadata for one platform: `requires` are its sources for the files, the SBOM, vulnerabilities and licenses. */
export function dependencyCheckMeta<I extends string, S extends string>(
  ids: DependencyCheckIds<I>,
  requires: { files: S[]; sbom: S[]; vulnerabilities: S[]; licenses: S[] },
  wording: DependencyWording,
): Record<I, CheckMeta<S>> {
  return {
    [ids.exploited]: {
      category: "Supply chain",
      severity: "critical",
      docs: wording.docs.supplyChain,
      requires: [...requires.files, ...requires.sbom, ...requires.vulnerabilities],
      attackPath: true,
      title: "Dependency has a vulnerability attackers are exploiting",
      why: "A package this repository uses has a vulnerability in CISA's catalog of known exploited vulnerabilities: attackers are using it now, with tools that are already public. Anything built from this code that runs the package is exposed.",
      fix: "1. Upgrade the package to the version the evidence names, in every part that uses it, and deploy. 2. If it comes in through another package, upgrade that one, or override the version (npm overrides, Yarn resolutions, a Go replace or a constraint). 3. Check what ran it before the upgrade for signs of compromise.",
    },
    [ids.vulnerable]: {
      category: "Supply chain",
      severity: "high",
      docs: wording.docs.supplyChain,
      requires: [...requires.files, ...requires.sbom, ...requires.vulnerabilities],
      title: "Dependency has a critical or high vulnerability",
      why: "A package this repository uses has a published vulnerability rated critical or high, or one that FIRST's EPSS rates likely to be exploited soon. How to exploit it is public, so whatever is built from this code inherits it until the package is upgraded.",
      fix: "1. Upgrade the package to the version the evidence names; it fixes every listed vulnerability that has a fix. 2. If it comes in through another package, upgrade that one, or override the version (npm overrides, Yarn resolutions, a Go replace or a constraint). 3. If the vulnerable code can't be reached from how you use it, mark the finding as accepted with the reason.",
    },
    [ids.malicious]: {
      category: "Supply chain",
      severity: "critical",
      docs: wording.docs.advisories,
      requires: [...requires.files, ...requires.sbom, ...requires.vulnerabilities],
      attackPath: true,
      title: "Dependency is a known malicious package",
      why: "The package is listed as malware: published to steal credentials, open a backdoor or run code when it's installed. Installing it is enough, so every developer machine and CI runner that installed this version may be compromised.",
      fix: "1. Remove the package, or move to a version that isn't listed, and regenerate the lock file. 2. Treat every machine and CI runner that installed it as compromised: rotate the credentials they held. 3. Check how it got in: a typo in the name, or a dependency that pulled it.",
    },
    [ids.actions]: {
      category: "Supply chain",
      severity: "low",
      docs: wording.docs.actions,
      requires: requires.files,
      title: "Workflows run third-party actions by a tag that can be moved",
      why: "A tag such as v4 can be pointed at different code at any time, by the action's owner or by whoever takes over their account. Workflows run that code with the repository's token and secrets, as happened with tj-actions/changed-files in 2025. A commit SHA can't be moved.",
      fix: `Pin each third-party action to the full commit SHA of the release you use, with the tag in a comment (uses: owner/action@<sha> # v4). ${wording.pinning} Actions owned by GitHub (actions/*, github/*) and your own organization aren't counted.`,
      ...wording.actions,
    },
    [ids.lock]: {
      category: "Supply chain",
      severity: "low",
      docs: wording.docs.lock,
      requires: requires.files,
      title: "Project installs dependencies without a lock file",
      why: "Without a lock file, or with version ranges in a requirements file, every install takes whatever version is newest at that moment. A malicious or broken release reaches your builds without anyone changing the code, and Keelson can't check those versions for vulnerabilities.",
      fix: "Commit the lock file your package manager writes (package-lock.json, yarn.lock, pnpm-lock.yaml, go.sum, Gemfile.lock, composer.lock, poetry.lock, Pipfile.lock), and install from it in CI (npm ci, pip install with pinned == versions or a lock).",
    },
    [ids.license]: {
      category: "Supply chain",
      severity: "low",
      docs: wording.docs.license,
      requires: [...requires.files, ...requires.sbom, ...requires.licenses],
      title: "Dependency under a strong copyleft license",
      why: "The package's license (such as GPL or AGPL) requires software that includes it to be released under the same terms when it's distributed, or for AGPL and SSPL when it's offered over a network. A repository that isn't under a compatible license may have to release its own code, or remove the package.",
      fix: "Check with whoever looks after licensing whether this use is allowed: it depends on how the software is distributed or offered. Otherwise replace the package with one under a permissive license. Mark the finding as accepted when the use is cleared.",
    },
  } as Record<I, CheckMeta<S>>;
}

/** Reports the dependency checks for one organization's repositories under a platform's IDs. */
export function reportDependencies<I extends string>(ids: DependencyCheckIds<I>, input: DependencyInput, report: (id: I, e: EvalInput) => void): void {
  const deps = input.dependencies;
  if (!deps) return;
  const repos = new Map(input.repos.map((r) => [r.name, r]));
  const own = input.org.toLowerCase();

  for (const rd of deps.repos) {
    const r = repos.get(rd.repo);
    if (!r) continue;
    const zone = r.name;
    const link = input.links.dependencies(r);

    // Actions by a tag: everything but GitHub's own and the organization's.
    const moving = rd.actions.filter((a) => {
      const owner = a.action.split("/")[0].toLowerCase();
      return owner !== "actions" && owner !== "github" && owner !== own && !/^[0-9a-f]{40}$/i.test(a.ref);
    });
    if (rd.actions.length) {
      const names = [...new Set(moving.map((a) => `${a.action}@${a.ref}`))];
      report(ids.actions, {
        zone,
        resource: r.name,
        pass: !moving.length,
        detail: moving.length ? `${listed(names)} ${names.length === 1 ? "is" : "are"} ${input.movable ?? "used by a tag"}` : "",
        evidence: moving.length ? { actions: moving.map((a): ActionsEvidence => ({ uses: `${a.action}@${a.ref}`, workflow: a.workflow })) } : null,
        link: input.links.file(r, moving[0]?.workflow ?? input.workflowsDir),
      });
    }

    for (const p of rd.parts) {
      if (p.workflows || p.devOnly) continue;
      const needsLock = p.unpinned.length > 0;
      if (!needsLock && !p.lockfile) continue;
      report(ids.lock, {
        zone,
        resource: p.path ? `${r.name}/${p.path}` : r.name,
        pass: !needsLock,
        detail: needsLock ? `${p.path || "The repository's root"} installs ${listed(p.unpinned)} without a pinned version` : "",
        evidence: needsLock ? { lock: { part: p.path, files: p.files, unpinned: p.unpinned } satisfies LockEvidence } : null,
        link: input.links.folder(r, p.path),
      });
    }

    if (!rd.packages) continue;
    const found = { exploited: false, vulnerable: false, malicious: false };
    for (const g of groups(rd.packages)) {
      const all = g.versions.flatMap((p) => p.vulns);
      const devOnly = g.versions.every((p) => p.devOnly);
      const where = usedByText(rd, g);
      const malicious = all.filter(isMalicious);
      const kev = all.filter((v) => v.kev && !isMalicious(v));
      const bad = all.filter((v) => serious(v) && !v.kev && !isMalicious(v));
      if (malicious.length) {
        found.malicious = true;
        report(ids.malicious, {
          zone,
          resource: resourceOf(g),
          pass: false,
          detail: [`${g.name} ${[...new Set(g.versions.map((p) => p.version))].join(", ")} is listed as malicious (${malicious[0].id})`, where]
            .filter(Boolean)
            .join("; "),
          evidence: evidenceOf(input, r, rd, g, isMalicious),
          link,
        });
        continue;
      }
      if (kev.length) {
        found.exploited = true;
        report(ids.exploited, {
          zone,
          resource: resourceOf(g),
          pass: false,
          severity: devOnly ? "high" : undefined,
          confidence: kev.every((v) => v.cpeOnly) ? "likely" : undefined,
          detail: [summary(g, kev, true), upgradeText(kev), where, devOnly ? "development only" : null].filter(Boolean).join("; "),
          evidence: evidenceOf(input, r, rd, g, (v) => v.kev || serious(v)),
          link,
        });
        continue;
      }
      if (bad.length) {
        found.vulnerable = true;
        const worst: Severity = bad.some((v) => v.severity === "critical") ? "critical" : bad.some((v) => v.severity === "high") ? "high" : "medium";
        const confidence: Confidence | undefined = bad.every((v) => v.cpeOnly) ? "likely" : undefined;
        // Only another package uses it, and nothing says it's about to be exploited: its vulnerable code is often never called.
        const remote = isTransitive(g) && bad.every((v) => (v.epss ?? 0) < EPSS_LIKELY);
        let severity: Severity = devOnly ? LOWER[worst] : worst;
        if (remote) severity = LOWER[severity];
        report(ids.vulnerable, {
          zone,
          resource: resourceOf(g),
          pass: false,
          severity,
          confidence,
          detail: [summary(g, bad), upgradeText(bad), where, devOnly ? "development only" : null, remote ? "unlikely to be exploited soon" : null]
            .filter(Boolean)
            .join("; "),
          evidence: evidenceOf(input, r, rd, g, serious),
          link,
        });
      }
    }
    for (const k of ["exploited", "vulnerable", "malicious"] as const) if (!found[k]) report(ids[k], { zone, resource: r.name, pass: true });

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
      report(ids.license, {
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
        link: input.links.licenses(r),
      });
    }
    if (!strong.length && rd.packages.some((p) => p.licenseRisk)) report(ids.license, { zone, resource: r.name, pass: true });
  }
}

const copyleft = (spdx: string | null) => !!spdx && /^(A?GPL|LGPL|SSPL|EUPL|OSL)/i.test(spdx);

function upgradeText(vulns: DepVuln[]): string | null {
  const to = upgradeFor(vulns);
  const unfixed = vulns.filter((v) => !v.fixedIn).length;
  if (!to) return "no fixed version yet";
  return `upgrade to ${to}${unfixed ? ` (${unfixed} without a fix yet)` : ""}`;
}
