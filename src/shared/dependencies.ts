// What Keelson knows about a repository's dependencies, from its software bill
// of materials: its parts (each project of a monorepo), its packages with where
// they're used, their known vulnerabilities and their licenses. Shared by the
// GitHub scan, the API and the web. Portable: no node: imports.

import type { ImageBuildLink } from "./images.ts";

/** One project inside a repository. A repository with one project has one part, at its root (path ""). */
export interface Part {
  /** Folder, relative to the repository's root; "" for the root. */
  path: string;
  /** The project's own name, from its manifest ("@acme/web", "github.com/acme/api"). */
  name: string | null;
  /** Package ecosystems its manifests use, in Keelson's words ("npm", "Go", "PyPI"…). */
  ecosystems: string[];
  /** Its manifest and lock files. */
  files: string[];
  /** The lock file that pins its dependencies: its own, or a workspace root's above it; null without one. */
  lockfile: string | null;
  /** Dependencies its own manifest names, with whether only for development. */
  direct: Record<string, { dev: boolean; ecosystem: string }>;
  /** Dependencies installed without a lock file or an exact version, when the part needs one. */
  unpinned: string[];
  /** Container base images its Dockerfiles start from. */
  images: string[];
  /** Exists for examples, tests or benchmarks. */
  devOnly: boolean;
  /** GitHub Actions workflows (the .github/workflows folder). */
  workflows?: boolean;
}

/** A known vulnerability of a dependency, as Grype matched it. */
export interface DepVuln {
  /** GitHub's advisory ID when there is one (GHSA-…), else the CVE or the source's own ID. */
  id: string;
  /** The same vulnerability's other IDs (its CVE). */
  aliases: string[];
  severity: "critical" | "high" | "medium" | "low" | "unknown";
  /** Highest CVSS base score given. */
  cvss: number | null;
  /** FIRST's EPSS: how likely it is to be exploited in the next 30 days (0 to 1), and its percentile. */
  epss: number | null;
  percentile: number | null;
  /** In CISA's catalog of vulnerabilities known to be exploited. */
  kev: boolean;
  /** CISA knows it was used in ransomware campaigns. */
  ransomware: boolean;
  /** The version that fixes it for this package, as Grype suggests; null when there is none. */
  fixedIn: string | null;
  /** "fixed", "not-fixed", "wont-fix" or "unknown". */
  state: string;
  summary: string;
  url: string | null;
  /** Grype's risk score: severity weighed by how likely and known exploitation is. */
  risk: number;
  /** Matched by CPE only (a product name guess), not by the package's own ecosystem: less certain. */
  cpeOnly: boolean;
}

/** Where a dependency is used: which part, and how. */
export interface DepUsage {
  part: string;
  /** Named in the part's own manifest, rather than pulled in by another package. */
  direct: boolean;
  dev: boolean;
}

/** One package a repository depends on, at one version. */
export interface DepPackage {
  name: string;
  version: string;
  /** Syft's package type ("npm", "go-module", "github-action"…). */
  type: string;
  /** Keelson's word for its ecosystem ("npm", "Go", "PyPI", "GitHub Actions"…). */
  ecosystem: string;
  purl: string | null;
  /** Lock or manifest files it was found in. */
  locations: string[];
  /** Its license expression, as the lock file states it; empty when it doesn't. */
  licenses: string[];
  /** Grant's risk class of its license: "permissive", "weak" (weak copyleft), "strong" (strong copyleft), "other" (not a known SPDX license), or null without one. */
  licenseRisk: "permissive" | "weak" | "strong" | "other" | null;
  usedBy: DepUsage[];
  /** Used only for development: a development dependency, or only by examples and tests. */
  devOnly: boolean;
  vulns: DepVuln[];
}

/** A GitHub Actions step that runs another repository's action. */
export interface ActionUse {
  /** "owner/repo" or "owner/repo/path". */
  action: string;
  ref: string;
  workflow: string;
}

/** What a repository depends on: its parts, packages and their known vulnerabilities and licenses. */
export interface RepoDependencies {
  repo: string;
  /** When its SBOM was made: the last time its manifest or lock files changed. */
  generatedAt: number;
  /** Bytes of code per language, from GitHub. */
  languages: Record<string, number> | null;
  parts: Part[];
  /** Null when Syft isn't installed: the parts are known, the packages aren't. */
  packages: DepPackage[] | null;
  actions: ActionUse[];
  /** Container images its workflows build and push; absent on views made before Keelson read them. */
  builds?: Omit<ImageBuildLink, "repo">[];
  /** Some manifest files were too large or too many to fetch, or the file list was cut short. */
  partial: boolean;
}

/** GET /api/dependencies: one repository's dependencies as its latest scan saw them. */
export interface DependenciesResponse {
  repo: string;
  account: string;
  accountId: string;
  /** "public", "private" or "internal". */
  visibility: string;
  defaultBranch: string;
  /** Link to the repository on GitHub. */
  url: string;
  dependencies: RepoDependencies | null;
  /** Tools that made it, and when Grype's database was built. */
  tools: { syft: string | null; grype: string | null; grant: string | null } | null;
  dbBuilt: string | null;
  /** Open findings in this repository from the dependency checks, by package resource. */
  findings: { fingerprint: string; checkId: string; resource: string; severity: string; title: string }[];
}

/** A vulnerability as a finding's evidence lists it. */
export interface EvidenceVuln {
  id: string;
  aliases: string[];
  /** The package version it affects. */
  version: string;
  severity: DepVuln["severity"];
  cvss: number | null;
  epss: number | null;
  percentile: number | null;
  kev: boolean;
  ransomware: boolean;
  fixedIn: string | null;
  state: string;
  summary: string;
  url: string | null;
  cpeOnly: boolean;
  /** Dependabot has an open alert for it in this repository. */
  dependabot: boolean;
}

/** Evidence of a vulnerable or malicious package (GDP-001, GDP-002, GDP-003). */
export interface DependencyEvidence {
  name: string;
  ecosystem: string;
  versions: {
    version: string;
    /** The smallest version that fixes the listed vulnerabilities, and every known one. */
    upgrade: string | null;
    upgradeAll: string | null;
    devOnly: boolean;
    locations: string[];
    usedBy: (DepUsage & { label: string })[];
    /** Every known vulnerability of this version, listed or not. */
    vulns: number;
  }[];
  vulnerabilities: EvidenceVuln[];
  /** Listed vulnerabilities left out of `vulnerabilities`. */
  more: number;
  /** Whether Dependabot tells anyone: off in the repository, alerting on this package, or on and silent about it. */
  dependabot: "off" | "alerting" | "silent" | null;
}

/** Evidence of actions used by a tag (GDP-004). */
export interface ActionsEvidence {
  uses: string;
  workflow: string;
}

/** Evidence of a project without a lock file (GDP-005). */
export interface LockEvidence {
  part: string;
  files: string[];
  unpinned: string[];
}

/** Evidence of a strong copyleft license (GLI-001). */
export interface LicenseEvidence {
  /** Each package and version; a finding for an npm scope (@ckeditor/*) lists every package in it. */
  licenses: { name?: string; version: string; licenses: string[]; usedBy: string[] }[];
  repositoryLicense: string | null;
}

/** The language each ecosystem's packages are written for, so packages can be found by language as well as by package manager. */
const LANGUAGE_OF: Record<string, string> = {
  npm: "JavaScript and TypeScript",
  PyPI: "Python",
  Go: "Go",
  Maven: "Java and Kotlin",
  NuGet: "C# and .NET",
  RubyGems: "Ruby",
  "crates.io": "Rust",
  Packagist: "PHP",
  PEAR: "PHP",
  Swift: "Swift and Objective-C",
  CocoaPods: "Swift and Objective-C",
  pub: "Dart",
  Hex: "Elixir and Erlang",
  Erlang: "Elixir and Erlang",
  Hackage: "Haskell",
  Conan: "C and C++",
  vcpkg: "C and C++",
  Terraform: "Terraform",
  "GitHub Actions": "GitHub Actions",
  opam: "OCaml",
  LuaRocks: "Lua",
  "SWI-Prolog": "Prolog",
};

/** The language of an ecosystem's packages; an ecosystem Keelson doesn't know is its own language. */
export const languageOf = (ecosystem: string): string => LANGUAGE_OF[ecosystem] ?? ecosystem;

/** A repository affected by the packages, vulnerabilities or licenses picked on the Dependencies page. */
export interface AffectedRepo {
  accountId: string;
  account: string;
  repo: string;
  /** "owner/repo" on GitHub, when the organization's login is known. */
  fullName: string;
  url: string | null;
  /** The picked packages it uses, with the version that fixes them. */
  packages: { name: string; version: string; ecosystem: string; upgrade: string | null }[];
}

/** GET /api/sbom/affected: the repositories behind a selection, across every page of the list. */
export interface AffectedResponse {
  repos: AffectedRepo[];
  /** Packages (at each version) the selection covers. */
  packages: number;
  /** The picked rows as they'd be copied: "name@version", advisory IDs, or license expressions. */
  names: string[];
  /** CVE IDs among the picked vulnerabilities (the vulnerabilities tab only). */
  cves: string[];
}

/** What the Dependencies page can filter packages by. */
export const PACKAGE_STATUSES = {
  vulnerable: "Vulnerable",
  exploited: "Exploited",
  fixable: "Has a fix",
  nofix: "No fix yet",
  malicious: "Malicious",
  clean: "No known vulnerability",
} as const;
export type PackageStatus = keyof typeof PACKAGE_STATUSES;

/** Grant's license risk classes, and packages whose lock file states no license. */
export const LICENSE_RISKS = {
  strong: "Strong copyleft",
  weak: "Weak copyleft",
  permissive: "Permissive",
  other: "Not a known license",
  none: "Not stated",
} as const;
export type LicenseRiskFilter = keyof typeof LICENSE_RISKS;

/** A finding the dependency checks raised for a package in one repository, with its triage. */
export interface PackageFinding {
  fingerprint: string;
  checkId: string;
  severity: string;
  /** Triage status: "open", "in_progress", "accepted" or "false_positive". */
  status: string;
}

/** One repository where a package (at one version) is used. */
export interface PackageUse {
  accountId: string;
  account: string;
  repo: string;
  /** The parts that use it, as the repository's page names them. */
  parts: { label: string; direct: boolean; dev: boolean }[];
  direct: boolean;
  devOnly: boolean;
  locations: string[];
  finding: PackageFinding | null;
}

/** A package at one version, across every repository in view. */
export interface PackageRow {
  name: string;
  version: string;
  ecosystem: string;
  type: string;
  purl: string | null;
  licenses: string[];
  licenseRisk: DepPackage["licenseRisk"];
  /** Used directly by at least one part somewhere. */
  direct: boolean;
  /** Used only for development everywhere. */
  devOnly: boolean;
  worst: DepVuln["severity"] | null;
  kev: boolean;
  malicious: boolean;
  epss: number | null;
  /** The smallest version that fixes every known vulnerability that has a fix. */
  upgrade: string | null;
  vulns: DepVuln[];
  uses: PackageUse[];
}

/** A known vulnerability, across every package and repository in view. */
export interface VulnRow extends Omit<DepVuln, "fixedIn" | "cpeOnly"> {
  packages: { name: string; version: string; ecosystem: string; fixedIn: string | null; repos: number }[];
  repos: number;
}

/** A license as Grant classifies it, across every package in view (the Grant report). */
export interface LicenseRow {
  /** The license expression as the lock files state it; "" for packages that state none. */
  license: string;
  risk: LicenseRiskFilter;
  packages: number;
  repos: number;
  ecosystems: string[];
}

/** GET /api/sbom: the summary the Dependencies page opens with. */
export interface SbomResponse {
  scan: import("./api.ts").ScanMeta | null;
  coverage: import("./api.ts").Coverage[];
  summary: {
    /** Repositories with an SBOM, and repositories in view without one. */
    repos: number;
    missing: number;
    /** Unique packages (name, version and ecosystem), and their uses across repositories. */
    packages: number;
    uses: number;
    vulnerable: number;
    exploited: number;
    malicious: number;
    fixable: number;
    copyleft: number;
    /** Unique vulnerabilities by severity. */
    vulnerabilities: { critical: number; high: number; medium: number; low: number; unknown: number };
    ecosystems: { name: string; packages: number }[];
    /** Packages by the language they're written for (languageOf), for the language filter. */
    languages: { name: string; packages: number }[];
    licenseRisks: Record<LicenseRiskFilter, number>;
    /** Repositories with an SBOM, for the repository filter. */
    repoList: { accountId: string; account: string; repo: string }[];
    tools: { syft: string | null; grype: string | null; grant: string | null } | null;
    dbBuilt: string | null;
  } | null;
}

/** A page of a filtered list, with how many rows match. */
export interface SbomPage<T> {
  rows: T[];
  total: number;
  offset: number;
}
