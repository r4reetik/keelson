// Stand-ins for Anchore's Syft, Grype and Grant, so GitHub's dependency scan runs
// end to end in tests and `npm run dev -- --mock` without the real tools or their
// 3 GB vulnerability database. Syft here reads the few kinds of files the mock
// repositories hold (npm lock files, requirements files, go.mod and workflows) and
// writes a document shaped like Syft's; Grype answers from a fictional table of
// vulnerabilities; Grant sorts licenses by their family. The packages and
// advisories are fictional.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { anchore } from "../../src/core/anchore.ts";

interface MockOptions {
  /** Pretend none of the tools is installed. */
  missing?: ("syft" | "grype" | "grant")[];
  /** Called with the files Syft was given (paths relative to its folder), to check what Keelson fetched. */
  onSyft?: (files: string[]) => void;
  /** A tool that prints something other than its report (Grant 0.7 with -q prints only a count). */
  garbled?: ("syft" | "grype" | "grant")[];
  /** Called with the packages Grype was given. */
  onGrype?: (packages: string[]) => void;
}

/** Fictional advisories, by "name@version". */
const VULNS: Record<
  string,
  { id: string; related?: string[]; severity: string; fix: string | null; kev?: boolean; epss?: number; malicious?: boolean; summary: string }[]
> = {
  "mock-xml-parser@0.9.1": [
    {
      id: "GHSA-mock-0001-0001",
      related: ["CVE-2026-90001"],
      severity: "Critical",
      fix: "0.9.4",
      kev: true,
      epss: 0.91,
      summary: "External entities let a request read files on the server.",
    },
    {
      id: "GHSA-mock-0001-0002",
      related: ["CVE-2026-90002"],
      severity: "Medium",
      fix: "0.9.3",
      epss: 0.004,
      summary: "Deeply nested documents exhaust memory.",
    },
  ],
  "mock-router@1.4.0": [
    { id: "GHSA-mock-0002-0002", related: ["CVE-2026-90003"], severity: "High", fix: "1.4.2", epss: 0.03, summary: "Encoded slashes bypass route guards." },
    { id: "GHSA-mock-0002-0003", related: ["CVE-2026-90004"], severity: "Medium", fix: "1.4.1", epss: 0.002, summary: "Open redirect through a crafted path." },
  ],
  "mock-path-match@0.2.0": [
    {
      id: "GHSA-mock-0003-0001",
      related: ["CVE-2026-90005"],
      severity: "Medium",
      fix: "0.2.5",
      epss: 0.34,
      summary: "A crafted path takes exponential time to match.",
    },
  ],
  "mock-test-runner@2.0.0": [
    {
      id: "GHSA-mock-0004-0001",
      related: ["CVE-2026-90006"],
      severity: "High",
      fix: "2.1.0",
      epss: 0.01,
      summary: "Test reports can run scripts in the viewer.",
    },
  ],
  "mock.example/httpkit@v1.2.0": [
    {
      id: "GO-2026-9001",
      related: ["CVE-2026-90007", "GHSA-mock-0005-0001"],
      severity: "Critical",
      fix: "1.2.3",
      epss: 0.05,
      summary: "Request smuggling through duplicate headers.",
    },
    // Grype also reports the CVE on its own; Keelson merges the two.
    { id: "CVE-2026-90007", severity: "High", fix: "1.2.3", epss: 0.05, summary: "Request smuggling through duplicate headers." },
  ],
  "mock-celery@4.0.0": [
    { id: "GHSA-mock-0006-0001", related: ["CVE-2026-90008"], severity: "Medium", fix: null, epss: 0.01, summary: "Task names aren't checked." },
  ],
  "mock-colorz@1.0.0": [
    {
      id: "MAL-2026-0001",
      severity: "Critical",
      fix: null,
      malicious: true,
      summary: "Malicious code in mock-colorz: steals environment variables when installed.",
    },
  ],
  "mock-actions/deploy@v2": [
    { id: "GHSA-mock-0007-0001", related: ["CVE-2026-90009"], severity: "High", fix: "2.0.4", epss: 0.12, summary: "The action prints secrets to the log." },
  ],
};

const LICENSE_RISK: [RegExp, string][] = [
  [/^(A?GPL|SSPL|EUPL|OSL)/i, "Strong Copyleft (High Risk)"],
  [/^(LGPL|MPL|EPL|CDDL)/i, "Weak Copyleft (Medium Risk)"],
  [/^(MIT|ISC|BSD|Apache|0BSD|Unlicense|CC0)/i, "Permissive (Low Risk)"],
];

const files = (dir: string): string[] =>
  readdirSync(dir, { recursive: true, encoding: "utf8" })
    .map((p) => join(dir, p))
    .filter((p) => statSync(p).isFile());

/** A Syft-shaped document from the files the mock repositories hold. */
function mockSyft(dir: string): string {
  const artifacts: Record<string, unknown>[] = [];
  const relationships: Record<string, unknown>[] = [];
  const add = (type: string, name: string, version: string, path: string, extra: Record<string, unknown> = {}) => {
    const id = `${type}-${name}-${version}-${artifacts.length}`;
    const purlType = { npm: "npm", python: "pypi", "go-module": "golang", "github-action": "github" }[type] ?? type;
    artifacts.push({
      id,
      name,
      version,
      type,
      foundBy: "mock-cataloger",
      locations: [{ path: `/${path}`, annotations: { evidence: "primary" } }],
      licenses: [],
      language: "",
      cpes: [],
      purl: `pkg:${purlType}/${name}@${version}`,
      metadataType: "",
      metadata: {},
      ...extra,
    });
    return id;
  };
  for (const file of files(dir)) {
    const path = relative(dir, file).split("\\").join("/");
    const text = readFileSync(file, "utf8");
    if (path.endsWith("package-lock.json")) {
      const lock = JSON.parse(text);
      const ids = new Map<string, string>();
      const deps = new Map<string, string[]>();
      for (const [key, e] of Object.entries<Record<string, any>>(lock.packages ?? {})) {
        if (!key || e.link) continue;
        const name = e.name ?? key.slice(key.lastIndexOf("node_modules/") + 13);
        const local = !key.includes("node_modules/");
        const id = add("npm", name, e.version ?? "UNKNOWN", path, {
          licenses: e.license ? [{ value: e.license, spdxExpression: e.license, type: "declared" }] : [],
          metadata: { resolved: local ? key : `https://registry.example/${name}`, integrity: local ? "" : "sha512-mock", dependencies: e.dependencies ?? null },
        });
        ids.set(name, id);
        deps.set(id, Object.keys(e.dependencies ?? {}));
      }
      for (const [id, names] of deps) for (const n of names) if (ids.has(n)) relationships.push({ parent: ids.get(n), child: id, type: "dependency-of" });
    } else if (/requirements[^/]*\.txt$/.test(path)) {
      for (const line of text.split("\n")) {
        const m = /^([\w.-]+)==([\w.]+)/.exec(line.trim());
        if (m) add("python", m[1], m[2], path);
      }
    } else if (path.endsWith("go.mod")) {
      for (const m of text.matchAll(/^\s*(?:require\s+)?([\w.-]+\.[\w./-]+)\s+(v[\w.-]+)/gm)) add("go-module", m[1], m[2], path);
    } else if (/^\.github\/workflows\//.test(path)) {
      for (const m of text.matchAll(/uses:\s*([^\s@]+)@(\S+)/g)) add("github-action", m[1], m[2], path);
    }
  }
  return JSON.stringify({
    artifacts,
    artifactRelationships: relationships,
    files: [],
    source: { id: "mock", name: "mock", type: "directory", metadata: { path: dir } },
    distro: {},
    descriptor: { name: "syft", version: "1.0.0-mock" },
    schema: { version: "16.1.0", url: "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.1.0.json" },
  });
}

function mockGrype(sbomFile: string, o: MockOptions): string {
  const doc = JSON.parse(readFileSync(sbomFile, "utf8"));
  o.onGrype?.(doc.artifacts.map((a: { name: string; version: string }) => `${a.name}@${a.version}`));
  const matches = doc.artifacts.flatMap((a: Record<string, any>) =>
    (VULNS[`${a.name}@${a.version}`] ?? []).map((v) => ({
      vulnerability: {
        id: v.id,
        dataSource: v.id.startsWith("GHSA") ? `https://github.com/advisories/${v.id}` : `https://osv.dev/vulnerability/${v.id}`,
        severity: v.severity,
        description: v.summary,
        cvss: [{ version: "3.1", metrics: { baseScore: v.severity === "Critical" ? 9.8 : v.severity === "High" ? 7.5 : 5.3 } }],
        knownExploited: v.kev ? [{ cve: v.related?.[0] ?? v.id, knownRansomwareCampaignUse: "Unknown" }] : [],
        epss: v.epss ? [{ cve: v.related?.[0] ?? v.id, epss: v.epss, percentile: Math.min(0.999, v.epss * 3) }] : [],
        fix: { versions: v.fix ? [v.fix] : [], state: v.fix ? "fixed" : "not-fixed" },
        risk: (v.epss ?? 0) * 100,
      },
      relatedVulnerabilities: (v.related ?? []).map((id) => ({ id, severity: v.severity })),
      matchDetails: [{ type: "exact-direct-match", fix: v.fix ? { suggestedVersion: v.fix } : undefined }],
      artifact: { id: a.id, name: a.name, version: a.version, type: a.type },
    })),
  );
  return JSON.stringify({
    matches,
    descriptor: { name: "grype", version: "0.0.0-mock", db: { status: { built: new Date(Date.now() - 6 * 3600_000).toISOString() } } },
  });
}

function mockGrant(sbomFile: string): string {
  const doc = JSON.parse(readFileSync(sbomFile, "utf8"));
  const packages = doc.artifacts.map((a: Record<string, any>) => ({
    id: `${a.type}:${a.name}@${a.version}`,
    name: a.name,
    licenses: (a.licenses ?? []).map((l: { value: string }) => ({ id: l.value, riskCategory: LICENSE_RISK.find(([re]) => re.test(l.value))?.[1] })),
  }));
  // Shaped like Grant 0.7's: the report sits under run.targets.
  return JSON.stringify({ tool: "grant", version: "0.0.0-mock", run: { argv: ["grant", "list"], targets: [{ evaluation: { findings: { packages } } }] } });
}

/** Replaces the tools until the returned function is called. */
export function installMockAnchore(o: MockOptions = {}): () => void {
  const real = { ...anchore };
  anchore.path = (tool) => (o.missing?.includes(tool) ? null : `/mock/${tool}`);
  anchore.version = async (tool) => `0.0.0-mock-${tool}`;
  anchore.syft = async (_bin, dir) => {
    o.onSyft?.(files(dir).map((f) => relative(dir, f).split("\\").join("/")));
    return mockSyft(dir);
  };
  anchore.grype = async (_bin, file) => (o.garbled?.includes("grype") ? "4\n" : mockGrype(file, o));
  anchore.grant = async (_bin, file) => (o.garbled?.includes("grant") ? "4\n" : mockGrant(file));
  // A real conversion needs Syft; the mock wraps the packages in the format's outline.
  anchore.convert = async (_bin, file, format) => {
    const doc = JSON.parse(readFileSync(file, "utf8"));
    const names = doc.artifacts.map((a: { name: string; version: string; purl?: string }) => ({ name: a.name, version: a.version, purl: a.purl }));
    return JSON.stringify(
      format.startsWith("cyclonedx") ? { bomFormat: "CycloneDX", specVersion: "1.6", components: names } : { spdxVersion: "SPDX-2.3", packages: names },
    );
  };
  return () => {
    Object.assign(anchore, real);
  };
}
