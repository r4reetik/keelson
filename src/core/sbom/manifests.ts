// Which files of a repository describe its dependencies, and what the repository
// is made of. Keelson fetches only these files, never the code: package manifests
// and lock files for Syft, GitHub Actions workflows, and Dockerfiles for their
// base images. From them it finds the repository's parts (each project of a
// monorepo: a Node.js workspace, a Go module, a Python service…), the
// dependencies each part names itself, and parts that install dependencies
// without a lock file. Pure: no I/O.

import { posix } from "node:path";

/** A file larger than this isn't fetched (a lock file is rarely over a few MB). */
export const MAX_FILE_BYTES = 15 * 1024 * 1024;
/** At most this many files per repository. */
export const MAX_FILES = 600;

/** Folders whose files aren't the repository's own dependencies: installed packages, build output, test fixtures. */
const SKIP_DIR =
  /(^|\/)(node_modules|bower_components|jspm_packages|vendor|\.venv|venv|env|site-packages|__pycache__|\.git|\.yarn|\.pnpm-store|dist|build|out|target|\.next|\.nuxt|coverage|testdata|fixtures?|__fixtures__|__snapshots__|\.terraform)(\/|$)/i;

/** Parts that only exist for development: dependencies used only there are less exposed. */
const DEV_DIR = /(^|\/)(examples?|samples?|demos?|tests?|__tests__|e2e|spec|benchmarks?|bench)(\/|$)/i;

/** Basenames Syft reads (its catalogers' globs), or that tell Keelson where a project is. */
const NAMES = new Set([
  // JavaScript
  "package.json",
  "package-lock.json",
  "npm-shrinkwrap.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "bun.lock",
  "bun.lockb",
  "deno.lock",
  // Python
  "Pipfile",
  "Pipfile.lock",
  "poetry.lock",
  "pyproject.toml",
  "setup.py",
  "setup.cfg",
  "uv.lock",
  "pdm.lock",
  // Go
  "go.mod",
  "go.sum",
  // Java and Kotlin
  "pom.xml",
  "gradle.lockfile",
  "build.gradle",
  "build.gradle.kts",
  // .NET
  "packages.lock.json",
  // Ruby
  "Gemfile",
  "Gemfile.lock",
  "gems.rb",
  "gems.locked",
  // Rust
  "Cargo.toml",
  "Cargo.lock",
  // PHP
  "composer.json",
  "composer.lock",
  // Swift and Objective-C
  "Package.swift",
  "Package.resolved",
  "Podfile",
  "Podfile.lock",
  // Dart
  "pubspec.yaml",
  "pubspec.lock",
  // Elixir and Erlang
  "mix.exs",
  "mix.lock",
  "rebar.config",
  "rebar.lock",
  // Haskell
  "stack.yaml.lock",
  "cabal.project.freeze",
  // C and C++
  "conanfile.txt",
  "conan.lock",
  "vcpkg.json",
  // Terraform providers
  ".terraform.lock.hcl",
  // GitHub Actions (composite actions)
  "action.yml",
  "action.yaml",
]);

/** A workflow file: GitHub Actions' folder, and the one Gitea Actions reads first. */
export const WORKFLOW_FILE = /^\.(github|gitea)\/workflows\/[^/]+\.ya?ml$/;
export const isWorkflowDir = (dir: string): boolean => dir === ".github/workflows" || dir === ".gitea/workflows";
/** GitLab CI's configuration: the file at the root, and the folder projects split it into by convention. */
export const CI_FILE = /^(\.gitlab-ci\.ya?ml|\.gitlab\/ci\/[^/]+\.ya?ml)$/;

/** Whether Keelson fetches a file at this path (relative to the repository's root). */
export function wanted(path: string): boolean {
  const dir = posix.dirname(path);
  const base = posix.basename(path);
  if (WORKFLOW_FILE.test(path) || CI_FILE.test(path)) return true;
  if (SKIP_DIR.test(dir === "." ? "" : dir)) return false;
  if (NAMES.has(base)) return true;
  if (/requirements[^/]*\.(txt|in)$/i.test(base) || /(^|\/)requirements\/[^/]+\.txt$/i.test(path)) return true;
  if (/\.(csproj|fsproj|vbproj|gemspec)$/i.test(base)) return true;
  return isDockerfile(base);
}

export const isDockerfile = (base: string) => /^(Dockerfile|Containerfile)([.-][\w.-]+)?$|\.(dockerfile|containerfile)$/i.test(base);

/** Basenames that make their folder a project. */
const PROJECT =
  /^(package\.json|go\.mod|pyproject\.toml|setup\.py|Pipfile|Cargo\.toml|pom\.xml|build\.gradle(\.kts)?|Gemfile|gems\.rb|composer\.json|pubspec\.yaml|mix\.exs|Package\.swift|Podfile|conanfile\.txt|vcpkg\.json|rebar\.config|.+\.(csproj|fsproj|vbproj))$/i;
const LOCKS =
  /^(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|deno\.lock|Pipfile\.lock|poetry\.lock|uv\.lock|pdm\.lock|go\.sum|gradle\.lockfile|packages\.lock\.json|Gemfile\.lock|gems\.locked|Cargo\.lock|composer\.lock|Package\.resolved|Podfile\.lock|pubspec\.lock|mix\.lock|rebar\.lock|conan\.lock|stack\.yaml\.lock|cabal\.project\.freeze)$/i;

export type { Part } from "../../shared/dependencies.ts";
import type { Part } from "../../shared/dependencies.ts";

/** Keelson's word for each manifest's ecosystem. */
function ecosystemOf(base: string): string | null {
  if (/^(package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|deno\.lock)$/.test(base)) return "npm";
  if (/^(go\.mod|go\.sum)$/.test(base)) return "Go";
  if (/^(Pipfile|Pipfile\.lock|poetry\.lock|pyproject\.toml|setup\.py|setup\.cfg|uv\.lock|pdm\.lock)$|requirements/i.test(base)) return "PyPI";
  if (/^(pom\.xml|gradle\.lockfile|build\.gradle(\.kts)?)$/.test(base)) return "Maven";
  if (/^packages\.lock\.json$|\.(cs|fs|vb)proj$/i.test(base)) return "NuGet";
  if (/^(Gemfile|Gemfile\.lock|gems\.rb|gems\.locked)$|\.gemspec$/.test(base)) return "RubyGems";
  if (/^Cargo\.(toml|lock)$/.test(base)) return "crates.io";
  if (/^composer\.(json|lock)$/.test(base)) return "Packagist";
  if (/^(Package\.swift|Package\.resolved)$/.test(base)) return "Swift";
  if (/^Podfile(\.lock)?$/.test(base)) return "CocoaPods";
  if (/^pubspec\.(yaml|lock)$/.test(base)) return "pub";
  if (/^(mix\.exs|mix\.lock)$/.test(base)) return "Hex";
  if (/^rebar\.(config|lock)$/.test(base)) return "Erlang";
  if (/^(stack\.yaml\.lock|cabal\.project\.freeze)$/.test(base)) return "Hackage";
  if (/^(conanfile\.txt|conan\.lock)$/.test(base)) return "Conan";
  if (base === "vcpkg.json") return "vcpkg";
  if (base === ".terraform.lock.hcl") return "Terraform";
  return null;
}

/** Keelson's word for a Syft package type. */
export function ecosystemOfType(type: string): string {
  const map: Record<string, string> = {
    npm: "npm",
    "go-module": "Go",
    python: "PyPI",
    "java-archive": "Maven",
    "jenkins-plugin": "Maven",
    gem: "RubyGems",
    "rust-crate": "crates.io",
    "php-composer": "Packagist",
    "php-pear": "PEAR",
    dotnet: "NuGet",
    "github-action": "GitHub Actions",
    "github-action-workflow": "GitHub Actions",
    pub: "pub",
    hex: "Hex",
    "erlang-otp": "Erlang",
    cocoapods: "CocoaPods",
    pod: "CocoaPods",
    swift: "Swift",
    swiplpack: "SWI-Prolog",
    hackage: "Hackage",
    conan: "Conan",
    terraform: "Terraform",
    opam: "opam",
    "lua-rock": "LuaRocks",
    vcpkg: "vcpkg",
    "dart-pub": "pub",
  };
  return map[type] ?? type;
}

/** Each part of a repository, from the paths of its fetched files and their contents. */
export function findParts(files: Map<string, string>): Part[] {
  const byDir = new Map<string, string[]>();
  for (const path of files.keys()) {
    const dir = posix.dirname(path) === "." ? "" : posix.dirname(path);
    byDir.set(dir, [...(byDir.get(dir) ?? []), path]);
  }
  const parts = new Map<string, Part>();
  const part = (dir: string): Part => {
    let p = parts.get(dir);
    if (!p) {
      p = { path: dir, name: null, ecosystems: [], files: [], lockfile: null, direct: {}, unpinned: [], images: [], devOnly: DEV_DIR.test(dir) };
      parts.set(dir, p);
    }
    return p;
  };

  for (const [dir, paths] of byDir) {
    const bases = paths.map((p) => posix.basename(p));
    if (isWorkflowDir(dir)) {
      const p = part(dir);
      p.workflows = true;
      p.name = dir.startsWith(".gitea") ? "Gitea Actions workflows" : "GitHub Actions workflows";
      p.ecosystems = ["GitHub Actions"];
      p.files = paths.sort();
      continue;
    }
    // A folder is a project when it has a manifest, a lock file or a Dockerfile; loose lock files belong to the nearest one above.
    const isProject = bases.some((b) => PROJECT.test(b) || LOCKS.test(b) || isDockerfile(b) || /requirements/i.test(b) || b === ".terraform.lock.hcl");
    if (!isProject && !bases.some((b) => /^action\.ya?ml$/.test(b))) continue;
    const p = part(dir);
    p.files.push(...paths.sort());
    for (const path of paths) {
      const base = posix.basename(path);
      const eco = ecosystemOf(base);
      if (eco && !p.ecosystems.includes(eco)) p.ecosystems.push(eco);
      if (/^action\.ya?ml$/.test(base) && !p.ecosystems.includes("GitHub Actions")) p.ecosystems.push("GitHub Actions");
      if (LOCKS.test(base)) p.lockfile ??= path;
      const text = files.get(path) ?? "";
      if (isDockerfile(base)) for (const img of baseImages(text)) if (!p.images.includes(img)) p.images.push(img);
      readManifest(p, base, text);
    }
  }

  // A workspace's packages share the lock file at its root, so a part without one of its own takes the nearest above it.
  const sorted = [...parts.values()].sort((a, b) => a.path.length - b.path.length || a.path.localeCompare(b.path));
  for (const p of sorted) {
    if (p.lockfile || p.workflows) continue;
    for (let dir = parentOf(p.path); dir !== null; dir = parentOf(dir)) {
      const up = parts.get(dir);
      const lock = up?.lockfile;
      if (lock && sharesEcosystem(p, up!, lock)) {
        p.lockfile = lock;
        break;
      }
    }
  }
  for (const p of sorted) p.unpinned = unpinnedOf(p, files);
  // Root first, then each project by path, workflows last.
  const order = (p: Part) => (p.path === "" ? 0 : p.workflows ? 2 : 1);
  return sorted.filter((p) => p.files.length).sort((a, b) => order(a) - order(b) || a.path.localeCompare(b.path));
}

const parentOf = (dir: string): string | null => (dir === "" ? null : posix.dirname(dir) === "." ? "" : posix.dirname(dir));
const sharesEcosystem = (p: Part, up: Part, lock: string) => {
  const eco = ecosystemOf(posix.basename(lock));
  return !!eco && p.ecosystems.includes(eco) && up.ecosystems.includes(eco);
};

/** The images a Dockerfile's FROM lines name, without build stages that name another stage. */
export function baseImages(text: string): string[] {
  const stages = new Set<string>();
  const out: string[] = [];
  for (const line of text.split("\n")) {
    const m = /^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/i.exec(line);
    if (!m) continue;
    const image = m[1];
    if (!stages.has(image.toLowerCase()) && image.toLowerCase() !== "scratch" && !image.includes("$")) out.push(image);
    if (m[2]) stages.add(m[2].toLowerCase());
  }
  return out;
}

function parseJson(text: string): any {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/** The part's name and the dependencies it names itself, from the manifests Keelson can read without running anything. */
function readManifest(p: Part, base: string, text: string): void {
  const add = (name: string, dev: boolean, ecosystem: string) => {
    const key = name.trim();
    if (!key) return;
    const prev = p.direct[key];
    // A dependency listed for both counts as a runtime one.
    p.direct[key] = { dev: prev ? prev.dev && dev : dev, ecosystem };
  };
  if (base === "package.json") {
    const j = parseJson(text);
    if (!j) return;
    if (typeof j.name === "string") p.name ??= j.name;
    for (const k of Object.keys(j.dependencies ?? {})) add(k, false, "npm");
    for (const k of Object.keys(j.optionalDependencies ?? {})) add(k, false, "npm");
    for (const k of Object.keys(j.devDependencies ?? {})) add(k, true, "npm");
  } else if (base === "composer.json") {
    const j = parseJson(text);
    if (!j) return;
    if (typeof j.name === "string") p.name ??= j.name;
    for (const k of Object.keys(j.require ?? {})) if (!/^(php|ext-|lib-)/.test(k)) add(k, false, "Packagist");
    for (const k of Object.keys(j["require-dev"] ?? {})) if (!/^(php|ext-|lib-)/.test(k)) add(k, true, "Packagist");
  } else if (base === "go.mod") {
    const mod = /^module\s+(\S+)/m.exec(text);
    if (mod) p.name ??= mod[1];
    for (const m of goRequires(text)) if (!m.indirect) add(m.path, false, "Go");
  } else if (/requirements/i.test(base)) {
    for (const r of requirementLines(text)) add(r.name, /dev|test|lint/i.test(base), "PyPI");
  } else if (base === "pyproject.toml") {
    const name = /^\s*name\s*=\s*["']([^"']+)["']/m.exec(section(text, "project") ?? section(text, "tool.poetry") ?? "");
    if (name) p.name ??= name[1];
    const project = section(text, "project");
    if (project) for (const d of tomlArray(project, "dependencies")) add(pep508Name(d), false, "PyPI");
    const poetry = section(text, "tool.poetry.dependencies");
    if (poetry) for (const k of tomlKeys(poetry)) if (k.toLowerCase() !== "python") add(k, false, "PyPI");
    for (const [title, body] of sections(text))
      if (/^tool\.poetry\.(group\.[^.]+\.)?dev-dependencies$|^tool\.poetry\.group\.[^.]+\.dependencies$/.test(title))
        for (const k of tomlKeys(body)) add(k, true, "PyPI");
  } else if (base === "Cargo.toml") {
    const name = /^\s*name\s*=\s*"([^"]+)"/m.exec(section(text, "package") ?? "");
    if (name) p.name ??= name[1];
    for (const k of tomlKeys(section(text, "dependencies") ?? "")) add(k, false, "crates.io");
    for (const k of [...tomlKeys(section(text, "dev-dependencies") ?? ""), ...tomlKeys(section(text, "build-dependencies") ?? "")]) add(k, true, "crates.io");
  } else if (base === "Gemfile" || base === "gems.rb") {
    let devGroup = false;
    for (const line of text.split("\n")) {
      if (/^\s*group\s+.*(:development|:test)/.test(line)) devGroup = true;
      else if (/^\s*end\b/.test(line)) devGroup = false;
      const m = /^\s*gem\s+["']([^"']+)["']/.exec(line);
      if (m) add(m[1], devGroup, "RubyGems");
    }
  } else if (base === "pom.xml") {
    const artifact = /<project[\s\S]*?<artifactId>([^<]+)<\/artifactId>/.exec(text.replace(/<parent>[\s\S]*?<\/parent>/, ""));
    if (artifact) p.name ??= artifact[1].trim();
    for (const m of text.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
      const id = /<artifactId>([^<]+)<\/artifactId>/.exec(m[1]);
      if (id) add(id[1].trim(), /<scope>\s*(test|provided)\s*<\/scope>/.test(m[1]), "Maven");
    }
  } else if (base === "pubspec.yaml") {
    const name = /^name:\s*(\S+)/m.exec(text);
    if (name) p.name ??= name[1];
  } else if (/\.(cs|fs|vb)proj$/i.test(base)) {
    p.name ??= base.replace(/\.(cs|fs|vb)proj$/i, "");
    for (const m of text.matchAll(/<PackageReference\s+Include="([^"]+)"/g)) add(m[1], false, "NuGet");
  }
}

/** go.mod's require lines: one at a time or in a block. */
export function goRequires(text: string): { path: string; indirect: boolean }[] {
  const out: { path: string; indirect: boolean }[] = [];
  let inBlock = false;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (/^require\s*\($/.test(line)) inBlock = true;
    else if (inBlock && line === ")") inBlock = false;
    else {
      const m = inBlock ? /^(\S+)\s+v\S+(.*)$/.exec(line) : /^require\s+(\S+)\s+v\S+(.*)$/.exec(line);
      if (m && !m[1].startsWith("//")) out.push({ path: m[1], indirect: /\/\/\s*indirect/.test(m[2]) });
    }
  }
  return out;
}

/** A requirements file's packages, with whether each is pinned to one version (== or ===). */
export function requirementLines(text: string): { name: string; pinned: boolean }[] {
  const out: { name: string; pinned: boolean }[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.replace(/\s+#.*$/, "").trim();
    if (!line || line.startsWith("#") || line.startsWith("-") || /^[a-z+]+:\/\//i.test(line) || line.startsWith(".") || line.startsWith("/")) continue;
    const name = pep508Name(line);
    if (!name) continue;
    out.push({ name, pinned: /===?\s*[\w.!+*-]+/.test(line.split(";")[0]) && !/\*/.test(line.split(";")[0]) });
  }
  return out;
}

const composerType = (text: string | undefined) => {
  try {
    return String(JSON.parse(text ?? "{}").type ?? "library");
  } catch {
    return "library";
  }
};

const pep508Name = (spec: string) => /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(spec)?.[1] ?? "";

/** [title] sections of a TOML file: just enough TOML for dependency tables. */
function sections(text: string): [string, string][] {
  const out: [string, string][] = [];
  let title = "";
  let body: string[] = [];
  for (const line of text.split("\n")) {
    const m = /^\s*\[([^\][]+)\]\s*$/.exec(line);
    if (m) {
      out.push([title, body.join("\n")]);
      title = m[1].trim();
      body = [];
    } else body.push(line);
  }
  out.push([title, body.join("\n")]);
  return out;
}
const section = (text: string, title: string) => sections(text).find(([t]) => t === title)?.[1] ?? null;
const tomlKeys = (body: string) => [...body.matchAll(/^\s*([A-Za-z0-9_.-]+|"[^"]+")\s*=/gm)].map((m) => m[1].replace(/"/g, ""));
function tomlArray(body: string, key: string): string[] {
  const m = new RegExp(`^\\s*${key}\\s*=\\s*\\[([\\s\\S]*?)\\]`, "m").exec(body);
  return m ? [...m[1].matchAll(/["']([^"']+)["']/g)].map((x) => x[1]) : [];
}

/**
 * Dependencies a part installs without a lock file, when its kind of project normally has one: an application's
 * npm or Composer packages, Ruby gems, Go modules without go.sum, Pipenv and Poetry projects, and requirements
 * files with versions that aren't pinned. Libraries (pyproject's own dependencies, Rust crates) don't lock.
 */
function unpinnedOf(p: Part, files: Map<string, string>): string[] {
  if (p.workflows) return [];
  const has = (re: RegExp) => p.files.some((f) => re.test(posix.basename(f)));
  const names = (eco: string) => Object.entries(p.direct).flatMap(([n, d]) => (d.ecosystem === eco ? [n] : []));
  const out: string[] = [];
  if (has(/^package\.json$/) && !p.lockfile?.match(/(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|deno\.lock)$/))
    out.push(...names("npm"));
  // A Composer package is a library unless it says it's a project (Composer's default type), and libraries don't commit
  // composer.lock; a library copied into an application (CodeIgniter's application/libraries) is one of these.
  const composer = p.files.find((f) => posix.basename(f) === "composer.json");
  if (composer && (p.path === "" || composerType(files.get(composer)) === "project") && !p.lockfile?.endsWith("composer.lock")) out.push(...names("Packagist"));
  if (has(/^(Gemfile|gems\.rb)$/) && !p.lockfile?.match(/(Gemfile\.lock|gems\.locked)$/)) out.push(...names("RubyGems"));
  if (has(/^go\.mod$/) && !has(/^go\.sum$/)) out.push(...names("Go"));
  if (has(/^Pipfile$/) && !has(/^Pipfile\.lock$/)) out.push("Pipfile packages");
  const pyproject = p.files.find((f) => posix.basename(f) === "pyproject.toml");
  if (pyproject && /^\s*\[tool\.poetry/m.test(files.get(pyproject) ?? "") && !has(/^poetry\.lock$/)) out.push(...names("PyPI"));
  // Requirements files pin with ==; anything else installs whatever is newest when it runs.
  if (!has(/^(poetry\.lock|Pipfile\.lock|uv\.lock|pdm\.lock)$/))
    for (const f of p.files) if (/requirements/i.test(posix.basename(f))) for (const r of requirementLines(files.get(f) ?? "")) if (!r.pinned) out.push(r.name);
  return [...new Set(out)].sort();
}
