// Runs Anchore's open-source scanners, when they are installed: Syft makes a
// software bill of materials (SBOM) from manifest and lock files, Grype matches
// its packages against known vulnerabilities, and Grant sorts their licenses by
// risk. Each is found like Amass: KEELSON_SYFT, KEELSON_GRYPE and KEELSON_GRANT
// name the binary ("off" never runs it), else the tool on the PATH.
//
// Nothing of Keelson's environment reaches them: each runs with only the PATH, a
// home folder of its own, proxy settings, and the tool's own settings below.
// Syft and Grant never use the network here (no registry lookups for licenses,
// no update checks). Grype downloads its vulnerability database from Anchore
// (grype.anchore.io) into the tool folder and refreshes it when a newer one is
// published; that is the only request any of them sends.

import { spawn } from "node:child_process";
import { accessSync, constants } from "node:fs";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { availableParallelism, constants as osConstants, setPriority, tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { env } from "../env.ts";

export type AnchoreTool = "syft" | "grype" | "grant";

/** How long each may run. Grype's first run downloads its database (a few hundred MB), so it gets longer. Tests lower them. */
export const anchoreLimits = { syftSeconds: 180, grypeSeconds: 1200, grantSeconds: 180 };

/** Output beyond this isn't read: a Syft or Grype document this large would be a repository Keelson can't summarise anyway. */
const MAX_OUTPUT = 512 * 1024 * 1024;

export class AnchoreError extends Error {}

/** The tool's binary: KEELSON_<TOOL> (a path, or "off"), else the tool on the PATH; null when there is none. */
export function anchorePath(tool: AnchoreTool, vars: NodeJS.ProcessEnv = process.env): string | null {
  const set = env(tool.toUpperCase(), vars);
  if (set === "off") return null;
  const candidates = set ? [set] : (vars.PATH ?? "").split(delimiter).map((dir) => join(dir, tool));
  return (
    candidates.find((p) => {
      try {
        accessSync(p, constants.X_OK);
        return true;
      } catch {
        return false;
      }
    }) ?? null
  );
}

/** Settings that keep each tool offline (except Grype's database) and quiet. */
const QUIET: Record<AnchoreTool, Record<string, string>> = {
  syft: {
    SYFT_CHECK_FOR_APP_UPDATE: "false",
    // No file listing or file contents in the SBOM: only packages.
    SYFT_FILE_METADATA_SELECTION: "none",
    // Licenses come from the lock files only: looking them up would send private package names to public registries.
    SYFT_GOLANG_SEARCH_REMOTE_LICENSES: "false",
    SYFT_GOLANG_SEARCH_LOCAL_MOD_CACHE_LICENSES: "false",
    SYFT_JAVA_USE_NETWORK: "false",
    SYFT_JAVASCRIPT_SEARCH_REMOTE_LICENSES: "false",
    SYFT_PYTHON_SEARCH_REMOTE_LICENSES: "false",
    // Development dependencies run on developers' machines and in CI, with their credentials: they count.
    SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES: "true",
  },
  grype: { GRYPE_CHECK_FOR_APP_UPDATE: "false", GRYPE_DB_AUTO_UPDATE: "true", GRYPE_DB_VALIDATE_AGE: "true" },
  grant: { GRANT_CHECK_FOR_APP_UPDATE: "false" },
};

const PROXY = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR"];

/**
 * Cores a scanner may use: half of the machine's, at most four. Scanners are written in Go and take every core they
 * find; on a laptop that makes everything else stutter for as long as a scan runs.
 */
export const scannerCpus = (): number => Math.max(1, Math.min(4, Math.floor(availableParallelism() / 2)));

/** Runs a tool to the end and resolves with its standard output; rejects with its last error line when it fails. */
export function runTool(
  tool: AnchoreTool,
  bin: string,
  args: string[],
  { seconds, extraEnv = {}, cwd, okCodes = [0] }: { seconds: number; extraEnv?: Record<string, string>; cwd?: string; okCodes?: number[] },
): Promise<string> {
  return runChild(label(tool), bin, args, { seconds, env: { ...QUIET[tool], ...extraEnv }, cwd, okCodes, fail: (m) => new AnchoreError(m) });
}

/**
 * Runs a scanner as a child process with nothing of Keelson's environment: only the PATH, a home folder of its own
 * (deleted afterwards), proxy settings and the variables given. Shared by the Anchore tools and Trivy (./trivy.ts).
 */
export async function runChild(
  name: string,
  bin: string,
  args: string[],
  {
    seconds,
    env: extra = {},
    cwd,
    okCodes = [0],
    fail = (m: string) => new Error(m),
  }: { seconds: number; env?: Record<string, string>; cwd?: string; okCodes?: number[]; fail?: (message: string) => Error },
): Promise<string> {
  const home = await mkdtemp(join(tmpdir(), `keelson-${name.toLowerCase()}-`));
  const childEnv: NodeJS.ProcessEnv = {
    PATH: process.env.PATH ?? "",
    HOME: home,
    XDG_CACHE_HOME: join(home, ".cache"),
    TMPDIR: home,
    // Go's runtime reads this: the scanner's work is spread over this many cores and no more.
    GOMAXPROCS: String(scannerCpus()),
    ...extra,
  };
  for (const k of PROXY) if (process.env[k]) childEnv[k] = process.env[k];
  try {
    return await new Promise<string>((resolve, reject) => {
      const child = spawn(bin, args, { env: childEnv, cwd: cwd ?? home, detached: true, stdio: ["ignore", "pipe", "pipe"] });
      // The lowest priority: a scan takes what's free and gives way to whatever the person at the machine is doing.
      try {
        if (child.pid) setPriority(child.pid, osConstants.priority.PRIORITY_LOW);
      } catch {
        /* the scan still runs, at normal priority */
      }
      const kill = () => {
        try {
          process.kill(-child.pid!, "SIGKILL");
        } catch {
          child.kill("SIGKILL");
        }
      };
      const out: Buffer[] = [];
      let size = 0;
      let err = "";
      child.stdout!.on("data", (b: Buffer) => {
        size += b.length;
        if (size <= MAX_OUTPUT) out.push(b);
      });
      child.stderr!.on("data", (b: Buffer) => {
        err = (err + b.toString()).slice(-8000);
      });
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        kill();
      }, seconds * 1000);
      child.once("error", (e) => {
        clearTimeout(timer);
        reject(fail(`${name} couldn't run: ${e.message}`));
      });
      child.once("close", (code) => {
        clearTimeout(timer);
        if (timedOut) return reject(fail(`${name} didn't finish within ${Math.round(seconds / 60)} minutes.`));
        if (size > MAX_OUTPUT) return reject(fail(`${name}'s output was larger than Keelson reads.`));
        if (code != null && okCodes.includes(code)) return resolve(Buffer.concat(out).toString("utf8"));
        reject(fail(`${name} failed: ${lastError(err) || `exit code ${code}`}`));
      });
    });
  } finally {
    await rm(home, { recursive: true, force: true }).catch(() => {});
  }
}

const label = (tool: AnchoreTool) => tool[0].toUpperCase() + tool.slice(1);

/** The most useful line of a tool's error output: its last ERROR line, without timestamps and colours. */
export function lastError(stderr: string): string {
  const lines = stderr
    .replace(/\u001b\[[0-9;]*m/g, "")
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
  const line = [...lines].reverse().find((l) => /error|fatal|failed/i.test(l)) ?? lines.at(-1) ?? "";
  return line
    .replace(/^\[\d+\]\s*/, "")
    .replace(/^(ERROR|FATAL)\s*/i, "")
    .slice(0, 240);
}

/** The installed version of a tool ("1.57.1"), or null when it can't tell. */
export async function toolVersion(tool: AnchoreTool, bin: string): Promise<string | null> {
  try {
    const out = await runTool(tool, bin, ["version", "-o", "json"], { seconds: 20 });
    return String(JSON.parse(out).version ?? "") || null;
  } catch {
    try {
      const out = await runTool(tool, bin, ["version"], { seconds: 20 });
      return /Version:\s*(\S+)/.exec(out)?.[1] ?? null;
    } catch {
      return null;
    }
  }
}

/** Where Grype keeps its database: the tool folder Keelson was given, or a temporary one for this process. */
let fallbackDir: string | null = null;
export async function grypeDbDir(toolDir: string | null): Promise<string> {
  const dir = toolDir ? join(toolDir, "grype") : (fallbackDir ??= join(tmpdir(), `keelson-grype-${process.pid}`));
  await mkdir(dir, { recursive: true, mode: 0o700 });
  return dir;
}

/**
 * How scans find and run the tools. The mock replaces it, so tests and the mock dev server never run the real
 * ones; each takes and returns the tools' own JSON documents.
 */
export const anchore = {
  path: (tool: AnchoreTool): string | null => anchorePath(tool),
  version: (tool: AnchoreTool, bin: string): Promise<string | null> => toolVersion(tool, bin),
  /** Syft over a folder of manifest and lock files: its JSON document. */
  syft: (bin: string, dir: string): Promise<string> =>
    runTool("syft", bin, ["scan", `dir:${dir}`, "-o", "syft-json", "-q", "--base-path", dir], { seconds: anchoreLimits.syftSeconds }),
  /** Grype over a Syft document on disk: its JSON report. */
  grype: async (bin: string, sbomFile: string, toolDir: string | null): Promise<string> =>
    runTool("grype", bin, [`sbom:${sbomFile}`, "-o", "json", "-q"], {
      seconds: anchoreLimits.grypeSeconds,
      extraEnv: { GRYPE_DB_CACHE_DIR: await grypeDbDir(toolDir) },
    }),
  /** A Syft document on disk in another SBOM format ("cyclonedx-json", "spdx-json"). */
  convert: (bin: string, sbomFile: string, format: string): Promise<string> => runTool("syft", bin, ["convert", sbomFile, "-o", format, "-q"], { seconds: 60 }),
  /** Grant's license list for a Syft document on disk: its JSON report. */
  grant: (bin: string, sbomFile: string): Promise<string> =>
    // Not -q: Grant 0.7 then prints only a count instead of its report.
    runTool("grant", bin, ["list", sbomFile, "-o", "json", "--disable-file-search"], { seconds: anchoreLimits.grantSeconds }),
};
