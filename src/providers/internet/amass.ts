// Runs OWASP Amass, when it is installed (the Docker image carries it), to find more of an entity's hostnames.
//
// Amass 5 works through a collection engine. For each scan Keelson starts its own engine
// with a home directory of its own (so its asset database belongs to the scan and is
// deleted afterwards), runs an enumeration of the entity's domains, the ones its
// connected accounts know, limited to them (-rigid), reads the names back and stops the
// engine. Amass 5.1's engine crashes when it is also given more than a few known names
// (-nf), so the names Keelson already has aren't passed; they only tell which of
// Amass's names are new. If the engine stops mid-run, the enumeration is stopped too and
// the engine's own error is the source's error.
//
// Amass runs passive: it asks its data sources and public DNS, and never connects to the
// entity's hosts (no -active, no brute forcing, no name alterations). Its engine listens
// on port 4000 while it runs, on every interface: Amass has no setting for that.

import { spawn, type ChildProcess } from "node:child_process";
import { accessSync, constants } from "node:fs";
import { openSync, closeSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { env } from "../../env.ts";

/** How long Amass may run: in all, and without finding anything new. Tests lower them. */
export const amassLimits = { minutes: 10, idleMinutes: 3, engineStartSeconds: 30 };

const ENGINE = "http://127.0.0.1:4000/api/v1/health";
/** Amass prints a line per name; more than this many bytes of output aren't read. */
const MAX_OUTPUT = 16 * 1024 * 1024;

export class AmassError extends Error {}

/** The Amass binary: KEELSON_AMASS (a path, or "off"), else `amass` on the PATH; null when there is none. */
export function amassPath(vars: NodeJS.ProcessEnv = process.env): string | null {
  const set = env("AMASS", vars);
  if (set === "off") return null;
  const candidates = set ? [set] : (vars.PATH ?? "").split(delimiter).map((dir) => join(dir, "amass"));
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

export interface AmassInput {
  domains: string[];
  onProgress?: (minutes: number) => void;
}

/** What Amass found under the domains: each name with the IPv4 addresses it resolved, if any. */
export async function runAmass(bin: string, input: AmassInput): Promise<Map<string, string[]>> {
  if (!input.domains.length) return new Map();
  const home = await mkdtemp(join(tmpdir(), "keelson-amass-"));
  // Nothing of Keelson's environment (its settings, a credential in a variable) reaches Amass: only the PATH and its own home.
  const childEnv = { PATH: process.env.PATH ?? "", HOME: home, XDG_CONFIG_HOME: join(home, ".config"), TMPDIR: home };
  let engine: ChildProcess | null = null;
  try {
    // An engine already on the port would be someone else's, writing to its own database.
    if (await engineUp()) throw new AmassError("Something is already listening on port 4000, where Amass's engine runs. Stop it and scan again.");
    // The engine's own output is kept in its home, so a crash can say why.
    const errors = join(home, "engine.err");
    const fd = openSync(errors, "w");
    engine = spawn(bin, ["engine", "-silent", "-nocolor", "-log-dir", home], { env: childEnv, cwd: home, detached: true, stdio: ["ignore", "ignore", fd] });
    closeSync(fd);
    const exited = new Promise<void>((resolve) => engine!.once("exit", () => resolve()));
    const deadline = Date.now() + amassLimits.engineStartSeconds * 1000;
    while (!(await engineUp())) {
      if (engine.exitCode != null || Date.now() > deadline) throw new AmassError("Amass's engine didn't start. Run `amass engine` by hand to see why.");
      await Promise.race([sleep(500), exited]);
    }

    const domains = join(home, "domains.txt");
    await writeFile(domains, `${input.domains.join("\n")}\n`);
    const started = Date.now();
    const tick = setInterval(() => input.onProgress?.(Math.floor((Date.now() - started) / 60_000)), 15_000);
    try {
      // Without its engine the enumeration would wait for nothing until the limit: it stops with it.
      await run(
        bin,
        ["enum", "-df", domains, "-rigid", "-silent", "-nocolor", "-timeout", String(amassLimits.idleMinutes)],
        childEnv,
        home,
        amassLimits.minutes * 60_000,
        exited,
      );
    } finally {
      clearInterval(tick);
    }
    if (engine.exitCode != null || engine.signalCode != null) {
      const why = (await readFile(errors, "utf8").catch(() => "")).split("\n").find((l) => /panic|fatal|error/i.test(l));
      throw new AmassError(`Amass's engine stopped during the scan${why ? `: ${why.trim().slice(0, 200)}` : ""}. Nothing it found was read.`);
    }
    const out = await run(bin, ["subs", "-df", domains, "-names", "-ipv4", "-nocolor"], childEnv, home, 120_000);
    return parseSubs(out);
  } finally {
    if (engine?.pid && engine.exitCode == null) {
      try {
        process.kill(-engine.pid, "SIGTERM");
      } catch {
        engine.kill("SIGTERM");
      }
    }
    await rm(home, { recursive: true, force: true }).catch(() => {});
  }
}

/** How Sonar finds and runs Amass; the mock replaces both, so tests and the mock dev server never run the real one. */
export const amass = {
  path: (): string | null => amassPath(),
  run: (bin: string, input: AmassInput): Promise<Map<string, string[]>> => runAmass(bin, input),
};

/** `amass subs -names -ipv4`: a name per line, then its addresses separated by commas when it has any. */
export function parseSubs(text: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const line of text.split("\n")) {
    const [name, ips] = line.trim().split(/\s+/, 2);
    if (!name?.includes(".")) continue;
    out.set(
      name.toLowerCase().replace(/\.$/, ""),
      (ips ?? "")
        .split(",")
        .map((ip) => ip.trim())
        .filter((ip) => /^\d{1,3}(\.\d{1,3}){3}$/.test(ip)),
    );
  }
  return out;
}

async function engineUp(): Promise<boolean> {
  try {
    // The engine listens on this machine: never through a network's proxy.
    const res = await fetch(ENGINE, { signal: AbortSignal.timeout(1000) });
    return res.ok;
  } catch {
    return false;
  }
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/** Runs a command to the end, or stops it at `limit` or when `stop` settles; resolves with its output either way. */
function run(bin: string, args: string[], childEnv: NodeJS.ProcessEnv, cwd: string, limit: number, stop?: Promise<void>): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, { env: childEnv, cwd, detached: true, stdio: ["ignore", "pipe", "pipe"] });
    const kill = () => {
      try {
        process.kill(-child.pid!, "SIGTERM");
      } catch {
        child.kill("SIGTERM");
      }
    };
    void stop?.then(() => child.exitCode == null && kill());
    let out = "";
    child.stdout!.on("data", (b: Buffer) => {
      if (out.length < MAX_OUTPUT) out += b.toString();
    });
    child.stderr!.resume();
    const timer = setTimeout(kill, limit);
    child.once("error", (e) => {
      clearTimeout(timer);
      reject(new AmassError(`Amass couldn't run: ${e.message}`));
    });
    child.once("exit", () => {
      clearTimeout(timer);
      resolve(out);
    });
  });
}
