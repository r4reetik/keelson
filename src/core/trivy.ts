// Runs Aqua Security's Trivy, when it is installed, to scan a container image
// straight from its registry: the packages in it, their known vulnerabilities, and
// credentials left in its files. KEELSON_TRIVY names the binary ("off" never runs
// it), else `trivy` on the PATH; like Syft and Grype it isn't in the Docker image.
//
// Trivy pulls the image's layers itself, reads them and keeps nothing of them:
// its cache (the tool folder Keelson was given) holds what it found in each
// layer, so an image it has seen is not downloaded again. Nothing of Keelson's
// environment reaches it. It gets a registry login that expires within hours,
// never the account's own credential, in a Docker configuration file written
// for that one run and that one registry host: Trivy offers a login given
// through TRIVY_USERNAME and TRIVY_PASSWORD to every registry it contacts, the
// ones it downloads its database from included. Besides the image's registry it
// asks only for its vulnerability database (and its Java index, about 1 GB, the
// first time an image holds JAR files), from the public registries Aqua
// publishes them to. Two processes can't share its cache, so images are scanned
// one at a time: every command that opens the cache waits its turn (`inTurn`),
// which is what lets the background reader finish its image while a new scan
// starts.
//
// An image named by its digest never changes, so it is pulled once. Trivy then
// writes its own bill of materials for what it read (`sbom`), and on later scans
// matches that against its current database (`match`), which contacts nothing
// and takes a fraction of a second.

import { accessSync, constants } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir, totalmem } from "node:os";
import { delimiter, join } from "node:path";
import { runChild, scannerCpus } from "./anchore.ts";
import { env } from "../env.ts";

/** How long one image may take, and how long a scan spends on images in all. Tests lower them. */
export const trivyLimits = { imageSeconds: 900, dbSeconds: 1200, totalSeconds: 1800 };
/** Matching a stored list of packages against the database takes well under a second; this is only a ceiling. */
const MATCH_SECONDS = 120;

export class TrivyError extends Error {
  /** The registry refused the login or the pull. */
  denied = false;
  /** The registry has no such image. */
  missing = false;
  /** The image has no build for the platform asked for (an arm64-only image asked for as amd64). */
  noPlatform = false;
  /** What the reference names isn't an image: a build attestation kept beside one, for example. */
  notImage = false;
  /** The failure is about this image or its registry, not about Trivy: other images can still be scanned. */
  image = false;
  /**
   * The registry's host couldn't be reached from where Keelson runs (no connection, or its name doesn't resolve): none
   * of its images can be pulled, and each try costs minutes of Trivy's retries.
   */
  unreachable: string | null = null;
}

/** A registry login for one scan. It reaches Trivy through its environment and is never stored or logged. */
export interface RegistryLogin {
  username: string;
  password: string;
}

/** Trivy's binary: KEELSON_TRIVY (a path, or "off"), else `trivy` on the PATH; null when there is none. */
export function trivyPath(vars: NodeJS.ProcessEnv = process.env): string | null {
  const set = env("TRIVY", vars);
  if (set === "off") return null;
  const candidates = set ? [set] : (vars.PATH ?? "").split(delimiter).map((dir) => join(dir, "trivy"));
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

/** Where Trivy keeps its database and what it found in each layer: the tool folder, or a temporary one for this process. */
let fallbackDir: string | null = null;
export async function trivyCacheDir(toolDir: string | null): Promise<string> {
  const dir = toolDir ? join(toolDir, "trivy") : (fallbackDir ??= join(tmpdir(), `keelson-trivy-${process.pid}`));
  await mkdir(dir, { recursive: true, mode: 0o700 });
  return dir;
}

/**
 * No update check and no usage reports (Trivy sends both in one request, skipped only when both are off): the only
 * requests left are the registry's and the database's. For an ECR host Trivy also asks the AWS SDK for a login; with
 * the instance metadata service off it finds no credentials, so it can't borrow the role of the machine Keelson runs on.
 */
const QUIET = {
  TRIVY_SKIP_VERSION_CHECK: "true",
  TRIVY_DISABLE_TELEMETRY: "true",
  TRIVY_NO_PROGRESS: "true",
  AWS_EC2_METADATA_DISABLED: "true",
  // A soft ceiling on Trivy's memory (a quarter of the machine's, at most 2 GB): past it Go collects garbage harder
  // instead of growing, so a large image doesn't push a laptop into swapping.
  GOMEMLIMIT: `${Math.max(256, Math.min(2048, Math.round(totalmem() / 4 / 1_048_576)))}MiB`,
};

/** What a failed pull says, without Trivy's chain of wrappers: the registry's own answer when there is one. */
export function trivyFailure(message: string): TrivyError {
  const flat = message.replace(/\s+/g, " ");
  // "remote error: GET https://ghcr.io/token?…: DENIED: requested access to the resource is denied"
  const registry = /(?:GET|HEAD|POST) https?:\/\/[^\s]+: (?:unexpected status code (\d{3})[^:]*:?|([A-Z_]{4,}):) ?(.{0,160})/.exec(flat);
  const code = registry?.[2] ?? registry?.[1] ?? "";
  const e = new TrivyError(registry ? `The registry answered ${code}${registry[3] ? `: ${registry[3].trim()}` : ""}`.slice(0, 240) : flat.slice(-240));
  e.denied = /^(UNAUTHORIZED|DENIED|401|403)$/.test(code) || /no basic auth credentials|authentication required|unauthorized/i.test(flat);
  e.missing = /^(MANIFEST_UNKNOWN|NAME_UNKNOWN|404)$/.test(code);
  // Learned on real registries: an index lists build attestations beside its images, and an image built only for
  // arm64 has nothing for Trivy's default, linux/amd64.
  e.notImage = /unsupported artifact type|attestation\.manifest/i.test(flat);
  e.noPlatform = /no child with platform/i.test(flat);
  if (e.notImage) e.message = "This isn't an image: it is a build attestation kept beside one.";
  else if (e.noPlatform) e.message = "The image has no build for the platform Keelson asked for.";
  // Learned on a real Container Registry instance whose internet access had an allowlist: Go's
  // 'Get "https://<host>/v2/": dial tcp <address>:443: connect: operation timed out', after minutes of retries.
  const net =
    !registry &&
    /dial tcp \S+ (?:connect: )?(?:operation timed out|i\/o timeout|connection refused|no route to host|network is unreachable)|dial tcp: lookup ([^\s:]+?)(?: on \S+)?: no such host|TLS handshake timeout/i.exec(
      flat,
    );
  if (net) {
    const host = /(?:Get|Head) "https?:\/\/([^/"]+)/.exec(flat)?.[1] ?? net[1] ?? "the registry";
    const why = net[1]
      ? "its name doesn't resolve here"
      : /refused/i.test(net[0])
        ? "the connection was refused"
        : /unreachable|no route/i.test(net[0])
          ? "there is no route to it"
          : "the connection timed out";
    e.unreachable = host;
    e.message = `Keelson couldn't connect to ${host} from where it runs: ${why}.`;
  }
  e.image = !!registry || e.denied || e.missing || e.notImage || e.noPlatform || !!net || /remote error|unable to find the specified image/i.test(flat);
  return e;
}

/** One command on Trivy's cache at a time, in the order they were asked for. */
let turn: Promise<unknown> = Promise.resolve();
function inTurn<T>(work: () => Promise<T>): Promise<T> {
  const mine = turn.then(work, work);
  turn = mine.catch(() => {});
  return mine;
}

async function run(bin: string, args: string[], seconds: number, extra: Record<string, string> = {}): Promise<string> {
  try {
    return await runChild("Trivy", bin, args, { seconds, env: { ...QUIET, ...extra }, fail: (m) => new TrivyError(m) });
  } catch (e) {
    throw trivyFailure((e as Error).message);
  }
}

/**
 * How scans find and run Trivy. The mock replaces it (dev/mock/trivy.ts), so tests and the mock dev server never run the
 * real one or pull an image.
 */
export const trivy = {
  path: (): string | null => trivyPath(),
  /** The installed version and when its vulnerability database was last updated; nulls when it can't tell. */
  async version(bin: string, toolDir: string | null): Promise<{ version: string | null; dbUpdated: string | null }> {
    try {
      const out = JSON.parse(await run(bin, ["version", "--format", "json", "--cache-dir", await trivyCacheDir(toolDir)], 30));
      return {
        version: String(out?.Version ?? "") || null,
        dbUpdated: typeof out?.VulnerabilityDB?.UpdatedAt === "string" ? out.VulnerabilityDB.UpdatedAt : null,
      };
    } catch {
      return { version: null, dbUpdated: null };
    }
  },
  /**
   * Trivy's JSON report for one image, pulled from its registry (never from a local Docker): every package, their known
   * vulnerabilities, and the credentials its secret scanner finds in files. `platform` picks a build of an image made
   * for several ("linux/arm64").
   */
  async image(bin: string, ref: string, login: RegistryLogin | null, toolDir: string | null, platform: string | null = null): Promise<string> {
    // The login goes in a Docker configuration for this run, under the image's registry host only, and is deleted after.
    const docker = await mkdtemp(join(tmpdir(), "keelson-registry-"));
    try {
      const host = ref.split("/")[0];
      const auths = login ? { [host]: { auth: Buffer.from(`${login.username}:${login.password}`).toString("base64") } } : {};
      await writeFile(join(docker, "config.json"), JSON.stringify({ auths }), { mode: 0o600 });
      const cache = await trivyCacheDir(toolDir);
      return await inTurn(() =>
        run(
          bin,
          [
            "image",
            "--format",
            "json",
            "--quiet",
            "--scanners",
            "vuln,secret",
            "--list-all-pkgs",
            "--image-src",
            "remote",
            "--cache-dir",
            cache,
            "--timeout",
            `${trivyLimits.imageSeconds}s`,
            // As many layers at a time as it has cores to work on them.
            "--parallel",
            String(scannerCpus()),
            // Trivy asks for linux/amd64 unless told otherwise.
            ...(platform ? ["--platform", platform] : []),
            ref,
          ],
          trivyLimits.imageSeconds + 30,
          { DOCKER_CONFIG: docker },
        ),
      );
    } finally {
      await rm(docker, { recursive: true, force: true }).catch(() => {});
    }
  },
  /**
   * Trivy's own bill of materials (CycloneDX) for a report it made, without contacting anything. The report is written to
   * a file for it, so the caller hands over only the report's packages, never the image's configuration.
   */
  async sbom(bin: string, report: string): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "keelson-sbom-"));
    try {
      const file = join(dir, "report.json");
      await writeFile(file, report, { mode: 0o600 });
      return await run(bin, ["convert", "--format", "cyclonedx", "--quiet", file], MATCH_SECONDS);
    } finally {
      await rm(dir, { recursive: true, force: true }).catch(() => {});
    }
  },
  /**
   * Trivy's JSON report for a bill of materials it made earlier: the same packages matched against today's database.
   * Nothing is pulled and no registry is contacted, so there is no login, and the database is the one already downloaded.
   */
  async match(bin: string, sbom: string, toolDir: string | null): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "keelson-sbom-"));
    try {
      const file = join(dir, "image.cdx.json");
      await writeFile(file, sbom, { mode: 0o600 });
      const cache = await trivyCacheDir(toolDir);
      return await inTurn(() =>
        run(
          bin,
          [
            "sbom",
            "--format",
            "json",
            "--quiet",
            "--skip-db-update",
            "--skip-java-db-update",
            "--offline-scan",
            "--cache-dir",
            cache,
            "--timeout",
            `${MATCH_SECONDS}s`,
            file,
          ],
          MATCH_SECONDS + 30,
        ),
      );
    } finally {
      await rm(dir, { recursive: true, force: true }).catch(() => {});
    }
  },
  /** Downloads Trivy's vulnerability database, or refreshes it when a newer one is published. No login is involved. */
  async updateDb(bin: string, toolDir: string | null): Promise<void> {
    const dir = await trivyCacheDir(toolDir);
    await inTurn(() =>
      run(bin, ["image", "--download-db-only", "--quiet", "--cache-dir", dir, "--timeout", `${trivyLimits.dbSeconds}s`], trivyLimits.dbSeconds + 30),
    );
  },
};
