// The scanners Keelson runs beside itself (Syft, Grype, Grant, Trivy, Amass), and
// what a data source that comes from one needs. The words depend on how Keelson
// runs: the Docker image carries them (a scanner added later may not be in it yet),
// and from a clone they are installed on the machine. Coverage is stored with each scan, so the Data coverage table
// words a scanner's row from here rather than from the text the scan kept, which
// may be from before the image carried it.

import type { Coverage, InstallKind } from "./api.ts";
import { PROVIDER_INFO } from "./providers.ts";

export interface ScannerTool {
  name: string;
  /** The variable that names its binary ("off" never runs it). */
  variable: string;
  /** The Docker image carries it, on the PATH. */
  inImage: boolean;
  /** Where its own docs say how to install it. */
  installUrl: string;
  /** What else it needs, said after where it comes from. */
  note?: string;
  /** What Keelson runs it for, in a few words (Settings). */
  purpose: string;
  /** The database it matches against, which Settings can update: where it comes from and how large it is. */
  database?: { from: string; size: string };
}

const DEFS = {
  syft: {
    name: "Syft",
    variable: "KEELSON_SYFT",
    inImage: true,
    installUrl: "https://github.com/anchore/syft#installation",
    purpose: "Software bill of materials for each repository",
  },
  grype: {
    name: "Grype",
    variable: "KEELSON_GRYPE",
    inImage: true,
    installUrl: "https://github.com/anchore/grype#installation",
    note: "Its database, about 3 GB, is downloaded from Anchore into the data folder",
    purpose: "Known vulnerabilities in dependencies",
    database: { from: "Anchore (grype.anchore.io)", size: "about 3 GB" },
  },
  grant: {
    name: "Grant",
    variable: "KEELSON_GRANT",
    inImage: true,
    installUrl: "https://github.com/anchore/grant#installation",
    purpose: "Dependencies' licenses",
  },
  trivy: {
    name: "Trivy",
    variable: "KEELSON_TRIVY",
    inImage: true,
    installUrl: "https://trivy.dev/latest/getting-started/installation/",
    note: "Its database, about 1.6 GB, is downloaded into the data folder",
    purpose: "Packages, vulnerabilities and credentials in container images",
    database: { from: "Aqua's public registries (mirror.gcr.io, ghcr.io)", size: "about 1.6 GB" },
  },
  amass: {
    name: "Amass 5",
    variable: "KEELSON_AMASS",
    inImage: true,
    installUrl: "https://github.com/owasp-amass/amass#installation",
    purpose: "Sonar's subdomain discovery",
  },
} satisfies Record<string, ScannerTool>;

export type ScannerToolKey = keyof typeof DEFS;
export const SCANNER_TOOLS: Record<ScannerToolKey, ScannerTool> = DEFS;

/** The scanners with a database Settings can update. */
export const DATABASE_TOOLS = (Object.keys(DEFS) as ScannerToolKey[]).filter((k) => SCANNER_TOOLS[k].database);

/** The data source key is a scanner's own (every provider names it the same: `syft`, `grype`, `trivy`…). */
export const isScannerTool = (key: string | undefined): key is ScannerToolKey => !!key && Object.hasOwn(DEFS, key);

/**
 * What a source from this scanner needs. Without `install`, for the docs and the source registries, both ways are
 * said; with it, only what applies where this copy of Keelson runs.
 */
export function toolNeed(key: ScannerToolKey, install?: InstallKind): string {
  const t = SCANNER_TOOLS[key];
  const where =
    install === "docker"
      ? t.inImage
        ? `${t.name}, which the Docker image includes: use the latest image, and leave ${t.variable} unset or set to the binary's path, not off`
        : `${t.name}, which isn't in the Docker image yet: mount its binary into the container and give its path in ${t.variable}`
      : install === "source"
        ? `${t.name} installed on the machine Keelson runs on: on the PATH, or its path in ${t.variable}`
        : t.inImage
          ? `${t.name}: included in the Docker image. Run from a clone, it must be on the PATH, or its path in ${t.variable}`
          : `${t.name} installed where Keelson runs: on the PATH, or its path in ${t.variable} (not in the Docker image yet)`;
  return t.note ? `${where}. ${t.note}` : where;
}

/** What a scan says when a scanner isn't there: the one failure of a scanner that installing it fixes. */
export const notInstalled = (name: string): string => `${name} isn't installed where Keelson runs.`;

/**
 * The scanner wasn't there. Any other failure of a scanner (an image it couldn't read, a database that didn't download)
 * means it ran, and saying it needs installing would send people the wrong way. A gap without a message is taken as
 * missing, as it was the only kind before scanners' errors were kept.
 */
export const scannerMissing = (c: Pick<Coverage, "message">): boolean => !c.message || /^[\w ]+ isn't installed where Keelson runs\.$/.test(c.message);

/**
 * What a source needs, in the words for where this copy runs: a scanner's from here, any other's as its scan kept it.
 * Nothing for a scanner that ran and failed: its message says why.
 */
export function coverageNeed(c: Pick<Coverage, "key" | "permission" | "message">, install?: InstallKind): string | undefined {
  if (!isScannerTool(c.key)) return c.permission;
  return scannerMissing(c) ? toolNeed(c.key, install) : undefined;
}

/**
 * What to do about an unreadable source: install a scanner (`missing`), read why a scanner that ran failed, give the
 * account a better credential, or fix the network.
 */
export type CoverageFix = { kind: "tool"; tool: ScannerToolKey; missing: boolean } | { kind: "credential" } | { kind: "network" } | { kind: "none" };

export function coverageFix(c: Pick<Coverage, "key" | "permission" | "message">): CoverageFix {
  if (isScannerTool(c.key)) return { kind: "tool", tool: c.key, missing: scannerMissing(c) };
  // Public DNS lookups and probes need no permission, only outbound network access.
  if (!c.permission) return { kind: "network" };
  // Read without a credential (public files, other accounts' scans) or a connection to a registry: the needs line says what it takes.
  if (c.permission.startsWith("None:") || c.key === "registryNetwork") return { kind: "none" };
  return { kind: "credential" };
}

/**
 * Why a page has nothing to show although a scan exists: which source couldn't be read and what to do, in one
 * sentence. A scanner is installed, a credential is replaced, anything else is said by what it needs.
 */
export function unreadableSentence(
  c: Pick<Coverage, "key" | "label" | "permission" | "provider" | "notReadableIn" | "message">,
  install?: InstallKind,
): string {
  const label = c.label.charAt(0).toLowerCase() + c.label.slice(1);
  const where = `Keelson can't read ${label}${c.notReadableIn?.length ? ` for ${c.notReadableIn.map((a) => a.name).join(", ")}` : ""}`;
  const fix = coverageFix(c);
  const need = coverageNeed(c, install);
  if (fix.kind === "credential")
    return `${where}. It needs ${need}: grant it, or replace the ${PROVIDER_INFO[c.provider ?? "cloudflare"].credential} on the Accounts page, then scan again.`;
  if (fix.kind === "network") return `${where}. Check that this server can reach the internet over HTTPS, then scan again.`;
  if (fix.kind === "tool" && !fix.missing) return `${where}: ${c.message}${/[.…]$/.test(c.message ?? "") ? "" : "."} Then scan again.`;
  return `${where}. It needs ${need}. Then scan again.`;
}
