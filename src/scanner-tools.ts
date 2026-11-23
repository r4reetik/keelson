// The scanners Keelson runs, as Settings shows them: which are installed, at which
// version, and when the vulnerability databases two of them match against (Grype's
// and Trivy's) were built. Scans already keep both current (Grype checks for a newer
// database each time it runs, Trivy before each scan that reads images); this is for
// updating one now, for example after a large advisory, or on a machine that was off.
//
// An update runs in the background, one per database, and is Keelson's own download:
// it takes the default network, as the scans' own updates do. Grype's and Trivy's
// commands on their databases take turns with a scan's (src/core/anchore.ts,
// src/core/trivy.ts), so an update never replaces a database a scan is reading.

import { anchore, type AnchoreTool } from "./core/anchore.ts";
import { trivy } from "./core/trivy.ts";
import { amass } from "./providers/internet/amass.ts";
import { installKind } from "./env.ts";
import { DATABASE_TOOLS, SCANNER_TOOLS, type ScannerToolKey } from "./shared/tools.ts";
import type { ScannerDatabase, ScannerRow, ScannersResponse } from "./shared/api.ts";

/** Versions and build dates are read again after this long; an update clears them at once. */
const FRESH_MS = 5 * 60_000;

type DatabaseTool = "grype" | "trivy";

interface Update {
  updating: boolean;
  updatedAt: string | null;
  error: string | null;
}

export class ScannerTools {
  readonly #toolDir: string | null;
  readonly #log: (msg: string) => void;
  readonly #updates = new Map<DatabaseTool, Update>();
  #read: { at: number; rows: Promise<ScannerRow[]> } | null = null;

  constructor(toolDir: string | null, log: (msg: string) => void = () => {}) {
    this.#toolDir = toolDir;
    this.#log = log;
  }

  /** The binary Keelson would run, or null when it isn't installed or is turned off. */
  path(key: ScannerToolKey): string | null {
    if (key === "trivy") return trivy.path();
    if (key === "amass") return amass.path();
    return anchore.path(key as AnchoreTool);
  }

  async status(): Promise<ScannersResponse> {
    if (!this.#read || Date.now() - this.#read.at > FRESH_MS) {
      const rows = this.#readAll();
      this.#read = { at: Date.now(), rows };
      // A failed read is tried again on the next request, not kept for five minutes.
      rows.catch(() => (this.#read = null));
    }
    const rows = await this.#read.rows;
    return {
      install: installKind(),
      scanners: rows.map((r) => (r.database ? { ...r, database: { ...r.database, ...this.#update(r.key as DatabaseTool) } } : r)),
    };
  }

  /** Starts updating a database. "running" when an update of it already is; "missing" when its scanner isn't installed. */
  update(key: DatabaseTool): "started" | "running" | "missing" {
    if (this.#update(key).updating) return "running";
    const bin = this.path(key);
    if (!bin) return "missing";
    const state: Update = { updating: true, updatedAt: null, error: null };
    this.#updates.set(key, state);
    const name = SCANNER_TOOLS[key].name;
    this.#log(`Updating ${name}'s database`);
    void (key === "grype" ? anchore.updateGrypeDb(bin, this.#toolDir) : trivy.updateDb(bin, this.#toolDir))
      .then(
        () => this.#log(`${name}'s database is up to date`),
        (e: Error) => {
          state.error = e.message;
          this.#log(`${name}'s database couldn't be updated: ${e.message}`);
        },
      )
      .finally(() => {
        state.updating = false;
        state.updatedAt = new Date().toISOString();
        this.#read = null;
      });
    return "started";
  }

  #update(key: DatabaseTool): Update {
    return this.#updates.get(key) ?? { updating: false, updatedAt: null, error: null };
  }

  #readAll(): Promise<ScannerRow[]> {
    return Promise.all(
      (Object.keys(SCANNER_TOOLS) as ScannerToolKey[]).map(async (key): Promise<ScannerRow> => {
        const tool = SCANNER_TOOLS[key];
        const bin = this.path(key);
        const { version, builtAt } = bin ? await this.#versionOf(key, bin) : { version: null, builtAt: null };
        const database: ScannerDatabase | null = tool.database ? { ...tool.database, builtAt, updating: false, updatedAt: null, error: null } : null;
        return { key, name: tool.name, purpose: tool.purpose, installed: !!bin, version, database };
      }),
    );
  }

  async #versionOf(key: ScannerToolKey, bin: string): Promise<{ version: string | null; builtAt: string | null }> {
    if (key === "trivy") {
      const v = await trivy.version(bin, this.#toolDir);
      return { version: v.version, builtAt: v.dbUpdated };
    }
    // Amass has no version command that answers in a form Keelson reads.
    if (key === "amass") return { version: null, builtAt: null };
    const [version, builtAt] = await Promise.all([
      anchore.version(key as AnchoreTool, bin),
      key === "grype" ? anchore.grypeDbBuilt(bin, this.#toolDir).catch(() => null) : null,
    ]);
    return { version, builtAt };
  }
}

export const isDatabaseTool = (key: string): key is DatabaseTool => (DATABASE_TOOLS as string[]).includes(key);
