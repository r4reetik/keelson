// CISA's catalog of known exploited vulnerabilities (KEV): the CVE IDs attackers
// are known to use. Trivy's report doesn't say which of an image's vulnerabilities
// are on it, so Keelson reads the catalog itself: one public file, fetched with a
// plain GET and no credential, at most once a day, and kept in the tool folder so a
// day without the network still has yesterday's list.

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

const URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const DAY = 86_400_000;
const TIMEOUT_MS = 30_000;

interface Stored {
  fetchedAt: number;
  ids: string[];
}

let memory: Stored | null = null;

async function fromDisk(toolDir: string | null): Promise<Stored | null> {
  if (!toolDir) return null;
  try {
    const s = JSON.parse(await readFile(join(toolDir, "kev.json"), "utf8")) as Stored;
    return Array.isArray(s?.ids) && typeof s.fetchedAt === "number" ? s : null;
  } catch {
    return null;
  }
}

async function download(): Promise<string[]> {
  const res = await fetch(URL, { signal: AbortSignal.timeout(TIMEOUT_MS), headers: { accept: "application/json" } });
  if (!res.ok) throw new Error(`CISA's catalog answered ${res.status}`);
  const body = (await res.json()) as { vulnerabilities?: { cveID?: unknown }[] };
  const ids = (body?.vulnerabilities ?? []).map((v) => String(v?.cveID ?? "")).filter((id) => /^CVE-\d{4}-\d+$/.test(id));
  // The catalog has held over a thousand entries for years: a short list is a broken download, not good news.
  if (ids.length < 100) throw new Error("CISA's catalog came back incomplete");
  return ids;
}

/** How scans read the catalog. The mock replaces it, so tests never ask CISA. */
export const kev = {
  /** The CVE IDs on the catalog. Throws when it was never read and can't be now. */
  async load(toolDir: string | null, now = Date.now()): Promise<Set<string>> {
    if (memory && now - memory.fetchedAt < DAY) return new Set(memory.ids);
    const stored = memory ?? (await fromDisk(toolDir));
    if (stored && now - stored.fetchedAt < DAY) {
      memory = stored;
      return new Set(stored.ids);
    }
    try {
      memory = { fetchedAt: now, ids: await download() };
      if (toolDir) {
        await mkdir(toolDir, { recursive: true, mode: 0o700 });
        await writeFile(join(toolDir, "kev.json"), JSON.stringify(memory), { mode: 0o600 });
      }
      return new Set(memory.ids);
    } catch (e) {
      // An older list is better than none: new entries are a handful a week.
      if (stored) return new Set(stored.ids);
      throw new Error(`CISA's list of known exploited vulnerabilities couldn't be read: ${(e as Error).message}`);
    }
  },
};
