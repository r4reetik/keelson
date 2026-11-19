// Support dates of the runtimes container images are built around (Node.js,
// nginx, Python, Go, Java…), from endoflife.date: for each release line, when it
// stops getting fixes and its newest patch release. Trivy knows the packages an
// image holds, but a runtime an official image installs from a tarball (Node.js
// in `node`, Python in `python`) is in no package list, so Trivy says nothing
// about it. Keelson reads the runtime's version from the image and asks here
// whether that release line is still supported and how far behind it is.
//
// One small public file per product, fetched with a plain GET and no credential,
// at most once a day, and kept in the tool folder so a day without the network
// still has yesterday's dates. Only the product's name is sent, never anything
// about an image.

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

const DAY = 86_400_000;
const TIMEOUT_MS = 15_000;

/** One release line of a product: "18" of Node.js, "1.25" of nginx. */
export interface ReleaseLine {
  cycle: string;
  /** When it stops (or stopped) getting fixes; true when it already has, with no date; false when no end is set. */
  eol: string | boolean;
  latest: string | null;
}

interface Stored {
  fetchedAt: number;
  products: Record<string, ReleaseLine[]>;
}

/** What Keelson can say about one version of a runtime. */
export interface Support {
  /** Its release line no longer gets fixes; null when the line isn't known. */
  eol: boolean | null;
  /** When the line stops getting fixes, when a date is set. */
  until: string | null;
  /** The newest release of its line, when the version is behind it. */
  latest: string | null;
}

let memory: Stored | null = null;

async function fromDisk(toolDir: string | null): Promise<Stored | null> {
  if (!toolDir) return null;
  try {
    const s = JSON.parse(await readFile(join(toolDir, "eol.json"), "utf8")) as Stored;
    return s && typeof s.fetchedAt === "number" && s.products && typeof s.products === "object" ? s : null;
  } catch {
    return null;
  }
}

async function download(product: string): Promise<ReleaseLine[]> {
  const res = await fetch(`https://endoflife.date/api/${encodeURIComponent(product)}.json`, {
    signal: AbortSignal.timeout(TIMEOUT_MS),
    headers: { accept: "application/json" },
  });
  if (!res.ok) throw new Error(`endoflife.date answered ${res.status} for ${product}`);
  const body = (await res.json()) as { cycle?: unknown; eol?: unknown; latest?: unknown }[];
  if (!Array.isArray(body)) throw new Error(`endoflife.date's answer for ${product} wasn't a list`);
  return body
    .filter((c) => typeof c?.cycle === "string" || typeof c?.cycle === "number")
    .map((c) => ({
      cycle: String(c.cycle),
      eol: typeof c.eol === "string" || typeof c.eol === "boolean" ? c.eol : false,
      latest: typeof c.latest === "string" ? c.latest : null,
    }));
}

/** Compares dotted versions numerically: "18.20.10" is after "18.20.8". */
function compare(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d;
  }
  return 0;
}

/** A version's release line and what that says about it. Null fields where the product or the line isn't known. */
export function supportOf(lines: ReleaseLine[] | undefined, version: string, now: number): Support {
  // The longest release line that starts the version at a dot: "1.25" for 1.25.3, "18" for 18.20.8.
  const line = [...(lines ?? [])].sort((a, b) => b.cycle.length - a.cycle.length).find((l) => version === l.cycle || version.startsWith(`${l.cycle}.`));
  if (!line) return { eol: null, until: null, latest: null };
  const until = typeof line.eol === "string" ? line.eol : null;
  const eol = line.eol === true || (until != null && Date.parse(until) <= now);
  return { eol, until, latest: line.latest && /^\d+(\.\d+)*$/.test(line.latest) && compare(line.latest, version) > 0 ? line.latest : null };
}

/** How scans read support dates. The mock replaces it, so tests never ask endoflife.date. */
export const eol = {
  /** The release lines of each product asked for. A product that couldn't be read is left out: nothing is said about it. */
  async load(products: string[], toolDir: string | null, now = Date.now()): Promise<Record<string, ReleaseLine[]>> {
    const stored = memory ?? (await fromDisk(toolDir));
    const fresh = stored && now - stored.fetchedAt < DAY ? stored : null;
    const out: Record<string, ReleaseLine[]> = {};
    let changed = false;
    for (const p of new Set(products)) {
      if (fresh?.products[p]) out[p] = fresh.products[p];
      else
        try {
          out[p] = await download(p);
          changed = true;
        } catch {
          // Yesterday's dates are better than none.
          if (stored?.products[p]) out[p] = stored.products[p];
        }
    }
    if (changed) {
      memory = { fetchedAt: fresh ? fresh.fetchedAt : now, products: { ...(fresh?.products ?? {}), ...out } };
      if (toolDir)
        try {
          await mkdir(toolDir, { recursive: true, mode: 0o700 });
          await writeFile(join(toolDir, "eol.json"), JSON.stringify(memory), { mode: 0o600 });
        } catch {
          /* kept in memory for this run */
        }
    } else if (fresh) memory = fresh;
    return out;
  },
};
