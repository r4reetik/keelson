// A compact index of what an account's scanned images hold: which package is in
// which image, and which vulnerability is in which package of which image. The
// Images page's lists across every image (vulnerabilities, components) are built
// from it, so the server never has to hold every image's full result in memory:
// on a real registry that was 400 results of a thousand packages each.
//
// Packages, vulnerabilities and fixed versions are each listed once; what is
// where is flat arrays of numbers that point at them. A scan writes the index to
// its account's cache (`imgindex`) when it has scanned its images; the server
// builds one from the stored results when an account has none yet.

import type { ImageScan, VulnSeverity } from "../shared/images.ts";

export const INDEX_FORMAT = 1;

export interface IndexedVuln {
  id: string;
  severity: VulnSeverity;
  cvss: number | null;
  kev: boolean;
  title: string;
  url: string | null;
}

export interface IndexedPackage {
  name: string;
  version: string;
  type: string;
  layer: "os" | "app";
  licenses: string[];
}

export interface ImageIndex {
  format: number;
  /** Each image's cache key; the arrays below name an image by its place here. */
  keys: string[];
  /** Each image's layers, bottom first: an image built on another starts with that one's layers. */
  layers: string[][];
  vulns: IndexedVuln[];
  packages: IndexedPackage[];
  /** Fixed versions, each once; place 0 is "no fix". */
  fixes: string[];
  /** Three numbers per package in an image: the image, the package, and 1 when the base image brought it. */
  has: number[];
  /** Five numbers per vulnerability in a package of an image: the image, the package, the vulnerability, its fix, and 1 for the base image. */
  hits: number[];
}

/** Builds an index one image at a time, so only one full result is in memory at once. */
export class IndexBuilder {
  readonly #keys: string[] = [];
  readonly #layers: string[][] = [];
  readonly #vulns: IndexedVuln[] = [];
  readonly #vulnAt = new Map<string, number>();
  readonly #packages: IndexedPackage[] = [];
  readonly #packageAt = new Map<string, number>();
  readonly #fixes: string[] = [""];
  readonly #fixAt = new Map<string, number>([["", 0]]);
  readonly #has: number[] = [];
  readonly #hits: number[] = [];

  #package(p: { name: string; version: string; type: string; layer: "os" | "app"; licenses?: string[] }): number {
    const key = `${p.type}|${p.name}|${p.version}`;
    let at = this.#packageAt.get(key);
    if (at === undefined) {
      at = this.#packages.push({ name: p.name, version: p.version, type: p.type, layer: p.layer, licenses: p.licenses ?? [] }) - 1;
      this.#packageAt.set(key, at);
    } else if (p.licenses?.length && !this.#packages[at].licenses.length) this.#packages[at].licenses = p.licenses;
    return at;
  }

  add(key: string, scan: ImageScan): void {
    const image = this.#keys.push(key) - 1;
    this.#layers.push(scan.layers ?? []);
    const seen = new Set<number>();
    for (const p of scan.packages) {
      const at = this.#package(p);
      // A package found twice in one image (two lock files) is in it once.
      if (seen.has(at)) continue;
      seen.add(at);
      this.#has.push(image, at, p.base ? 1 : 0);
    }
    for (const v of scan.vulns) {
      const pkg = this.#package({ name: v.pkg, version: v.version, type: v.type, layer: v.layer });
      if (!seen.has(pkg)) {
        seen.add(pkg);
        this.#has.push(image, pkg, v.base ? 1 : 0);
      }
      let vuln = this.#vulnAt.get(v.id);
      if (vuln === undefined) {
        vuln = this.#vulns.push({ id: v.id, severity: v.severity, cvss: v.cvss, kev: v.kev, title: v.title, url: v.url }) - 1;
        this.#vulnAt.set(v.id, vuln);
      } else if (v.kev) this.#vulns[vuln].kev = true;
      const fixed = v.fixedIn ?? "";
      let fix = this.#fixAt.get(fixed);
      if (fix === undefined) {
        fix = this.#fixes.push(fixed) - 1;
        this.#fixAt.set(fixed, fix);
      }
      this.#hits.push(image, pkg, vuln, fix, v.base ? 1 : 0);
    }
  }

  done(): ImageIndex {
    return {
      format: INDEX_FORMAT,
      keys: this.#keys,
      layers: this.#layers,
      vulns: this.#vulns,
      packages: this.#packages,
      fixes: this.#fixes,
      has: this.#has,
      hits: this.#hits,
    };
  }
}
