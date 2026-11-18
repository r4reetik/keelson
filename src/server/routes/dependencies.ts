// A repository's dependencies, from its account's latest scan: its parts, every
// package with where it's used, known vulnerabilities and licenses
// (GET /api/dependencies), and its software bill of materials to download as
// CycloneDX, SPDX or Syft's own JSON (GET /api/dependencies/sbom). Both name the
// account and repository; an account the user can't see answers 404.

import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AppContext } from "../env.ts";
import type { Routes } from "../router.ts";
import { displayName } from "../../store/repo.ts";
import { HttpError, notFound, badRequest } from "../errors.ts";
import { ownAccount } from "../access.ts";
import { anchore } from "../../core/anchore.ts";
import type { Context } from "hono";
import type { AppEnv } from "../env.ts";
import { LICENSE_RISKS, PACKAGE_STATUSES } from "../../shared/dependencies.ts";
import type { AffectedResponse, DependenciesResponse, LicenseRiskFilter, PackageStatus, RepoDependencies, SbomResponse } from "../../shared/dependencies.ts";
import { coverage, latestScans, scanMeta } from "../scope.ts";
import { csvCell, slug } from "../present.ts";
import { affectedRepos, licensePage, packageCsv, packagePage, sbomSummary, vulnPage, type AffectedTab, type SbomFilters } from "../sbom.ts";

interface StoredView {
  dependencies: RepoDependencies;
  tools: DependenciesResponse["tools"];
  dbBuilt: string | null;
}

/** Download formats, with the Syft output name and the file's suffix. */
const FORMATS: Record<string, { syft: string | null; suffix: string; label: string }> = {
  cyclonedx: { syft: "cyclonedx-json", suffix: "cdx.json", label: "CycloneDX" },
  spdx: { syft: "spdx-json", suffix: "spdx.json", label: "SPDX" },
  syft: { syft: null, suffix: "syft.json", label: "Syft" },
};

export function dependencyRoutes(r: Routes, { repo }: AppContext) {
  r.get("/api/dependencies", (c) => {
    const accountId = c.req.query("account");
    const name = c.req.query("repo");
    if (!accountId || !name) throw badRequest("Name the account and the repository.");
    const account = ownAccount(repo, c, accountId);
    const view = repo.cache.get<StoredView>(account.id, `deps:${name}`);
    if (!view) throw notFound("Keelson hasn't read this repository's dependencies yet. They are read on the next scan.");
    const scan = repo.scans.latest(account.id);
    const row = scan?.snap.repos?.find((x) => x.name === name);
    const findings = scan
      ? repo.findings
          .forScan(scan.id, repo.settings.get().slaDays)
          .filter((f) => f.zone === name && f.category === "Supply chain" && !f.settled)
          .map((f) => ({ fingerprint: f.fingerprint, checkId: f.checkId, resource: f.resource, severity: f.severity, title: f.title }))
      : [];
    const login = scan?.snap.links?.githubOrgs?.[0] ?? null;
    return c.json({
      repo: name,
      account: displayName(account),
      accountId: account.id,
      visibility: row?.visibility ?? "private",
      defaultBranch: row?.defaultBranch ?? "main",
      url: login ? `https://github.com/${encodeURIComponent(login)}/${encodeURIComponent(name)}` : "https://github.com",
      dependencies: view.dependencies,
      tools: view.tools,
      dbBuilt: view.dbBuilt,
      findings,
    } satisfies DependenciesResponse);
  });

  r.get("/api/dependencies/sbom", async (c) => {
    const accountId = c.req.query("account");
    const name = c.req.query("repo");
    const format = FORMATS[c.req.query("format") || "cyclonedx"];
    if (!accountId || !name) throw badRequest("Name the account and the repository.");
    if (!format) throw badRequest("Pick a format: cyclonedx, spdx or syft.");
    const account = ownAccount(repo, c, accountId);
    const cached = repo.cache.get<{ sbom: Record<string, unknown> | null; generatedAt: number }>(account.id, `sbom:${name}`);
    if (!cached?.sbom) throw notFound("There is no SBOM for this repository yet. It is made on the next scan, when Syft is installed.");
    // The stored document keeps only packages; Syft's other sections are put back so any Syft-JSON reader accepts it.
    const doc = {
      ...cached.sbom,
      files: [],
      source: { id: name, name, version: "", type: "directory", metadata: { path: name } },
      distro: {},
    };
    const file = `${name.replace(/[^\w.-]+/g, "_")}.${format.suffix}`;
    let body = JSON.stringify(doc);
    if (format.syft) {
      const bin = anchore.path("syft");
      if (!bin) throw new HttpError(409, "Syft isn't installed where Keelson runs, so the SBOM can only be downloaded as Syft JSON.");
      const dir = await mkdtemp(join(tmpdir(), "keelson-sbom-"));
      try {
        await writeFile(join(dir, "sbom.json"), body);
        body = await anchore.convert(bin, join(dir, "sbom.json"), format.syft);
      } finally {
        await rm(dir, { recursive: true, force: true }).catch(() => {});
      }
    }
    return new Response(body, { headers: { "content-type": "application/json; charset=utf-8", "content-disposition": `attachment; filename="${file}"` } });
  });
}

/**
 * The Dependencies page, for the view's scope: a summary (GET /api/sbom), and filtered pages of packages,
 * vulnerabilities and licenses (the Grant report), with the packages as CSV, and the repositories a selection affects
 * (GET /api/sbom/affected). Filters are query parameters.
 */
/** Rows a selection may name, which keeps the address under Node's header limit; a larger one is "every row that matches", sent without keys. */
export const MAX_KEYS = 200;

export function sbomRoutes(r: Routes, { repo }: AppContext) {
  const filters = (c: Context<AppEnv>): SbomFilters => {
    const q = (k: string) => c.req.query(k) || undefined;
    const status = q("status");
    const risk = q("risk");
    return {
      q: q("q")?.slice(0, 200),
      ecosystem: q("ecosystem"),
      language: q("language"),
      status: status && status in PACKAGE_STATUSES ? (status as PackageStatus) : undefined,
      severity: q("severity"),
      risk: risk && risk in LICENSE_RISKS ? (risk as LicenseRiskFilter) : undefined,
      // An empty license means "states none", so it's read as given.
      license: c.req.query("license"),
      usage: q("usage") === "direct" || q("usage") === "transitive" ? (q("usage") as "direct" | "transitive") : undefined,
      env: q("env") === "runtime" || q("env") === "dev" ? (q("env") as "runtime" | "dev") : undefined,
      repo: q("repo"),
      triage: q("triage"),
      vuln: q("vuln"),
    };
  };
  const paging = (c: Context<AppEnv>) => ({
    offset: Math.max(0, Number(c.req.query("offset")) || 0),
    limit: Math.min(200, Math.max(1, Number(c.req.query("limit")) || 100)),
  });

  r.get("/api/sbom", (c) => {
    const s = latestScans(repo, c.get("scope"));
    return c.json({ scan: scanMeta(s), coverage: coverage(s), summary: sbomSummary(repo, s) } satisfies SbomResponse);
  });
  r.get("/api/sbom/packages", (c) => {
    const { offset, limit } = paging(c);
    return c.json(packagePage(repo, latestScans(repo, c.get("scope")), filters(c), c.req.query("sort") || "risk", offset, limit));
  });
  r.get("/api/sbom/vulnerabilities", (c) => {
    const { offset, limit } = paging(c);
    return c.json(vulnPage(repo, latestScans(repo, c.get("scope")), filters(c), offset, limit));
  });
  r.get("/api/sbom/licenses", (c) => {
    const { offset, limit } = paging(c);
    return c.json(licensePage(repo, latestScans(repo, c.get("scope")), filters(c), offset, limit));
  });
  // The repositories behind picked rows (`key`, repeatable), or behind every row the filters match when none is picked.
  r.get("/api/sbom/affected", (c) => {
    const tab = c.req.query("tab") || "packages";
    if (!["packages", "vulnerabilities", "licenses"].includes(tab)) throw badRequest("Pick packages, vulnerabilities or licenses.");
    const keys = c.req.queries("key") ?? [];
    if (keys.length > MAX_KEYS) throw badRequest(`Pick at most ${MAX_KEYS} rows, or none to take every row that matches the filters.`);
    return c.json(affectedRepos(repo, latestScans(repo, c.get("scope")), tab as AffectedTab, filters(c), keys) satisfies AffectedResponse);
  });
  r.get("/api/sbom/packages.csv", (c) => {
    const scope = c.get("scope");
    const rows = packageCsv(repo, latestScans(repo, scope), filters(c));
    const csv = rows.map((row) => row.map(csvCell).join(",")).join("\r\n");
    return new Response(`﻿${csv}`, {
      headers: { "content-type": "text/csv; charset=utf-8", "content-disposition": `attachment; filename="keelson-dependencies-${slug(scope.label)}.csv"` },
    });
  });
}
