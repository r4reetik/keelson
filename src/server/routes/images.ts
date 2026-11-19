// The Images page, for the view's scope: its numbers (GET /api/images), then a
// page at a time of images, running workloads, vulnerabilities and components
// (the inventory of what the images are made of), with the same filters as CSV.
// One image in full is GET /api/images/detail, and its software bill of materials
// GET /api/images/sbom. The images a repository builds are asked for by account
// and repository (GET /api/images/built-by), joined across its entity; an account
// the user can't see answers 404.
//
// Lists are served 50 rows at a time, and a row carries only the first few of the
// images or workloads it names: a registry has hundreds of images, and sending
// every row at once made the page slow on any laptop.

import type { Context } from "hono";
import type { AppContext, AppEnv } from "../env.ts";
import type { Routes } from "../router.ts";
import { ownAccount } from "../access.ts";
import { badRequest, notFound } from "../errors.ts";
import {
  componentCsv,
  componentPage,
  componentTypes,
  imageDetail,
  imagePage,
  imagesBuiltBy,
  imagesSummary,
  imagesView,
  registriesIn,
  scanOf,
  vulnCsv,
  vulnPage,
  workloadPage,
  type ImageFilters,
} from "../images.ts";
import { SBOM_FORMATS, sbomOf, type SbomFormat } from "../image-sbom.ts";
import { csvCell, slug } from "../present.ts";
import {
  COMPONENT_KIND_LABEL,
  IMAGE_STATUSES,
  imageName,
  type ComponentKind,
  type ImageDetailResponse,
  type ImagesResponse,
  type ImageUse,
  type ImageVulnStatus,
} from "../../shared/images.ts";

const USES: ImageUse[] = ["internet", "running", "pulled", "stored"];
/** Rows a selection may name, which keeps the address under Node's header limit; a larger one is "every row that matches". */
export const MAX_KEYS = 200;
const oneOf = <T extends string>(value: string | undefined, allowed: readonly T[]): T | undefined => (allowed.includes(value as T) ? (value as T) : undefined);

export function imageRoutes(r: Routes, { repo }: AppContext) {
  const filters = (c: Context<AppEnv>): ImageFilters => {
    const q = (k: string) => c.req.query(k) || undefined;
    const keys = c.req.queries("key") ?? [];
    if (keys.length > MAX_KEYS) throw badRequest(`Pick at most ${MAX_KEYS} rows, or none to take every row that matches the filters.`);
    const status = q("status");
    const kind = q("kind");
    return {
      q: q("q")?.slice(0, 200),
      use: oneOf(q("use"), USES),
      has: q("has"),
      registry: q("registry"),
      builder: oneOf(q("builder"), ["known", "unknown"] as const),
      reach: oneOf(q("reach"), ["internet", "private", "unknown"] as const),
      severity: q("severity"),
      status: status && status in IMAGE_STATUSES ? (status as ImageVulnStatus) : undefined,
      layer: oneOf(q("layer"), ["os", "app"] as const),
      from: oneOf(q("from"), ["base", "added"] as const),
      kind: kind && kind in COMPONENT_KIND_LABEL ? (kind as ComponentKind) : undefined,
      type: q("type"),
      vulnerable: q("vulnerable") === "yes" || undefined,
      eol: q("eol") === "yes" || undefined,
      image: q("image"),
      ...(keys.length ? { keys } : {}),
    };
  };
  const paging = (c: Context<AppEnv>) => ({
    offset: Math.max(0, Number(c.req.query("offset")) || 0),
    limit: Math.min(200, Math.max(1, Number(c.req.query("limit")) || 50)),
    // A selection's rows in full: every image a vulnerability is in, not the first few.
    full: c.req.query("full") === "1",
  });
  const csv = (rows: unknown[][], name: string) =>
    new Response(`﻿${rows.map((row) => row.map(csvCell).join(",")).join("\r\n")}`, {
      headers: { "content-type": "text/csv; charset=utf-8", "content-disposition": `attachment; filename="${name}.csv"` },
    });

  r.get("/api/images", (c) => {
    const view = imagesView(repo, c.get("scope"));
    const summary = imagesSummary(repo, view);
    return c.json({
      scan: view.scan,
      coverage: view.coverage,
      summary,
      registries: registriesIn(view),
      types: summary ? componentTypes(repo, view) : [],
    } satisfies ImagesResponse);
  });
  r.get("/api/images/list", (c) => {
    const { offset, limit, full } = paging(c);
    return c.json(imagePage(repo, imagesView(repo, c.get("scope")), filters(c), offset, limit, full));
  });
  r.get("/api/images/workloads", (c) => {
    const { offset, limit } = paging(c);
    return c.json(workloadPage(imagesView(repo, c.get("scope")), filters(c), offset, limit));
  });
  r.get("/api/images/vulnerabilities", (c) => {
    const { offset, limit, full } = paging(c);
    return c.json(vulnPage(repo, imagesView(repo, c.get("scope")), filters(c), offset, limit, full));
  });
  r.get("/api/images/components", (c) => {
    const { offset, limit, full } = paging(c);
    return c.json(componentPage(repo, imagesView(repo, c.get("scope")), filters(c), offset, limit, full));
  });
  r.get("/api/images/detail", (c) => {
    const id = c.req.query("id");
    if (!id) throw badRequest("Name the image.");
    const detail = imageDetail(repo, imagesView(repo, c.get("scope")), id);
    if (!detail) throw notFound("This image isn't in the view's latest scans. It may have been deleted, or replaced by a newer build.");
    return c.json(detail satisfies ImageDetailResponse);
  });
  // One image's software bill of materials, from what its scan kept.
  r.get("/api/images/sbom", (c) => {
    const id = c.req.query("id");
    const format = (c.req.query("format") || "cyclonedx") as SbomFormat;
    if (!id) throw badRequest("Name the image.");
    if (!(format in SBOM_FORMATS)) throw badRequest("Pick a format: cyclonedx or spdx.");
    const image = imagesView(repo, c.get("scope")).byId.get(id);
    const scan = image && scanOf(repo, image);
    if (!image || !scan) throw notFound("There is no bill of materials for this image: Keelson hasn't scanned it.");
    const file = `${imageName(image).replace(/[^\w.-]+/g, "_")}_${(image.tags[0] ?? "image").replace(/[^\w.-]+/g, "_")}.${SBOM_FORMATS[format]}`;
    return new Response(JSON.stringify(sbomOf(format, image, scan), null, 1), {
      headers: { "content-type": "application/json; charset=utf-8", "content-disposition": `attachment; filename="${file}"` },
    });
  });
  r.get("/api/images/vulnerabilities.csv", (c) => {
    const scope = c.get("scope");
    return csv(vulnCsv(repo, imagesView(repo, scope), filters(c)), `keelson-image-vulnerabilities-${slug(scope.label)}`);
  });
  r.get("/api/images/components.csv", (c) => {
    const scope = c.get("scope");
    return csv(componentCsv(repo, imagesView(repo, scope), filters(c)), `keelson-image-components-${slug(scope.label)}`);
  });
}

/** Not scoped: named by account and repository, like a repository's dependencies. */
export function imageBuildRoutes(r: Routes, { repo }: AppContext) {
  r.get("/api/images/built-by", (c) => {
    const accountId = c.req.query("account");
    const name = c.req.query("repo");
    if (!accountId || !name) throw badRequest("Name the account and the repository.");
    const account = ownAccount(repo, c, accountId);
    const org = repo.scans.latest(account.id)?.snap.links?.githubOrgs?.[0];
    if (!org) return c.json({ images: [] });
    // Every account of the repository's entity: the images it builds are kept and run in the entity's other accounts.
    const entity = repo.resolveScope(`e:${account.entityId}`, c.get("user").entities);
    if (!entity) return c.json({ images: [] });
    return c.json({ images: imagesBuiltBy(imagesView(repo, entity), `${org}/${name}`) });
  });
}
