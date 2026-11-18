// Compliance checklists for the accounts in view (?framework=iso27001 | pci-dss),
// and the same checklist as CSV. An indication from what Keelson reads,
// computed from the latest scans and current triage on each request, like the
// score; nothing about it is recorded by hand.

import type { Context } from "hono";
import type { AppContext, AppEnv } from "../env.ts";
import type { Routes } from "../router.ts";
import { checkStats, latestScans, scanMeta, scopeFindings } from "../scope.ts";
import { csvCell, slug } from "../present.ts";
import { badRequest } from "../errors.ts";
import { assess, FRAMEWORKS } from "../../compliance/index.ts";
import { CONTROL_STATUS_LABEL, FRAMEWORK_IDS, type ComplianceResponse, type FrameworkId } from "../../shared/compliance.ts";

export function complianceRoutes(r: Routes, { repo }: AppContext) {
  const build = (c: Context<AppEnv>) => {
    const id = (c.req.query("framework") || FRAMEWORK_IDS[0]) as FrameworkId;
    if (!FRAMEWORK_IDS.includes(id)) throw badRequest(`Unknown framework. Pick one of ${FRAMEWORK_IDS.join(", ")}.`);
    const fw = FRAMEWORKS[id];
    const scope = c.get("scope");
    const scans = latestScans(repo, scope);
    const result = assess(fw, {
      providers: new Set(scans.map((s) => s.account.provider)),
      stats: checkStats(scans),
      coverage: scans.map((s) => s.scan.snap.coverage || []),
      findings: scopeFindings(repo, scans, repo.settings.get()),
      disabled: repo.settings.overrides().disabled,
    });
    return {
      scope,
      body: {
        scan: scanMeta(scans),
        framework: fw.info,
        frameworks: FRAMEWORK_IDS.map((f) => FRAMEWORKS[f].info),
        groups: fw.groups,
        ...result,
      } satisfies ComplianceResponse,
    };
  };

  r.get("/api/compliance", (c) => c.json(build(c).body));

  r.get("/api/export/compliance.csv", (c) => {
    const { scope, body } = build(c);
    const header = [
      "requirement",
      "title",
      "group",
      "status",
      "open findings",
      "worst severity",
      "accepted risks",
      "checks",
      "checks without enough permission",
      "checks turned off",
      "covers",
      "note",
    ];
    const rows = body.controls.map((x) => [
      x.id,
      x.title,
      x.group,
      CONTROL_STATUS_LABEL[x.status],
      x.open,
      x.worst ?? "",
      x.accepted,
      x.checks.map((k) => k.id).join(" "),
      x.checks
        .filter((k) => k.skipped)
        .map((k) => k.id)
        .join(" "),
      x.checks
        .filter((k) => k.disabled)
        .map((k) => k.id)
        .join(" "),
      x.refs ?? "",
      x.note ?? "",
    ]);
    const csv = [header.join(","), ...rows.map((row) => row.map(csvCell).join(","))].join("\r\n");
    const name = `keelson-${slug(body.framework.short)}-${slug(scope.label)}-${String(body.scan?.finishedAt || "").slice(0, 10)}`;
    return new Response("﻿" + csv, { headers: { "content-type": "text/csv; charset=utf-8", "content-disposition": `attachment; filename="${name}.csv"` } });
  });
}
