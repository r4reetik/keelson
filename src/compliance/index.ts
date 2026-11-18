// Assesses a framework's controls against the latest scans in a view. A control
// takes every check its topics and single checks name, keeps those of the
// platforms in view, and reads their results: open findings fail it; checks
// that couldn't read what they need leave it without enough permission; a
// control with no check is out of scope. It's an indication from what Keelson
// reads, never an assessment, and nothing is recorded by hand. Statuses aren't
// stored: they follow the latest scans and current triage, like the score.

import { CHECK_BY_ID, providerOfCheck, SC_CLASSES } from "../providers/catalog.ts";
import { SEVERITY_WEIGHT, type Severity } from "../shared/severity.ts";
import { CONTROL_STATUSES, type ControlCheck, type ControlResult, type ControlStatus, type FrameworkId, type TopicId } from "../shared/compliance.ts";
import type { Coverage, Finding } from "../shared/api.ts";
import type { ProviderId } from "../shared/providers.ts";
import { ISO27001 } from "./iso27001.ts";
import { PCI_DSS } from "./pci-dss.ts";
import { TOPICS } from "./topics.ts";
import type { ControlDef, Framework } from "./types.ts";

export type { Framework, ControlDef };
export { TOPICS };

export const FRAMEWORKS: Record<FrameworkId, Framework> = { iso27001: ISO27001, "pci-dss": PCI_DSS };

/** Every check a control names, directly or through its topics, in a stable order. */
export function checksOf(control: ControlDef): string[] {
  return [...new Set([...(control.topics ?? []).flatMap((t) => TOPICS[t].checks), ...(control.checks ?? [])])];
}

/** The controls of every framework that a check gives evidence for, e.g. { iso27001: ["8.5"], "pci-dss": ["8.4"] }. */
export function controlsOfCheck(checkId: string): Partial<Record<FrameworkId, string[]>> {
  const out: Partial<Record<FrameworkId, string[]>> = {};
  for (const [id, fw] of Object.entries(FRAMEWORKS) as [FrameworkId, Framework][]) {
    const hits = fw.controls.filter((c) => checksOf(c).includes(checkId)).map((c) => c.id);
    if (hits.length) out[id] = hits;
  }
  return out;
}

export interface AssessInput {
  /** Platforms of the accounts in view that have a scan. */
  providers: Set<ProviderId>;
  /** Per-check counts summed over the latest scans in view. */
  stats: Record<string, { evaluated: number; failed: number }>;
  /** Each scan's coverage; checks named in a failed source's skippedChecks couldn't run. */
  coverage: Coverage[][];
  /** Findings in view with current triage. */
  findings: Finding[];
  disabled: Set<string>;
}

const checkTitle = (id: string) => CHECK_BY_ID[id]?.title ?? SC_CLASSES[id.slice(3)]?.title ?? id;

export function assess(fw: Framework, input: AssessInput): { controls: ControlResult[]; counts: Record<ControlStatus, number> } {
  const skipped = new Set(input.coverage.flatMap((cov) => cov.filter((c) => !c.ok).flatMap((c) => c.skippedChecks ?? [])));
  const byCheck = new Map<string, Finding[]>();
  for (const f of input.findings) (byCheck.get(f.checkId) ?? byCheck.set(f.checkId, []).get(f.checkId)!).push(f);

  const controls = fw.controls.map((def): ControlResult => {
    const mapped = checksOf(def);
    const checks = mapped
      .filter((id) => input.providers.has(providerOfCheck(id)))
      .map((id): ControlCheck => {
        const def = CHECK_BY_ID[id];
        const found = byCheck.get(id) ?? [];
        return {
          id,
          provider: providerOfCheck(id),
          spans: def?.spans ?? [],
          title: checkTitle(id),
          severity: def?.severity ?? found[0]?.severity ?? "medium",
          evaluated: input.stats[id]?.evaluated ?? 0,
          open: found.filter((f) => !f.settled).length,
          accepted: found.filter((f) => f.status === "accepted").length,
          skipped: skipped.has(id),
          disabled: input.disabled.has(id),
        };
      });
    const open = input.findings.filter((f) => !f.settled && checks.some((c) => c.id === f.checkId));
    const worst = open.reduce<Severity | null>((w, f) => (!w || SEVERITY_WEIGHT[f.severity] > SEVERITY_WEIGHT[w] ? f.severity : w), null);
    const ran = checks.filter((c) => c.evaluated > 0 || c.open > 0);
    // An open finding is a "no" whatever else couldn't run; a "yes" needs every check that applies to have run.
    const status: ControlStatus = !mapped.length
      ? "out_of_scope"
      : open.length
        ? "failing"
        : checks.some((c) => c.skipped)
          ? "no_permission"
          : !ran.length || checks.some((c) => c.disabled)
            ? "undetermined"
            : "passing";
    return {
      id: def.id,
      title: def.title,
      group: def.group,
      status,
      refs: def.refs ?? null,
      note: def.note ?? null,
      topics: (def.topics ?? []).map((t: TopicId) => ({ id: t, label: TOPICS[t].label, about: TOPICS[t].about })),
      checks,
      open: open.length,
      accepted: checks.reduce((s, c) => s + c.accepted, 0),
      worst,
    };
  });
  const counts = Object.fromEntries(CONTROL_STATUSES.map((s) => [s, controls.filter((c) => c.status === s).length])) as Record<ControlStatus, number>;
  return { controls, counts };
}
