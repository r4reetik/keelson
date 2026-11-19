// The checks every platform with a registry runs over the images it scanned:
// known exploited vulnerabilities, critical and high ones with a fix, an operating
// system past its end of life, and credentials stored in the image. One set of
// definitions, instantiated per platform with its own ID prefix (AIM for AWS, LIM
// for Alibaba Cloud, GIM for GitHub), since check IDs carry their platform.
//
// A finding is one per image repository, whatever the tag, so triage survives the
// next build. Vulnerabilities are findings only for images in use: run by a
// workload Keelson reads, or pulled lately. How exposed the workload is sets the
// severity, so the same vulnerability is rated higher in a service the internet
// reaches than in one inside the network. Stored images show on the Images page
// without findings; a credential in an image is a finding wherever the image is.

import type { CheckMeta, Report } from "./checks/define.ts";
import { githubRepoOf, usageOf, runningIn, type ImageHighlights } from "./images.ts";
import type { Confidence, Severity } from "./types.ts";
import type { EvidenceStep } from "../shared/api.ts";
import {
  buildMatches,
  moreInUse,
  shortDigest,
  vulnText,
  type ImageBuildLink,
  type ImageBuildRef,
  type ImageEntry,
  type ImageScan,
  type ImagesSnapshot,
  type ImageUse,
  type ImageVuln,
  type WorkloadLink,
} from "../shared/images.ts";

export type ImageCheckId<P extends string> = `${P}-001` | `${P}-002` | `${P}-003` | `${P}-004`;

const REBUILD =
  "1. Rebuild the image with the fixed versions: update the base image for operating system packages, and the lock file for the application's own dependencies (the Images page says which is which). 2. Push it and deploy the workloads that run it. 3. Where there is no fix yet, limit who can reach the workload until there is.";

/**
 * The image checks' metadata for one platform. `images` are the sources that list and scan images; `kev` is CISA's list;
 * `docs` are the platform's own pages on scanning images and on keeping secrets out of them.
 */
export function imageCheckMeta<P extends string, S extends string>(
  prefix: P,
  requires: { images: S[]; kev: S[] },
  docs: { scanning: string; secrets: string },
): Record<ImageCheckId<P>, CheckMeta<S>> {
  return {
    [`${prefix}-001`]: {
      category: "Supply chain",
      severity: "critical",
      docs: docs.scanning,
      requires: [...requires.images, ...requires.kev],
      attackPath: true,
      title: "Image in use has a vulnerability attackers are exploiting",
      why: "A package in the image has a vulnerability on CISA's list of known exploited vulnerabilities (cisa.gov/known-exploited-vulnerabilities-catalog), and something runs the image. Attackers already have working exploits for it, and a service the internet reaches is where they try them first.",
      fix: REBUILD,
    },
    [`${prefix}-002`]: {
      category: "Supply chain",
      severity: "high",
      docs: docs.scanning,
      requires: requires.images,
      title: "Image in use has critical or high vulnerabilities with a fix",
      why: "The image runs with packages that have known critical or high vulnerabilities, and fixed versions exist. Each rebuild that doesn't pick them up leaves a known way in for longer.",
      fix: REBUILD,
    },
    [`${prefix}-003`]: {
      category: "Supply chain",
      severity: "medium",
      docs: docs.scanning,
      requires: requires.images,
      title: "Image in use is built on an operating system or runtime past its end of life",
      why: "The operating system release in the image, or the release line of the runtime it is built around (Node.js, Python, nginx…), no longer gets security fixes. Vulnerabilities found in it from now on stay open, and scanners stop reporting them for it.",
      fix: "Change the Dockerfile's FROM line to a release that is still supported (or to the newest tag of the same base image), rebuild, test and deploy.",
    },
    [`${prefix}-004`]: {
      category: "Secrets",
      severity: "high",
      docs: docs.secrets,
      requires: requires.images,
      title: "Credential stored inside an image",
      why: "Anyone who can pull the image can read the credential, from every copy of the image in every registry and cache, for as long as those exist. Deleting the file in a later layer doesn't remove it from the earlier one.",
      fix: "1. Rotate the credential: treat it as leaked. 2. Remove it from the build: pass secrets at run time (the platform's secret store) or with a build secret mount, and add the file to .dockerignore. 3. Rebuild, deploy, and delete the old image tags.",
    },
  } as Record<ImageCheckId<P>, CheckMeta<S>>;
}

export interface ImageCheckInput {
  snapshot: ImagesSnapshot;
  scans: Map<string, ImageHighlights>;
  /** Every workload known in the entity: the account's own and its siblings'. */
  workloads: WorkloadLink[];
  /** Images the entity's GitHub repositories build, when a GitHub account is connected. */
  builds: ImageBuildLink[];
  /** The entity's GitHub repositories ("org/name"), to name an image's builder by its name when nothing else does. */
  repos?: string[];
  now: number;
  /** How a finding names an image's repository: its location, its name and its page in the platform's console. */
  where: (e: ImageEntry) => { zone: string | null; resource: string; link: string | null };
}

const lower = (s: Severity): Severity => (s === "critical" ? "high" : s === "high" ? "medium" : "low");
const tagOf = (e: ImageEntry) => e.tags[0] ?? shortDigest(e.digest);
const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** "ECS service web (cluster main, eu-west-1), which the internet reaches through load balancer web-alb". */
function workloadText(w: WorkloadLink): string {
  const place = [w.group, w.region, w.account].filter(Boolean).join(", ");
  const reach = w.internet === true ? `, which the internet reaches${w.via.length ? ` through ${w.via[0]}` : ""}` : "";
  return `${w.kind} ${w.name}${place ? ` (${place})` : ""}${reach}`;
}

function usageText(use: ImageUse, uses: { workload: WorkloadLink }[], e: ImageEntry): string {
  if (uses.length) {
    const seen = new Set<WorkloadLink>();
    const list = uses.map((u) => u.workload).filter((w) => !seen.has(w) && seen.add(w));
    const first = [...list].sort((a, b) => Number(b.internet === true) - Number(a.internet === true))[0];
    return `Runs in ${workloadText(first)}${list.length > 1 ? ` and ${plural(list.length - 1, "other workload", "other workloads")}` : ""}.`;
  }
  if (use === "pulled")
    return `Pulled on ${String(e.pulledAt).slice(0, 10)}, by something Keelson doesn't read (a Kubernetes cluster or an instance, for example).`;
  return "";
}

const packageText = (v: ImageVuln) => `${v.pkg} ${v.version}${v.fixedIn ? ` → ${v.fixedIn}` : ""} (${v.id})`;

type BuildHow = ImageBuildRef["how"];
/** Words in an image repository's name that say where it is deployed, not what it is: "web-prod" and "staging/web" are built from "web". */
const STAGE = "prod|production|staging|stage|stg|dev|develop|uat|qa|preprod|test|sandbox";

/**
 * Who builds an image: its own label, the GitHub package's repository, or a workflow that pushes an image of its name.
 * When none of those says, a repository of the entity with the image repository's own name is taken as the builder
 * (pipelines outside GitHub Actions leave no other trace), and only when exactly one has that name. `repos` are the
 * entity's repositories ("org/name").
 */
export function buildersOf(
  e: ImageEntry,
  scan: Pick<ImageScan, "source"> | null,
  builds: ImageBuildLink[],
  repos: string[] = [],
): { repo: string; how: BuildHow; workflow: string | null }[] {
  const out: { repo: string; how: BuildHow; workflow: string | null }[] = [];
  const add = (repo: string, how: BuildHow, workflow: string | null = null) => {
    if (!out.some((b) => b.repo === repo)) out.push({ repo, how, workflow });
  };
  const labelled = githubRepoOf(scan?.source ?? e.summary?.source ?? null);
  if (labelled) add(labelled, "label");
  if (e.linkedRepo) add(e.linkedRepo.toLowerCase(), "package");
  for (const b of builds) if (buildMatches(b, e)) add(b.repo, "workflow", b.workflow);
  if (!out.length && repos.length) {
    const tail = e.repository.split("/").pop() ?? "";
    const names = new Set([tail, tail.replace(new RegExp(`[-_.](${STAGE})$`), ""), tail.replace(new RegExp(`^(${STAGE})[-_.]`), "")]);
    const same = repos.filter((r) => names.has(r.split("/")[1]?.toLowerCase() ?? ""));
    if (same.length === 1) add(same[0].toLowerCase(), "name");
  }
  return out;
}

/** Runs the image checks over what a scan found. Images that weren't scanned are neither passed nor failed. */
export function reportImages<P extends string>(prefix: P, i: ImageCheckInput, report: Report<ImageCheckId<P>>): void {
  const id = (n: 1 | 2 | 3 | 4) => `${prefix}-00${n}` as ImageCheckId<P>;
  // One finding per repository: its images are judged together, the most exposed deciding the severity.
  const groups = new Map<string, { at: ReturnType<ImageCheckInput["where"]>; images: ImageEntry[] }>();
  for (const e of i.snapshot.images) {
    if (!e.summary) continue;
    const at = i.where(e);
    const key = `${at.zone ?? ""}|${at.resource}`;
    const g = groups.get(key) ?? { at, images: [] };
    g.images.push(e);
    groups.set(key, g);
  }
  for (const { at, images } of groups.values()) {
    const judged = images.map((e) => {
      const uses = runningIn(e, i.workloads);
      const scan = i.scans.get(e.key) ?? null;
      return { e, uses, use: usageOf(e, uses, i.now), scan, s: e.summary! };
    });
    const inUse = judged.filter((j) => j.use !== "stored");
    const chain = (j: (typeof judged)[number], what: string): EvidenceStep[] => {
      const builders = buildersOf(j.e, j.scan, i.builds, i.repos);
      return [
        { label: "Image", value: `${at.resource}:${tagOf(j.e)}${j.e.digest ? ` (${shortDigest(j.e.digest)})` : ""}, in ${j.e.registry}` },
        { label: "Found", value: what },
        ...(usageText(j.use, j.uses, j.e) ? [{ label: "In use", value: usageText(j.use, j.uses, j.e) }] : []),
        ...(builders.length
          ? [
              {
                label: "Built by",
                value: builders
                  .map(
                    (b) =>
                      `${b.repo}${b.workflow ? ` (${b.workflow})` : b.how === "label" ? " (the image's source label)" : b.how === "name" ? " (a repository of the same name)" : ""}`,
                  )
                  .join(", "),
              },
            ]
          : []),
      ];
    };
    const evidence = (list: typeof judged, what: (j: (typeof judged)[number]) => string) => ({
      chain: chain(list[0], what(list[0])),
      // Names the images for the Images page, which shows everything else about them.
      image: { images: list.map((j) => ({ key: j.e.key, registry: j.e.registry, repository: j.e.repository, tag: j.e.tags[0] ?? null, digest: j.e.digest })) },
    });
    const worstUse = (list: typeof judged) => list.reduce<ImageUse>((u, j) => moreInUse(u, j.use), "stored");
    const also = (list: typeof judged) => (list.length > 1 ? ` ${plural(list.length - 1, "other tag has", "other tags have")} the same.` : "");

    if (inUse.length) {
      // Known exploited vulnerabilities.
      const exploited = inUse.filter((j) => j.s.exploited.length);
      if (exploited.length) {
        const use = worstUse(exploited);
        const j = exploited.find((x) => x.use === use)!;
        const hits = (j.scan?.vulns ?? []).filter((v) => v.kev);
        const what = `${plural(j.s.exploited.length, "known exploited vulnerability", "known exploited vulnerabilities")}: ${hits.slice(0, 3).map(packageText).join(", ") || j.s.exploited.slice(0, 3).join(", ")}`;
        report(id(1), {
          ...at,
          pass: false,
          severity: use === "internet" ? "critical" : "high",
          confidence: use === "pulled" ? "likely" : undefined,
          detail: `${tagOf(j.e)} has ${what}. ${usageText(j.use, j.uses, j.e)}${also(exploited)}`.trim(),
          evidence: evidence(exploited, () => what),
        });
      } else report(id(1), { ...at, pass: true });

      // Critical and high vulnerabilities that a rebuild would fix.
      const fixable = inUse.filter((j) => j.s.fixable.critical + j.s.fixable.high > 0);
      if (fixable.length) {
        const use = worstUse(fixable);
        const j = [...fixable].sort((a, b) => b.s.fixable.critical - a.s.fixable.critical).find((x) => x.use === use)!;
        const base: Severity = fixable.some((x) => x.s.fixable.critical > 0) ? "high" : "medium";
        const top = (j.scan?.vulns ?? []).filter((v) => v.fixedIn && (v.severity === "critical" || v.severity === "high")).slice(0, 3);
        const what = `${vulnText(j.s.fixable)} ${j.s.fixable.critical + j.s.fixable.high === 1 ? "vulnerability" : "vulnerabilities"} with a fix${top.length ? `: ${top.map(packageText).join(", ")}` : ""}`;
        report(id(2), {
          ...at,
          pass: false,
          severity: use === "internet" ? base : lower(base),
          confidence: use === "pulled" ? "likely" : undefined,
          detail: `${tagOf(j.e)} has ${what}. ${usageText(j.use, j.uses, j.e)}${also(fixable)}`.trim(),
          evidence: evidence(fixable, () => what),
        });
      } else report(id(2), { ...at, pass: true });

      // An operating system release, or a runtime's release line, that no longer gets fixes.
      const ended = (j: (typeof judged)[number]) => [
        ...(j.s.eol && j.s.os ? [j.s.os] : []),
        ...(j.s.runtimes ?? []).filter((r) => r.eol).map((r) => `${r.name} ${r.version}`),
      ];
      const known = inUse.filter((j) => j.s.os || j.s.runtimes?.some((r) => r.eol != null));
      const eol = known.filter((j) => ended(j).length);
      if (eol.length) {
        const use = worstUse(eol);
        const j = eol.find((x) => x.use === use)!;
        const names = ended(j).join(" and ");
        const what = `${names} no longer ${ended(j).length === 1 ? "gets" : "get"} security fixes`;
        report(id(3), {
          ...at,
          pass: false,
          severity: use === "internet" ? "medium" : "low",
          detail:
            `${tagOf(j.e)} is built on ${names}, which no longer ${ended(j).length === 1 ? "gets" : "get"} security fixes. ${usageText(j.use, j.uses, j.e)}${also(eol)}`.trim(),
          evidence: evidence(eol, () => what),
        });
      } else if (known.length) report(id(3), { ...at, pass: true });
    }

    // Credentials, wherever the image is: stored is enough for someone to pull it.
    const leaking = judged.filter((j) => j.s.secrets > 0);
    if (leaking.length) {
      const j = leaking.find((x) => x.scan?.secrets.some((s) => !s.likely)) ?? leaking[0];
      const found = j.scan?.secrets ?? [];
      const certain = found.filter((s) => !s.likely);
      const shown = (certain.length ? certain : found).slice(0, 3);
      const isPublic = leaking.some((x) => x.e.public === true && x.e.own);
      const what = shown.length ? shown.map((s) => `${s.kind} in ${s.where}`).join("; ") : plural(j.s.secrets, "credential", "credentials");
      const confidence: Confidence | undefined = certain.length ? undefined : "likely";
      report(id(4), {
        ...at,
        pass: false,
        severity: !certain.length ? "medium" : isPublic ? "critical" : "high",
        confidence,
        detail: `${tagOf(j.e)} holds ${what}${found.length > shown.length ? ` and ${found.length - shown.length} more` : ""}.${isPublic ? " Anyone can pull this image." : ""}${also(leaking)}`,
        evidence: evidence(leaking, () => what),
      });
    } else report(id(4), { ...at, pass: true });
  }
}
