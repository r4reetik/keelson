// What a dependency finding's evidence shows, and the pieces the Repository page
// shares with it: which version to upgrade to, where in the repository the
// package is used (each part of a monorepo, directly or through another
// package), and each vulnerability with how likely it is to be exploited.

import type { ReactNode } from "react";
import { Badge, Link, Table, Tooltip } from "@cloudflare/kumo";
import { ArrowRightIcon, ArrowSquareOutIcon, FireIcon, ShieldCheckIcon } from "@phosphor-icons/react";
import {
  plural,
  type ActionsEvidence,
  type DependencyEvidence,
  type EvidenceVuln,
  type Finding,
  type LicenseEvidence,
  type LockEvidence,
  type Severity,
} from "../lib.ts";
import { SeverityBadge } from "./ui.tsx";
import { MoreNames } from "./full-list.tsx";

/** A vulnerability's severity as a badge; Grype's "unknown" reads as Info. */
export const VulnSeverity = ({ severity }: { severity: string }) => (
  <SeverityBadge severity={(["critical", "high", "medium", "low"].includes(severity) ? severity : "info") as Severity} />
);

/** "34%", or "<1%" for the long tail: EPSS as people read it. */
export const epssText = (epss: number | null) => (epss == null ? "—" : epss < 0.01 ? "<1%" : `${Math.round(epss * 100)}%`);

/** Known to be exploited, and used by ransomware: the two facts that should jump out. */
export function ExploitedBadges({ kev, ransomware }: { kev: boolean; ransomware?: boolean }) {
  return (
    <>
      {kev && (
        <Tooltip content="In CISA's catalog of known exploited vulnerabilities: attackers are using it">
          <Badge variant="red" icon={<FireIcon weight="fill" />}>
            Exploited
          </Badge>
        </Tooltip>
      )}
      {ransomware && <Badge variant="error">Ransomware</Badge>}
    </>
  );
}

/** A table of vulnerabilities: ID and summary, severity, CVSS, EPSS, whether it's exploited, and the version that fixes it. */
export function VulnTable({
  vulns,
  showVersion,
}: {
  vulns: (Omit<EvidenceVuln, "version" | "dependabot"> & { version?: string; dependabot?: boolean })[];
  showVersion?: boolean;
}) {
  return (
    <div className="overflow-x-auto rounded-md ring ring-kumo-line">
      <Table layout="auto">
        <Table.Header variant="compact">
          <Table.Row>
            <Table.Head>Vulnerability</Table.Head>
            <Table.Head className="whitespace-nowrap">Severity</Table.Head>
            {showVersion && <Table.Head className="whitespace-nowrap">Version</Table.Head>}
            <Table.Head className="whitespace-nowrap">
              <Tooltip content="FIRST's EPSS: how likely it is to be exploited in the next 30 days">
                <span>Exploit chance</span>
              </Tooltip>
            </Table.Head>
            <Table.Head className="whitespace-nowrap">Fixed in</Table.Head>
          </Table.Row>
        </Table.Header>
        <Table.Body>
          {vulns.map((v) => (
            <Table.Row key={`${v.id}-${v.version ?? ""}`}>
              <Table.Cell className="min-w-64 align-top">
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  {v.url ? (
                    <Link href={v.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 font-mono text-xs">
                      {v.id} <ArrowSquareOutIcon />
                    </Link>
                  ) : (
                    <span className="font-mono text-xs">{v.id}</span>
                  )}
                  {v.aliases.slice(0, 2).map((a) => (
                    <span key={a} className="font-mono text-xs text-kumo-subtle">
                      {a}
                    </span>
                  ))}
                  <span className="text-xs">
                    <MoreNames names={v.aliases} shown={2} title={`Other names of ${v.id}`} noun={["ID", "IDs"]} />
                  </span>
                  <ExploitedBadges kev={v.kev} ransomware={v.ransomware} />
                  {v.cpeOnly && (
                    <Tooltip content="Matched by product name (CPE) rather than the package's own ecosystem: check it applies">
                      <Badge variant="outline">Likely</Badge>
                    </Tooltip>
                  )}
                  {v.dependabot && (
                    <Tooltip content="Dependabot has an open alert for it in this repository">
                      <Badge variant="neutral">Dependabot</Badge>
                    </Tooltip>
                  )}
                </div>
                {v.summary && <p className="mt-1 line-clamp-2 max-w-2xl text-xs text-kumo-subtle">{v.summary}</p>}
              </Table.Cell>
              <Table.Cell className="whitespace-nowrap align-top">
                <span className="inline-flex items-center gap-2">
                  <VulnSeverity severity={v.severity} />
                  {v.cvss != null && <span className="text-xs tabular-nums text-kumo-subtle">CVSS {v.cvss.toFixed(1)}</span>}
                </span>
              </Table.Cell>
              {showVersion && <Table.Cell className="whitespace-nowrap align-top font-mono text-xs">{v.version}</Table.Cell>}
              <Table.Cell className="whitespace-nowrap align-top tabular-nums">{epssText(v.epss)}</Table.Cell>
              <Table.Cell className="whitespace-nowrap align-top">
                {v.fixedIn ? (
                  <span className="font-mono text-xs">{v.fixedIn}</span>
                ) : (
                  <span className="text-kumo-subtle">{v.state === "wont-fix" ? "Won't be fixed" : "No fix yet"}</span>
                )}
              </Table.Cell>
            </Table.Row>
          ))}
        </Table.Body>
      </Table>
    </div>
  );
}

/** Where a package is used: each part, directly or through another package, and whether only for development. */
export function UsedBy({ usages }: { usages: { label: string; direct: boolean; dev: boolean }[] }) {
  if (!usages.length) return <span className="text-kumo-subtle">Not related to a project</span>;
  return (
    <ul className="flex flex-col gap-1">
      {usages.map((u) => (
        <li key={u.label} className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-xs text-kumo-default">{u.label}</span>
          <span className="text-xs text-kumo-subtle">{u.direct ? "direct dependency" : "through another package"}</span>
          {u.dev && <Badge variant="outline">Development</Badge>}
        </li>
      ))}
    </ul>
  );
}

function Section({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <div className="mb-1 text-xs font-medium uppercase tracking-wide text-kumo-subtle">{label}</div>
      <div className="text-kumo-default">{children}</div>
    </div>
  );
}

const DEPENDABOT: Record<NonNullable<DependencyEvidence["dependabot"]>, string> = {
  off: "Dependabot alerts are off in this repository, so GitHub isn't telling anyone about this.",
  alerting: "Dependabot reports this package too.",
  silent: "Dependabot alerts are on, but Dependabot has no open alert for this package.",
};

/** The evidence of a vulnerable or malicious package. */
function Dependency({ d, f }: { d: DependencyEvidence; f: Finding }) {
  const repoHref = f.zone ? `/repositories/${encodeURIComponent(f.accountId)}/${encodeURIComponent(f.zone)}` : null;
  const malicious = d.vulnerabilities.some((v) => [v.id, ...v.aliases].some((id) => id.startsWith("MAL-")));
  return (
    <>
      <Section label={malicious ? "What to do" : "Upgrade"}>
        <ul className="flex flex-col gap-1.5">
          {d.versions.map((v) => (
            <li key={v.version} className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-sm">
                {d.name} {v.version}
              </span>
              {malicious ? (
                <span>remove it, then rotate what it could reach</span>
              ) : v.upgrade ? (
                <>
                  <ArrowRightIcon className="text-kumo-subtle" />
                  <span className="font-mono text-sm font-medium">{v.upgrade}</span>
                  {v.upgradeAll && v.upgradeAll !== v.upgrade ? (
                    <span className="text-kumo-subtle">
                      ({v.upgradeAll} fixes all {v.vulns} known)
                    </span>
                  ) : v.vulns > 1 ? (
                    <span className="text-kumo-subtle">fixes all {v.vulns} known vulnerabilities</span>
                  ) : null}
                </>
              ) : (
                <span className="text-kumo-subtle">no fixed version yet</span>
              )}
              {v.devOnly && <Badge variant="outline">Development only</Badge>}
            </li>
          ))}
        </ul>
      </Section>
      <Section label="Where it's used">
        <div className="flex flex-col gap-3">
          {d.versions.map((v) => (
            <div key={v.version}>
              {d.versions.length > 1 && <div className="mb-1 font-mono text-xs text-kumo-subtle">{v.version}</div>}
              <UsedBy usages={v.usedBy} />
              <p className="mt-1 text-xs text-kumo-subtle">Recorded in {v.locations.join(", ")}</p>
            </div>
          ))}
        </div>
      </Section>
      <Section label={plural(d.vulnerabilities.length + d.more, "vulnerability", "vulnerabilities")}>
        <VulnTable vulns={d.vulnerabilities} showVersion={d.versions.length > 1} />
        {d.more > 0 && <p className="mt-2 text-xs text-kumo-subtle">And {plural(d.more, "more", "more")}, lower in risk.</p>}
      </Section>
      <p className="flex flex-wrap items-center gap-x-4 gap-y-1 text-kumo-subtle">
        {d.dependabot && (
          <span className="inline-flex items-center gap-1.5">
            <ShieldCheckIcon /> {DEPENDABOT[d.dependabot]}
          </span>
        )}
        {repoHref && (
          <Link variant="plain" href={repoHref}>
            Every dependency of {f.zone}
          </Link>
        )}
      </p>
    </>
  );
}

function Actions({ list }: { list: ActionsEvidence[] }) {
  return (
    <Section label="Actions used by a tag">
      <ul className="flex flex-col gap-1">
        {list.map((a) => (
          <li key={`${a.uses}-${a.workflow}`} className="flex flex-wrap items-baseline gap-x-2">
            <span className="font-mono text-sm">{a.uses}</span>
            <span className="text-xs text-kumo-subtle">in {a.workflow}</span>
          </li>
        ))}
      </ul>
    </Section>
  );
}

function Lock({ l }: { l: LockEvidence }) {
  return (
    <Section label="Installed without a pinned version">
      <p className="flex flex-wrap gap-x-2 gap-y-1">
        {l.unpinned.map((n) => (
          <span key={n} className="font-mono text-sm">
            {n}
          </span>
        ))}
      </p>
      <p className="mt-1 text-xs text-kumo-subtle">From {l.files.join(", ")}</p>
    </Section>
  );
}

function License({ l }: { l: LicenseEvidence }) {
  return (
    <Section label="Licenses">
      <ul className="flex flex-col gap-1">
        {l.licenses.map((x) => (
          <li key={`${x.name ?? ""}@${x.version}`} className="flex flex-wrap items-baseline gap-x-2">
            <span className="font-mono text-sm">
              {x.name ? `${x.name} ` : ""}
              {x.version}
            </span>
            <span>{x.licenses.join(", ") || "unknown"}</span>
            {x.usedBy.length > 0 && <span className="text-xs text-kumo-subtle">used by {x.usedBy.join(", ")}</span>}
          </li>
        ))}
      </ul>
      <p className="mt-1 text-xs text-kumo-subtle">
        {l.repositoryLicense ? `The repository is under ${l.repositoryLicense}.` : "GitHub doesn't detect a license for the repository."}
      </p>
    </Section>
  );
}

/** Evidence keys this file shows, so the raw view leaves them out. */
export const DEPENDENCY_EVIDENCE_KEYS = ["dependency", "actions", "lock", "license"];

/** The views for a finding's dependency evidence, or null when it has none. */
export function DependencyEvidenceView({ f }: { f: Finding }) {
  const e = f.evidence;
  if (!e) return null;
  const d = e.dependency as DependencyEvidence | undefined;
  const actions = e.actions as ActionsEvidence[] | undefined;
  const lock = e.lock as LockEvidence | undefined;
  const license = e.license as LicenseEvidence | undefined;
  if (!d && !actions && !lock && !license) return null;
  return (
    <>
      {d && <Dependency d={d} f={f} />}
      {actions && <Actions list={actions} />}
      {lock && <Lock l={lock} />}
      {license && <License l={license} />}
    </>
  );
}
