// Compliance: a framework's requirements (ISO/IEC 27001, PCI DSS) with what Keelson's
// checks say about each in the accounts in view: failing, passing, undetermined
// (not enough permission, or nothing in view to check) or out of scope. It's an
// indication from what Keelson reads, never an assessment, and asks for nothing
// by hand.
// Framework, status, group and search live in the URL.

import { Fragment, useMemo, useState } from "react";
import { Badge, Button, Input, Link, Select, Table, Tabs, Tooltip, useKumoToastManager } from "@cloudflare/kumo";
import { ArrowSquareOutIcon, CaretDownIcon, CaretRightIcon, DownloadSimpleIcon, XIcon } from "@phosphor-icons/react";
import { useScopedApi, useShell } from "../shell.tsx";
import {
  CONTROL_STATUS_HINT,
  CONTROL_STATUS_LABEL,
  CONTROL_STATUSES,
  downloadFile,
  FRAMEWORK_IDS,
  num,
  plural,
  setParams,
  useLocation,
  withScope,
  type ComplianceResponse,
  type ControlCheck,
  type ControlResult,
  type ControlStatus,
  type FrameworkId,
} from "../lib.ts";
import { ListCard, NoRows, Page, PageState, PlatformMark, Row, SeverityBadge, Stat, Tag } from "../components/ui.tsx";

const TITLE = "Compliance";
const DESCRIPTION =
  "An indication of how the accounts in view stand against ISO/IEC 27001 and PCI DSS, from what Keelson's checks read. It says where Keelson can't tell, and which requirements are out of its scope. It isn't an assessment or a certificate.";
const ALL = "all";

const STATUS_BADGE: Record<ControlStatus, "error" | "warning" | "success" | "neutral" | "info"> = {
  failing: "error",
  passing: "success",
  no_permission: "warning",
  undetermined: "neutral",
  out_of_scope: "neutral",
};

export function ControlStatusBadge({ status }: { status: ControlStatus }) {
  return (
    <Tooltip content={CONTROL_STATUS_HINT[status]}>
      <span className="inline-flex">
        <Badge variant={STATUS_BADGE[status]} appearance="dot">
          {CONTROL_STATUS_LABEL[status]}
        </Badge>
      </span>
    </Tooltip>
  );
}

export function CompliancePage() {
  const { params } = useLocation();
  const { view } = useShell();
  const toasts = useKumoToastManager();
  const framework = (FRAMEWORK_IDS as readonly string[]).includes(params.get("framework") || "") ? (params.get("framework") as FrameworkId) : FRAMEWORK_IDS[0];
  const { data, error, loading, reload } = useScopedApi<ComplianceResponse>(`/api/compliance?framework=${framework}`);
  const status = params.get("status") || ALL;
  const group = params.get("group") || ALL;
  const q = params.get("q") || "";
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const controls = useMemo(() => {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean);
    return (data?.controls || []).filter(
      (c) =>
        (status === ALL || c.status === status) &&
        (group === ALL || c.group === group) &&
        words.every((w) => `${c.id} ${c.title} ${c.refs ?? ""} ${c.checks.map((k) => k.id).join(" ")}`.toLowerCase().includes(w)),
    );
  }, [data, status, group, q]);

  if (error || !data || data.framework.id !== framework)
    return <PageState title={TITLE} description={DESCRIPTION} error={error} loading={loading || !error} empty={false} retry={reload} />;
  if (!data.scan) return <PageState title={TITLE} description={DESCRIPTION} error={null} loading={false} empty />;

  const counts = data.counts;
  const decided = counts.failing + counts.passing;
  const exportCsv = async () => {
    try {
      await downloadFile(withScope(`/api/export/compliance.csv?framework=${framework}`, view.key), "compliance.csv");
    } catch (e) {
      toasts.add({ title: "Couldn't export", description: (e as Error).message, variant: "error" });
    }
  };
  const pick = (s: ControlStatus) => setParams({ status: status === s ? null : s });
  const flip = (id: string) => {
    const n = new Set(expanded);
    if (n.has(id)) n.delete(id);
    else n.add(id);
    setExpanded(n);
  };
  const filtered = status !== ALL || group !== ALL || !!q;

  return (
    <Page
      title={TITLE}
      description={DESCRIPTION}
      actions={
        <Button variant="secondary" icon={<DownloadSimpleIcon />} onClick={() => void exportCsv()}>
          Export CSV
        </Button>
      }
    >
      <div className="flex flex-col gap-3">
        <Tabs
          value={framework}
          onValueChange={(v: string) => setParams({ framework: v === FRAMEWORK_IDS[0] ? null : v, status: null, group: null, q: null })}
          tabs={data.frameworks.map((f) => ({ value: f.id, label: f.name }))}
        />
        <p className="m-0 max-w-4xl text-sm text-kumo-subtle">
          {data.framework.about} {data.framework.scopeNote}{" "}
          <Link href={data.framework.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1">
            The standard, from {data.framework.publisher} <ArrowSquareOutIcon aria-hidden />
          </Link>
        </p>
      </div>

      <Row>
        <Stat
          label="Failing"
          value={num(counts.failing)}
          note={`of ${plural(decided, "requirement")} Keelson could decide`}
          hint={CONTROL_STATUS_HINT.failing}
          onClick={() => pick("failing")}
        />
        <Stat
          label="Passing"
          value={num(counts.passing)}
          note="Every check behind it ran, nothing open"
          hint={CONTROL_STATUS_HINT.passing}
          onClick={() => pick("passing")}
        />
        <Stat
          label="Undetermined"
          value={num(counts.no_permission + counts.undetermined)}
          note={counts.no_permission ? `${num(counts.no_permission)} for lack of permission` : "Nothing in view to check"}
          hint="Keelson can't say yes or no yet: it doesn't have enough permission, or none of the checks apply to the accounts in view."
          onClick={() => pick(counts.no_permission ? "no_permission" : "undetermined")}
        />
        <Stat
          label="Out of scope"
          value={num(counts.out_of_scope)}
          note="Policies, people and premises"
          hint={CONTROL_STATUS_HINT.out_of_scope}
          onClick={() => pick("out_of_scope")}
        />
      </Row>

      <ListCard
        toolbar={
          <>
            <Input
              className="w-full min-w-48 sm:w-auto sm:flex-1"
              aria-label="Search requirements"
              placeholder="Search requirements or check IDs"
              value={q}
              onChange={(e) => setParams({ q: e.target.value || null })}
            />
            <Select
              aria-label="Status"
              className="min-w-36 flex-1 sm:w-44 sm:flex-none"
              value={status}
              onValueChange={(v) => setParams({ status: v === ALL ? null : String(v) })}
              items={{ [ALL]: "Every status", ...Object.fromEntries(CONTROL_STATUSES.map((s) => [s, `${CONTROL_STATUS_LABEL[s]} (${counts[s]})`])) }}
            />
            <Select
              aria-label={framework === "pci-dss" ? "Requirement" : "Theme"}
              className="min-w-36 flex-1 sm:w-64 sm:flex-none"
              value={group}
              onValueChange={(v) => setParams({ group: v === ALL ? null : String(v) })}
              items={{ [ALL]: framework === "pci-dss" ? "Every requirement" : "Every theme", ...Object.fromEntries(data.groups.map((g) => [g, g])) }}
            />
            {filtered && (
              <Button size="sm" variant="ghost" icon={<XIcon />} onClick={() => setParams({ status: null, group: null, q: null })}>
                Clear filters
              </Button>
            )}
          </>
        }
        footer={
          <>
            <span>
              {plural(controls.length, "requirement")}
              {filtered ? ` of ${num(data.controls.length)}` : ""}
            </span>
            <span>An indication from the latest scans and current triage; accepted risks don't fail a requirement.</span>
          </>
        }
      >
        {controls.length ? (
          <Table layout="auto">
            <Table.Header variant="compact">
              <Table.Row>
                <Table.Head className="w-10">
                  <span className="sr-only">Expand</span>
                </Table.Head>
                <Table.Head>Control</Table.Head>
                <Table.Head>Status</Table.Head>
                <Table.Head>Open findings</Table.Head>
                <Table.Head className="hidden md:table-cell">Checks behind it</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {data.groups.map((g) => {
                const rows = controls.filter((c) => c.group === g);
                if (!rows.length) return null;
                return (
                  <Fragment key={g}>
                    <Table.Row>
                      <Table.Cell colSpan={5} className="bg-kumo-recessed py-2 text-sm font-medium text-kumo-default">
                        {g}
                      </Table.Cell>
                    </Table.Row>
                    {rows.map((c) => (
                      <ControlRows key={c.id} control={c} open={expanded.has(c.id)} onFlip={() => flip(c.id)} />
                    ))}
                  </Fragment>
                );
              })}
            </Table.Body>
          </Table>
        ) : (
          <NoRows>No requirements match.</NoRows>
        )}
      </ListCard>
    </Page>
  );
}

function ControlRows({ control: c, open, onFlip }: { control: ControlResult; open: boolean; onFlip: () => void }) {
  const providers = [...new Set(c.checks.map((k) => k.provider))];
  return (
    <>
      <Table.Row className="cursor-pointer" onClick={onFlip}>
        <Table.Cell onClick={(e: React.MouseEvent) => e.stopPropagation()}>
          <Button
            variant="ghost"
            size="sm"
            shape="square"
            aria-expanded={open}
            aria-label={`${open ? "Collapse" : "Expand"} ${c.id}`}
            onClick={onFlip}
            icon={open ? <CaretDownIcon /> : <CaretRightIcon />}
          />
        </Table.Cell>
        <Table.Cell className="max-w-2xl">
          <div className="flex min-w-0 items-center gap-2">
            <Tag>{c.id}</Tag>
            <span className="truncate text-kumo-default">{c.title}</span>
          </div>
          {c.topics.length > 0 && <div className="mt-0.5 truncate text-sm text-kumo-subtle">{c.topics.map((t) => t.label).join(" · ")}</div>}
        </Table.Cell>
        <Table.Cell>
          <ControlStatusBadge status={c.status} />
        </Table.Cell>
        <Table.Cell className="whitespace-nowrap">
          {c.worst ? (
            <span className="inline-flex items-center gap-2">
              <SeverityBadge severity={c.worst} />
              <span className="tabular-nums text-kumo-default">{num(c.open)}</span>
            </span>
          ) : (
            <span className="text-kumo-subtle">{c.checks.length ? "None" : ""}</span>
          )}
        </Table.Cell>
        <Table.Cell className="hidden whitespace-nowrap text-kumo-subtle md:table-cell">
          {c.checks.length ? (
            <span className="inline-flex items-center gap-2">
              <span className="tabular-nums" title="Checks with something to evaluate in the accounts in view, of the checks behind this control">
                {num(c.checks.filter((k) => k.evaluated > 0 || k.open > 0).length)} of {plural(c.checks.length, "check")} ran
              </span>
              <PlatformMark provider={providers} />
            </span>
          ) : null}
        </Table.Cell>
      </Table.Row>
      {open && (
        <Table.Row>
          <Table.Cell colSpan={5} className="bg-kumo-recessed p-4">
            <ControlDetail control={c} />
          </Table.Cell>
        </Table.Row>
      )}
    </>
  );
}

function ControlDetail({ control: c }: { control: ControlResult }) {
  return (
    <div className="flex flex-col gap-3 text-sm">
      {(c.note || c.refs) && (
        <div className="flex flex-col gap-1">
          {c.refs && (
            <p className="m-0">
              <span className="font-medium text-kumo-default">Keelson's checks cover: </span>
              <span className="text-kumo-default">{c.refs}</span>
            </p>
          )}
          {c.note && <p className="m-0 text-kumo-default">{c.note}</p>}
        </div>
      )}
      {c.topics.length > 0 && (
        <ul className="m-0 flex list-none flex-col gap-1 p-0">
          {c.topics.map((t) => (
            <li key={t.id}>
              <span className="font-medium text-kumo-default">{t.label}: </span>
              <span className="text-kumo-subtle">{t.about}</span>
            </li>
          ))}
        </ul>
      )}
      {c.checks.length > 0 ? (
        <div className="overflow-hidden rounded-lg bg-kumo-base ring ring-kumo-hairline">
          <Table layout="auto">
            <Table.Header variant="compact">
              <Table.Row>
                <Table.Head>Check</Table.Head>
                <Table.Head>Result in view</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {[...c.checks].sort(byResult).map((k) => (
                <Table.Row key={k.id}>
                  <Table.Cell className="max-w-xl">
                    <div className="flex min-w-0 items-center gap-2">
                      <PlatformMark provider={k.provider} spans={k.spans} />
                      <Tag>{k.id}</Tag>
                      <span className="truncate text-kumo-default">{k.title}</span>
                    </div>
                  </Table.Cell>
                  <Table.Cell className="whitespace-nowrap">
                    <CheckResult check={k} />
                  </Table.Cell>
                </Table.Row>
              ))}
            </Table.Body>
          </Table>
        </div>
      ) : (
        c.status !== "out_of_scope" && (
          <p className="m-0 text-kumo-subtle">Undetermined: none of the checks behind this requirement are for the platforms in view.</p>
        )
      )}
    </div>
  );
}

// Open findings first, then what couldn't run, then passes, then checks with nothing to evaluate.
const rank = (k: ControlCheck) => (k.open ? 0 : k.skipped || k.disabled ? 1 : k.evaluated ? 2 : 3);
const byResult = (a: ControlCheck, b: ControlCheck) => rank(a) - rank(b) || a.id.localeCompare(b.id);

function CheckResult({ check: k }: { check: ControlCheck }) {
  const accepted = k.accepted > 0 && (
    <Link href={`/findings?check=${encodeURIComponent(k.id)}&status=accepted`} className="ml-2">
      {num(k.accepted)} accepted
    </Link>
  );
  if (k.open)
    return (
      <>
        <Link href={`/findings?check=${encodeURIComponent(k.id)}`} className="text-kumo-danger">
          {plural(k.open, "open finding")}
        </Link>
        {accepted}
      </>
    );
  if (k.disabled) return <span className="text-kumo-warning">Turned off on the Checks page</span>;
  if (k.skipped) return <span className="text-kumo-warning">Not enough permission to run in every account</span>;
  if (k.evaluated)
    return (
      <span className="text-kumo-default">
        Nothing open on {plural(k.evaluated, "resource")} checked
        {accepted}
      </span>
    );
  return <span className="text-kumo-subtle">Nothing to check</span>;
}
