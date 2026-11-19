// Container images across the registries in view (Amazon ECR, Alibaba Cloud
// Container Registry, GitHub Container Registry) and the images workloads run from
// public registries, as Trivy scanned them. Four tabs over filters kept in the
// URL: images (what's in each, where it runs, who builds it), running (each
// workload with its images and how the internet reaches it), vulnerabilities, and
// components: the inventory of every package, runtime and operating system the
// images are made of, at each version.
//
// Every tab is served a page of 50 rows at a time. A registry has hundreds of
// images and thousands of components: drawing them all at once, and again each
// time the scan status refreshed, is what made this page slow.

import { memo, useEffect, useState, type ReactNode } from "react";
import { Badge, Banner, Button, DropdownMenu, Input, Link, Pagination, Select, Table, Tabs, Tooltip, useKumoToastManager } from "@cloudflare/kumo";
import { CaretDownIcon, DownloadSimpleIcon, GlobeIcon, KeyIcon, WarningIcon, XIcon } from "@phosphor-icons/react";
import {
  api,
  COMPONENT_KIND_LABEL,
  dateOnly,
  IMAGE_STATUSES,
  IMAGE_USE_LABEL,
  imageName,
  num,
  plural,
  REGISTRY_LABEL,
  setParams,
  useLocation,
  withScope,
  type ComponentRow,
  type ImageBrief,
  type ImageList,
  type ImageRow,
  type ImagesResponse,
  type ImageVulnRow,
  type RegistryKind,
  type Severity,
  type WorkloadRow,
} from "../lib.ts";
import { useScopedApi, useShell } from "../shell.tsx";
import { ListCard, NoRows, Page, PageState, ProviderIcon, Row, SeverityBadge, Stat } from "../components/ui.tsx";
import { ExploitedBadges, VulnSeverity } from "../components/dependencies.tsx";
import { BuiltBy, ImageName, imageHref, imageTag, Reach, registryText, UseBadge, VulnCountsView, workloadPlace } from "../components/images.tsx";
import { CopyMenu, DownloadCsvButton, SelectPage, SelectRow, SelectionBar, downloadCsv, useSelection, type Selection } from "../components/selection.tsx";

const TITLE = "Images";
const DESCRIPTION =
  "Container images in your registries and the ones your workloads run, scanned with Trivy: what each is made of, which repository builds it, where it runs and whether the internet reaches it.";
const PER_PAGE = 50;
const ALL = "all";
type Tab = "images" | "running" | "vulnerabilities" | "components";
const TABS: Tab[] = ["images", "running", "vulnerabilities", "components"];
/** The list each tab reads, and the filters it sends. */
const ENDPOINT: Record<Tab, string> = { images: "list", running: "workloads", vulnerabilities: "vulnerabilities", components: "components" };
const TAB_FILTERS: Record<Tab, string[]> = {
  images: ["q", "use", "has", "registry", "builder"],
  running: ["q", "reach", "has"],
  vulnerabilities: ["q", "status", "severity", "use", "layer", "from", "image"],
  components: ["q", "kind", "vulnerable", "eol", "type", "use", "image"],
};
const FILTERS = [...new Set(Object.values(TAB_FILTERS).flat())];
const NOUN: Record<Tab, [string, string]> = {
  images: ["image", "images"],
  running: ["workload", "workloads"],
  vulnerabilities: ["vulnerability", "vulnerabilities"],
  components: ["component", "components"],
};
const USE_FILTER = { internet: "Internet-facing", running: "Running", pulled: "Pulled lately or running", stored: "Stored only" };
const IN_IMAGES = { internet: "In internet-facing images", running: "In running images", pulled: "In images in use" };
const HAS = {
  exploited: "Known exploited vulnerability",
  fixable: "Critical or high with a fix",
  eol: "Operating system or runtime past end of life",
  secrets: "Stored credential",
  findings: "Open finding",
  unscanned: "Not scanned",
};
const SEVERITY_FILTERS = { critical: "Critical", high: "High or worse", medium: "Medium or worse", low: "Low or worse" };
const EMPTY: Record<Tab, string> = {
  images: "No images in this view's registries.",
  running:
    "No workload that runs images in this view: Keelson reads ECS services, Elastic Container Instance groups and Function Compute functions built from an image.",
  vulnerabilities: "No known vulnerabilities in the scanned images.",
  components: "No components: no image has been scanned yet.",
};

const fullRef = (i: ImageRow) => `${imageName(i)}:${imageTag(i)}`;
const briefRef = (i: ImageBrief) => `${i.name}${i.tag ? `:${i.tag}` : ""}`;
type AnyRow = ImageRow | (WorkloadRow & { key: string }) | ImageVulnRow | ComponentRow;
/** How each tab names a row, for picking it. */
const keyOf = (tab: Tab, r: AnyRow): string =>
  tab === "images" ? (r as ImageRow).id : tab === "vulnerabilities" ? (r as ImageVulnRow).id : (r as ComponentRow | (WorkloadRow & { key: string })).key;

/** A search box that waits for a pause in typing before it changes the address, so a list isn't asked for on every key. */
function Search({ placeholder, value, onChange }: { placeholder: string; value: string; onChange: (v: string) => void }) {
  const [text, setText] = useState(value);
  useEffect(() => setText(value), [value]);
  useEffect(() => {
    if (text === value) return;
    const t = setTimeout(() => onChange(text), 250);
    return () => clearTimeout(t);
  }, [text, value, onChange]);
  return (
    <Input className="w-full min-w-48 sm:w-64" aria-label={placeholder} placeholder={placeholder} value={text} onChange={(e) => setText(e.target.value)} />
  );
}

export function ImagesPage() {
  const { view, multi, status } = useShell();
  // Images a scan had no time for are read in the background while Keelson keeps running; after a restart they wait for the next scan.
  const inBackground = !!status?.background?.inScope;
  const { params } = useLocation();
  const tab = (TABS.includes(params.get("tab") as Tab) ? params.get("tab") : "images") as Tab;
  const page = Math.max(1, Number(params.get("page")) || 1);
  const { data, error, loading, reload } = useScopedApi<ImagesResponse>("/api/images");
  const toasts = useKumoToastManager();

  const query = new URLSearchParams();
  for (const k of TAB_FILTERS[tab]) if (params.has(k)) query.set(k, params.get(k)!);
  const filterQuery = query.toString();
  const list = useScopedApi<ImageList<AnyRow>>(
    data?.summary ? `/api/images/${ENDPOINT[tab]}?${filterQuery}&offset=${(page - 1) * PER_PAGE}&limit=${PER_PAGE}` : null,
  );
  const selection = useSelection([tab, filterQuery]);

  const s = data?.summary;
  if (error || !data || !s) {
    const gaps = (data?.coverage ?? []).filter((c) => !c.ok);
    return (
      <PageState
        title={TITLE}
        description={DESCRIPTION}
        error={error}
        loading={!data && loading}
        empty={!!data}
        retry={reload}
        emptyText={
          data?.scan
            ? gaps.length
              ? `${gaps[0].label}: ${gaps[0].message ?? `needs ${gaps[0].permission}`}`
              : "No container registry or workload that runs images is in this view's latest scans. They are read from AWS, Alibaba Cloud and GitHub accounts on the next scan."
            : undefined
        }
      />
    );
  }

  const filter = (next: Record<string, string | null>) => setParams({ ...next, page: null });
  const goTo = (to: Tab, next: Record<string, string | null> = {}) =>
    setParams({ ...Object.fromEntries([...FILTERS, "page"].map((k) => [k, null])), tab: to === "images" ? null : to, ...next });
  const select = (key: string, label: string, items: Record<string, string>, className = "sm:w-48") => (
    <Select
      aria-label={label}
      className={`min-w-36 flex-1 sm:flex-none ${className}`}
      value={params.get(key) ?? ALL}
      onValueChange={(v) => filter({ [key]: v === ALL ? null : String(v) })}
      items={{ [ALL]: label, ...items }}
    />
  );
  const search = (placeholder: string) => <Search placeholder={placeholder} value={params.get("q") || ""} onChange={(v) => filter({ q: v || null })} />;

  const rows = list.data?.rows ?? [];
  const total = list.data?.total ?? 0;
  const active = TAB_FILTERS[tab].filter((k) => params.has(k));
  const csvHref = (name: "vulnerabilities" | "components") => withScope(`/api/images/${name}.csv?${tab === name ? filterQuery : ""}`, view.key);

  /**
   * The rows behind the selection, in full (every image a vulnerability is in, not the first few a row shows): the
   * picked ones by their keys, or every row the filters match.
   */
  const picked = async <T,>(): Promise<T[]> => {
    const out: T[] = [];
    const ask = async (extra: string) => api<ImageList<T>>(withScope(`/api/images/${ENDPOINT[tab]}?${filterQuery}&full=1&limit=200&${extra}`, view.key));
    if (selection.all)
      for (let offset = 0; offset < Math.min(total, 5000); offset += 200) {
        const p = await ask(`offset=${offset}`);
        out.push(...p.rows);
        if (p.rows.length < 200) break;
      }
    else {
      const keys = [...selection.keys];
      for (let n = 0; n < keys.length; n += 100)
        out.push(
          ...(
            await ask(
              keys
                .slice(n, n + 100)
                .map((k) => `key=${encodeURIComponent(k)}`)
                .join("&"),
            )
          ).rows,
        );
    }
    return out;
  };
  const lines =
    <T,>(what: [string, string], of: (rows: T[]) => string[]) =>
    async () => ({ lines: of(await picked<T>()), what });
  const download = async <T,>(name: string, header: string[], of: (r: T) => unknown[][]) => {
    try {
      downloadCsv(name, [header, ...(await picked<T>()).flatMap(of)]);
    } catch (e) {
      toasts.add({ title: "Couldn't read the selection", description: (e as Error).message, variant: "error" });
    }
  };

  const toolbar: Record<Tab, ReactNode> = {
    images: (
      <>
        {search("Image, tag, repository, base or runtime")}
        {select("use", "In use or not", USE_FILTER)}
        {select("has", "Anything found", HAS, "sm:w-72")}
        {data.registries.length > 1 &&
          select("registry", "Every registry", Object.fromEntries(data.registries.map((k) => [k, REGISTRY_LABEL[k as RegistryKind]])), "sm:w-56")}
        {select("builder", "Built by anyone", { known: "Repository known", unknown: "Repository unknown" })}
      </>
    ),
    running: (
      <>
        {search("Workload, image, account or hostname")}
        {select("reach", "Reachable or not", { internet: "Internet-facing", private: "Not from the internet", unknown: "Keelson can't tell" })}
        {select("has", "Any image", { exploited: "Runs a known exploited vulnerability", unscanned: "Runs an image that isn't scanned" }, "sm:w-72")}
      </>
    ),
    vulnerabilities: (
      <>
        {search("CVE, advisory or package")}
        {select("status", "Any status", IMAGE_STATUSES)}
        {select("severity", "Any severity", SEVERITY_FILTERS)}
        {select("use", "In any image", IN_IMAGES, "sm:w-60")}
        {select("layer", "Any kind of package", { os: "Operating system packages", app: "Application packages" }, "sm:w-60")}
        {select("from", "Base image or not", { base: "Came with the base image", added: "Added by the image's own build" }, "sm:w-64")}
      </>
    ),
    components: (
      <>
        {search("Component or type")}
        {select("kind", "Every kind", COMPONENT_KIND_LABEL, "sm:w-60")}
        {select("vulnerable", "Vulnerable or not", { yes: "With a known vulnerability" }, "sm:w-60")}
        {select("eol", "Supported or not", { yes: "Past end of life" })}
        {data.types.length > 1 && select("type", "Every package type", Object.fromEntries(data.types.map((t) => [t, t])))}
        {select("use", "In any image", IN_IMAGES, "sm:w-60")}
      </>
    ),
  };

  const selectionActions: Record<Tab, ReactNode> = {
    images: (
      <>
        <CopyMenu
          items={[
            { label: "Images (registry/name:tag)", run: lines<ImageRow>(["image", "images"], (r) => r.map(fullRef)) },
            {
              label: "Images by digest",
              run: lines<ImageRow>(["image", "images"], (r) => r.filter((i) => i.digest).map((i) => `${imageName(i)}@${i.digest}`)),
            },
            {
              label: "Repositories that build them",
              run: lines<ImageRow>(["repository", "repositories"], (r) => r.flatMap((i) => i.builtBy.map((b) => b.repo))),
            },
            {
              label: "Workloads that run them",
              run: lines<ImageRow>(["workload", "workloads"], (r) => r.flatMap((i) => i.workloads.map((w) => `${w.kind} ${w.name} (${workloadPlace(w)})`))),
            },
          ]}
        />
        <DownloadCsvButton
          onClick={() =>
            download<ImageRow>(
              "keelson-images",
              [
                "image",
                "tag",
                "digest",
                "registry",
                "account",
                "in use",
                "runs in",
                "internet-facing",
                "hostnames",
                "built by",
                "operating system",
                "runtimes",
                "base image",
                "past end of life",
                "components",
                "critical",
                "high",
                "medium",
                "low",
                "critical or high with a fix",
                "known exploited",
                "stored credentials",
                "pushed",
                "last pulled",
                "scanned",
              ],
              (i) => [
                [
                  imageName(i),
                  i.tags.join(" "),
                  i.digest ?? "",
                  REGISTRY_LABEL[i.kind],
                  i.account,
                  IMAGE_USE_LABEL[i.use],
                  i.workloads.map((w) => `${w.kind} ${w.name}`).join("; "),
                  i.workloads.some((w) => w.internet === true),
                  [...new Set(i.workloads.flatMap((w) => w.hosts))].join(" "),
                  i.builtBy.map((b) => b.repo).join(" "),
                  i.summary?.os ?? "",
                  (i.summary?.runtimes ?? []).map((r) => `${r.name} ${r.version}`).join("; "),
                  i.summary?.baseName ?? "",
                  i.summary ? i.summary.eol || !!i.summary.runtimes?.some((r) => r.eol) : "",
                  i.summary?.packages ?? "",
                  i.summary?.vulns.critical ?? "",
                  i.summary?.vulns.high ?? "",
                  i.summary?.vulns.medium ?? "",
                  i.summary?.vulns.low ?? "",
                  i.summary ? i.summary.fixable.critical + i.summary.fixable.high : "",
                  i.summary?.exploited.join(" ") ?? "",
                  i.summary?.secrets ?? "",
                  i.pushedAt ?? "",
                  i.pulledAt ?? "",
                  i.summary?.scannedAt ?? i.error ?? "not scanned",
                ],
              ],
            )
          }
        />
      </>
    ),
    running: (
      <>
        <CopyMenu
          items={[
            { label: "Workloads", run: lines<WorkloadRow>(["workload", "workloads"], (r) => r.map((w) => `${w.kind} ${w.name} (${workloadPlace(w)})`)) },
            { label: "Images they run", run: lines<WorkloadRow>(["image", "images"], (r) => r.flatMap((w) => w.containers.map((c) => c.image))) },
            { label: "Hostnames", run: lines<WorkloadRow>(["hostname", "hostnames"], (r) => r.flatMap((w) => w.hosts)) },
          ]}
        />
        <DownloadCsvButton
          onClick={() =>
            download<WorkloadRow>(
              "keelson-workloads",
              [
                "workload",
                "kind",
                "in",
                "region",
                "account",
                "internet-facing",
                "through",
                "hostnames",
                "container",
                "image",
                "scanned",
                "critical",
                "high",
                "known exploited",
              ],
              (w) =>
                w.containers.map((c) => [
                  w.name,
                  w.kind,
                  w.group ?? "",
                  w.region,
                  w.account,
                  w.internet ?? "unknown",
                  w.via.join("; "),
                  w.hosts.join(" "),
                  c.name,
                  c.image,
                  c.imageId ? "yes" : (c.unscanned ?? "no"),
                  c.vulns?.critical ?? "",
                  c.vulns?.high ?? "",
                  c.exploited,
                ]),
            )
          }
        />
      </>
    ),
    vulnerabilities: (
      <>
        <CopyMenu
          items={[
            { label: "Vulnerability IDs", run: lines<ImageVulnRow>(["ID", "IDs"], (r) => r.map((v) => v.id)) },
            { label: "Images they are in", run: lines<ImageVulnRow>(["image", "images"], (r) => r.flatMap((v) => v.images.map(briefRef))) },
            {
              label: "Upgrades to make",
              run: lines<ImageVulnRow>(["upgrade", "upgrades"], (r) =>
                r.flatMap((v) => v.packages.map((p) => `${p.name} ${p.version} → ${p.fixedIn ?? "no fix yet"}`)),
              ),
            },
          ]}
        />
        <DownloadCsvButton
          onClick={() =>
            download<ImageVulnRow>(
              "keelson-image-vulnerabilities",
              [
                "vulnerability",
                "severity",
                "cvss",
                "known exploited",
                "package",
                "version",
                "fixed in",
                "from",
                "came with the base image",
                "images",
                "most exposed image",
              ],
              (v) =>
                v.packages.map((p) => [
                  v.id,
                  v.severity,
                  v.cvss ?? "",
                  v.kev ? "yes" : "",
                  p.name,
                  p.version,
                  p.fixedIn ?? "",
                  p.layer === "os" ? "operating system" : "application",
                  v.base ? "yes" : "",
                  v.images.map(briefRef).join(" "),
                  IMAGE_USE_LABEL[v.use],
                ]),
            )
          }
        />
      </>
    ),
    components: (
      <>
        <CopyMenu
          items={[
            { label: "Components (name@version)", run: lines<ComponentRow>(["component", "components"], (r) => r.map((c) => `${c.name}@${c.version}`)) },
            { label: "Images they are in", run: lines<ComponentRow>(["image", "images"], (r) => r.flatMap((c) => c.images.map(briefRef))) },
            {
              label: "Upgrades to make",
              run: lines<ComponentRow>(["upgrade", "upgrades"], (r) => r.filter((c) => c.fixedIn).map((c) => `${c.name} ${c.version} → ${c.fixedIn}`)),
            },
          ]}
        />
        <DownloadCsvButton
          onClick={() =>
            download<ComponentRow>(
              "keelson-image-components",
              [
                "component",
                "version",
                "kind",
                "type",
                "images",
                "most exposed",
                "critical",
                "high",
                "known exploited",
                "past end of life",
                "upgrade to",
                "in images",
              ],
              (c) => [
                [
                  c.name,
                  c.version,
                  COMPONENT_KIND_LABEL[c.kind],
                  c.type,
                  c.imageCount,
                  IMAGE_USE_LABEL[c.use],
                  c.vulns.critical,
                  c.vulns.high,
                  c.kev ? "yes" : "",
                  c.eol == null ? "" : c.eol ? "yes" : "no",
                  c.fixedIn ?? "",
                  c.images.map(briefRef).join(" "),
                ],
              ],
            )
          }
        />
      </>
    ),
  };

  const gaps = data.coverage.filter((c) => !c.ok);
  const picking = selection.all || selection.keys.size > 0;
  const pageKeys = rows.map((r) => keyOf(tab, r));

  return (
    <Page
      title={TITLE}
      description={DESCRIPTION}
      actions={
        s.scanned > 0 && (
          <DropdownMenu>
            <DropdownMenu.Trigger
              render={
                <Button size="sm" icon={<DownloadSimpleIcon />}>
                  Export <CaretDownIcon />
                </Button>
              }
            />
            <DropdownMenu.Content align="end">
              <DropdownMenu.Group>
                <DropdownMenu.Label>As CSV, with this tab's filters</DropdownMenu.Label>
                <DropdownMenu.Item onClick={() => window.open(csvHref("components"), "_self")}>Components (the inventory)</DropdownMenu.Item>
                <DropdownMenu.Item onClick={() => window.open(csvHref("vulnerabilities"), "_self")}>Vulnerabilities, by image</DropdownMenu.Item>
              </DropdownMenu.Group>
            </DropdownMenu.Content>
          </DropdownMenu>
        )
      }
    >
      {gaps.length > 0 && (
        <Banner
          variant="alert"
          icon={<WarningIcon weight="fill" />}
          title={gaps.some((c) => c.key === "trivy") ? "Images aren't scanned yet" : "Some image data isn't read"}
          description={
            <ul className="list-disc space-y-1 pl-5">
              {gaps.map((c) => (
                <li key={`${c.provider}${c.key}`}>
                  {c.label}: {c.message ?? `needs ${c.permission}.`}
                  {c.message && c.permission && <span className="text-kumo-subtle"> Needs: {c.permission}.</span>}
                </li>
              ))}
            </ul>
          }
        />
      )}
      <Row cols={4}>
        <Stat
          label="Images"
          value={num(s.images)}
          note={`${num(s.scanned)} scanned${s.waiting ? `, ${num(s.waiting)} ${inBackground ? "being read in the background" : "wait for the next scan"}` : ""} · ${plural(s.repositories, "repository", "repositories")} in your registries`}
          onClick={() => goTo("images")}
        />
        <Stat
          label="Internet-facing"
          value={num(s.uses.internet)}
          note={`Run by a workload the internet reaches · ${num(s.uses.internet + s.uses.running)} run in ${plural(s.workloads, "workload")}, ${num(s.uses.pulled)} pulled lately`}
          onClick={() => goTo("images", { use: "internet" })}
        />
        <Stat
          label="Known exploited"
          value={num(s.exploited)}
          note={`Images with a vulnerability attackers use${s.exploitedInternet ? `, ${num(s.exploitedInternet)} of them internet-facing` : ""} · ${num(s.secrets)} hold a stored credential`}
          onClick={() => goTo("images", { has: "exploited" })}
        />
        <Stat
          label="Components"
          value={num(s.components)}
          note={`Packages, runtimes and operating systems at each version · ${num(s.componentsAtRisk)} with a known vulnerability or past end of life`}
          onClick={() => goTo("components")}
        />
      </Row>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <Tabs
          value={tab}
          onValueChange={(v) => goTo(v as Tab)}
          tabs={[
            { value: "images", label: `Images ${num(s.images)}` },
            { value: "running", label: `Running ${num(s.workloads)}` },
            { value: "vulnerabilities", label: "Vulnerabilities" },
            { value: "components", label: `Components ${num(s.components)}` },
          ]}
        />
        <span className="text-sm text-kumo-subtle">
          {[
            s.trivy && `Trivy ${s.trivy}`,
            s.dbUpdated && `vulnerability data from ${new Date(s.dbUpdated).toLocaleDateString()}`,
            // An image is pulled once; after that a scan only checks its stored packages against the newer database.
            s.pulled != null && `last scan pulled ${num(s.pulled)} and checked ${num(s.checked ?? 0)} without pulling`,
          ]
            .filter(Boolean)
            .join(" · ")}
        </span>
      </div>

      <ListCard
        toolbar={
          picking ? (
            <SelectionBar selection={selection} noun={NOUN[tab]} total={total} pageKeys={pageKeys}>
              {selectionActions[tab]}
            </SelectionBar>
          ) : (
            <>
              {toolbar[tab]}
              {params.get("image") && TAB_FILTERS[tab].includes("image") && <Badge variant="outline">One image</Badge>}
              {active.length > 0 && (
                <Button size="sm" variant="ghost" icon={<XIcon />} onClick={() => goTo(tab)}>
                  Clear filters
                </Button>
              )}
            </>
          )
        }
        footer={
          <>
            <span>
              {list.loading && !list.data ? "Loading…" : plural(total, NOUN[tab][0], NOUN[tab][1])}
              {tab === "images" && " · most exposed first"}
              {tab === "running" && s.workloadsUnscanned > 0 && ` · ${num(s.workloadsUnscanned)} run an image Keelson didn't scan`}
              {tab === "components" && " · vulnerable and unsupported first"}
            </span>
            {total > PER_PAGE && (
              <Pagination page={page} setPage={(p: number) => setParams({ page: p === 1 ? null : String(p) })} perPage={PER_PAGE} totalCount={total} />
            )}
          </>
        }
      >
        {list.error ? (
          <NoRows>{list.error.message}</NoRows>
        ) : !rows.length ? (
          <NoRows>{list.loading ? "Loading…" : active.length ? "Nothing matches these filters." : EMPTY[tab]}</NoRows>
        ) : tab === "images" ? (
          <ImagesTable rows={rows as ImageRow[]} selection={selection} multi={multi} />
        ) : tab === "running" ? (
          <WorkloadsTable rows={rows as (WorkloadRow & { key: string })[]} selection={selection} />
        ) : tab === "vulnerabilities" ? (
          <VulnerabilitiesTable rows={rows as ImageVulnRow[]} selection={selection} />
        ) : (
          <ComponentsTable rows={rows as ComponentRow[]} selection={selection} />
        )}
      </ListCard>
    </Page>
  );
}

/** What an image is built on, in a line: its operating system, the runtime it is built around, and whether either is past its end of life. */
function BuiltOn({ image }: { image: ImageRow }) {
  const s = image.summary;
  if (!s) return <span className="text-kumo-subtle">—</span>;
  const ended = s.eol || !!s.runtimes?.some((r) => r.eol);
  return (
    <span className="flex flex-col gap-0.5">
      <span className="inline-flex items-center gap-2 whitespace-nowrap">
        {s.os ?? <span className="text-kumo-subtle">No operating system</span>}
        {ended && (
          <span title="An operating system release or a runtime's release line in this image no longer gets security fixes">
            <Badge variant="warning">End of life</Badge>
          </span>
        )}
      </span>
      {(s.runtimes?.length ?? 0) > 0 && (
        <span className="whitespace-nowrap text-sm text-kumo-subtle">{s.runtimes!.map((r) => `${r.name} ${r.version}`).join(" · ")}</span>
      )}
    </span>
  );
}

const ImagesTable = memo(function ImagesTable({ rows, selection, multi }: { rows: ImageRow[]; selection: Selection; multi: boolean }) {
  return (
    <Table layout="auto">
      <Table.Header variant="compact">
        <Table.Row>
          <Table.Head className="w-10">
            <SelectPage selection={selection} keys={rows.map((i) => i.id)} label="Select every image on this page" />
          </Table.Head>
          <Table.Head sticky="left">Image</Table.Head>
          <Table.Head className="whitespace-nowrap">In use</Table.Head>
          <Table.Head className="whitespace-nowrap">Vulnerabilities</Table.Head>
          <Table.Head className="whitespace-nowrap">Built on</Table.Head>
          <Table.Head className="whitespace-nowrap">Built by</Table.Head>
          <Table.Head className="whitespace-nowrap">Pushed</Table.Head>
          <Table.Head className="whitespace-nowrap">Findings</Table.Head>
        </Table.Row>
      </Table.Header>
      <Table.Body>
        {rows.map((i) => {
          const s = i.summary;
          const open = i.findings.filter((f) => f.status === "open" || f.status === "in_progress");
          const first = i.workloads[0];
          const fixable = s ? s.fixable.critical + s.fixable.high : 0;
          return (
            <Table.Row key={i.id}>
              <Table.Cell className="align-top">
                <SelectRow selection={selection} id={i.id} label={`Select ${i.repository}:${imageTag(i)}`} />
              </Table.Cell>
              <Table.Cell sticky="left" className="max-w-96 align-top">
                <span className="flex items-center gap-2">
                  <ImageName image={i} />
                  {i.public && i.own && (
                    <span title="Anyone can pull this image">
                      <Badge variant="outline">Public</Badge>
                    </span>
                  )}
                  {s && s.secrets > 0 && (
                    <span title={`${plural(s.secrets, "credential")} stored in the image`}>
                      <Badge variant="red" icon={<KeyIcon weight="fill" />}>
                        Credential
                      </Badge>
                    </span>
                  )}
                </span>
                <div className="truncate text-sm text-kumo-subtle">
                  {registryText(i)}
                  {multi && !i.own ? ` · ${i.account}` : ""}
                  {i.tags.length > 1 ? ` · also ${i.tags.slice(1, 4).join(", ")}` : ""}
                </div>
              </Table.Cell>
              <Table.Cell className="align-top">
                <UseBadge use={i.use} />
                {first && (
                  <div className="mt-1 max-w-64 truncate text-sm text-kumo-subtle">
                    {first.kind} {first.name}
                    {i.workloadCount > 1 ? ` and ${num(i.workloadCount - 1)} more` : ""}
                  </div>
                )}
              </Table.Cell>
              <Table.Cell className="align-top">
                {s ? (
                  <>
                    <VulnCountsView vulns={s.vulns} exploited={s.exploited.length} />
                    {fixable > 0 && (
                      <div className="mt-1 text-sm text-kumo-subtle">
                        {num(fixable)} critical or high {fixable === 1 ? "has" : "have"} a fix
                      </div>
                    )}
                  </>
                ) : (
                  <span title={i.error ?? "It waits for a later scan: one scan only spends so long on images."}>
                    <Badge variant="outline">Not scanned</Badge>
                  </span>
                )}
              </Table.Cell>
              <Table.Cell className="align-top">
                <BuiltOn image={i} />
              </Table.Cell>
              <Table.Cell className="align-top">
                <BuiltBy builds={i.builtBy} />
              </Table.Cell>
              <Table.Cell className="whitespace-nowrap align-top text-kumo-subtle">{i.pushedAt ? dateOnly(i.pushedAt) : "—"}</Table.Cell>
              <Table.Cell className="align-top">
                {open.length ? (
                  <span className="flex flex-col gap-1">
                    {open.slice(0, 3).map((f) => (
                      <Link
                        key={f.fingerprint}
                        variant="plain"
                        href={`/findings/${f.fingerprint}`}
                        className="inline-flex items-center gap-1.5 whitespace-nowrap"
                      >
                        <SeverityBadge severity={f.severity as Severity} />
                        <span className="font-mono text-xs text-kumo-subtle">{f.checkId}</span>
                      </Link>
                    ))}
                    {open.length > 3 && <span className="text-xs text-kumo-subtle">and {num(open.length - 3)} more</span>}
                  </span>
                ) : (
                  <span className="text-kumo-subtle">{i.findings.length ? "Triaged" : "None"}</span>
                )}
              </Table.Cell>
            </Table.Row>
          );
        })}
      </Table.Body>
    </Table>
  );
});

const WorkloadsTable = memo(function WorkloadsTable({ rows, selection }: { rows: (WorkloadRow & { key: string })[]; selection: Selection }) {
  return (
    <Table layout="auto">
      <Table.Header variant="compact">
        <Table.Row>
          <Table.Head className="w-10">
            <SelectPage selection={selection} keys={rows.map((w) => w.key)} label="Select every workload on this page" />
          </Table.Head>
          <Table.Head sticky="left">Workload</Table.Head>
          <Table.Head className="whitespace-nowrap">Reached from the internet</Table.Head>
          <Table.Head className="whitespace-nowrap">Images it runs</Table.Head>
        </Table.Row>
      </Table.Header>
      <Table.Body>
        {rows.map((w) => (
          <Table.Row key={w.key}>
            <Table.Cell className="align-top">
              <SelectRow selection={selection} id={w.key} label={`Select ${w.name}`} />
            </Table.Cell>
            <Table.Cell sticky="left" className="align-top">
              <span className="inline-flex items-center gap-2 whitespace-nowrap">
                <ProviderIcon provider={w.provider} />
                {w.link ? (
                  <Link href={w.link} target="_blank" rel="noopener noreferrer">
                    {w.name}
                  </Link>
                ) : (
                  w.name
                )}
                <span className="text-sm text-kumo-subtle">{w.kind}</span>
                {w.running != null && w.running > 1 && <span className="text-sm tabular-nums text-kumo-subtle">× {num(w.running)}</span>}
              </span>
              <div className="text-sm text-kumo-subtle">{workloadPlace(w)}</div>
            </Table.Cell>
            <Table.Cell className="align-top">
              <Reach internet={w.internet} via={w.via} hosts={w.hosts} />
            </Table.Cell>
            <Table.Cell className="align-top">
              <ul className="flex flex-col gap-1.5">
                {w.containers.map((c) => (
                  <li key={`${c.name}${c.image}`} className="flex flex-wrap items-center gap-x-3 gap-y-1">
                    {c.imageId ? (
                      <Link variant="plain" href={imageHref(c.imageId)} className="max-w-xl truncate font-mono text-xs">
                        {shortRef(c.image)}
                      </Link>
                    ) : (
                      <span className="max-w-xl truncate font-mono text-xs">{shortRef(c.image)}</span>
                    )}
                    {c.vulns ? (
                      <VulnCountsView vulns={c.vulns} exploited={c.exploited} />
                    ) : (
                      <span title={c.unscanned ?? "Not scanned"}>
                        <Badge variant="outline">Not scanned</Badge>
                      </span>
                    )}
                  </li>
                ))}
                {!w.containers.length && <li className="text-kumo-subtle">Its images couldn't be read</li>}
              </ul>
            </Table.Cell>
          </Table.Row>
        ))}
      </Table.Body>
    </Table>
  );
});

/** A reference with its digest cut short: "…/web@sha256:ab12cd34ef56…". */
const shortRef = (ref: string) => ref.replace(/@sha256:([a-f0-9]{12})[a-f0-9]+$/, "@sha256:$1…");

/** The first few images a row names, most exposed first, and how many more there are. */
function InImages({ images, count, use }: { images: ImageBrief[]; count: number; use: ImageBrief["use"] }) {
  return (
    <>
      <span className="inline-flex items-center gap-2 whitespace-nowrap">
        <UseBadge use={use} />
        <span className="tabular-nums text-kumo-subtle">{plural(count, "image")}</span>
      </span>
      <ul className="mt-1 flex flex-col gap-0.5">
        {images.map((i) => (
          <li key={i.id} className="max-w-80 truncate">
            <Link variant="plain" href={imageHref(i.id)} className="font-mono text-xs">
              {i.name.split("/").slice(1).join("/")}
              {i.tag ? `:${i.tag}` : ""}
            </Link>
          </li>
        ))}
        {count > images.length && <li className="text-xs text-kumo-subtle">and {num(count - images.length)} more</li>}
      </ul>
    </>
  );
}

const VulnerabilitiesTable = memo(function VulnerabilitiesTable({ rows, selection }: { rows: ImageVulnRow[]; selection: Selection }) {
  return (
    <Table layout="auto">
      <Table.Header variant="compact">
        <Table.Row>
          <Table.Head className="w-10">
            <SelectPage selection={selection} keys={rows.map((v) => v.id)} label="Select every vulnerability on this page" />
          </Table.Head>
          <Table.Head sticky="left">Vulnerability</Table.Head>
          <Table.Head className="whitespace-nowrap">Severity</Table.Head>
          <Table.Head className="whitespace-nowrap">Components</Table.Head>
          <Table.Head className="whitespace-nowrap">Images</Table.Head>
        </Table.Row>
      </Table.Header>
      <Table.Body>
        {rows.map((v) => (
          <Table.Row key={v.id}>
            <Table.Cell className="align-top">
              <SelectRow selection={selection} id={v.id} label={`Select ${v.id}`} />
            </Table.Cell>
            <Table.Cell sticky="left" className="min-w-72 align-top">
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                {v.url ? (
                  <Link href={v.url} target="_blank" rel="noopener noreferrer" className="font-mono text-xs">
                    {v.id}
                  </Link>
                ) : (
                  <span className="font-mono text-xs">{v.id}</span>
                )}
                <ExploitedBadges kev={v.kev} />
                {v.base && (
                  <span title="Everywhere it is found, it came with the base image: a newer base image fixes it">
                    <Badge variant="neutral">Base image</Badge>
                  </span>
                )}
              </div>
              {v.title && <p className="mt-1 line-clamp-2 max-w-xl text-xs text-kumo-subtle">{v.title}</p>}
            </Table.Cell>
            <Table.Cell className="whitespace-nowrap align-top">
              <span className="inline-flex items-center gap-2">
                <VulnSeverity severity={v.severity} />
                {v.cvss != null && <span className="text-xs tabular-nums text-kumo-subtle">CVSS {v.cvss.toFixed(1)}</span>}
              </span>
            </Table.Cell>
            <Table.Cell className="align-top text-sm">
              <ul className="flex flex-col gap-0.5">
                {v.packages.map((p) => (
                  <li key={`${p.type}${p.name}@${p.version}`} className="whitespace-nowrap">
                    <span className="font-mono text-xs">
                      {p.name} {p.version}
                    </span>
                    <span className="text-xs text-kumo-subtle">
                      {" "}
                      {p.fixedIn ? `→ ${p.fixedIn}` : "· no fix yet"} · {p.layer === "os" ? "operating system" : p.type}
                    </span>
                  </li>
                ))}
                {v.packageCount > v.packages.length && (
                  <li className="text-xs text-kumo-subtle">and {num(v.packageCount - v.packages.length)} more versions</li>
                )}
              </ul>
            </Table.Cell>
            <Table.Cell className="align-top">
              <InImages images={v.images} count={v.imageCount} use={v.use} />
            </Table.Cell>
          </Table.Row>
        ))}
      </Table.Body>
    </Table>
  );
});

const ComponentsTable = memo(function ComponentsTable({ rows, selection }: { rows: ComponentRow[]; selection: Selection }) {
  return (
    <Table layout="auto">
      <Table.Header variant="compact">
        <Table.Row>
          <Table.Head className="w-10">
            <SelectPage selection={selection} keys={rows.map((c) => c.key)} label="Select every component on this page" />
          </Table.Head>
          <Table.Head sticky="left">Component</Table.Head>
          <Table.Head className="whitespace-nowrap">Version</Table.Head>
          <Table.Head className="whitespace-nowrap">Known problems</Table.Head>
          <Table.Head className="whitespace-nowrap">Upgrade to</Table.Head>
          <Table.Head className="whitespace-nowrap">Images</Table.Head>
          <Table.Head className="whitespace-nowrap">License</Table.Head>
        </Table.Row>
      </Table.Header>
      <Table.Body>
        {rows.map((c) => (
          <Table.Row key={c.key}>
            <Table.Cell className="align-top">
              <SelectRow selection={selection} id={c.key} label={`Select ${c.name} ${c.version}`} />
            </Table.Cell>
            <Table.Cell sticky="left" className="align-top">
              <span className="inline-flex items-center gap-2 whitespace-nowrap">
                <Link
                  variant="plain"
                  href={`/images?tab=vulnerabilities&q=${encodeURIComponent(c.name)}`}
                  className={c.worst ? undefined : "pointer-events-none text-kumo-default"}
                >
                  {c.name}
                </Link>
                {c.base && c.kind !== "os" && c.kind !== "runtime" && (
                  <span title="Wherever it is found, it came with the base image">
                    <Badge variant="neutral">Base image</Badge>
                  </span>
                )}
              </span>
              <div className="text-sm text-kumo-subtle">
                {COMPONENT_KIND_LABEL[c.kind]}
                {c.kind === "os-package" || c.kind === "app-package" ? ` · ${c.type}` : ""}
              </div>
            </Table.Cell>
            <Table.Cell className="whitespace-nowrap align-top font-mono text-xs">
              {c.version.length > 28 ? `${c.version.slice(0, 14)}…` : c.version || "—"}
            </Table.Cell>
            <Table.Cell className="align-top">
              <span className="inline-flex flex-wrap items-center gap-x-3 gap-y-1">
                {c.eol && (
                  <span title="This release no longer gets security fixes">
                    <Badge variant="warning">End of life</Badge>
                  </span>
                )}
                {c.worst ? (
                  <VulnCountsView vulns={c.vulns} exploited={c.kev ? 1 : 0} all />
                ) : c.eol ? null : c.kind === "runtime" || c.kind === "os" ? (
                  <span className="text-kumo-subtle">{c.eol === false ? "Still supported" : "Support unknown"}</span>
                ) : (
                  <span className="text-kumo-subtle">None known</span>
                )}
              </span>
            </Table.Cell>
            <Table.Cell className="whitespace-nowrap align-top font-mono text-xs">
              {c.fixedIn ?? (c.worst ? <span className="font-sans text-kumo-subtle">No fix yet</span> : "")}
            </Table.Cell>
            <Table.Cell className="align-top text-sm">
              <span className="inline-flex items-center gap-2">
                <span className="tabular-nums">{num(c.imageCount)}</span>
                {c.use === "internet" && (
                  <Tooltip content="At least one of them is internet-facing">
                    <GlobeIcon weight="fill" className="text-kumo-warning" />
                  </Tooltip>
                )}
                <span className="max-w-72 truncate text-kumo-subtle">
                  {c.images.map((i) => i.name.split("/").pop()).join(", ")}
                  {c.imageCount > c.images.length ? ` and ${num(c.imageCount - c.images.length)} more` : ""}
                </span>
              </span>
            </Table.Cell>
            <Table.Cell className="max-w-48 truncate align-top text-sm text-kumo-subtle">{c.licenses.join(", ") || "—"}</Table.Cell>
          </Table.Row>
        ))}
      </Table.Body>
    </Table>
  );
});
