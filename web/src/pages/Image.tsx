// One container image, from the code that builds it to where it runs: the
// repository and workflow behind it, the registry that keeps it, the workloads
// that run it and how the internet reaches them, then what Trivy found in it.
// Each vulnerability says where it is fixed: in the base image, in the
// repository's code, or by rebuilding an image that is behind its code.

import { useState, type ReactNode } from "react";
import { Badge, Banner, Button, ClipboardText, DropdownMenu, Input, Link, Select, Table, Tooltip } from "@cloudflare/kumo";
import { ArrowLeftIcon, ArrowRightIcon, CaretDownIcon, DownloadSimpleIcon, KeyIcon, WarningIcon } from "@phosphor-icons/react";
import {
  dateOnly,
  dateTime,
  FIX_PLACE_HINT,
  FIX_PLACE_LABEL,
  FIX_PLACES,
  HttpError,
  imageName,
  navigate,
  num,
  plural,
  REGISTRY_LABEL,
  setParams,
  shortDigest,
  useLocation,
  withScope,
  type FixPlace,
  type ImageDetailResponse,
  type ImageVulnDetail,
  type Severity,
} from "../lib.ts";
import { useScopedApi, useShell } from "../shell.tsx";
import { Card, KeyValue, ListCard, NoRows, Page, PageState, ProviderIcon, Row, SeverityBadge, Stat } from "../components/ui.tsx";
import { ExploitedBadges, VulnSeverity } from "../components/dependencies.tsx";
import { BuiltBy, imageHref, imageTag, Reach, UseBadge, VulnCountsView, workloadPlace } from "../components/images.tsx";
import { CopyMenu } from "../components/selection.tsx";

const ALL = "all";
/** Rows a table shows before "Show more": an image can hold a thousand packages, and drawing them all makes the page slow. */
const SHOWN = 50;
const RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
const PLACE_VARIANT: Record<FixPlace, "orange" | "warning" | "neutral" | "outline"> = {
  code: "orange",
  rebuild: "warning",
  base: "neutral",
  build: "outline",
  app: "outline",
};
const megabytes = (bytes: number | null) => (bytes == null ? "—" : `${num(Math.round(bytes / 1_000_000))} MB`);

export function ImagePage() {
  const { params } = useLocation();
  const id = params.get("id") ?? "";
  const { data, error, loading, reload } = useScopedApi<ImageDetailResponse>(id ? `/api/images/detail?id=${encodeURIComponent(id)}` : null);
  const { view } = useShell();
  const [shown, setShown] = useState(SHOWN);
  const [shownPackages, setShownPackages] = useState(SHOWN);
  const back = (
    <Button variant="ghost" size="sm" icon={<ArrowLeftIcon />} onClick={() => navigate("/images")}>
      Images
    </Button>
  );
  if (error || !data) {
    const missing = !id || (error instanceof HttpError && error.status === 404);
    return (
      <PageState
        title="Image"
        actions={back}
        error={missing ? null : error}
        loading={!!id && loading}
        empty={missing}
        emptyText={error?.message ?? "Open an image from the Images page."}
        retry={reload}
      />
    );
  }

  const { image, scan } = data;
  const s = image.summary;
  const name = `${image.repository}:${imageTag(image)}`;
  const q = (params.get("q") || "").toLowerCase();
  const place = params.get("where") as FixPlace | null;
  const minSeverity = RANK[params.get("severity") ?? ""] ?? 0;
  const fixableOnly = params.get("fix") === "yes";
  const vulns = (scan?.vulns ?? []).filter(
    (v) =>
      (!q || `${v.id} ${v.pkg} ${v.title}`.toLowerCase().includes(q)) &&
      (!place || v.where === place) &&
      RANK[v.severity] >= minSeverity &&
      (!fixableOnly || !!v.fixedIn),
  );
  const pq = (params.get("pq") || "").toLowerCase();
  const packages = (scan?.packages ?? []).filter((p) => !pq || `${p.name} ${p.type} ${p.path ?? ""}`.toLowerCase().includes(pq));
  const open = image.findings.filter((f) => f.status === "open" || f.status === "in_progress");
  const sbom = (format: string) => withScope(`/api/images/sbom?id=${encodeURIComponent(image.id)}&format=${format}`, view.key);
  const base = data.base;
  const ended = [...(s?.eol && s.os ? [s.os] : []), ...(scan?.runtimes ?? []).filter((r) => r.eol).map((r) => `${r.name} ${r.version}`)];
  const root = scan?.user != null && ["", "0", "root"].includes(scan.user);

  return (
    <Page
      title={
        <span className="inline-flex flex-wrap items-center gap-3">
          <ProviderIcon provider={image.provider} className="h-6 w-6" />
          <span className="break-all">{name}</span>
          <UseBadge use={image.use} />
        </span>
      }
      description={`${imageName(image)}, in ${REGISTRY_LABEL[image.kind]}${image.own ? ` (${image.account}${image.region ? `, ${image.region}` : ""})` : ""}.`}
      actions={
        <>
          {back}
          {scan && (
            <DropdownMenu>
              <DropdownMenu.Trigger
                render={
                  <Button size="sm" icon={<DownloadSimpleIcon />}>
                    Download SBOM <CaretDownIcon />
                  </Button>
                }
              />
              <DropdownMenu.Content align="end">
                <DropdownMenu.Group>
                  <DropdownMenu.Label>Every component of this image</DropdownMenu.Label>
                  <DropdownMenu.Item onClick={() => window.open(sbom("cyclonedx"), "_self")}>CycloneDX JSON, with vulnerabilities</DropdownMenu.Item>
                  <DropdownMenu.Item onClick={() => window.open(sbom("spdx"), "_self")}>SPDX JSON</DropdownMenu.Item>
                </DropdownMenu.Group>
              </DropdownMenu.Content>
            </DropdownMenu>
          )}
        </>
      }
    >
      {!s && (
        <Banner
          variant="alert"
          icon={<WarningIcon weight="fill" />}
          title="Keelson hasn't scanned this image"
          description={
            image.error ?? "It waits for a later scan: one scan only spends so long on images. The ones workloads run go first, then the ones never scanned."
          }
        />
      )}

      {/* From code to production: who builds it, where it is kept, what runs it. */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1fr_auto_1fr_auto_1.4fr] xl:items-stretch">
        <Card title="Built by">
          {image.builtBy.length ? (
            <div className="flex flex-col gap-3 text-sm">
              <BuiltBy builds={image.builtBy} />
              <KeyValue
                items={[
                  ...(image.builtBy[0].workflow
                    ? [
                        [
                          "Workflow",
                          <span key="w" className="font-mono text-xs">
                            {image.builtBy[0].workflow}
                          </span>,
                        ] as [ReactNode, ReactNode],
                      ]
                    : []),
                  ...(scan?.revision
                    ? [
                        [
                          "Commit",
                          <span key="c" className="font-mono text-xs">
                            {scan.revision.slice(0, 12)}
                          </span>,
                        ] as [ReactNode, ReactNode],
                      ]
                    : []),
                  ...(scan?.created ? [["Built", <span key="b">{dateTime(scan.created)}</span>] as [ReactNode, ReactNode]] : []),
                ]}
              />
            </div>
          ) : (
            <p className="text-sm text-kumo-subtle">
              Keelson doesn't know which repository builds it. It reads the image's source label (org.opencontainers.image.source) and the workflows of
              connected GitHub organizations that push an image of this name.
            </p>
          )}
        </Card>
        <Arrow />
        <Card title="Stored in">
          <KeyValue
            items={[
              ["Registry", REGISTRY_LABEL[image.kind]],
              [
                "Host",
                <span key="h" className="break-all font-mono text-xs">
                  {image.registry}
                </span>,
              ],
              ...(image.own ? [["Account", image.account] as [ReactNode, ReactNode]] : []),
              ["Tags", image.tags.length ? image.tags.join(", ") : "None"],
              ["Digest", image.digest ? <ClipboardText key="d" text={image.digest} /> : "Unknown"],
              ["Pushed", image.pushedAt ? dateOnly(image.pushedAt) : "Unknown"],
              ...(image.pulledAt ? [["Last pulled", dateOnly(image.pulledAt)] as [ReactNode, ReactNode]] : []),
              ["Who can pull it", image.public == null ? "Unknown" : image.public ? "Anyone" : "Only who the registry lets in"],
              // An image is pulled once; every scan after that matches its packages against the newer database.
              ...(scan ? [["Read by Keelson", dateOnly(scan.scannedAt)] as [ReactNode, ReactNode]] : []),
              ...(scan?.dbUpdated ? [["Vulnerabilities as of", dateOnly(scan.dbUpdated)] as [ReactNode, ReactNode]] : []),
            ]}
          />
        </Card>
        <Arrow />
        <Card title={`Runs in ${plural(image.workloads.length, "workload")}`} flush>
          {image.workloads.length ? (
            <ul className="divide-y divide-kumo-hairline">
              {image.workloads.map((w) => (
                <li key={`${w.kind}${w.name}${w.container}${w.region}`} className="flex flex-col gap-1.5 px-4 py-3 text-sm">
                  <span className="inline-flex flex-wrap items-center gap-2">
                    <ProviderIcon provider={w.provider} />
                    {w.link ? (
                      <Link href={w.link} target="_blank" rel="noopener noreferrer">
                        {w.name}
                      </Link>
                    ) : (
                      w.name
                    )}
                    <span className="text-kumo-subtle">
                      {w.kind} · {workloadPlace(w)}
                    </span>
                  </span>
                  <Reach internet={w.internet} via={w.via} hosts={w.hosts} />
                  {w.byTag && (
                    <span className="text-xs text-kumo-subtle">
                      Named by tag ({w.image.split(":").pop()}): if the tag moved since it started, it still runs the older image.
                    </span>
                  )}
                </li>
              ))}
            </ul>
          ) : (
            <p className="px-4 py-4 text-sm text-kumo-subtle">
              {image.use === "pulled"
                ? `Nothing Keelson reads runs it, but it was pulled on ${dateOnly(image.pulledAt)}: something does, such as a Kubernetes cluster or an instance.`
                : "Nothing Keelson reads runs it. Keelson reads ECS services, Elastic Container Instance groups and Function Compute functions; Kubernetes workloads aren't read yet."}
            </p>
          )}
        </Card>
      </div>

      {s && scan && (
        <>
          <Row cols={4}>
            <Stat
              label="Vulnerabilities"
              value={<VulnCountsView vulns={s.vulns} exploited={s.exploited.length} all />}
              note={`${num(s.fixable.critical + s.fixable.high)} critical or high ${s.fixable.critical + s.fixable.high === 1 ? "has" : "have"} a fix`}
            />
            <Stat
              label="Built on"
              value={[s.os, ...scan.runtimes.map((r) => `${r.name} ${r.version}`)].filter(Boolean).join(" · ") || "No operating system"}
              note={
                ended.length
                  ? `${ended.join(" and ")} no longer ${ended.length === 1 ? "gets" : "get"} security fixes`
                  : s.os || scan.runtimes.length
                    ? "Still supported, as far as Keelson can tell"
                    : "A distroless or scratch image"
              }
            />
            <Stat
              label="Components"
              value={num(s.packages + scan.runtimes.length + (scan.os ? 1 : 0))}
              note={`${megabytes(scan.size)} · ${scan.platform ?? `linux/${scan.architecture ?? "unknown"}`}${base?.baseLayers ? ` · ${num(base.packages)} came with the base image` : ""}`}
            />
            <Stat
              label="Runs as"
              value={scan.user == null ? "Unknown" : root ? "root" : scan.user}
              note={scan.user == null ? "The image's configuration wasn't read" : root ? "The image sets no other user" : "Set in the image"}
              hint="The user the image's processes run as unless the workload sets another"
            />
          </Row>

          {base && (
            <Card
              title="What it is built on"
              description="The base image brings most of what is in an image. A vulnerability in a layer the base image brought is fixed by moving to a newer base, not in your code."
            >
              <KeyValue
                items={[
                  [
                    "Base image",
                    base.image ? (
                      <span key="i">
                        <Link variant="plain" href={imageHref(base.image.id)}>
                          {base.image.name.split("/").slice(1).join("/")}
                          {base.image.tag ? `:${base.image.tag}` : ""}
                        </Link>
                        <span className="text-kumo-subtle"> · another image in your registries: this one starts with its layers</span>
                      </span>
                    ) : base.names.length ? (
                      <span key="n">
                        <span className="font-mono text-xs">{base.names.join(", ")}</span>
                        <span className="text-kumo-subtle">
                          {" "}
                          · {base.from === "label" ? "the image says so itself" : "the FROM lines of the Dockerfiles in the repository that builds it"}
                        </span>
                      </span>
                    ) : (
                      <span key="u" className="text-kumo-subtle">
                        Not named: the image carries no base image label, and Keelson hasn't read a Dockerfile for it
                      </span>
                    ),
                  ],
                  ["Operating system", s.os ? `${s.os}${s.eol ? " (past its end of life)" : ""}` : "None found"],
                  ...(scan.runtimes.length
                    ? [
                        [
                          "Runtime",
                          <ul key="r" className="flex flex-col gap-1">
                            {scan.runtimes.map((r) => (
                              <li key={r.name} className="flex flex-wrap items-center gap-2">
                                <span>
                                  {r.name} {r.version}
                                </span>
                                {r.eol && <Badge variant="warning">End of life{r.until ? ` since ${dateOnly(r.until)}` : ""}</Badge>}
                                {r.eol === false && <span className="text-kumo-subtle">supported{r.until ? ` until ${dateOnly(r.until)}` : ""}</span>}
                                {r.latest && <span className="text-kumo-subtle">· newest in its release line: {r.latest}</span>}
                              </li>
                            ))}
                          </ul>,
                        ] as [ReactNode, ReactNode],
                      ]
                    : []),
                  [
                    "Layers",
                    base.baseLayers
                      ? `${num(base.baseLayers)} of ${num(base.layers)} came with the base image, with ${plural(base.packages, "package")}`
                      : base.layers
                        ? `${num(base.layers)}; the build history doesn't show where the base image ends`
                        : "Not recorded: this image was scanned before Keelson kept its layers. The next scan reads them",
                  ],
                  ...(base.baseLayers
                    ? [
                        [
                          "Vulnerabilities from the base image",
                          <span key="v" className="inline-flex flex-wrap items-center gap-3">
                            <VulnCountsView vulns={base.vulns} all />
                            {data.places.base > 0 && (
                              <Link variant="plain" render={<button type="button" onClick={() => setParams({ where: "base" })} />}>
                                Show them
                              </Link>
                            )}
                          </span>,
                        ] as [ReactNode, ReactNode],
                      ]
                    : []),
                ]}
              />
            </Card>
          )}

          {scan.secrets.length > 0 && (
            <Card
              title="Credentials stored in the image"
              description="Anyone who can pull the image can read these. Keelson keeps the kind and the place, never the value."
            >
              <ul className="flex flex-col gap-2 text-sm">
                {scan.secrets.map((x) => (
                  <li key={`${x.kind}${x.where}`} className="flex flex-wrap items-center gap-2">
                    <KeyIcon weight="fill" className="text-kumo-danger" />
                    <span>{x.kind}</span>
                    <span className="text-kumo-subtle">in</span>
                    <span className="font-mono text-xs">{x.where}</span>
                    {x.likely && (
                      <Tooltip content="Only the variable's name says so: its value matched no known credential format">
                        <Badge variant="outline">Likely</Badge>
                      </Tooltip>
                    )}
                  </li>
                ))}
              </ul>
            </Card>
          )}

          {scan.vulns.length > 0 && (
            <Card title="Where to fix" description="Each vulnerability is fixed in one of these places. Pick one to see its vulnerabilities.">
              <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
                {FIX_PLACES.filter((p) => data.places[p] > 0).map((p) => (
                  <button
                    key={p}
                    type="button"
                    onClick={() => setParams({ where: place === p ? null : p })}
                    className={`rounded-md p-3 text-left ring ${place === p ? "ring-kumo-brand" : "ring-kumo-line hover:ring-kumo-brand"}`}
                  >
                    <span className="flex items-center justify-between gap-2">
                      <Badge variant={PLACE_VARIANT[p]}>{FIX_PLACE_LABEL[p]}</Badge>
                      <span className="text-lg font-semibold tabular-nums text-kumo-default">{num(data.places[p])}</span>
                    </span>
                    <span className="mt-2 block text-sm text-kumo-subtle">{FIX_PLACE_HINT[p]}</span>
                  </button>
                ))}
              </div>
            </Card>
          )}

          <ListCard
            title={`Vulnerabilities ${num(scan.vulns.length)}`}
            actions={
              <CopyMenu
                label="Copy shown"
                variant="ghost"
                items={[
                  { label: "Vulnerability IDs", run: () => ({ lines: vulns.map((v) => v.id), what: ["ID", "IDs"] }) },
                  {
                    label: "Upgrades to make",
                    run: () => ({ lines: vulns.map((v) => `${v.pkg} ${v.version} → ${v.fixedIn ?? "no fix yet"}`), what: ["upgrade", "upgrades"] }),
                  },
                ]}
              />
            }
            toolbar={
              <>
                <Input
                  className="w-full min-w-48 sm:w-64"
                  aria-label="Search vulnerabilities"
                  placeholder="CVE or package"
                  value={params.get("q") || ""}
                  onChange={(e) => setParams({ q: e.target.value || null })}
                />
                <Select
                  aria-label="Severity"
                  className="min-w-36 flex-1 sm:w-44 sm:flex-none"
                  value={params.get("severity") ?? ALL}
                  onValueChange={(v) => setParams({ severity: v === ALL ? null : String(v) })}
                  items={{ [ALL]: "Any severity", critical: "Critical", high: "High or worse", medium: "Medium or worse" }}
                />
                <Select
                  aria-label="Where it is fixed"
                  className="min-w-36 flex-1 sm:w-48 sm:flex-none"
                  value={place ?? ALL}
                  onValueChange={(v) => setParams({ where: v === ALL ? null : String(v) })}
                  items={{ [ALL]: "Fixed anywhere", ...Object.fromEntries(FIX_PLACES.filter((p) => data.places[p] > 0).map((p) => [p, FIX_PLACE_LABEL[p]])) }}
                />
                <Select
                  aria-label="Fix"
                  className="min-w-36 flex-1 sm:w-40 sm:flex-none"
                  value={params.get("fix") ?? ALL}
                  onValueChange={(v) => setParams({ fix: v === ALL ? null : String(v) })}
                  items={{ [ALL]: "Fix or not", yes: "Has a fix" }}
                />
              </>
            }
            footer={
              <span>
                {vulns.length === scan.vulns.length
                  ? plural(vulns.length, "vulnerability", "vulnerabilities")
                  : `${num(vulns.length)} of ${num(scan.vulns.length)}`}
              </span>
            }
          >
            {!vulns.length ? (
              <NoRows>{scan.vulns.length ? "Nothing matches these filters." : "Trivy found no known vulnerability in this image."}</NoRows>
            ) : (
              <VulnTable vulns={vulns.slice(0, shown)} />
            )}
            {vulns.length > shown && (
              <div className="border-t border-kumo-hairline p-3 text-center">
                <Button variant="ghost" size="sm" onClick={() => setShown(shown + SHOWN)}>
                  Show {num(Math.min(SHOWN, vulns.length - shown))} more
                </Button>
              </div>
            )}
          </ListCard>

          <ListCard
            title={`Packages ${num(scan.packages.length)}`}
            toolbar={
              <Input
                className="w-full min-w-48 sm:w-64"
                aria-label="Search packages"
                placeholder="Package, type or file"
                value={params.get("pq") || ""}
                onChange={(e) => setParams({ pq: e.target.value || null })}
              />
            }
            footer={
              <span>
                {num(Math.min(packages.length, shownPackages))} of {plural(packages.length, "package")} shown · search to find one
              </span>
            }
          >
            {!packages.length ? (
              <NoRows>No package matches.</NoRows>
            ) : (
              <Table layout="auto">
                <Table.Header variant="compact">
                  <Table.Row>
                    <Table.Head sticky="left">Package</Table.Head>
                    <Table.Head className="whitespace-nowrap">Version</Table.Head>
                    <Table.Head className="whitespace-nowrap">Kind</Table.Head>
                    <Table.Head className="whitespace-nowrap">Came with</Table.Head>
                    <Table.Head className="whitespace-nowrap">Recorded in</Table.Head>
                    <Table.Head className="whitespace-nowrap">License</Table.Head>
                  </Table.Row>
                </Table.Header>
                <Table.Body>
                  {packages.slice(0, shownPackages).map((p) => (
                    <Table.Row key={`${p.type}${p.name}${p.version}${p.path}`}>
                      <Table.Cell sticky="left" className="whitespace-nowrap">
                        {p.name}
                      </Table.Cell>
                      <Table.Cell className="whitespace-nowrap font-mono text-xs">{p.version}</Table.Cell>
                      <Table.Cell className="whitespace-nowrap text-sm text-kumo-subtle">
                        {p.layer === "os" ? `Operating system (${p.type})` : p.type}
                      </Table.Cell>
                      <Table.Cell className="whitespace-nowrap text-sm text-kumo-subtle">
                        {base?.baseLayers ? (p.base ? "The base image" : "This image's build") : "—"}
                      </Table.Cell>
                      <Table.Cell className="max-w-96 truncate font-mono text-xs text-kumo-subtle">{p.path ?? "—"}</Table.Cell>
                      <Table.Cell className="max-w-48 truncate text-sm text-kumo-subtle">{p.licenses.join(", ") || "—"}</Table.Cell>
                    </Table.Row>
                  ))}
                </Table.Body>
              </Table>
            )}
            {packages.length > shownPackages && (
              <div className="border-t border-kumo-hairline p-3 text-center">
                <Button variant="ghost" size="sm" onClick={() => setShownPackages(shownPackages + 200)}>
                  Show {num(Math.min(200, packages.length - shownPackages))} more
                </Button>
              </div>
            )}
          </ListCard>
        </>
      )}

      {(image.findings.length > 0 || data.siblings.length > 0) && (
        <Row cols={2}>
          {image.findings.length > 0 && (
            <Card title={`Findings ${num(open.length)} open`}>
              <ul className="flex flex-col gap-2 text-sm">
                {image.findings.map((f) => (
                  <li key={f.fingerprint} className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={f.severity as Severity} />
                    <Link variant="plain" href={`/findings/${f.fingerprint}`}>
                      {f.title}
                    </Link>
                    {f.status !== "open" && <Badge variant="outline">{f.status.replace("_", " ")}</Badge>}
                  </li>
                ))}
              </ul>
            </Card>
          )}
          {data.siblings.length > 0 && (
            <Card title="Other images of this repository">
              <ul className="flex flex-col gap-2 text-sm">
                {data.siblings.map((x) => (
                  <li key={x.id} className="flex flex-wrap items-center gap-3">
                    <Link variant="plain" href={imageHref(x.id)} className="font-mono text-xs">
                      {x.tags[0] ?? shortDigest(x.digest)}
                    </Link>
                    <UseBadge use={x.use} />
                    {x.vulns ? <VulnCountsView vulns={x.vulns} /> : <span className="text-kumo-subtle">Not scanned</span>}
                    {x.pushedAt && <span className="text-kumo-subtle">pushed {dateOnly(x.pushedAt)}</span>}
                  </li>
                ))}
              </ul>
            </Card>
          )}
        </Row>
      )}
    </Page>
  );
}

/** The arrow between the steps of the chain; it points down when they stack. */
function Arrow() {
  return (
    <span className="flex items-center justify-center text-kumo-subtle" aria-hidden>
      <ArrowRightIcon className="h-5 w-5 rotate-90 xl:rotate-0" />
    </span>
  );
}

function VulnTable({ vulns }: { vulns: ImageVulnDetail[] }) {
  return (
    <Table layout="auto">
      <Table.Header variant="compact">
        <Table.Row>
          <Table.Head sticky="left">Vulnerability</Table.Head>
          <Table.Head className="whitespace-nowrap">Severity</Table.Head>
          <Table.Head className="whitespace-nowrap">Package</Table.Head>
          <Table.Head className="whitespace-nowrap">Fixed in</Table.Head>
          <Table.Head className="whitespace-nowrap">Where to fix</Table.Head>
        </Table.Row>
      </Table.Header>
      <Table.Body>
        {vulns.map((v) => (
          <Table.Row key={`${v.id}${v.pkg}${v.version}${v.path}`}>
            <Table.Cell sticky="left" className="min-w-64 align-top">
              <span className="inline-flex flex-wrap items-center gap-2">
                {v.url ? (
                  <Link href={v.url} target="_blank" rel="noopener noreferrer" className="font-mono text-xs">
                    {v.id}
                  </Link>
                ) : (
                  <span className="font-mono text-xs">{v.id}</span>
                )}
                <ExploitedBadges kev={v.kev} />
              </span>
              {v.title && <p className="mt-1 line-clamp-2 max-w-xl text-xs text-kumo-subtle">{v.title}</p>}
            </Table.Cell>
            <Table.Cell className="whitespace-nowrap align-top">
              <span className="inline-flex items-center gap-2">
                <VulnSeverity severity={v.severity} />
                {v.cvss != null && <span className="text-xs tabular-nums text-kumo-subtle">CVSS {v.cvss.toFixed(1)}</span>}
              </span>
            </Table.Cell>
            <Table.Cell className="align-top">
              <span className="whitespace-nowrap font-mono text-xs">
                {v.pkg} {v.version}
              </span>
              <div className="max-w-80 truncate text-xs text-kumo-subtle">{v.path ?? (v.layer === "os" ? `${v.type} package` : v.type)}</div>
            </Table.Cell>
            <Table.Cell className="whitespace-nowrap align-top font-mono text-xs">
              {v.fixedIn ?? <span className="font-sans text-kumo-subtle">{v.status === "will_not_fix" ? "Won't be fixed" : "No fix yet"}</span>}
            </Table.Cell>
            <Table.Cell className="align-top">
              <Tooltip content={FIX_PLACE_HINT[v.where]}>
                <Badge variant={PLACE_VARIANT[v.where]}>{FIX_PLACE_LABEL[v.where]}</Badge>
              </Tooltip>
              {v.inCode && (
                <div className="mt-1 whitespace-nowrap text-xs text-kumo-subtle">
                  the repository has {v.inCode}
                  {v.where === "rebuild" ? ", which is fixed" : ""}
                </div>
              )}
            </Table.Cell>
          </Table.Row>
        ))}
      </Table.Body>
    </Table>
  );
}
