// Pieces the Images page, an image's own page and a repository's page share: how
// much an image is in use, its vulnerabilities by severity, who builds it, and the
// workloads that run it with how the internet reaches them.

import type { ReactNode } from "react";
import { Badge, Link, Tooltip } from "@cloudflare/kumo";
import { CloudArrowDownIcon, CubeIcon, GlobeIcon, PlayIcon } from "@phosphor-icons/react";
import {
  IMAGE_USE_LABEL,
  imageName,
  num,
  REGISTRY_LABEL,
  shortDigest,
  type ImageBuildRef,
  type ImageRow,
  type ImageUse,
  type ImageWorkloadRef,
  type ProviderId,
  type VulnCounts,
} from "../lib.ts";
import { ProviderIcon, SeverityBadge } from "./ui.tsx";
import { MoreLink, type FullList, type FullListColumn } from "./full-list.tsx";
import { ExploitedBadges } from "./dependencies.tsx";

const USE_BADGE: Record<ImageUse, { variant: "orange" | "neutral" | "outline" | "secondary"; icon: ReactNode; hint: string }> = {
  internet: { variant: "orange", icon: <GlobeIcon weight="fill" />, hint: "A workload the internet can reach runs it" },
  running: {
    variant: "neutral",
    icon: <PlayIcon weight="fill" />,
    hint: "A workload runs it; the internet doesn't reach that workload, as far as Keelson can tell",
  },
  pulled: {
    variant: "outline",
    icon: <CloudArrowDownIcon />,
    hint: "Pulled in the last 30 days by something Keelson doesn't read, such as a Kubernetes cluster",
  },
  stored: { variant: "secondary", icon: <CubeIcon />, hint: "Kept in the registry; nothing Keelson reads runs it" },
};

/** How much an image is in use: icon and label, never colour alone. */
export function UseBadge({ use }: { use: ImageUse }) {
  const u = USE_BADGE[use];
  return (
    <Tooltip content={u.hint}>
      <Badge variant={u.variant} icon={u.icon}>
        {IMAGE_USE_LABEL[use]}
      </Badge>
    </Tooltip>
  );
}

/** Critical and high counts as badges, with known exploited ones called out; "None known" when clean. */
export function VulnCountsView({ vulns, exploited = 0, all }: { vulns: VulnCounts; exploited?: number; all?: boolean }) {
  const levels = (all ? (["critical", "high", "medium", "low"] as const) : (["critical", "high"] as const)).filter((l) => vulns[l] > 0);
  const rest = all ? 0 : vulns.medium + vulns.low + vulns.unknown;
  if (!levels.length && !rest) return <span className="text-kumo-subtle">None known</span>;
  return (
    <span className="inline-flex flex-wrap items-center gap-x-3 gap-y-1">
      {exploited > 0 && <ExploitedBadges kev />}
      {levels.map((l) => (
        <span key={l} className="inline-flex items-center gap-1.5 whitespace-nowrap">
          <SeverityBadge severity={l} />
          <span className="tabular-nums text-kumo-subtle">{num(vulns[l])}</span>
        </span>
      ))}
      {!levels.length && rest > 0 && <span className="whitespace-nowrap text-kumo-subtle">{num(rest)} medium or lower</span>}
    </span>
  );
}

/** The image's page in Keelson. The id holds slashes and colons, so it travels as a query parameter. */
export const imageHref = (id: string) => `/images/view?id=${encodeURIComponent(id)}`;

/** "web:1.4.2", or the digest's start for an untagged image. */
export const imageTag = (i: Pick<ImageRow, "tags" | "digest">) => i.tags[0] ?? shortDigest(i.digest);

/** The repository's name as its registry lists it, with the registry beside it and the platform's mark. */
export function ImageName({ image, link = true }: { image: ImageRow; link?: boolean }) {
  const name = `${image.repository}:${imageTag(image)}`;
  return (
    <span className="inline-flex min-w-0 items-center gap-2">
      <ProviderIcon provider={image.provider} />
      {link ? (
        <Link variant="plain" href={imageHref(image.id)} className="truncate">
          {name}
        </Link>
      ) : (
        <span className="truncate">{name}</span>
      )}
    </span>
  );
}

/** Where an image is kept: the registry's kind and its account or host. */
export const registryText = (i: ImageRow) =>
  `${REGISTRY_LABEL[i.kind]}${i.own ? ` · ${i.account}` : i.kind === "other" ? ` · ${i.registry}` : ""}${i.region ? ` · ${i.region}` : ""}`;

const HOW: Record<ImageBuildRef["how"], string> = {
  label: "The image's own source label names this repository",
  package: "GitHub links the package to this repository",
  workflow: "A workflow in this repository pushes an image of this name",
  name: "Nothing names the builder; this is the one repository with the image repository's name",
};

/** The repository that builds an image: a link to its page in Keelson when its organization is connected. */
export function BuiltBy({ builds }: { builds: ImageBuildRef[] }) {
  if (!builds.length) return <span className="text-kumo-subtle">Unknown</span>;
  return (
    <span className="flex flex-col gap-0.5">
      {builds.map((b) => {
        const name = b.name ?? b.repo.split("/")[1];
        return (
          <span key={b.repo} title={`${HOW[b.how]}${b.workflow ? ` (${b.workflow})` : ""}`}>
            <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
              <ProviderIcon provider={"github" as ProviderId} />
              {b.accountId ? (
                <Link variant="plain" href={`/repositories/${encodeURIComponent(b.accountId)}/${encodeURIComponent(name)}`}>
                  {b.repo}
                </Link>
              ) : (
                <Link href={`https://github.com/${b.repo}`} target="_blank" rel="noopener noreferrer">
                  {b.repo}
                </Link>
              )}
              {b.how === "workflow" && <span className="text-xs text-kumo-subtle">from its workflow</span>}
              {b.how === "name" && <span className="text-xs text-kumo-subtle">by its name</span>}
            </span>
          </span>
        );
      })}
    </span>
  );
}

/** "ECS service web", with what holds it and where. */
export const workloadPlace = (w: { group: string | null; region: string; account: string }) => [w.group, w.region, w.account].filter(Boolean).join(" · ");

/** How the internet reaches a workload, in a line: the way in and the hostnames that lead there. */
export function Reach({ internet, via, hosts, name }: Pick<ImageWorkloadRef, "internet" | "via" | "hosts"> & { name: string }) {
  if (internet == null) return <span className="text-kumo-subtle">Keelson can't tell</span>;
  if (!internet) return <span className="text-kumo-subtle">Not from the internet</span>;
  return (
    <span className="flex max-w-80 flex-col items-start gap-1">
      <Badge variant="orange" icon={<GlobeIcon weight="fill" />}>
        Internet-facing
      </Badge>
      <span className="text-sm text-kumo-subtle">Through {via[0] ?? "a public address"}</span>
      {hosts.length > 0 && (
        <span className="text-xs text-kumo-subtle">
          {hosts.slice(0, 3).join(", ")}
          {hosts.length > 3 && (
            <>
              {" "}
              <MoreLink list={() => hostnamesList(name, hosts)}>and {num(hosts.length - 3)} more</MoreLink>
            </>
          )}
        </span>
      )}
    </span>
  );
}

/** Every hostname that leads to a workload. */
export const hostnamesList = (name: string, hosts: string[]): FullList<string> => ({
  title: `Hostnames that reach ${name}`,
  description: "Names in the entity's DNS that point at a load balancer in front of it.",
  noun: ["hostname", "hostnames"],
  columns: [
    { label: "Hostname", value: (h) => h, copy: { label: "Hostnames", what: ["hostname", "hostnames"] }, className: "font-mono text-xs" },
    { label: "Link", value: (h) => `https://${h}`, copy: { label: "Links (https://…)", what: ["link", "links"] }, csvOnly: true },
  ],
  rows: hosts,
  keyOf: (h) => h,
  file: "keelson-hostnames",
});

const yesNo = (v: boolean | null | undefined) => (v == null ? "" : v ? "yes" : "no");
const reachText = (internet: boolean | null) => (internet == null ? "Keelson can't tell" : internet ? "Internet-facing" : "Not from the internet");

/** A workload that runs an image, as a row of a list in full: what runs, where, and how the internet reaches it. */
export const WORKLOAD_COLUMNS: FullListColumn<ImageWorkloadRef>[] = [
  {
    label: "Workload",
    value: (w) => `${w.kind} ${w.name}`,
    copy: { label: "Workloads", what: ["workload", "workloads"] },
    cell: (w) =>
      w.link ? (
        <Link href={w.link} target="_blank" rel="noopener noreferrer">
          {w.kind} {w.name}
        </Link>
      ) : (
        `${w.kind} ${w.name}`
      ),
  },
  { label: "Where", value: (w) => workloadPlace(w), className: "align-top text-sm text-kumo-subtle" },
  { label: "From the internet", value: (w) => reachText(w.internet) },
  { label: "Through", value: (w) => w.via },
  { label: "Hostnames", value: (w) => w.hosts, copy: { label: "Hostnames", what: ["hostname", "hostnames"] }, className: "align-top font-mono text-xs" },
  { label: "Container", value: (w) => w.container },
  { label: "Image as the workload names it", value: (w) => w.image, copy: { label: "Image references", what: ["image", "images"] }, csvOnly: true },
  { label: "Named by a tag", value: (w) => yesNo(w.byTag), csvOnly: true },
  { label: "Cluster or group", value: (w) => w.group ?? "", csvOnly: true },
  { label: "Region", value: (w) => w.region, csvOnly: true },
  { label: "Account", value: (w) => w.account, csvOnly: true },
  { label: "Platform", value: (w) => w.provider, csvOnly: true },
  { label: "Console link", value: (w) => w.link ?? "", csvOnly: true },
];

export const workloadKey = (w: ImageWorkloadRef) => `${w.provider}|${w.account}|${w.region}|${w.group ?? ""}|${w.kind}|${w.name}|${w.container}`;

/** The workloads that run an image, every one of them. */
export const workloadsList = (image: string, rows: ImageWorkloadRef[] | (() => Promise<ImageWorkloadRef[]>)): FullList<ImageWorkloadRef> => ({
  title: `Workloads that run ${image}`,
  description: "Each with how the internet reaches it, as far as Keelson can read.",
  noun: ["workload", "workloads"],
  columns: WORKLOAD_COLUMNS,
  rows,
  keyOf: workloadKey,
  file: "keelson-workloads",
});

/** An image as it is pulled by name: "registry/repository:tag". */
export const fullRef = (i: ImageRow) => `${imageName(i)}:${imageTag(i)}`;

/**
 * An image as a row of a list in full, and as a line of the Images page's CSV: the table shows what tells images apart
 * (where it runs, who builds it, what was found), the CSV everything the scan kept of it.
 */
export const IMAGE_COLUMNS: FullListColumn<ImageRow>[] = [
  {
    label: "Image",
    value: fullRef,
    copy: { label: "Images (registry/name:tag)", what: ["image", "images"] },
    cell: (i) => (
      <span className="flex flex-col gap-0.5">
        <ImageName image={i} />
        <span className="text-xs text-kumo-subtle">{registryText(i)}</span>
      </span>
    ),
  },
  { label: "In use", value: (i) => IMAGE_USE_LABEL[i.use], cell: (i) => <UseBadge use={i.use} /> },
  {
    label: "Runs in",
    value: (i) => i.workloads.map((w) => `${w.kind} ${w.name} (${workloadPlace(w)})`),
    copy: { label: "Workloads that run them", what: ["workload", "workloads"] },
    cell: (i) =>
      i.workloads.length ? (
        <ul className="flex flex-col gap-0.5">
          {i.workloads.map((w) => (
            <li key={workloadKey(w)}>
              {w.kind} {w.name}
              <span className="text-kumo-subtle">
                {" "}
                · {workloadPlace(w)}
                {w.internet ? " · internet-facing" : ""}
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <span className="text-kumo-subtle">Nothing Keelson reads</span>
      ),
  },
  {
    label: "Built by",
    value: (i) => i.builtBy.map((b) => b.repo),
    copy: { label: "Repositories that build them", what: ["repository", "repositories"] },
    cell: (i) => <BuiltBy builds={i.builtBy} />,
  },
  {
    label: "Vulnerabilities",
    value: (i) => (i.summary ? SEVERITY_ORDER.map((sev) => `${i.summary!.vulns[sev]} ${sev}`).join(", ") : "not scanned"),
    cell: (i) =>
      i.summary ? <VulnCountsView vulns={i.summary.vulns} exploited={i.summary.exploited.length} /> : <span className="text-kumo-subtle">Not scanned</span>,
  },
  { label: "Tags", value: (i) => i.tags, csvOnly: true },
  { label: "Digest", value: (i) => i.digest ?? "", csvOnly: true },
  {
    label: "Image by digest",
    value: (i) => (i.digest ? `${imageName(i)}@${i.digest}` : ""),
    copy: { label: "Images by digest", what: ["image", "images"] },
    csvOnly: true,
  },
  { label: "Registry", value: (i) => REGISTRY_LABEL[i.kind], csvOnly: true },
  { label: "Account", value: (i) => i.account, csvOnly: true },
  { label: "Internet-facing", value: (i) => yesNo(i.workloads.some((w) => w.internet === true)), csvOnly: true },
  {
    label: "Hostnames",
    value: (i) => [...new Set(i.workloads.flatMap((w) => w.hosts))],
    copy: { label: "Hostnames that reach them", what: ["hostname", "hostnames"] },
    csvOnly: true,
  },
  { label: "Operating system", value: (i) => i.summary?.os ?? "", csvOnly: true },
  { label: "Runtimes", value: (i) => (i.summary?.runtimes ?? []).map((r) => `${r.name} ${r.version}`), csvOnly: true },
  { label: "Base image", value: (i) => i.summary?.baseName ?? "", csvOnly: true },
  { label: "Past end of life", value: (i) => (i.summary ? yesNo(i.summary.eol || !!i.summary.runtimes?.some((r) => r.eol)) : ""), csvOnly: true },
  { label: "Components", value: (i) => (i.summary ? String(i.summary.packages) : ""), csvOnly: true },
  { label: "Critical", value: (i) => (i.summary ? String(i.summary.vulns.critical) : ""), csvOnly: true },
  { label: "High", value: (i) => (i.summary ? String(i.summary.vulns.high) : ""), csvOnly: true },
  { label: "Medium", value: (i) => (i.summary ? String(i.summary.vulns.medium) : ""), csvOnly: true },
  { label: "Low", value: (i) => (i.summary ? String(i.summary.vulns.low) : ""), csvOnly: true },
  { label: "Critical or high with a fix", value: (i) => (i.summary ? String(i.summary.fixable.critical + i.summary.fixable.high) : ""), csvOnly: true },
  { label: "Known exploited", value: (i) => i.summary?.exploited ?? [], csvOnly: true },
  { label: "Stored credentials", value: (i) => (i.summary ? String(i.summary.secrets) : ""), csvOnly: true },
  { label: "Open findings", value: (i) => i.findings.filter((f) => f.status === "open" || f.status === "in_progress").map((f) => f.checkId), csvOnly: true },
  { label: "Pushed", value: (i) => i.pushedAt ?? "", csvOnly: true },
  { label: "Last pulled", value: (i) => i.pulledAt ?? "", csvOnly: true },
  { label: "Scanned", value: (i) => i.summary?.scannedAt ?? i.error ?? "not scanned", csvOnly: true },
];
const SEVERITY_ORDER = ["critical", "high", "medium", "low"] as const;
