// Pieces the Images page, an image's own page and a repository's page share: how
// much an image is in use, its vulnerabilities by severity, who builds it, and the
// workloads that run it with how the internet reaches them.

import type { ReactNode } from "react";
import { Badge, Link, Tooltip } from "@cloudflare/kumo";
import { CloudArrowDownIcon, CubeIcon, GlobeIcon, PlayIcon } from "@phosphor-icons/react";
import {
  IMAGE_USE_LABEL,
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
export function Reach({ internet, via, hosts }: Pick<ImageWorkloadRef, "internet" | "via" | "hosts">) {
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
          {hosts.length > 3 ? ` and ${num(hosts.length - 3)} more` : ""}
        </span>
      )}
    </span>
  );
}
