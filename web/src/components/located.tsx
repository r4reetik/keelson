// "In your infrastructure": the addresses and hostnames a finding names, followed into
// the entity's other accounts (src/server/locate.ts). A Cloudflare finding about an
// address says which ECS instance or EC2 load balancer holds it, a hostname the DNS
// record and load balancer it goes through, and, for a finding about a port, whether
// the holder's security groups really let anyone reach it. Loaded on its own, so the
// finding shows at once and this fills in.

import { Badge, Link } from "@cloudflare/kumo";
import { CheckCircleIcon, QuestionIcon, WarningCircleIcon } from "@phosphor-icons/react";
import { dashboardName, useApi, type LocatedItem, type LocatedResponse } from "../lib.ts";
import { ProviderIcon } from "./ui.tsx";

const STATUS: Record<LocatedItem["status"], { text: string; variant: "success" | "warning" | "neutral" | "outline" }> = {
  found: { text: "In your accounts", variant: "success" },
  released: { text: "Released", variant: "warning" },
  outside: { text: "Not in your accounts", variant: "neutral" },
  unknown: { text: "Not found", variant: "outline" },
};

export function LocatedSection({ fingerprint }: { fingerprint: string }) {
  const { data } = useApi<LocatedResponse>(`/api/finding/${fingerprint}/located`);
  if (!data?.items.length) return null;
  return (
    <div>
      <div className="mb-1 text-xs font-medium uppercase tracking-wide text-kumo-subtle">In your infrastructure</div>
      <ul className="flex flex-col gap-3">
        {data.items.map((item) => (
          <Item key={`${item.kind}:${item.value}`} item={item} />
        ))}
      </ul>
    </div>
  );
}

function Item({ item }: { item: LocatedItem }) {
  const status = STATUS[item.status];
  return (
    <li className="rounded-md border border-kumo-hairline p-3">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <span className="break-all font-mono text-kumo-default">{item.value}</span>
        <Badge variant={status.variant}>{status.text}</Badge>
      </div>
      <p className="mt-1 text-kumo-default">{item.summary}</p>
      {item.steps.length > 0 && (
        <ol className="mt-2 flex flex-col gap-1.5">
          {item.steps.map((s, i) => (
            <li key={i} className="flex gap-2">
              <span className="mt-0.5 inline-flex h-4 w-4 shrink-0 items-center justify-center">
                {s.provider ? <ProviderIcon provider={s.provider} className="h-3.5 w-3.5" /> : <span className="h-1.5 w-1.5 rounded-full bg-kumo-recessed" />}
              </span>
              <div className="min-w-0">
                <span className="text-xs text-kumo-subtle">{s.label}</span>
                <div className="break-words text-kumo-default">
                  {s.value}
                  {s.link && (
                    <>
                      {" "}
                      <Link href={s.link} target="_blank" rel="noopener noreferrer">
                        Open in the {dashboardName(s.link)}
                      </Link>
                    </>
                  )}
                </div>
              </div>
            </li>
          ))}
        </ol>
      )}
      {item.ports.length > 0 && (
        <ul className="mt-2 flex flex-col gap-1">
          {item.ports.map((p, i) => (
            <li key={i} className="flex items-start gap-2">
              {p.open === true ? (
                <WarningCircleIcon weight="fill" className="mt-0.5 h-4 w-4 shrink-0 text-kumo-danger" aria-label={`${p.service} is reachable`} />
              ) : p.open === false ? (
                <CheckCircleIcon weight="fill" className="mt-0.5 h-4 w-4 shrink-0 text-kumo-success" aria-label={`${p.service} isn't open to anyone`} />
              ) : (
                <QuestionIcon className="mt-0.5 h-4 w-4 shrink-0 text-kumo-subtle" aria-label="Unknown" />
              )}
              <span>
                <span className="font-medium">{p.service}</span>: {p.detail}
              </span>
            </li>
          ))}
        </ul>
      )}
    </li>
  );
}
