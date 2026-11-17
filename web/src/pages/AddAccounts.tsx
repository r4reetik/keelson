// Adding accounts, as pages of its own rather than a dialog. /accounts/add is the
// platform catalog: every platform as a card, grouped by category and searchable,
// so it stays easy to scan however many platforms Keelson supports (a new one only
// needs its PROVIDER_INFO entry). /accounts/add/<platform> walks through that
// platform: create the credential with its own steps, paste and verify it, choose
// the accounts and the entity they belong to, see what it can read, and end on a
// summary with what to do next. ?entity=<id> carries the entity it was opened from.
// The credential is only held in memory: a reload starts again from it.

import { useState } from "react";
import { Badge, Button, Empty, Input, LayerCard, Link, Tabs } from "@cloudflare/kumo";
import { ArrowLeftIcon, CheckCircleIcon, MagnifyingGlassIcon, PlusIcon } from "@phosphor-icons/react";
import { useShell } from "../shell.tsx";
import {
  capitalize,
  isProvider,
  link,
  matchesProvider,
  navigate,
  PLATFORM_CATEGORIES,
  plural,
  PROVIDER_INFO,
  PROVIDERS,
  setParams,
  useApi,
  useLocation,
  type AccountsResponse,
  type PlatformCategory,
  type ProviderId,
} from "../lib.ts";
import { Card, Page, PageState, ProviderIcon, Steps } from "../components/ui.tsx";
import { AccountsStep, CredentialStep, EntityStep, PermissionsStep, TokenHelp, useConnect, type Connected } from "../components/connect.tsx";

type Entity = AccountsResponse["entities"][number];

const TITLE = "Add accounts";
const STEPS = ["Platform", "Credential", "Accounts", "Done"];
/** The steps in a platform's own words: "Teams" on Vercel, "Organizations" on GitHub. */
const stepsFor = (p: ProviderId) => ["Platform", "Credential", capitalize(PROVIDER_INFO[p].accounts), "Done"];
const CATEGORIES = Object.keys(PLATFORM_CATEGORIES) as PlatformCategory[];
/** Where to ask for a platform that isn't here yet. */
const REQUEST = "https://github.com/r4reetik/keelson/discussions";

/** The entities and their accounts: who already has what, and where new accounts can go. */
function useEntities() {
  const { dataVersion } = useShell();
  return useApi<{ entities: Entity[] }>("/api/accounts", [dataVersion]);
}

/** The entity the flow was opened from (?entity=<id>), when it is one the user can see. */
function useEntityParam(entities: Entity[] | undefined): Entity | undefined {
  const { params } = useLocation();
  const id = Number(params.get("entity"));
  return id ? entities?.find((e) => e.id === id) : undefined;
}

const withEntity = (path: string, entity?: Entity) => (entity ? `${path}?entity=${entity.id}` : path);

// ---- the catalog

export function AddAccountsPage() {
  const { data, error, loading, reload } = useEntities();
  const { params } = useLocation();
  const entity = useEntityParam(data?.entities);
  const q = params.get("q") || "";
  const category = (CATEGORIES as string[]).includes(params.get("category") || "") ? (params.get("category") as PlatformCategory) : null;
  const description = entity
    ? `Choose a platform to add ${entity.name}'s accounts on. Each platform shows how to create a read-only credential there.`
    : "Choose a platform. Each one shows how to create a read-only credential there, then you pick the accounts to scan and the entity they belong to.";
  if (error || !data) return <PageState title={TITLE} description={description} error={error} loading={loading} empty={false} retry={reload} />;

  const connected = (p: ProviderId) => data.entities.flatMap((e) => e.accounts).filter((a) => a.provider === p).length;
  const shown = PROVIDERS.filter((p) => (!category || PROVIDER_INFO[p].category === category) && matchesProvider(p, q));
  // Without a filter the catalog reads by category; a search or a chosen category is one list.
  const groups =
    q || category
      ? [{ key: "found", label: null, list: shown }]
      : CATEGORIES.map((c) => ({ key: c, label: c, list: shown.filter((p) => PROVIDER_INFO[p].category === c) }));

  return (
    <Page title={TITLE} description={description}>
      <Steps steps={STEPS} current={0} />
      <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <Tabs
          variant="segmented"
          value={category ?? "all"}
          onValueChange={(v: string) => setParams({ category: v === "all" ? null : v })}
          tabs={[{ value: "all", label: "All" }, ...CATEGORIES.map((c) => ({ value: c, label: PLATFORM_CATEGORIES[c].label }))]}
        />
        <Input
          className="w-full md:w-72"
          aria-label="Search platforms"
          placeholder="Search platforms or services"
          value={q}
          onChange={(e) => setParams({ q: e.target.value || null })}
        />
      </div>

      {!shown.length ? (
        <LayerCard>
          <Empty
            icon={<MagnifyingGlassIcon size={32} />}
            title={`Nothing matches "${q}"`}
            description="Search by a platform's name or one of its services, such as S3, Workers or OSS."
            contents={
              <Button variant="secondary" onClick={() => setParams({ q: null, category: null })}>
                Show every platform
              </Button>
            }
          />
        </LayerCard>
      ) : (
        groups
          .filter((g) => g.list.length)
          .map((g) => (
            <section key={g.key} className="flex flex-col gap-3">
              {g.label && (
                <div>
                  <h2 className="m-0 text-base font-semibold text-kumo-default">{PLATFORM_CATEGORIES[g.label as PlatformCategory].label}</h2>
                  <p className="m-0 text-sm text-kumo-subtle">{PLATFORM_CATEGORIES[g.label as PlatformCategory].description}</p>
                </div>
              )}
              <ul className="m-0 grid list-none grid-cols-1 gap-3 p-0 sm:grid-cols-2 xl:grid-cols-3">
                {g.list.map((p) => (
                  <li key={p} className="flex">
                    <PlatformCard provider={p} connected={connected(p)} href={withEntity(`/accounts/add/${p}`, entity)} />
                  </li>
                ))}
              </ul>
            </section>
          ))
      )}

      <p className="m-0 text-sm text-kumo-subtle">
        Don't see your platform? Google Cloud and Google Workspace are next.{" "}
        <Link href={REQUEST} target="_blank" rel="noopener noreferrer">
          Ask for another
        </Link>
        .
      </p>
    </Page>
  );
}

/** What connecting a platform takes, in a few words: "Read-only access key", "Shodan API key, optional". */
function credentialLine(provider: ProviderId): string {
  const info = PROVIDER_INFO[provider];
  if (info.fields.every((f) => f.optional)) return `${capitalize(info.credential)}, optional`;
  // Where the platform can't issue a read-only credential, Keelson's GET-only rule is what keeps it reading.
  return info.readOnlyCredential ? `Read-only ${info.credential}` : `${capitalize(info.credential)}, used only to read`;
}

/** One platform in the catalog: its mark, what Keelson checks there, and how many of its accounts are connected. */
function PlatformCard({ provider, connected, href }: { provider: ProviderId; connected: number; href: string }) {
  const info = PROVIDER_INFO[provider];
  return (
    <a
      {...link(href)}
      className="group flex w-full flex-col gap-3 rounded-lg border border-kumo-line bg-kumo-base p-4 no-underline transition-colors hover:border-kumo-brand focus-visible:outline-2 focus-visible:outline-kumo-brand"
    >
      <span className="flex items-center gap-3">
        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-kumo-recessed">
          <ProviderIcon provider={provider} className="h-5 w-5 text-kumo-default" />
        </span>
        <span className="min-w-0 flex-1">
          <span className="block truncate text-base font-semibold text-kumo-default">{info.label}</span>
          <span className="block text-sm text-kumo-subtle">{credentialLine(provider)}</span>
        </span>
        {connected > 0 && <Badge variant="neutral">{info.perEntity ? `${connected} watched` : `${connected} connected`}</Badge>}
      </span>
      <span className="text-sm text-kumo-subtle">{info.blurb}</span>
    </a>
  );
}

// ---- one platform

export function AddPlatformPage({ params: route }: { params: Record<string, string> }) {
  const { data, error, loading, reload } = useEntities();
  const entity = useEntityParam(data?.entities);
  const provider = isProvider(route.platform) ? route.platform : null;
  if (!provider)
    return (
      <Page title={TITLE}>
        <LayerCard>
          <Empty
            title="Keelson doesn't connect to that platform"
            description="Choose one from the list of platforms."
            contents={<Button onClick={() => navigate("/accounts/add")}>See every platform</Button>}
          />
        </LayerCard>
      </Page>
    );
  const info = PROVIDER_INFO[provider];
  const title = info.perEntity ? "Watch from the internet" : `Add ${info.label} ${info.accounts}`;
  if (error || !data) return <PageState title={title} description={info.covers} error={error} loading={loading} empty={false} retry={reload} />;
  // A credential belongs to one platform: switching platforms starts again.
  return <PlatformFlow key={provider} provider={provider} entities={data.entities} entity={entity} />;
}

function PlatformFlow({ provider, entities, entity }: { provider: ProviderId; entities: Entity[]; entity?: Entity }) {
  const { limited, refreshSession, empty } = useShell();
  const info = PROVIDER_INFO[provider];
  const c = useConnect({ provider, entities, defaultEntityId: entity?.id, newEntity: !limited });
  const [done, setDone] = useState<{ result: Connected; entity: string; first: boolean } | null>(null);
  const cred = info.credential;
  const verb = info.perEntity ? "watch" : "scan";
  const step = done ? 3 : c.valid && c.accounts.length ? 2 : 1;

  const finish = async () => {
    const first = empty;
    const r = await c.save();
    if (!r) return;
    await refreshSession();
    setDone({ result: r, entity: c.targetName, first });
    window.scrollTo({ top: 0 });
  };

  const back = (
    <Link href={withEntity("/accounts/add", entity)} className="inline-flex items-center gap-1.5 text-sm">
      <ArrowLeftIcon /> All platforms
    </Link>
  );
  // The mark sits in the text flow, so a title that wraps on a phone doesn't leave it on a line of its own.
  const heading = (
    <>
      <span className="mr-3 inline-flex h-9 w-9 items-center justify-center rounded-md bg-kumo-recessed align-middle">
        <ProviderIcon provider={provider} className="h-5 w-5 text-kumo-default" />
      </span>
      {info.perEntity ? "Watch from the internet" : `Add ${info.label} ${info.accounts}`}
    </>
  );
  const description = `Keelson checks ${info.covers}${entity ? `, for ${entity.name}` : ""}. It only reads.`;

  if (done) return <Done provider={provider} done={done} entity={entity} heading={heading} description={description} />;

  return (
    <Page title={heading} description={description} actions={back}>
      <Steps steps={stepsFor(provider)} current={step} />
      <div className="grid grid-cols-1 items-start gap-6 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
        <Card title={info.fields.every((f) => f.optional) ? `Before you start` : `Create the ${cred}`} className="lg:sticky lg:top-20">
          <TokenHelp provider={provider} />
        </Card>
        <div className="flex min-w-0 flex-col gap-6">
          <Card title={info.fields.every((f) => f.optional) ? `Add a ${cred}, if you have one` : `Paste the ${cred}`}>
            <CredentialStep c={c} />
          </Card>
          <Card title={`Choose the ${info.accounts} to ${verb}`}>
            {c.valid && c.accounts.length ? (
              <AccountsStep c={c} />
            ) : (
              <p className="m-0 text-sm text-kumo-subtle">
                {info.perEntity
                  ? `Once you continue, the ${info.accounts} Sonar can watch are listed here.`
                  : `Once the ${cred} is verified, the ${info.accounts} it can reach are listed here.`}
              </p>
            )}
          </Card>
          {!info.perEntity && (
            <Card title="Choose the entity">
              {c.valid && c.ids.length ? (
                <EntityStep c={c} />
              ) : (
                <p className="m-0 text-sm text-kumo-subtle">
                  The company or team that owns these {info.accounts}. An entity can hold accounts on every platform.
                </p>
              )}
            </Card>
          )}
          <Card
            title={`Check what the ${cred} can read`}
            footer={
              <>
                {c.err && c.valid && <span className="mr-auto text-sm text-kumo-danger">{c.err}</span>}
                <Button
                  variant="primary"
                  icon={<PlusIcon />}
                  disabled={!c.valid || !c.ids.length || c.busy === "verify"}
                  loading={c.busy === "save"}
                  onClick={finish}
                >
                  {`${info.perEntity ? "Watch" : "Add"} ${c.ids.length ? plural(c.ids.length, info.account, info.accounts) : info.accounts} and scan`}
                </Button>
              </>
            }
          >
            {c.valid && c.accounts.length ? (
              <PermissionsStep c={c} />
            ) : (
              <p className="m-0 text-sm text-kumo-subtle">
                Keelson tries each data source it reads, so you see which checks would be skipped before anything is added.
              </p>
            )}
          </Card>
        </div>
      </div>
    </Page>
  );
}

/** The end of the flow: what was added and where, and what to do next. */
function Done({
  provider,
  done,
  entity,
  heading,
  description,
}: {
  provider: ProviderId;
  done: { result: Connected; entity: string; first: boolean };
  entity?: Entity;
  heading: React.ReactNode;
  description: string;
}) {
  const info = PROVIDER_INFO[provider];
  const added = done.result.added.length;
  const what = added ? plural(added, info.account, info.accounts) : `The ${info.credential}`;
  const title = !added
    ? `${capitalize(info.credential)} replaced`
    : info.perEntity
      ? `Sonar is watching ${what}`
      : `${capitalize(what)} added${done.entity ? ` to ${done.entity}` : ""}`;
  return (
    <Page title={heading} description={description}>
      <Steps steps={stepsFor(provider)} current={3} />
      <LayerCard>
        <Empty
          icon={<CheckCircleIcon size={32} weight="fill" className="text-kumo-success" />}
          title={title}
          description={
            done.first
              ? "The first scan has started. Its findings show up on the Overview as soon as it finishes."
              : "Scans have started. Their findings show up on the Overview and Findings pages as each one finishes."
          }
          contents={
            <div className="flex flex-wrap justify-center gap-2">
              <Button variant="primary" onClick={() => navigate("/")}>
                Open the Overview
              </Button>
              <Button variant="secondary" icon={<PlusIcon />} onClick={() => navigate(withEntity("/accounts/add", entity))}>
                {entity ? `Add another platform to ${entity.name}` : "Add another platform"}
              </Button>
              <Button variant="ghost" onClick={() => navigate("/accounts")}>
                Back to Accounts
              </Button>
            </div>
          }
        />
      </LayerCard>
    </Page>
  );
}
