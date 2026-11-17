// The parts of adding a platform's accounts, which the Add accounts page
// (web/src/pages/AddAccounts.tsx) lays out as steps: how to create the credential
// (TokenHelp, one per provider), the credential and its check, the accounts it
// reaches, the entity they belong to, and what it can read. The state lives in
// useConnect; everything is worded from PROVIDER_INFO, so nothing branches on a
// provider's name.

import { useEffect, useMemo, useState } from "react";
import { Badge, Banner, Button, CodeBlock, Input, Link, Select, SensitiveInput, Table, LayerCard, useKumoToastManager } from "@cloudflare/kumo";
import { ArrowSquareOutIcon, CheckCircleIcon, WarningIcon, XCircleIcon } from "@phosphor-icons/react";
import {
  accountIdForEntity,
  alibabaPolicy,
  api,
  capitalize,
  CREDENTIAL_SEPARATOR,
  githubAppTemplate,
  plural,
  PROVIDER_INFO,
  sameName,
  type ProviderId,
  type SessionEntity,
  type TemplateResponse,
} from "../lib.ts";
import { FormGrid } from "./ui.tsx";
import type { PermissionProbe, VisibleAccount, VerifyResponse, AddAccountsResponse } from "../lib.ts";
type Probe = PermissionProbe;
type Verify = VerifyResponse;
export type Connected = AddAccountsResponse;

const NEW = "new";

/** How to create the credential, one set of steps per provider. A new provider doesn't compile until it has one. */
const TOKEN_HELP: Record<ProviderId, () => React.ReactNode> = {
  cloudflare: CloudflareTokenHelp,
  vercel: VercelTokenHelp,
  aws: AwsTokenHelp,
  alibaba: AlibabaTokenHelp,
  github: GithubTokenHelp,
  internet: InternetTokenHelp,
};

export function TokenHelp({ provider = "cloudflare" }: { provider?: ProviderId }) {
  const Help = TOKEN_HELP[provider];
  return <Help />;
}

/** The credential as it is sent and stored: one field as it is, several joined in order. */
export const joinCredential = (values: string[]) => (values.every((v) => v) ? values.join(CREDENTIAL_SEPARATOR) : "");

/**
 * The provider's credential inputs: one for a token, two for an AWS access key. Secret fields
 * are hidden while typing. The description sits under the last field.
 */
export function CredentialFields({
  provider,
  values,
  onChange,
  onEnter,
  description,
  error,
}: {
  provider: ProviderId;
  values: string[];
  onChange: (values: string[]) => void;
  onEnter?: () => void;
  description?: string;
  error?: string;
}) {
  const fields = PROVIDER_INFO[provider].fields;
  const inputs = fields.map((f, i) => {
    const last = i === fields.length - 1;
    const props = {
      className: "w-full",
      label: f.label,
      placeholder: f.placeholder,
      value: values[i] ?? "",
      onChange: (e: React.ChangeEvent<HTMLInputElement>) => onChange(fields.map((_, j) => (j === i ? e.target.value.trim() : (values[j] ?? "")))),
      // Enter submits a pasted credential, like a form.
      onKeyDown: (e: React.KeyboardEvent) => {
        if (e.key === "Enter") onEnter?.();
      },
      description: last ? description : undefined,
      variant: (last && error ? "error" : "default") as "error" | "default",
      error: last ? error || undefined : undefined,
    };
    return f.secret ? <SensitiveInput key={f.label} {...props} /> : <Input key={f.label} {...props} autoComplete="off" spellCheck={false} />;
  });
  return fields.length > 1 ? <FormGrid>{inputs}</FormGrid> : inputs[0];
}

function CloudflareTokenHelp() {
  const [url, setUrl] = useState<string | null>(null);
  useEffect(() => {
    api<TemplateResponse>("/api/accounts/template?provider=cloudflare")
      .then((r) => setUrl(r.url))
      .catch(() => {});
  }, []);
  return (
    <ol className="ml-5 list-decimal space-y-2 text-base text-kumo-default marker:text-kumo-subtle">
      <li>
        In the Cloudflare dashboard, go to <span className="font-medium">My Profile → API Tokens → Create Token</span> and pick the{" "}
        <span className="font-medium">Read all resources</span> template. It covers every check and can only read.{" "}
        <Link href="https://dash.cloudflare.com/profile/api-tokens" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1">
          Open API Tokens <ArrowSquareOutIcon />
        </Link>
      </li>
      <li>
        Prefer the smallest grant?{" "}
        {url ? (
          <Link href={url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1">
            Start from a pre-filled read-only token <ArrowSquareOutIcon />
          </Link>
        ) : (
          "Start from a pre-filled read-only token"
        )}{" "}
        and add the Security Center, Tunnel, Notifications and Access read permissions that the template link can't pre-fill.
      </li>
      <li>
        Include the accounts you want to scan. One token can cover several accounts; accounts that belong to another company usually need their own token,
        created by someone with access to them.
      </li>
    </ol>
  );
}

function VercelTokenHelp() {
  return (
    <ol className="ml-5 list-decimal space-y-2 text-base text-kumo-default marker:text-kumo-subtle">
      <li>
        In Vercel, go to <span className="font-medium">Account Settings → Tokens</span> and create a token named Keelson.{" "}
        <Link href="https://vercel.com/account/settings/tokens" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1">
          Open Tokens <ArrowSquareOutIcon />
        </Link>
      </li>
      <li>
        Set <span className="font-medium">Scope</span> to the team you want to scan, or <span className="font-medium">Full Account</span> for every team you
        belong to and your personal projects. Choose an expiration date.
      </li>
      <li>Keelson only reads from Vercel. Teams that belong to another company usually need their own token, created by one of their members.</li>
    </ol>
  );
}

function AwsTokenHelp() {
  return (
    <ol className="ml-5 list-decimal space-y-2 text-base text-kumo-default marker:text-kumo-subtle">
      <li>
        In the AWS console, go to <span className="font-medium">IAM → Users → Create user</span>. Name it keelson and leave console access off.{" "}
        <Link href="https://console.aws.amazon.com/iam/home#/users/create" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1">
          Open IAM <ArrowSquareOutIcon />
        </Link>
      </li>
      <li>
        Choose <span className="font-medium">Attach policies directly</span> and attach AWS's managed <span className="font-medium">SecurityAudit</span> policy.
        It reads configuration only: it can't change anything, and it can't read what is stored in your buckets or databases.
      </li>
      <li>
        Open the user, go to <span className="font-medium">Security credentials → Create access key</span>, choose{" "}
        <span className="font-medium">Application running outside AWS</span>, and paste the key ID and the secret into Keelson. An access key belongs to one AWS
        account, so each account needs its own.
      </li>
    </ol>
  );
}

function AlibabaTokenHelp() {
  const toasts = useKumoToastManager();
  const policy = alibabaPolicy();
  return (
    <ol className="ml-5 list-decimal space-y-2 text-base text-kumo-default marker:text-kumo-subtle">
      <li>
        In the RAM console, go to <span className="font-medium">Permissions → Policies → Create Policy</span>, choose the JSON editor, and paste this policy.
        Name it keelson-read-only. It lists only the reads Keelson makes: it can't change anything, and it can't read the files in your OSS buckets or the
        values of your secrets, which Alibaba Cloud's ReadOnlyAccess policy can.{" "}
        <Link href="https://ram.console.alibabacloud.com/policies/new" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1">
          Open RAM <ArrowSquareOutIcon />
        </Link>
        <div className="mt-2 max-h-48 overflow-y-auto">
          <CodeBlock lang="jsonc" code={policy} />
        </div>
        <Button
          className="mt-2"
          size="sm"
          onClick={() =>
            navigator.clipboard
              .writeText(policy)
              .then(() => toasts.add({ title: "Policy copied", variant: "success" }))
              .catch(() => {})
          }
        >
          Copy policy
        </Button>
      </li>
      <li>
        Go to <span className="font-medium">Identities → Users → Create User</span>, name it keelson, and choose{" "}
        <span className="font-medium">Using permanent AccessKey to access</span> only, without console access. Then give it the keelson-read-only policy under{" "}
        <span className="font-medium">Add Permissions</span>.
      </li>
      <li>
        Copy the AccessKey ID and AccessKey secret it shows, and paste them into Keelson. An AccessKey belongs to one Alibaba Cloud account, so each account
        needs its own. Don't use the main account's AccessKey.
      </li>
    </ol>
  );
}

function GithubTokenHelp() {
  const [org, setOrg] = useState("");
  return (
    <ol className="ml-5 list-decimal space-y-2 text-base text-kumo-default marker:text-kumo-subtle">
      <li className="space-y-2">
        <div>Register a GitHub App for Keelson in the organization you want to scan. The link fills in read-only permissions and no webhook.</div>
        <div className="flex flex-wrap items-center gap-3">
          <Input
            className="w-56"
            aria-label="Organization"
            placeholder="Organization name"
            value={org}
            onChange={(e) => setOrg(e.target.value.trim())}
            autoComplete="off"
            spellCheck={false}
          />
          <Link href={githubAppTemplate(org || null)} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1">
            Register the App{org ? ` in ${org}` : ""} <ArrowSquareOutIcon />
          </Link>
        </div>
      </li>
      <li>
        Check the permissions are all <span className="font-medium">Read-only</span>, then choose <span className="font-medium">Create GitHub App</span>. App
        names are unique across GitHub, so change the name if it's taken.
      </li>
      <li>
        On the App's page, copy the <span className="font-medium">App ID</span>. Under <span className="font-medium">Private keys</span>, choose{" "}
        <span className="font-medium">Generate a private key</span> and paste the whole downloaded file into Keelson.
      </li>
      <li>
        Choose <span className="font-medium">Install App</span> and install it on the organization, on all repositories or the ones to scan. To scan more
        organizations with one App, make it public under <span className="font-medium">Advanced</span> and install it on each. Keelson only reads, and asks
        GitHub for a read-only token on every scan.
      </li>
    </ol>
  );
}

function InternetTokenHelp() {
  return (
    <ol className="ml-5 list-decimal space-y-2 text-base text-kumo-default marker:text-kumo-subtle">
      <li>
        Sonar watches an entity from outside. It starts from the domains, DNS records and addresses of the entity's other accounts, finds more hostnames in
        certificate transparency logs, and asks Shodan what it has seen open on the entity's addresses. It sends nothing to your hosts.
      </li>
      <li>It sends the entity's domain names to crt.sh and Shodan, and its public addresses to Shodan.</li>
      <li>
        A Shodan API key is optional. With one, Keelson also gets the product and version on each port and the subdomains Shodan knows; without one it uses
        Shodan's free InternetDB.{" "}
        <Link href="https://account.shodan.io/" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1">
          Open your Shodan account <ArrowSquareOutIcon />
        </Link>
      </li>
      <li>Choose the entities to watch. Connect their other accounts first: Sonar starts from what those know.</li>
    </ol>
  );
}

export interface ConnectOptions {
  provider: ProviderId;
  entities: SessionEntity[];
  /** The entity the flow was opened from: its accounts go there, and Sonar watches it. */
  defaultEntityId?: number;
  /** Offer "New entity…". Off for someone an admin limited to some entities. */
  newEntity: boolean;
}

/**
 * The state of adding one platform's accounts: the credential, what it can reach, which of those to add, the entity
 * they belong to and what the credential can read. A credential belongs to one provider, so use it under
 * key={provider}. It never leaves memory: a reload starts again from the credential.
 */
export function useConnect({ provider, entities, defaultEntityId, newEntity }: ConnectOptions) {
  const info = PROVIDER_INFO[provider];
  // A per-entity provider (Sonar) lists entities rather than accounts, and its credential may be left empty.
  const perEntity = !!info.perEntity;
  const optional = info.fields.every((f) => f.optional);
  const [values, setValuesRaw] = useState<string[]>(() => info.fields.map(() => ""));
  const token = joinCredential(values);
  const [result, setResult] = useState<Verify | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [probedKey, setProbedKey] = useState("");
  const [entity, setEntity] = useState(defaultEntityId != null ? String(defaultEntityId) : entities[0] ? String(entities[0].id) : NEW);
  const [entityName, setEntityName] = useState("");
  const [busy, setBusy] = useState<"verify" | "save" | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const ids = useMemo(() => [...selected].sort(), [selected]);
  // The server probes permissions on the first few accounts only; it says how many.
  const probeLimit = result?.probeLimit ?? ids.length;
  const key = ids.slice(0, probeLimit).join(",");

  const verify = async (accountIds: string[]) => {
    setBusy("verify");
    setErr(null);
    try {
      const r = await api<Verify>("/api/accounts/verify", { method: "POST", body: { provider, token, accountIds } });
      setResult(r);
      setProbedKey(accountIds.slice(0, r.probeLimit).join(","));
      // First check of a credential: select every account it can see that isn't added yet, then check those.
      if (r.token.valid && !accountIds.length) {
        // A credential that reaches an account already added most likely belongs to the same company.
        const sibling = r.accounts.find((a) => a.added && a.entityId != null);
        if (defaultEntityId == null && sibling && entities.some((e) => e.id === sibling.entityId)) setEntity(String(sibling.entityId));
        const fresh = r.accounts
          // Opened from one entity, Sonar watches that one; the others can still be ticked.
          .filter((a) => !a.added && (!perEntity || defaultEntityId == null || a.id === accountIdForEntity(defaultEntityId)))
          .map((a) => a.id)
          .sort();
        setSelected(new Set(fresh));
        if (fresh.length) await verify(fresh);
      }
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const valid = !!result?.token.valid;
  const accounts = result?.accounts || [];
  const suggestedName = accounts.find((a) => a.id === ids[0])?.name || "My organization";

  const save = async (): Promise<Connected | null> => {
    setBusy("save");
    setErr(null);
    try {
      const target = entity === NEW ? { entityName: entityName.trim() || suggestedName } : { entityId: Number(entity) };
      const r = await api<Connected>("/api/accounts", { method: "POST", body: { provider, token, accountIds: ids, ...target } });
      setBusy(null);
      return r;
    } catch (e) {
      setErr((e as Error).message);
      setBusy(null);
      return null;
    }
  };

  const probes = mergeProbes(result?.probes || {}, accounts);
  return {
    provider,
    info,
    perEntity,
    optional,
    entities,
    newEntity,
    values,
    /** A changed credential is a new one: what the old one could see no longer applies. */
    setValues: (v: string[]) => {
      setValuesRaw(v);
      setResult(null);
      setSelected(new Set());
    },
    reset: () => {
      setValuesRaw(info.fields.map(() => ""));
      setResult(null);
      setSelected(new Set());
      setErr(null);
    },
    token,
    result,
    valid,
    accounts,
    ids,
    selected,
    toggle: (id: string, on: boolean) =>
      setSelected((s) => {
        const n = new Set(s);
        if (on) n.add(id);
        else n.delete(id);
        return n;
      }),
    selectAll: (on: boolean) => setSelected(new Set(on ? accounts.map((a) => a.id) : [])),
    entity,
    setEntity,
    entityName,
    setEntityName,
    suggestedName,
    // Typing the name of an entity that already exists most likely means that entity, not a second one.
    existing: entity === NEW ? entities.find((e) => sameName(e.name, entityName || suggestedName)) : undefined,
    targetName: entity === NEW ? entityName.trim() || suggestedName : (entities.find((e) => String(e.id) === entity)?.name ?? ""),
    probes,
    gaps: probes.filter((p) => !p.ok),
    probeLimit,
    /** The selection changed since the permissions were checked. */
    stale: valid && ids.length > 0 && key !== probedKey,
    busy,
    err,
    verify,
    save,
  };
}
export type Connect = ReturnType<typeof useConnect>;

/** The credential's inputs, the check, and what was wrong with it. */
export function CredentialStep({ c }: { c: Connect }) {
  const { info, optional, token, result, valid, busy, err, accounts } = c;
  const cred = info.credential;
  return (
    <div className="flex flex-col gap-4">
      <CredentialFields
        provider={c.provider}
        values={c.values}
        onChange={c.setValues}
        onEnter={() => {
          if ((token || optional) && !result && !busy) void c.verify([]);
        }}
        description={`${optional ? "Leave it empty to use only what needs no key. " : ""}Stored only on this machine, readable by your user only. It is never shown again or sent anywhere except ${info.apiHost}.`}
      />
      {err && !valid && <Banner variant="error" icon={<XCircleIcon weight="fill" />} title="Something went wrong" description={err} />}
      {result && !valid && (
        <Banner
          variant="error"
          icon={<XCircleIcon weight="fill" />}
          title={`${info.label} rejected this ${cred}`}
          description={result.token.message || "Check that it was copied completely and hasn't expired."}
        />
      )}
      {valid && !accounts.length && (
        <Banner variant="alert" icon={<WarningIcon weight="fill" />} title={`This ${cred} can't see any ${info.account}`} description={info.noAccounts} />
      )}
      <div className="flex flex-wrap items-center justify-end gap-2">
        {valid ? (
          <>
            <span className="mr-auto inline-flex items-center gap-1.5 text-sm text-kumo-default">
              <CheckCircleIcon weight="fill" className="text-kumo-success" />
              {capitalize(cred)} accepted. It reaches {plural(accounts.length, info.account, info.accounts)}.
            </span>
            <Button variant="secondary" onClick={c.reset}>
              Use another {cred}
            </Button>
          </>
        ) : (
          <Button variant="primary" disabled={!token && !optional} loading={busy === "verify"} onClick={() => c.verify([])}>
            {optional && !token ? "Continue without a key" : `Verify ${cred}`}
          </Button>
        )}
      </div>
    </div>
  );
}

/** The accounts (or, for Sonar, the entities) the credential reaches, to tick the ones to add. */
export function AccountsStep({ c }: { c: Connect }) {
  const { info, perEntity, accounts, ids, selected } = c;
  const Unit = capitalize(info.account);
  const entityOf = (id: number | null) => c.entities.find((e) => e.id === id)?.name;
  const [q, setQ] = useState("");
  const shown = accounts.filter((a) => !q || `${a.name} ${a.id}`.toLowerCase().includes(q.trim().toLowerCase()));
  return (
    <div className="flex flex-col gap-3">
      {accounts.length > 8 && (
        <Input
          className="w-full sm:w-72"
          aria-label={`Search ${info.accounts}`}
          placeholder={`Search ${info.accounts}`}
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
      )}
      <LayerCard className="max-h-80 overflow-auto bg-kumo-base p-0">
        <Table layout="auto">
          <Table.Header variant="compact">
            <Table.Row>
              <Table.CheckHead
                aria-label="Select all"
                checked={ids.length === accounts.length}
                indeterminate={ids.length > 0 && ids.length < accounts.length}
                onCheckedChange={() => c.selectAll(ids.length !== accounts.length)}
              />
              <Table.Head>{Unit}</Table.Head>
              {!perEntity && <Table.Head>{Unit} ID</Table.Head>}
              <Table.Head>
                <span className="sr-only">State</span>
              </Table.Head>
            </Table.Row>
          </Table.Header>
          <Table.Body>
            {shown.map((a) => (
              <Table.Row
                key={a.id}
                variant={selected.has(a.id) ? "selected" : "default"}
                className="cursor-pointer"
                onClick={() => c.toggle(a.id, !selected.has(a.id))}
              >
                <Table.CheckCell
                  checked={selected.has(a.id)}
                  onCheckedChange={(v: boolean) => c.toggle(a.id, v)}
                  onClick={(e: React.MouseEvent) => e.stopPropagation()}
                  aria-label={`${perEntity ? "Watch" : "Scan"} ${a.name}`}
                />
                <Table.Cell className="max-w-64 truncate text-kumo-default">{a.name}</Table.Cell>
                {!perEntity && <Table.Cell className="font-mono text-xs text-kumo-subtle">{a.id}</Table.Cell>}
                <Table.Cell className="whitespace-nowrap text-right">
                  {a.added && (
                    <Badge variant="neutral">
                      {selected.has(a.id)
                        ? `${capitalize(info.credential)} will be replaced`
                        : perEntity
                          ? "Watched"
                          : `Added${entityOf(a.entityId) ? ` to ${entityOf(a.entityId)}` : ""}`}
                    </Badge>
                  )}
                </Table.Cell>
              </Table.Row>
            ))}
          </Table.Body>
        </Table>
      </LayerCard>
      <span className="text-sm text-kumo-subtle">
        {ids.length
          ? `${plural(ids.length, info.account, info.accounts)} selected.`
          : perEntity && accounts.every((a) => a.added)
            ? `Every ${info.account} is already watched.`
            : `Select at least one ${info.account}.`}
      </span>
    </div>
  );
}

/** Which entity the new accounts belong to: an existing one, or a new one with a name. */
export function EntityStep({ c }: { c: Connect }) {
  const { info, entities, entity, existing } = c;
  return (
    <FormGrid>
      {entities.length > 0 && (
        <Select
          className="w-full"
          label="Entity"
          hideLabel={false}
          value={entity}
          onValueChange={(v) => c.setEntity(String(v))}
          description={`The company or team that owns these ${info.accounts}. An entity can hold accounts from every platform. Ones already added stay where they are.`}
          items={{ ...Object.fromEntries(entities.map((e) => [String(e.id), e.name])), ...(c.newEntity ? { [NEW]: "New entity…" } : {}) }}
        />
      )}
      {entity === NEW && (
        <Input
          className="w-full"
          label={entities.length ? "New entity name" : "Entity name"}
          placeholder={c.suggestedName}
          value={c.entityName}
          maxLength={80}
          onChange={(e) => c.setEntityName(e.target.value)}
          description={
            existing ? (
              <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
                {existing.name} already exists.
                <Button type="button" size="sm" variant="secondary" onClick={() => c.setEntity(String(existing.id))}>
                  Add to {existing.name}
                </Button>
              </span>
            ) : entities.length ? undefined : (
              `The company or team that owns these ${info.accounts}. Later you can add its accounts on other platforms to the same entity, and other companies as separate entities.`
            )
          }
        />
      )}
    </FormGrid>
  );
}

/** What the credential can read on the selected accounts, and which checks are skipped where it can't. */
export function PermissionsStep({ c }: { c: Connect }) {
  const { info, ids, probes, gaps, stale, probeLimit, busy } = c;
  const cred = info.credential;
  if (stale || !probes.length)
    return (
      <div className="flex flex-wrap items-center justify-between gap-3">
        <span className="text-sm text-kumo-subtle">
          {ids.length ? `Check what the ${cred} can read on the ${info.accounts} you chose.` : `Choose at least one ${info.account} first.`}
        </span>
        <Button variant="secondary" disabled={!ids.length} loading={busy === "verify"} onClick={() => c.verify(ids)}>
          Check permissions
        </Button>
      </div>
    );
  return (
    <div className="flex flex-col gap-4">
      {gaps.length ? (
        <Banner
          variant="alert"
          icon={<WarningIcon weight="fill" />}
          title={`${plural(gaps.length, "data source")} not readable`}
          description={`You can add the ${info.accounts} now; the checks below are skipped until the ${cred} ${info.needsToRead}.`}
        />
      ) : (
        <Banner
          icon={<CheckCircleIcon weight="fill" />}
          title={`The ${cred} can read everything Keelson checks`}
          description={`${plural(probes.length, "data source")} checked${ids.length > probeLimit ? ` on the first ${probeLimit} ${info.accounts}` : ""}.`}
        />
      )}
      <LayerCard className="max-h-80 overflow-auto bg-kumo-base p-0">
        <Table>
          <Table.Header variant="compact">
            <Table.Row>
              <Table.Head>Data</Table.Head>
              <Table.Head>Used for</Table.Head>
              <Table.Head>Access</Table.Head>
            </Table.Row>
          </Table.Header>
          <Table.Body>
            {[...probes]
              .sort((a, b) => Number(a.ok) - Number(b.ok))
              .map((p) => (
                <Table.Row key={p.source}>
                  <Table.Cell>
                    <div className="text-kumo-default">{p.source}</div>
                    {!p.ok && <div className="text-xs text-kumo-subtle">Needs {p.permission}</div>}
                  </Table.Cell>
                  <Table.Cell className="text-xs text-kumo-subtle">{p.powers}</Table.Cell>
                  <Table.Cell>
                    {p.ok ? (
                      <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
                        <CheckCircleIcon weight="fill" className="text-kumo-success" />
                        Readable
                      </span>
                    ) : (
                      <span className="inline-flex items-start gap-1.5">
                        <XCircleIcon weight="fill" className="mt-0.5 shrink-0 text-kumo-danger" />
                        {p.missing.length < ids.length ? `No access in ${p.missing.join(", ")}` : "No access"}
                      </span>
                    )}
                  </Table.Cell>
                </Table.Row>
              ))}
          </Table.Body>
        </Table>
      </LayerCard>
    </div>
  );
}

/** One row per data source; `missing` names the probed accounts that can't read it. */
function mergeProbes(byAccount: Record<string, Probe[]>, accounts: VisibleAccount[]) {
  const name = (id: string) => accounts.find((a) => a.id === id)?.name || id;
  const out = new Map<string, Probe & { missing: string[] }>();
  for (const [id, list] of Object.entries(byAccount)) {
    for (const p of list) {
      const cur = out.get(p.source) || out.set(p.source, { ...p, ok: true, missing: [] }).get(p.source)!;
      if (!p.ok) {
        cur.ok = false;
        cur.missing.push(name(id));
      }
    }
  }
  return [...out.values()];
}
