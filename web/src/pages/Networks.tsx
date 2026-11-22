// Networks, for admins: the ways Keelson's requests can leave the machine it
// runs on (a proxy into a VPN or zero trust network, the certificates that
// network signs with), and which one each platform's requests use. A platform
// that only answers from inside a company's network is scanned through it.
// Keelson never runs a VPN client itself; each kind of network says how to give
// it a route in.

import { useEffect, useRef, useState } from "react";
import {
  Badge,
  Button,
  Dialog,
  DropdownMenu,
  Empty,
  Input,
  InputArea,
  LayerCard,
  Link,
  Loader,
  Select,
  SensitiveInput,
  Table,
  useKumoToastManager,
} from "@cloudflare/kumo";
import {
  ArrowSquareOutIcon,
  CheckCircleIcon,
  DotsThreeIcon,
  PencilSimpleIcon,
  PlugsConnectedIcon,
  PlusIcon,
  ShareNetworkIcon,
  TrashIcon,
  XCircleIcon,
} from "@phosphor-icons/react";
import {
  api,
  choiceValue,
  NETWORK_KIND_INFO,
  NETWORK_KINDS,
  plural,
  PROVIDER_INFO,
  PROVIDERS,
  PROXY_DEFAULT_PORT,
  PROXY_PROTOCOL_LABEL,
  PROXY_PROTOCOLS,
  proxyAddress,
  useApi,
  networkChoice,
  type NetworkInput,
  type NetworkKind,
  type NetworkRow,
  type NetworksResponse,
  type NetworkTarget,
  type NetworkTestResponse,
  type ProxyProtocol,
} from "../lib.ts";
import { Card, DialogHeader, FormGrid, ListCard, Page, PageState, ProviderIcon, SettingRow, SettingRows } from "../components/ui.tsx";

const TITLE = "Networks";
const DESCRIPTION =
  "How Keelson's requests reach each platform. When a platform only answers from inside your VPN or zero trust network, or that network inspects TLS, add the network here and choose it for the platform.";
const DIRECT = "This machine's own connection";
const KIND_ITEMS = Object.fromEntries(NETWORK_KINDS.map((k) => [k, NETWORK_KIND_INFO[k].label])) as Record<NetworkKind, string>;
/** How a network is reached: one of the proxy types, or none when the machine is already on it. */
type Via = ProxyProtocol | "none";
const VIA_ITEMS: Record<Via, string> = {
  none: "No proxy: this machine is already on the network",
  ...(Object.fromEntries(PROXY_PROTOCOLS.map((p) => [p, PROXY_PROTOCOL_LABEL[p]])) as Record<ProxyProtocol, string>),
};

type Modal = { kind: "edit"; network: NetworkRow | null } | { kind: "test"; network: NetworkRow } | { kind: "remove"; network: NetworkRow } | null;

const targetLabel = (t: NetworkTarget) => (t === "default" ? "Default" : PROVIDER_INFO[t].label);

export function NetworksPage() {
  const { data, error, loading, reload, setData } = useApi<NetworksResponse>("/api/networks");
  const toasts = useKumoToastManager();
  const [modal, setModal] = useState<Modal>(null);

  if (error || !data) return <PageState title={TITLE} description={DESCRIPTION} error={error} loading={loading} empty={false} retry={reload} />;

  const { networks, use } = data;
  const nameOf = (id: number | null) => (id == null ? DIRECT : (networks.find((n) => n.id === id)?.name ?? DIRECT));
  const change = async (send: () => Promise<NetworksResponse>, done: string): Promise<boolean> => {
    try {
      setData(await send());
      toasts.add({ title: done, variant: "success" });
      return true;
    } catch (e) {
      toasts.add({ title: "Couldn't save", description: (e as Error).message, variant: "error" });
      void reload();
      return false;
    }
  };
  const choose = (target: NetworkTarget, value: string) => {
    const network = choiceValue(value);
    const where = typeof network === "number" ? nameOf(network) : network === "direct" ? DIRECT.toLowerCase() : `the default (${nameOf(use.default)})`;
    return change(
      () => api<NetworksResponse>("/api/network-use", { method: "PUT", body: { target, network } }),
      `${target === "default" ? "The default" : PROVIDER_INFO[target].label} now goes through ${where}`,
    );
  };
  const choices = Object.fromEntries(networks.map((n) => [`net:${n.id}`, n.name]));

  return (
    <Page
      title={TITLE}
      description={DESCRIPTION}
      actions={
        <Button variant="primary" icon={<PlusIcon />} onClick={() => setModal({ kind: "edit", network: null })}>
          Add network
        </Button>
      }
    >
      {networks.length ? (
        <ListCard footer={<span>{plural(networks.length, "network")}</span>}>
          <Table layout="auto">
            <Table.Header variant="compact">
              <Table.Row>
                <Table.Head>Network</Table.Head>
                <Table.Head className="whitespace-nowrap">Goes through</Table.Head>
                <Table.Head>Trusts</Table.Head>
                <Table.Head className="whitespace-nowrap">Used by</Table.Head>
                <Table.Head className="w-12">
                  <span className="sr-only">Options</span>
                </Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {networks.map((n) => (
                <Table.Row key={n.id}>
                  <Table.Cell className="max-w-72">
                    <div className="truncate font-medium text-kumo-default">{n.name}</div>
                    <div className="truncate text-sm text-kumo-subtle">{NETWORK_KIND_INFO[n.kind].label}</div>
                  </Table.Cell>
                  <Table.Cell className="max-w-72">
                    {n.proxy ? (
                      <>
                        <div className="truncate font-mono text-sm text-kumo-default">{proxyAddress(n.proxy)}</div>
                        <div className="truncate text-sm text-kumo-subtle">
                          {n.proxy.username ? `Signs in as ${n.proxy.username}${n.proxy.hasPassword ? "" : ", without a password"}` : "No sign-in"}
                        </div>
                      </>
                    ) : (
                      <span className="text-kumo-subtle">{DIRECT}</span>
                    )}
                  </Table.Cell>
                  <Table.Cell className="max-w-72">
                    <Certificates network={n} />
                  </Table.Cell>
                  <Table.Cell>
                    {n.usedBy.length ? (
                      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                        {n.usedBy.map((t) => (
                          <span key={t} className="inline-flex items-center gap-1.5 whitespace-nowrap text-kumo-default">
                            {t !== "default" && <ProviderIcon provider={t} />}
                            {targetLabel(t)}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <span className="text-kumo-subtle">Nothing yet</span>
                    )}
                  </Table.Cell>
                  <Table.Cell>
                    <DropdownMenu>
                      <DropdownMenu.Trigger
                        render={<Button variant="ghost" size="sm" shape="square" icon={<DotsThreeIcon weight="bold" />} aria-label={`${n.name} options`} />}
                      />
                      <DropdownMenu.Content align="end">
                        <DropdownMenu.Item icon={PlugsConnectedIcon} onClick={() => setModal({ kind: "test", network: n })}>
                          Test
                        </DropdownMenu.Item>
                        <DropdownMenu.Item icon={PencilSimpleIcon} onClick={() => setModal({ kind: "edit", network: n })}>
                          Edit
                        </DropdownMenu.Item>
                        <DropdownMenu.Separator />
                        <DropdownMenu.Item icon={TrashIcon} variant="danger" onClick={() => setModal({ kind: "remove", network: n })}>
                          Remove network
                        </DropdownMenu.Item>
                      </DropdownMenu.Content>
                    </DropdownMenu>
                  </Table.Cell>
                </Table.Row>
              ))}
            </Table.Body>
          </Table>
        </ListCard>
      ) : (
        <LayerCard className="py-8">
          <Empty
            icon={<ShareNetworkIcon size={40} className="text-kumo-inactive" />}
            title="No networks yet"
            description="Every request leaves over this machine's own connection. Add a network for Netskope, Cloudflare WARP, an OpenVPN tunnel or any proxy, then choose which platforms go through it."
            contents={
              <Button variant="secondary" icon={<PlusIcon />} onClick={() => setModal({ kind: "edit", network: null })}>
                Add network
              </Button>
            }
          />
        </LayerCard>
      )}

      <Card
        title="Which network each platform uses"
        description="A scan of an account, and adding one, sends every request to its platform through the network chosen here. Changes apply to the next scan."
      >
        <SettingRows>
          <SettingRow
            title="Default"
            description="Platforms set to Default below, and what Keelson reads for itself: vulnerability catalogs, scanners' databases, update checks and alerts."
          >
            <Select
              aria-label="Default network"
              className="w-full min-w-0"
              value={networkChoice(use, "default")}
              items={{ direct: DIRECT, ...choices }}
              onValueChange={(v) => void choose("default", String(v))}
            />
          </SettingRow>
          {PROVIDERS.map((p) => (
            <SettingRow
              key={p}
              title={
                <span className="inline-flex items-center gap-2">
                  <ProviderIcon provider={p} />
                  {PROVIDER_INFO[p].label}
                </span>
              }
              description={`Requests to ${PROVIDER_INFO[p].apiHost}, and anything else its scans read.`}
            >
              <Select
                aria-label={`Network for ${PROVIDER_INFO[p].label}`}
                className="w-full min-w-0"
                value={networkChoice(use, p)}
                items={{ inherit: `Default (${nameOf(use.default)})`, direct: DIRECT, ...choices }}
                onValueChange={(v) => void choose(p, String(v))}
              />
            </SettingRow>
          ))}
        </SettingRows>
      </Card>

      {modal?.kind === "edit" && (
        <NetworkDialog
          network={modal.network}
          taken={networks.filter((n) => n.id !== modal.network?.id).map((n) => n.name.toLowerCase())}
          onClose={() => setModal(null)}
          onSave={(input) =>
            change(
              () =>
                modal.network
                  ? api<NetworksResponse>(`/api/networks/${modal.network.id}`, { method: "PUT", body: input })
                  : api<NetworksResponse>("/api/networks", { method: "POST", body: input }),
              modal.network ? `${input.name} saved` : `${input.name} added. Choose which platforms use it below.`,
            )
          }
        />
      )}
      {modal?.kind === "test" && <TestDialog network={modal.network} onClose={() => setModal(null)} />}
      {modal?.kind === "remove" && (
        <RemoveDialog
          network={modal.network}
          fallback={nameOf(use.default === modal.network.id ? null : use.default)}
          onClose={() => setModal(null)}
          onConfirm={() =>
            change(() => api<NetworksResponse>(`/api/networks/${modal.network.id}`, { method: "DELETE", body: {} }), `${modal.network.name} removed`)
          }
        />
      )}
    </Page>
  );
}

/** Who a network's certificates name and until when; never the certificates themselves. */
function Certificates({ network }: { network: NetworkRow }) {
  if (!network.certificates.length) return <span className="text-kumo-subtle">Public authorities only</span>;
  return (
    <div className="flex flex-col gap-1">
      {network.certificates.map((c) => (
        <div key={c.fingerprint} className="flex min-w-0 items-center gap-2" title={`SHA-256 ${c.fingerprint}`}>
          <span className="truncate text-kumo-default">{c.subject}</span>
          {c.expired ? <Badge variant="destructive">Expired</Badge> : <span className="shrink-0 text-sm text-kumo-subtle">until {c.expires.slice(0, 10)}</span>}
        </div>
      ))}
    </div>
  );
}

/** What a test found: where requests come out, and which platforms answered. */
function TestResult({ result }: { result: NetworkTestResponse }) {
  const reached = result.reached.filter((r) => r.ok).length;
  // The network itself is down: every platform fails the same way, and the reason is worth saying once.
  const same = !reached && new Set(result.reached.map((r) => r.error)).size === 1 ? result.reached[0]?.error : null;
  if (same)
    return (
      <div className="flex items-start gap-2 text-sm">
        <XCircleIcon weight="fill" className="mt-0.5 shrink-0 text-kumo-danger" />
        <div className="min-w-0">
          <div className="font-medium text-kumo-default">No platform could be reached through this network.</div>
          <div className="text-kumo-subtle">{same}</div>
        </div>
      </div>
    );
  return (
    <div className="flex flex-col gap-3">
      <p className="m-0 text-sm text-kumo-default">
        {result.egress ? (
          <>
            Requests come out at <span className="font-mono">{result.egress.address}</span>
            {result.egress.warp ? ", through Cloudflare WARP" : ""}. That is the address to add to a platform's allowlist.
          </>
        ) : (
          "Keelson couldn't tell which address requests come out at."
        )}{" "}
        {reached === result.reached.length ? "Every platform answered." : `${reached} of ${plural(result.reached.length, "platform")} answered.`}
      </p>
      <ul className="m-0 flex list-none flex-col gap-2 p-0">
        {result.reached.map((r) => (
          <li key={r.provider} className="flex min-w-0 items-start gap-2 text-sm">
            {r.ok ? (
              <CheckCircleIcon weight="fill" className="mt-0.5 shrink-0 text-kumo-success" />
            ) : (
              <XCircleIcon weight="fill" className="mt-0.5 shrink-0 text-kumo-danger" />
            )}
            <div className="min-w-0">
              <span className="font-medium text-kumo-default">{PROVIDER_INFO[r.provider].label}</span>{" "}
              <span className="text-kumo-subtle">
                {r.host}
                {r.ok && r.ms != null ? `, answered in ${r.ms} ms` : ""}
              </span>
              {r.error && <div className="text-kumo-subtle">{r.error}</div>}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

function TestDialog({ network, onClose }: { network: NetworkRow; onClose: () => void }) {
  const [result, setResult] = useState<NetworkTestResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const started = useRef(false);
  useEffect(() => {
    // Once, even when the effect runs twice in development.
    if (started.current) return;
    started.current = true;
    api<NetworkTestResponse>("/api/networks/test", { method: "POST", body: { id: network.id } })
      .then(setResult)
      .catch((e: Error) => setError(e.message));
  }, [network.id]);
  return (
    <Dialog.Root open onOpenChange={(o: boolean) => !o && onClose()}>
      <Dialog size="lg" className="p-6">
        <DialogHeader title={`Test ${network.name}`} description="One request to each platform through this network, without any credential." />
        {result ? (
          <TestResult result={result} />
        ) : error ? (
          <p className="m-0 text-sm text-kumo-danger">{error}</p>
        ) : (
          <div className="flex items-center gap-2 text-sm text-kumo-subtle">
            <Loader size="sm" /> Asking each platform
          </div>
        )}
        <div className="mt-6 flex justify-end">
          <Button variant="primary" onClick={onClose}>
            Done
          </Button>
        </div>
      </Dialog>
    </Dialog.Root>
  );
}

function NetworkDialog({
  network,
  taken,
  onClose,
  onSave,
}: {
  network: NetworkRow | null;
  taken: string[];
  onClose: () => void;
  onSave: (input: NetworkInput) => Promise<boolean>;
}) {
  const [kind, setKind] = useState<NetworkKind>(network?.kind ?? "netskope");
  const [name, setName] = useState(network?.name ?? "");
  const [via, setVia] = useState<Via>(network ? (network.proxy?.protocol ?? "none") : (NETWORK_KIND_INFO.netskope.proxy?.protocol ?? "none"));
  const [host, setHost] = useState(network?.proxy?.host ?? "");
  const [port, setPort] = useState(network?.proxy ? String(network.proxy.port) : "");
  const [username, setUsername] = useState(network?.proxy?.username ?? "");
  const [password, setPassword] = useState("");
  const kept = network?.certificates ?? [];
  // The stored certificates stay until they are replaced or removed; their text never comes back from the server.
  const [keepCa, setKeepCa] = useState(kept.length > 0);
  const [ca, setCa] = useState("");
  const [busy, setBusy] = useState(false);
  const [testing, setTesting] = useState(false);
  const [tested, setTested] = useState<NetworkTestResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const file = useRef<HTMLInputElement>(null);
  const info = NETWORK_KIND_INFO[kind];

  // A kind fills in what it usually looks like, but never over what was typed or stored.
  const pickKind = (next: NetworkKind) => {
    setKind(next);
    if (network) return;
    const usual = NETWORK_KIND_INFO[next].proxy;
    const untouched = !host.trim() || host === NETWORK_KIND_INFO[kind].proxy?.host;
    if (!untouched) return;
    setVia(usual?.protocol ?? (NETWORK_KIND_INFO[next].inspectsTls ? "none" : "http"));
    setHost(usual?.host ?? "");
    setPort(usual ? String(usual.port) : "");
  };

  const clash = taken.includes(name.trim().toLowerCase());
  const portNumber = Number(port || (via === "none" ? 0 : PROXY_DEFAULT_PORT[via]));
  const hasCa = keepCa || !!ca.trim();
  const complete = !!name.trim() && !clash && (via === "none" ? hasCa : !!host.trim() && Number.isInteger(portNumber) && portNumber > 0 && portNumber < 65536);
  const samePassword = !!network?.proxy?.hasPassword && !password && username.trim() === (network.proxy.username ?? "");
  const input = (): NetworkInput => ({
    name: name.trim(),
    kind,
    proxy:
      via === "none" ? null : { protocol: via, host: host.trim(), port: portNumber, username: username.trim() || null, ...(samePassword ? {} : { password }) },
    ...(keepCa ? {} : { ca }),
  });

  const test = async () => {
    setTesting(true);
    setErr(null);
    setTested(null);
    try {
      setTested(await api<NetworkTestResponse>("/api/networks/test", { method: "POST", body: { id: network?.id, network: input() } }));
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setTesting(false);
    }
  };

  return (
    <Dialog.Root open onOpenChange={(o: boolean) => !o && onClose()}>
      <Dialog size="xl" className="max-h-[90vh] overflow-y-auto p-6">
        <DialogHeader
          title={network ? `Edit ${network.name}` : "Add network"}
          description="A network is a proxy to send requests through, a certificate to trust when the network inspects TLS, or both."
        />
        <form
          className="flex flex-col gap-4"
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            setErr(null);
            if (await onSave(input())) onClose();
            else setBusy(false);
          }}
        >
          <FormGrid>
            <Select
              className="w-full"
              label="Kind"
              hideLabel={false}
              value={kind}
              onValueChange={(v) => pickKind(v as NetworkKind)}
              items={KIND_ITEMS}
              description={info.summary}
            />
            <Input
              className="w-full"
              label="Name"
              placeholder={`${info.label} (office)`}
              value={name}
              onChange={(e) => setName(e.target.value)}
              autoComplete="off"
              variant={clash ? "error" : "default"}
              error={clash ? `${name.trim()} already exists. Pick another name.` : undefined}
              description={clash ? undefined : "What you'll pick it by for each platform."}
            />
          </FormGrid>

          <div className="rounded-lg bg-kumo-recessed px-4 py-3 text-sm text-kumo-default">
            <div className="font-medium">Giving Keelson a route into {info.label}</div>
            <ul className="m-0 mt-2 flex list-disc flex-col gap-1.5 pl-5 text-kumo-subtle">
              {info.setup.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
            {info.docs && (
              <div className="mt-2">
                <Link href={info.docs} target="_blank" rel="noreferrer">
                  {info.label} documentation
                  <ArrowSquareOutIcon className="ml-1 inline align-[-2px]" />
                </Link>
              </div>
            )}
          </div>

          <Select
            className="w-full"
            label="Requests go through"
            hideLabel={false}
            value={via}
            onValueChange={(v) => setVia(v as Via)}
            items={VIA_ITEMS}
            description={
              via === "none"
                ? "Requests leave over this machine's own connection, and Keelson trusts the certificate below."
                : via === "socks5"
                  ? "The proxy looks names up itself, so names that exist only inside the network work."
                  : "The proxy must allow CONNECT to port 443."
            }
          />
          {via !== "none" && (
            <>
              <FormGrid>
                <Input
                  className="w-full"
                  label="Proxy host"
                  placeholder="proxy.example.com"
                  value={host}
                  onChange={(e) => setHost(e.target.value)}
                  autoComplete="off"
                  autoCapitalize="none"
                  spellCheck={false}
                  description="A name or an address this machine can reach."
                />
                <Input
                  className="w-full"
                  label="Port"
                  type="number"
                  min={1}
                  max={65535}
                  placeholder={String(PROXY_DEFAULT_PORT[via])}
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                />
              </FormGrid>
              <FormGrid>
                <Input
                  className="w-full"
                  label="Username (optional)"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  autoComplete="off"
                  autoCapitalize="none"
                  spellCheck={false}
                />
                <SensitiveInput
                  className="w-full"
                  label="Password (optional)"
                  value={password}
                  disabled={!username.trim()}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) => setPassword(e.target.value)}
                  description={
                    samePassword
                      ? "A password is stored. Type a new one to replace it."
                      : via === "http"
                        ? "Kept with your platform credentials, never shown again. A plain HTTP proxy receives it unencrypted."
                        : "Kept with your platform credentials, never shown again."
                  }
                />
              </FormGrid>
            </>
          )}

          {keepCa ? (
            <div className="flex flex-col gap-1.5">
              <span className="text-sm font-medium text-kumo-default">Certificates it trusts</span>
              <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-kumo-hairline px-3 py-2">
                <div className="min-w-0 text-sm">{network && <Certificates network={network} />}</div>
                <div className="flex shrink-0 gap-2">
                  <Button type="button" size="sm" variant="secondary" onClick={() => setKeepCa(false)}>
                    Replace or remove
                  </Button>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex flex-col gap-2">
              <InputArea
                label={info.inspectsTls || via === "none" ? "Certificate to trust" : "Certificate to trust (optional)"}
                placeholder={"-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----"}
                value={ca}
                onValueChange={setCa}
                minRows={4}
                className="font-mono text-xs"
                spellCheck={false}
                description={
                  kept.length
                    ? "Leave empty to remove the stored certificates."
                    : "The root certificate the network signs with when it inspects TLS, as PEM. Only requests through this network trust it. Never a private key."
                }
              />
              <div>
                <input
                  ref={file}
                  type="file"
                  accept=".pem,.crt,.cer,.txt"
                  className="hidden"
                  onChange={async (e) => {
                    const picked = e.target.files?.[0];
                    if (picked) setCa(await picked.text());
                    e.target.value = "";
                  }}
                />
                <Button type="button" size="sm" variant="secondary" onClick={() => file.current?.click()}>
                  Choose a file
                </Button>
              </div>
            </div>
          )}

          {err && <p className="m-0 text-sm text-kumo-danger">{err}</p>}
          {tested && (
            <div className="rounded-lg border border-kumo-hairline px-4 py-3">
              <TestResult result={tested} />
            </div>
          )}

          <div className="flex flex-wrap justify-between gap-2">
            <Button type="button" variant="secondary" icon={<PlugsConnectedIcon />} loading={testing} disabled={!complete || busy} onClick={() => void test()}>
              Test
            </Button>
            <div className="flex gap-2">
              <Dialog.Close
                render={(p) => (
                  <Button {...p} variant="secondary">
                    Cancel
                  </Button>
                )}
              />
              <Button type="submit" variant="primary" loading={busy} disabled={!complete || testing}>
                {network ? "Save" : "Add network"}
              </Button>
            </div>
          </div>
        </form>
      </Dialog>
    </Dialog.Root>
  );
}

function RemoveDialog({
  network,
  fallback,
  onClose,
  onConfirm,
}: {
  network: NetworkRow;
  fallback: string;
  onClose: () => void;
  onConfirm: () => Promise<boolean>;
}) {
  const [busy, setBusy] = useState(false);
  const used = network.usedBy.map(targetLabel);
  return (
    <Dialog.Root open onOpenChange={(o: boolean) => !o && onClose()}>
      <Dialog size="base" className="p-6">
        <DialogHeader
          title={`Remove ${network.name}?`}
          description={
            used.length
              ? `${used.join(", ")} ${used.length === 1 ? "goes" : "go"} through it now, and will go through ${fallback === DIRECT ? DIRECT.toLowerCase() : fallback} from the next scan. Its stored password and certificates are deleted.`
              : "Nothing goes through it now. Its stored password and certificates are deleted."
          }
        />
        <div className="mt-6 flex justify-end gap-2">
          <Dialog.Close
            render={(p) => (
              <Button {...p} variant="secondary">
                Cancel
              </Button>
            )}
          />
          <Button
            variant="destructive"
            loading={busy}
            onClick={async () => {
              setBusy(true);
              if (await onConfirm()) onClose();
              else setBusy(false);
            }}
          >
            Remove network
          </Button>
        </div>
      </Dialog>
    </Dialog.Root>
  );
}
