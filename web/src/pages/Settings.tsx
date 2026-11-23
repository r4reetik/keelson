// Instance-wide settings. Every control saves as soon as it changes, like the
// switches on the Accounts and Checks pages; text fields save when they lose focus.

import { useEffect, useState } from "react";
import { Banner, Button, Input, Link, Select, Switch, useKumoToastManager } from "@cloudflare/kumo";
import { ArrowCircleUpIcon, ArrowSquareOutIcon, CheckCircleIcon, InfoIcon, WarningIcon } from "@phosphor-icons/react";
import {
  ago,
  api,
  link,
  ROLE_INFO,
  SCANNER_TOOLS,
  SCORED_SEVERITIES,
  SEVERITY_LABEL,
  toolNeed,
  useApi,
  type ScannerRow,
  type ScannersResponse,
  type Settings,
  type UpdateStatus,
} from "../lib.ts";
import { Card, FormGrid, Page, PageState, SettingRow, SettingRows } from "../components/ui.tsx";
import { useShell } from "../shell.tsx";

const TITLE = "Settings";
const DESCRIPTION = "Scan schedule, history, how findings are tracked, updates, and the scanners Keelson runs. These apply to every account.";
const UPGRADING_DOCS = "https://github.com/r4reetik/keelson/blob/main/docs/upgrading.md";
const HOURS = Object.fromEntries(Array.from({ length: 24 }, (_, h) => [String(h), `${String(h).padStart(2, "0")}:00 UTC`]));
type Save = (patch: Record<string, unknown>, label: string) => Promise<boolean>;

export function SettingsPage() {
  const { data, error, loading, reload, setData } = useApi<Settings>("/api/settings");
  const toasts = useKumoToastManager();
  const { can, session } = useShell();
  const editable = can("settings");

  if (error || !data) return <PageState title={TITLE} description={DESCRIPTION} error={error} loading={loading} empty={false} retry={reload} />;

  const save: Save = async (patch, label) => {
    try {
      setData(await api<Settings>("/api/settings", { method: "PUT", body: patch }));
      toasts.add({ title: `${label} saved`, variant: "success" });
      return true;
    } catch (e) {
      toasts.add({ title: "Couldn't save", description: (e as Error).message, variant: "error" });
      void reload();
      return false;
    }
  };

  return (
    <Page title={TITLE} description={DESCRIPTION}>
      {!editable && (
        <Banner
          variant="default"
          icon={<InfoIcon weight="fill" />}
          title={`Only admins can change these settings. Your role (${ROLE_INFO[session.user?.role ?? "viewer"].label}) can see them.`}
        />
      )}
      {/* A disabled fieldset disables every control inside it, so a role that can't save sees the values without editing them. */}
      <fieldset disabled={!editable} className="contents">
        <ScansCard s={data} save={save} locked={!editable} />
        <PolicyCard s={data} save={save} />
        <LinksCard s={data} save={save} />
        <UpdatesCard s={data} save={save} locked={!editable} />
      </fieldset>
      <ScannersCard editable={editable} />
    </Page>
  );
}

/** A number field that saves on blur or Enter, and only when the value changed and is valid. */
function NumberField({
  label,
  value,
  min,
  max,
  unit,
  onSave,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  unit?: string;
  onSave: (n: number) => void;
}) {
  const [v, setV] = useState(String(value));
  const n = Number(v);
  const valid = Number.isInteger(n) && n >= min && n <= max;
  const commit = () => {
    if (valid && n !== value) onSave(n);
    else if (!valid) setV(String(value));
  };
  return (
    <div className="flex items-center gap-2">
      <Input
        aria-label={label}
        className="w-full"
        type="number"
        min={min}
        max={max}
        value={v}
        onChange={(e) => setV(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => {
          if (e.key === "Enter") commit();
        }}
        variant={valid ? "default" : "error"}
      />
      {unit && <span className="shrink-0 text-sm text-kumo-subtle">{unit}</span>}
    </div>
  );
}

/** `locked`: the fieldset already disables everything; switches also need it passed to look disabled. */
function ScansCard({ s, save, locked }: { s: Settings; save: Save; locked: boolean }) {
  return (
    <Card title="Scans">
      <SettingRows>
        <SettingRow
          end
          title="Daily scan"
          description="Scan every account once a day, one after another. Accounts can be left out of the daily scan on the Accounts page. You can always run a scan by hand."
        >
          <Switch
            aria-label="Daily scan"
            checked={s.schedule.enabled}
            disabled={locked}
            onCheckedChange={(v: boolean) => save({ schedule: { enabled: v } }, v ? "Daily scan on" : "Daily scan off")}
          />
        </SettingRow>
        <SettingRow title="Time" description="When the daily scan starts. A missed scan runs shortly after Keelson next starts.">
          <Select
            aria-label="Scan time"
            className="w-full"
            value={String(s.schedule.hourUtc)}
            items={HOURS}
            disabled={!s.schedule.enabled || locked}
            onValueChange={(v) => save({ schedule: { hourUtc: Number(v), minuteUtc: 0 } }, "Scan time")}
          />
        </SettingRow>
        <SettingRow
          end
          title="Confirm subdomain takeovers"
          description="Sends a GET to each of your hostnames that points at a cloud provider (S3, Vercel, Heroku, GitHub Pages and others), at most 100 per scan, and checks for that provider's 'doesn't exist' page. Turn off to keep every request inside your providers' APIs."
        >
          <Switch
            aria-label="Confirm subdomain takeovers"
            checked={s.probes.takeover}
            disabled={locked}
            onCheckedChange={(v: boolean) => save({ probes: { takeover: v } }, v ? "Takeover checks on" : "Takeover checks off")}
          />
        </SettingRow>
        <SettingRow title="History" description="How long to keep each account's scans. The latest scan is always kept.">
          <NumberField
            key={s.retentionDays}
            label="Days of history"
            value={s.retentionDays}
            min={7}
            max={3650}
            unit="days"
            onSave={(n) => save({ retentionDays: n }, "History")}
          />
        </SettingRow>
      </SettingRows>
    </Card>
  );
}

function PolicyCard({ s, save }: { s: Settings; save: Save }) {
  return (
    <Card
      title="Findings policy"
      description={
        <>
          Company email domains, used to spot outside members and Access rules, are set per entity on the <Link {...link("/accounts")}>Accounts page</Link>.
        </>
      }
    >
      <SettingRows>
        <SettingRow title="Days to fix (SLA)" description="Findings without a due date are flagged overdue after this many days, by severity.">
          <FormGrid cols={4}>
            {SCORED_SEVERITIES.map((k) => (
              <div key={`${k}-${s.slaDays[k]}`} className="flex flex-col gap-1.5">
                <span className="text-sm font-medium text-kumo-default">{SEVERITY_LABEL[k]}</span>
                <NumberField
                  label={`${SEVERITY_LABEL[k]} SLA in days`}
                  value={s.slaDays[k]}
                  min={1}
                  max={3650}
                  onSave={(n) => save({ slaDays: { [k]: n } }, `${SEVERITY_LABEL[k]} SLA`)}
                />
              </div>
            ))}
          </FormGrid>
        </SettingRow>
      </SettingRows>
    </Card>
  );
}

function LinksCard({ s, save }: { s: Settings; save: Save }) {
  const [baseUrl, setBaseUrl] = useState(s.baseUrl || "");
  const commit = () => {
    if (baseUrl.trim().replace(/\/$/, "") !== (s.baseUrl || "")) void save({ baseUrl }, "Link URL");
  };
  // The address this page was opened at is almost always the answer, unless it's this machine only.
  const here = location.origin;
  const offerHere = !baseUrl.trim() && !/^https?:\/\/(localhost|127\.|\[::1\])/.test(here);
  return (
    <Card
      title="Notifications"
      description={
        <>
          Each entity sends its own accounts' alerts to its own Slack channel or webhook, so alerts never cross between companies. Set them on the{" "}
          <Link {...link("/accounts")}>Accounts page</Link>.
        </>
      }
    >
      <SettingRows>
        <SettingRow title="Link URL" description="Optional. The address people use to open Keelson, so alerts can link straight to each finding.">
          <Input
            aria-label="Keelson URL"
            className="w-full"
            placeholder="https://keelson.internal.example.com"
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            onBlur={commit}
            onKeyDown={(e) => {
              if (e.key === "Enter") commit();
            }}
            description={
              offerHere ? (
                <Button
                  type="button"
                  size="sm"
                  variant="secondary"
                  onClick={() => {
                    setBaseUrl(here);
                    void save({ baseUrl: here }, "Link URL");
                  }}
                >
                  Use {here}
                </Button>
              ) : undefined
            }
          />
        </SettingRow>
      </SettingRows>
    </Card>
  );
}

/** How to move to `version`, for the way this copy was installed. */
function upgradeSteps(u: UpdateStatus, version: string): { text: string; command: string } {
  if (u.install === "docker") {
    const sameLine = u.latest?.sameLine;
    return {
      text: sameLine
        ? `If your image tag is :${u.line} or :latest, pull it again and restart. With a pinned version, change the tag to :${version} first.`
        : `${version} starts a new release line. Change your image tag to :${version
            .split(".")
            .slice(0, version.startsWith("0.") ? 2 : 1)
            .join(".")} (or :${version}), then pull and restart.`,
      command: "docker compose pull && docker compose up -d",
    };
  }
  return {
    text: "In your clone, check out the release, build it and restart Keelson.",
    command: `git fetch --tags && git checkout v${version} && npm ci && npm run build`,
  };
}

function UpdatesCard({ s, save, locked }: { s: Settings; save: Save; locked: boolean }) {
  const { data: u, reload, setData } = useApi<UpdateStatus>("/api/updates", s.updates.check);
  const [checking, setChecking] = useState(false);
  const checkNow = async () => {
    setChecking(true);
    try {
      setData(await api<UpdateStatus>("/api/updates/check", { method: "POST", body: {} }));
    } catch {
      void reload();
    } finally {
      setChecking(false);
    }
  };
  const steps = u?.latest && upgradeSteps(u, u.latest.version);
  return (
    <div id="updates" className="scroll-mt-6">
      <Card title="Updates">
        <SettingRows>
          <SettingRow
            end
            title="Check for updates"
            description={
              u?.lockedOff
                ? "Turned off for this installation with KEELSON_UPDATE_CHECK=off."
                : "Shortly after start and then daily, reads the public list of Keelson releases on GitHub. Nothing about this installation is sent."
            }
          >
            <Switch
              aria-label="Check for updates"
              checked={s.updates.check && !u?.lockedOff}
              disabled={u?.lockedOff || locked}
              onCheckedChange={(v: boolean) => save({ updates: { check: v } }, v ? "Update checks on" : "Update checks off")}
            />
          </SettingRow>
          {u && (
            <div className="flex flex-col gap-3 py-4 last:pb-0">
              {u.latest ? (
                <Banner
                  variant={u.breaking ? "alert" : undefined}
                  icon={u.breaking ? <WarningIcon weight="fill" /> : <ArrowCircleUpIcon weight="fill" />}
                  title={`Keelson ${u.latest.version} is available`}
                  description={
                    <>
                      You're on {u.current}
                      {u.newerCount > 1 ? `, ${u.newerCount} releases behind` : ""}.{" "}
                      {u.breaking
                        ? "It includes breaking changes: read the release notes before upgrading."
                        : u.latest.sameLine
                          ? "It's a compatible update."
                          : "It starts a new release line; the release notes list what changed."}{" "}
                      <Link href={u.latest.url} target="_blank" rel="noreferrer">
                        Release notes
                      </Link>
                    </>
                  }
                />
              ) : (
                <div className="flex items-center gap-2 text-sm text-kumo-default">
                  <CheckCircleIcon weight="fill" className="text-kumo-success" />
                  {u.enabled
                    ? u.checkedAt
                      ? `Keelson ${u.current} is the latest version.`
                      : `Running Keelson ${u.current}. The first check runs shortly after start.`
                    : `Running Keelson ${u.current}. Update checks are off.`}
                </div>
              )}
              {steps && (
                <div className="flex flex-col gap-2 text-sm text-kumo-subtle">
                  <span>{steps.text}</span>
                  <code className="rounded-md bg-kumo-recessed px-3 py-2 font-mono text-xs text-kumo-default">{steps.command}</code>
                  <span>
                    Your database is backed up automatically before an upgrade changes it.{" "}
                    <Link href={UPGRADING_DOCS} target="_blank" rel="noreferrer">
                      Upgrading Keelson
                    </Link>
                  </span>
                </div>
              )}
              {u.inLine && (
                <p className="text-sm text-kumo-default">
                  Not ready for {u.latest?.version}? {u.inLine.version} is the newest compatible update on {u.line}:{" "}
                  <code className="rounded bg-kumo-recessed px-1.5 py-0.5 font-mono text-xs">
                    {u.install === "docker" ? `ghcr.io/r4reetik/keelson:${u.line}` : `git checkout v${u.inLine.version}`}
                  </code>{" "}
                  <Link href={u.inLine.url} target="_blank" rel="noreferrer">
                    Notes
                  </Link>
                </p>
              )}
              <div className="flex flex-wrap items-center gap-3 text-xs text-kumo-subtle">
                {u.enabled && (
                  <Button size="sm" variant="secondary" loading={checking} onClick={checkNow}>
                    Check now
                  </Button>
                )}
                {u.checkedAt && <span>Last checked {ago(u.checkedAt)}</span>}
                {u.error && <span>· The last check failed ({u.error}); it will try again tomorrow.</span>}
              </div>
            </div>
          )}
        </SettingRows>
      </Card>
    </div>
  );
}

/**
 * The scanners Keelson runs, and the two vulnerability databases they match against. Scans keep those current on their
 * own; Update now is for using the newest advisories at once. Only admins see the button.
 */
function ScannersCard({ editable }: { editable: boolean }) {
  const { data, error, reload, setData } = useApi<ScannersResponse>("/api/scanners");
  const toasts = useKumoToastManager();
  const updating = !!data?.scanners.some((r) => r.database?.updating);
  // While a database downloads, ask how it is going every few seconds; nothing is asked otherwise.
  useEffect(() => {
    if (!updating) return;
    const timer = setInterval(() => void reload(), 3000);
    return () => clearInterval(timer);
  }, [updating, reload]);

  const update = async (r: ScannerRow) => {
    try {
      setData(await api<ScannersResponse>(`/api/scanners/${r.key}/database`, { method: "POST", body: {} }));
    } catch (e) {
      toasts.add({ title: `Couldn't update ${r.name}'s database`, description: (e as Error).message, variant: "error" });
    }
  };

  return (
    <div id="scanners" className="scroll-mt-6">
      <Card
        title="Scanners"
        description="The tools Keelson runs for dependencies, container images and Sonar. Scans keep Grype's and Trivy's vulnerability databases current on their own; update one here to match against the newest advisories on the next scan."
      >
        {error ? (
          <p className="text-sm text-kumo-danger">Couldn't read the scanners: {error.message}</p>
        ) : !data ? (
          <p className="text-sm text-kumo-subtle">Reading the scanners…</p>
        ) : (
          <SettingRows>
            {data.scanners.map((r) => (
              <SettingRow
                key={r.key}
                end
                title={r.name}
                description={
                  <span className="flex flex-col gap-1">
                    <span>{r.purpose}</span>
                    {r.installed ? (
                      r.database && <DatabaseLine r={r} />
                    ) : (
                      <span>
                        Needs {toolNeed(r.key, data.install)}.{" "}
                        {data.install === "source" && (
                          <Link href={SCANNER_TOOLS[r.key].installUrl} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1">
                            How to install {r.name} <ArrowSquareOutIcon />
                          </Link>
                        )}
                      </span>
                    )}
                  </span>
                }
              >
                <div className="flex items-center gap-3">
                  <span className={r.installed ? "text-sm tabular-nums text-kumo-default" : "text-sm text-kumo-subtle"}>
                    {r.installed ? (r.version ?? "Installed") : "Not installed"}
                  </span>
                  {editable && r.installed && r.database && (
                    <Button size="sm" variant="secondary" loading={r.database.updating} onClick={() => update(r)}>
                      {r.database.updating ? "Updating" : "Update now"}
                    </Button>
                  )}
                </div>
              </SettingRow>
            ))}
          </SettingRows>
        )}
      </Card>
    </div>
  );
}

/** When a scanner's database was built, where it comes from, and how the last update asked for here went. */
function DatabaseLine({ r }: { r: ScannerRow }) {
  const d = r.database!;
  return (
    <>
      <span>
        {d.builtAt ? `Database built ${ago(d.builtAt)}` : "No database yet: the first scan that needs it downloads it"}. It comes from {d.from}, {d.size}.
      </span>
      {d.updating ? (
        <span>Downloading the newest database. Scans that need it wait until it is in place.</span>
      ) : d.error ? (
        <span className="text-kumo-danger">The update failed: {d.error}</span>
      ) : d.updatedAt ? (
        <span>Updated {ago(d.updatedAt)}.</span>
      ) : null}
    </>
  );
}
