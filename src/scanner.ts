// Scans accounts one at a time from a queue and tracks live progress for the UI.
// One account at a time keeps the request rate predictable when several accounts
// share a token (providers' rate limits are per token). What a scan
// reads and checks is up to the account's provider (src/providers).
//
// A scan may leave images it had no time to read (a backlog). Once no scan is
// running or queued they are read in the background, one account at a time, and
// the account is then scanned again, which pulls nothing and reports what they
// hold. A new scan always goes first: the background gives way after the image
// it is on. A backlog lives in memory, with its scan's registry access: after a
// restart the account's next scan picks up where it was.

import { computeScore, severityCounts } from "./core/engine.ts";
import type { ImageBacklog } from "./core/images.ts";
import { PROVIDER } from "./providers/index.ts";
import { notifyScan } from "./notify.ts";
import { displayName, type Account, type Repo } from "./store/repo.ts";
import type { TokenVault } from "./config.ts";
import { NO_RELATED, type Related } from "./core/types.ts";
import { LINK_KEYS, LINK_PROVIDER, type LinkKey, type ScanSnapshot } from "./shared/api.ts";
import { through, type Route } from "./core/net.ts";
import { checkRoute, originFor, routeFor } from "./networks.ts";
import { ScannerTools } from "./scanner-tools.ts";

export interface ScanState {
  running: boolean;
  /** The account being scanned now. */
  accountId: string | null;
  scanId: number | null;
  trigger: string | null;
  startedAt: string | null;
  phase: string | null;
  done: number | null;
  total: number | null;
  /** Accounts waiting their turn, in order. */
  queued: string[];
}

/** Images being read after their scans finished. */
export interface BackgroundState {
  /** The account whose images are read now, or next when a scan is in the way. */
  accountId: string;
  done: number;
  total: number;
  /** Accounts with images to read after this one. */
  queued: string[];
}

export interface ScanResult {
  accountId: string;
  scanId: number;
  score: number | null;
  findings: number;
  newFindings: number;
}

interface Job {
  accountId: string;
  trigger: string;
  promise: Promise<ScanResult>;
  resolve: (r: ScanResult) => void;
  reject: (e: unknown) => void;
}

const IDLE: ScanState = { running: false, accountId: null, scanId: null, trigger: null, startedAt: null, phase: null, done: null, total: null, queued: [] };

export class Scanner {
  state: ScanState = { ...IDLE };
  /** What the background is reading; null when no scan left anything. */
  background: BackgroundState | null = null;
  readonly #repo: Repo;
  readonly #vault: TokenVault;
  readonly #log: (msg: string) => void;
  readonly #toolDir: string | null;
  /** The scanners scans run, and their databases (Settings). */
  readonly tools: ScannerTools;
  #jobs: Job[] = [];
  #current: Job | null = null;
  /** What scans left to read, by account, in the order they finished. */
  #backlogs = new Map<string, { backlog: ImageBacklog; done: number }>();
  #working: Promise<void> | null = null;

  /** `toolDir`: where scanners keep data between scans (Grype's database), or null to keep none. */
  constructor(repo: Repo, vault: TokenVault, log: (msg: string) => void, opts: { toolDir?: string | null } = {}) {
    this.#repo = repo;
    this.#vault = vault;
    this.#log = log;
    this.#toolDir = opts.toolDir ?? null;
    this.tools = new ScannerTools(this.#toolDir, log);
  }

  #perEntity(accountId: string): boolean {
    const a = this.#repo.accounts.get(accountId);
    return !!a && !!PROVIDER[a.provider].info.perEntity;
  }

  isBusy(accountId: string): boolean {
    return this.#current?.accountId === accountId || this.#jobs.some((j) => j.accountId === accountId);
  }

  /**
   * Queues scans for the given accounts (every account when omitted). Accounts
   * already queued or running aren't queued twice; `done` settles when all the
   * requested accounts have finished.
   */
  start(trigger: string, accountIds?: string[]): { queued: string[]; alreadyRunning: boolean; done: Promise<ScanResult[]> } {
    const ids = accountIds ?? this.#repo.accounts.list().map((a) => a.id);
    if (!ids.length) throw new Error("Add an account before scanning.");
    const queued: string[] = [];
    const promises = ids.map((id) => {
      const existing = this.#current?.accountId === id ? this.#current : this.#jobs.find((j) => j.accountId === id);
      if (existing) return existing.promise;
      let resolve!: Job["resolve"], reject!: Job["reject"];
      const promise = new Promise<ScanResult>((res, rej) => {
        resolve = res;
        reject = rej;
      });
      // Callers that don't await the scan still get errors logged instead of an unhandled rejection.
      promise.catch(() => {});
      this.#jobs.push({ accountId: id, trigger, promise, resolve, reject });
      queued.push(id);
      return promise;
    });
    this.state = { ...this.state, queued: this.#jobs.map((j) => j.accountId) };
    if (!this.#current) void this.#drain();
    // Settles once every requested account has finished, and rejects if any of them failed.
    const done = Promise.allSettled(promises).then((rs) => {
      const failed = rs.find((r) => r.status === "rejected");
      if (failed) throw failed.reason;
      return rs.map((r) => (r as PromiseFulfilledResult<ScanResult>).value);
    });
    done.catch(() => {});
    return { queued, alreadyRunning: queued.length === 0, done };
  }

  async #drain(): Promise<void> {
    while (this.#jobs.length) {
      // A per-entity account (Sonar) reads its siblings' latest scans, so it waits until no other account is queued.
      const next = this.#jobs.findIndex((j) => !this.#perEntity(j.accountId));
      const job = this.#jobs.splice(Math.max(next, 0), 1)[0];
      this.#current = job;
      try {
        job.resolve(await this.#scan(job));
      } catch (e) {
        job.reject(e);
      }
    }
    this.#current = null;
    this.state = { ...IDLE };
    this.#resume();
  }

  /** Settles when no scan is running or queued and the background has nothing left to read. For tests and shutdown. */
  async idle(): Promise<void> {
    while (this.#current || this.#jobs.length || this.#working) {
      await Promise.allSettled([this.#current?.promise, ...this.#jobs.map((j) => j.promise), this.#working]);
      // A scan's promise settles a moment before the queue moves on.
      await new Promise((r) => setImmediate(r));
    }
  }

  #busy(): boolean {
    return !!this.#current || this.#jobs.length > 0;
  }

  #show(): void {
    const [first, ...rest] = this.#backlogs.keys();
    const b = first ? this.#backlogs.get(first)! : null;
    this.background = b ? { accountId: first, done: b.done, total: b.backlog.total, queued: rest } : null;
  }

  /** Starts reading backlogs when nothing else is going on. */
  #resume(): void {
    this.#show();
    if (this.#working || this.#busy() || !this.#backlogs.size) return;
    this.#working = this.#work().finally(() => {
      this.#working = null;
      // A scan may have come and gone while the last image was being read.
      this.#resume();
    });
  }

  async #work(): Promise<void> {
    while (!this.#busy()) {
      const accountId = this.#backlogs.keys().next().value;
      if (accountId === undefined) return;
      const entry = this.#backlogs.get(accountId)!;
      const account = this.#repo.accounts.get(accountId);
      if (!account) {
        this.#backlogs.delete(accountId);
        continue;
      }
      let out = { finished: true, read: 0 };
      try {
        // Images are pulled through the network chosen for the account's platform, as its scan's were.
        out = await through(routeFor(this.#repo, this.#vault, account.provider), () =>
          entry.backlog.run({
            // A scan that was asked for goes first; a removed account has nowhere to keep results.
            stop: () => this.#busy() || !this.#repo.accounts.get(accountId),
            onProgress: (done) => {
              entry.done = done;
              this.#show();
            },
          }),
        );
      } catch (e) {
        this.#log(`Reading ${displayName(account)}'s remaining images stopped: ${(e as Error)?.message || e}`);
      }
      // Its account was scanned again meanwhile: that scan's own backlog, if any, has taken this one's place.
      if (this.#backlogs.get(accountId) !== entry) continue;
      if (!out.finished) {
        if (this.#repo.accounts.get(accountId)) return;
        this.#backlogs.delete(accountId);
        continue;
      }
      this.#backlogs.delete(accountId);
      this.#show();
      if (!out.read) continue;
      // The results are in the account's cache: a scan now pulls nothing, and reports what the images hold.
      this.#log(
        `Read ${out.read} more ${out.read === 1 ? "image" : "images"} of ${displayName(account)} in the background; scanning it again for their findings`,
      );
      this.start("images", [accountId]);
    }
  }

  async #scan(job: Job): Promise<ScanResult> {
    const account = this.#repo.accounts.get(job.accountId);
    if (!account) throw new Error(`Account ${job.accountId} was removed.`);
    const { id, started } = this.#repo.scans.create(account.id, job.trigger);
    this.state = {
      running: true,
      accountId: account.id,
      scanId: id,
      trigger: job.trigger,
      startedAt: started,
      phase: "Starting",
      done: null,
      total: null,
      queued: this.#jobs.map((j) => j.accountId),
    };
    const token = this.#vault.get(account.tokenId);
    if (!token) {
      const msg = `The ${PROVIDER[account.provider].info.credential} for this account is missing. Replace it on the Accounts page.`;
      this.#repo.scans.fail(id, msg, 0);
      this.#log(`Scan ${id} (${displayName(account)}) failed: ${msg}`);
      throw new Error(msg);
    }
    const provider = PROVIDER[account.provider];
    let calls = 0;
    let route: Route | null = null;
    try {
      const settings = this.#repo.settings.get();
      const entity = this.#repo.entities.get(account.entityId);
      const siblings = this.#siblings(account);
      const overrides = this.#repo.settings.overrides();
      const prev = this.#repo.scans.latest(account.id);
      // Every request of the scan leaves through the network chosen for the platform (Networks page).
      route = routeFor(this.#repo, this.#vault, account.provider);
      await checkRoute(route, originFor(account.provider, token.token));
      const out = await through(route, () =>
        provider.scan({
          token: token.token,
          account,
          probeTakeovers: settings.probes.takeover,
          previous: prev?.snapshot ? (JSON.parse(prev.snapshot as string) as ScanSnapshot) : null,
          cache: this.#repo.cache.for(account.id),
          toolDir: this.#toolDir,
          engine: {
            orgDomains: [...(entity?.orgDomains || []), ...siblings.domains],
            disabledChecks: overrides.disabled,
            severityOverrides: overrides.severity,
            related: siblings.related,
          },
          onProgress: (p) => {
            this.state = { ...this.state, phase: p.phase, done: p.done ?? null, total: p.total ?? null };
          },
        }),
      );
      calls = out.calls;
      const result = out.evaluation;
      const settled = this.#repo.findings.settled();
      const scored = result.findings.map((f) => ({ ...f, settled: settled.has(f.fingerprint!) }));
      const score = computeScore(result.categories, scored);
      const counts = severityCounts(scored.filter((f) => !f.settled));

      const snapshot: ScanSnapshot = { accountName: out.accountName, coverage: out.coverage, checks: result.checkStats, ...out.snapshot };

      this.#repo.scans.complete(id, { findings: result.findings, score: score.overall, counts, categories: result.categories, snapshot, calls });
      // What the scan had no time to read waits for the queue to empty; a scan that read everything clears what an earlier one left.
      if (out.backlog?.total) this.#backlogs.set(account.id, { backlog: out.backlog, done: 0 });
      else this.#backlogs.delete(account.id);
      this.#show();
      this.#repo.scans.prune(account.id, settings.retentionDays);
      // Keep the provider's name current, for accounts renamed in its dashboard.
      if (out.accountName && out.accountName !== account.name) this.#repo.accounts.update(account.id, { name: out.accountName });

      // Alert only on findings that are new since the previous scan (never on the first scan).
      let fresh: typeof result.findings = [];
      if (prev && entity) {
        const before = new Set(this.#repo.scans.fingerprints(prev.id as number).map((r) => r.fingerprint));
        fresh = result.findings.filter((f) => !before.has(f.fingerprint!) && !settled.has(f.fingerprint!));
        // A fresh finding that was seen before has come back after being resolved.
        const reopened = new Set(
          this.#repo.findings
            .forScan(id, settings.slaDays)
            .filter((f) => f.reopened)
            .map((f) => f.fingerprint),
        );
        await notifyScan(
          entity.notifications,
          settings.baseUrl,
          {
            accountId: account.id,
            accountName: account.alias || out.accountName || account.name || account.id,
            provider: provider.info.label,
            entityName: entity.name,
            scanId: id,
            finishedAt: new Date().toISOString(),
            score: score.overall,
            counts,
            newFindings: fresh.map((f) => ({
              fingerprint: f.fingerprint!,
              severity: f.severity,
              title: f.title,
              resource: f.resource,
              zone: f.zone,
              reopened: reopened.has(f.fingerprint!),
            })),
          },
          this.#log,
        );
      }
      this.#log(
        `Scan ${id} (${displayName(account)}) finished: score ${score.overall ?? "n/a"}, ${result.findings.length} findings, ${calls} API calls${route ? `, through ${route.name}` : ""}`,
      );
      return { accountId: account.id, scanId: id, score: score.overall, findings: result.findings.length, newFindings: fresh.length };
    } catch (e) {
      this.#repo.scans.fail(id, String((e as Error)?.message || e), calls || Number((e as { calls?: number })?.calls) || 0);
      this.#log(`Scan ${id} (${displayName(account)}) failed${route ? ` through ${route.name}` : ""}: ${(e as Error)?.message || e}`);
      throw e;
    }
  }

  /**
   * What the entity's other accounts share with this one, from their latest scans: the domains they
   * own (internal email domains), and the links that checks spanning providers compare against.
   * A provider with no scanned account in the entity stays null, so those checks are skipped; so does
   * a list that any account of its provider hasn't published yet.
   */
  #siblings(account: Account): { domains: string[]; related: Related } {
    const domains: string[] = [];
    const related: Related = { ...NO_RELATED, unknown: [] };
    const merge = <K extends LinkKey>(k: K, list: NonNullable<Related[K]>) => {
      related[k] = [...(related[k] ?? []), ...list] as Related[K];
    };
    const unknown = new Set<LinkKey>();
    for (const a of this.#repo.accounts.list()) {
      if (a.entityId !== account.entityId || a.id === account.id) continue;
      const s = this.#repo.scans.latest(a.id);
      const snap = s?.snapshot ? (JSON.parse(s.snapshot as string) as ScanSnapshot) : null;
      if (snap) domains.push(...PROVIDER[a.provider].ownedDomains(snap));
      // Every list this account's provider publishes: merged when it's there, unknown when it isn't.
      for (const k of LINK_KEYS) {
        if (LINK_PROVIDER[k] !== a.provider) continue;
        const list = snap?.links?.[k];
        if (list) merge(k, list);
        else unknown.add(k);
      }
    }
    // A list that one account couldn't supply is incomplete, and an incomplete list is never used.
    for (const k of unknown) related[k] = null;
    related.unknown = [...unknown];
    return { domains, related };
  }
}
