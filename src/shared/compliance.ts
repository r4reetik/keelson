// Compliance frameworks as the API and the web see them: which frameworks there
// are, how a control's status reads, and the shapes of the Compliance page. The
// frameworks' controls and their mapping to checks live in src/compliance/.

import type { ProviderId } from "./providers.ts";
import type { ScanMeta } from "./api.ts";
import type { Severity } from "./severity.ts";

export const FRAMEWORK_IDS = ["iso27001", "pci-dss"] as const;
export type FrameworkId = (typeof FRAMEWORK_IDS)[number];

export const TOPIC_IDS = [
  "mfa",
  "sso",
  "authentication",
  "passwords",
  "privileged-access",
  "least-privilege",
  "access-lifecycle",
  "credentials",
  "secrets",
  "encryption-in-transit",
  "encryption-at-rest",
  "key-management",
  "certificates",
  "network-exposure",
  "segmentation",
  "data-exposure",
  "web-protection",
  "availability",
  "backups",
  "page-scripts",
  "logging",
  "monitoring",
  "active-threats",
  "malware",
  "vulnerabilities",
  "secure-config",
  "cloud-governance",
  "change-control",
  "secure-development",
  "environment-separation",
  "source-code",
  "supply-chain",
  "third-party-access",
  "dns",
  "email",
  "inventory",
  "remote-access",
  "endpoints",
  "web-filtering",
] as const;
export type TopicId = (typeof TOPIC_IDS)[number];

/**
 * What Keelson can say about a control from what it reads in the accounts in view. It's an indication, not an
 * assessment: Keelson never asks for evidence, and says plainly where it can't tell.
 * - failing: a check behind the control has an open finding (not accepted risk or a false positive).
 * - passing: every check behind it that applies ran, and nothing is open.
 * - no_permission: nothing is open, but a check behind it couldn't run because a credential lacks a permission.
 * - undetermined: nothing is open, but Keelson can't tell: none of its checks apply to the accounts in view, or one is turned off.
 * - out_of_scope: no check of Keelson's can speak to it (policies, people, premises).
 */
export const CONTROL_STATUSES = ["failing", "passing", "no_permission", "undetermined", "out_of_scope"] as const;
export type ControlStatus = (typeof CONTROL_STATUSES)[number];

export const CONTROL_STATUS_LABEL: Record<ControlStatus, string> = {
  failing: "Failing",
  passing: "Passing",
  no_permission: "Not enough permission",
  undetermined: "Undetermined",
  out_of_scope: "Out of scope",
};

export const CONTROL_STATUS_HINT: Record<ControlStatus, string> = {
  failing: "A check behind this requirement has an open finding.",
  passing: "Every check behind this requirement that applies to the accounts in view ran, and nothing is open.",
  no_permission:
    "Nothing is open, but Keelson doesn't have enough permission to decide: a check behind it couldn't read what it needs. Grant the missing permission and scan again.",
  undetermined: "Undetermined by Keelson right now: none of the checks behind this requirement apply to the accounts in view, or one is turned off.",
  out_of_scope: "Out of scope for Keelson: this requirement is about policies, people or premises, which no configuration Keelson reads can show.",
};

export interface FrameworkInfo {
  id: FrameworkId;
  /** "ISO/IEC 27001:2022" */
  name: string;
  /** "ISO 27001", for tabs and file names. */
  short: string;
  version: string;
  /** Who publishes it, and where to get the standard itself. */
  publisher: string;
  url: string;
  /** One or two sentences: what it is and who needs it. */
  about: string;
  /** What Keelson's indication can and can't say for this framework. */
  scopeNote: string;
}

/** A check mapped to a control, with its results in the accounts in view. */
export interface ControlCheck {
  id: string;
  provider: ProviderId;
  spans: ProviderId[];
  title: string;
  severity: Severity;
  /** Resources the check evaluated in the latest scans. */
  evaluated: number;
  /** Open findings (not accepted risk or false positive). */
  open: number;
  /** Findings accepted as a risk. */
  accepted: number;
  /** The check couldn't run in at least one account in view (a source it reads was unreadable). */
  skipped: boolean;
  /** Turned off on the Checks page. */
  disabled: boolean;
}

export interface ControlResult {
  id: string;
  title: string;
  /** The theme (ISO) or principal requirement (PCI DSS) it belongs to. */
  group: string;
  status: ControlStatus;
  /** The parts of the control Keelson's checks speak to, e.g. "8.4.1, 8.4.2, 8.4.3". */
  refs: string | null;
  /** What part of the requirement Keelson's checks can't see, or how to read them. */
  note: string | null;
  topics: { id: TopicId; label: string; about: string }[];
  /** Mapped checks of the platforms in view. */
  checks: ControlCheck[];
  open: number;
  accepted: number;
  /** The worst severity among open findings. */
  worst: Severity | null;
}

export interface ComplianceResponse {
  scan: ScanMeta | null;
  framework: FrameworkInfo;
  frameworks: FrameworkInfo[];
  /** The groups in the standard's order. */
  groups: string[];
  controls: ControlResult[];
  counts: Record<ControlStatus, number>;
}
