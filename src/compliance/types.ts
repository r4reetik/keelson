// How a framework is written: its controls, in the standard's order, each naming
// the topics (src/compliance/topics.ts) and single checks that give evidence for
// it. A control with neither is out of scope for Keelson, and is still listed so
// the checklist is complete. Titles are the standards' short control names; the
// notes are Keelson's own words, never the standards' text.

import type { FrameworkInfo, TopicId } from "../shared/compliance.ts";

export interface ControlDef {
  id: string;
  title: string;
  group: string;
  topics?: TopicId[];
  /** Single checks, where a whole topic would be too broad. */
  checks?: string[];
  /** The parts of the control Keelson's checks speak to. */
  refs?: string;
  /** What the requirement covers that Keelson's checks can't see, or, out of scope, what it's about. */
  note?: string;
}

export interface Framework {
  info: FrameworkInfo;
  groups: string[];
  controls: ControlDef[];
}
