// The public addresses a cloud account held, carried from scan to scan, so an
// address that left the account is known as released. A DNS record that still
// points at one is dangling: the cloud gives released addresses to other
// customers. AWS and Alibaba Cloud scans keep one each.

import type { AddressHistory } from "../shared/api.ts";

const KEEP_RELEASED_DAYS = 180;
const MAX_RELEASED = 2000;

/**
 * Carries the account's address history one scan forward: an address held at the last complete scan and missing
 * now was released. A released address is forgotten when the account holds it again, or after six months. When
 * this scan couldn't read every region (`current` null) the history is kept as it was.
 */
export function addressHistory(previous: AddressHistory | null | undefined, current: string[] | null, now: number): AddressHistory {
  if (!current) return previous ?? { held: [], released: [] };
  const have = new Set(current);
  const cutoff = now - KEEP_RELEASED_DAYS * 86_400_000;
  const released = (previous?.released ?? []).filter((r) => !have.has(r.ip) && Date.parse(r.at) >= cutoff);
  const known = new Set(released.map((r) => r.ip));
  const at = new Date(now).toISOString();
  for (const ip of previous?.held ?? []) if (!have.has(ip) && !known.has(ip)) released.push({ ip, at });
  return { held: current, released: released.slice(-MAX_RELEASED) };
}
