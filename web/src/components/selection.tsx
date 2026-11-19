// Picking rows in a list and acting on them: copy their names, links or the
// repositories they affect, or download them as CSV. One pattern for every list
// (Findings, Dependencies, Repositories, Attack surface), so selecting works the
// same everywhere: tick rows, tick the header for the page, then "Select all N
// that match" to take every row the filters match, across pages.

import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Button, Checkbox, DropdownMenu, Link, useKumoToastManager } from "@cloudflare/kumo";
import { CopyIcon, DownloadSimpleIcon } from "@phosphor-icons/react";
import { num, plural } from "../lib.ts";

export interface Selection {
  keys: Set<string>;
  /** Every row the filters match is selected, including rows on other pages. */
  all: boolean;
  has: (key: string) => boolean;
  toggle: (keys: string[], on: boolean) => void;
  selectAll: () => void;
  clear: () => void;
}

/** A selection that starts over whenever `resetOn` changes (the filters, the tab): rows picked under other filters would be invisible. */
export function useSelection(resetOn: unknown): Selection {
  const [keys, setKeys] = useState<Set<string>>(new Set());
  const [all, setAll] = useState(false);
  const reset = JSON.stringify(resetOn);
  // biome-ignore lint/correctness/useExhaustiveDependencies: `reset` is the trigger, compared by value
  useEffect(() => {
    setKeys(new Set());
    setAll(false);
  }, [reset]);
  // The same object until the selection itself changes, so a table given it can skip a redraw its page didn't cause.
  return useMemo(
    () => ({
      keys,
      all,
      has: (k) => all || keys.has(k),
      toggle: (ks, on) => {
        setAll(false);
        setKeys((prev) => {
          // Leaving "every row that matches" keeps the rows picked by hand, which include the page's: "Select all" is offered only once it's ticked.
          const next = new Set(prev);
          for (const k of ks) on ? next.add(k) : next.delete(k);
          return next;
        });
      },
      selectAll: () => setAll(true),
      clear: () => {
        setKeys(new Set());
        setAll(false);
      },
    }),
    [keys, all],
  );
}

/** The header's box: ticks or unticks every row on this page. */
export function SelectPage({ selection, keys, label = "Select every row on this page" }: { selection: Selection; keys: string[]; label?: string }) {
  const on = keys.length > 0 && keys.every((k) => selection.has(k));
  return (
    <Checkbox
      aria-label={label}
      checked={on}
      indeterminate={!on && keys.some((k) => selection.has(k))}
      onCheckedChange={(v: boolean) => selection.toggle(keys, v)}
    />
  );
}

export function SelectRow({ selection, id, label }: { selection: Selection; id: string; label: string }) {
  return <Checkbox aria-label={label} checked={selection.has(id)} onCheckedChange={(v: boolean) => selection.toggle([id], v)} />;
}

/**
 * Takes the toolbar's place while rows are selected: how many, the offer to take every row that matches when the
 * whole page is ticked and there are more, the actions, and a way out.
 */
export function SelectionBar({
  selection,
  noun,
  total,
  pageKeys,
  children,
}: {
  selection: Selection;
  /** Singular and plural: ["package", "packages"]. */
  noun: [string, string];
  /** Rows that match the filters, on every page. */
  total: number;
  /** Rows on the page shown. */
  pageKeys: string[];
  children: ReactNode;
}) {
  const count = selection.all ? total : selection.keys.size;
  const pageTicked = pageKeys.length > 0 && pageKeys.every((k) => selection.has(k));
  return (
    <>
      <span className="px-1 text-sm font-medium text-kumo-default">
        {selection.all ? `All ${plural(total, noun[0], noun[1])} that match are selected` : `${plural(count, noun[0], noun[1])} selected`}
      </span>
      {!selection.all && pageTicked && total > selection.keys.size && (
        <Link render={<button type="button" onClick={selection.selectAll} />} className="text-sm">
          Select all {num(total)} that match
        </Link>
      )}
      {children}
      <Button variant="ghost" onClick={selection.clear}>
        Clear selection
      </Button>
    </>
  );
}

/** Puts text on the clipboard. Browsers offer the clipboard API only on HTTPS and localhost, so a team server on plain HTTP falls back to a hidden text field. */
export async function copyText(text: string): Promise<void> {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.appendChild(area);
  area.select();
  const ok = document.execCommand("copy");
  area.remove();
  if (!ok) throw new Error("The browser didn't allow copying. Select the text and copy it yourself.");
}

/** What a Copy menu item produces: lines to copy, and what they are, for the toast ("12 repositories"). */
export interface CopyResult {
  lines: string[];
  what: [string, string];
}

export interface CopyItem {
  label: string;
  run: () => CopyResult | Promise<CopyResult>;
}

/** Copies one item per line, without duplicates, and says how many. */
export function useCopy() {
  const toasts = useKumoToastManager();
  return async (run: CopyItem["run"]) => {
    try {
      const { lines, what } = await run();
      const unique = [...new Set(lines.filter(Boolean))];
      if (!unique.length) {
        toasts.add({ title: `No ${what[1]} to copy`, variant: "info" });
        return;
      }
      await copyText(unique.join("\n"));
      toasts.add({ title: `Copied ${plural(unique.length, what[0], what[1])}`, description: "One per line.", variant: "success" });
    } catch (e) {
      toasts.add({ title: "Couldn't copy", description: (e as Error).message, variant: "error" });
    }
  };
}

/** A "Copy" button with a menu of what to copy. Every item copies one value per line, ready to paste into a ticket, a script or a spreadsheet. */
export function CopyMenu({ items, label = "Copy", variant = "secondary" }: { items: CopyItem[]; label?: string; variant?: "secondary" | "ghost" }) {
  const copy = useCopy();
  return (
    <DropdownMenu>
      <DropdownMenu.Trigger
        render={
          <Button variant={variant} icon={<CopyIcon />}>
            {label}
          </Button>
        }
      />
      <DropdownMenu.Content>
        {items.map((i) => (
          <DropdownMenu.Item key={i.label} onClick={() => void copy(i.run)}>
            {i.label}
          </DropdownMenu.Item>
        ))}
      </DropdownMenu.Content>
    </DropdownMenu>
  );
}

const csvCell = (v: unknown) => {
  const s = v == null ? "" : String(v);
  // A leading =, +, - or @ would run as a formula in a spreadsheet.
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return /[",\n\r]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
};

/** Saves rows as a CSV file, made in the browser from what the page already has. */
export function downloadCsv(name: string, rows: unknown[][]) {
  const csv = `﻿${rows.map((r) => r.map(csvCell).join(",")).join("\r\n")}`;
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  a.download = name.endsWith(".csv") ? name : `${name}.csv`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

/** A "Download CSV" button for what's selected or shown. */
export function DownloadCsvButton({ onClick, label = "Download CSV" }: { onClick: () => void | Promise<void>; label?: string }) {
  return (
    <Button variant="secondary" icon={<DownloadSimpleIcon />} onClick={() => void onClick()}>
      {label}
    </Button>
  );
}
