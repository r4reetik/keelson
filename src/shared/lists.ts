// A list as text: what the web app's "see them all" dialog (web/src/components/full-list.tsx)
// filters, copies and exports. A column says what it holds of a row as text; from
// that come the filter, the lines Copy puts on the clipboard, and the CSV, which
// carries every column, the ones the table leaves out included. Here, not in the
// web app, so it is tested.

export interface TextColumn<T> {
  /** The column's heading, in the table and in the CSV. */
  label: string;
  /** What the column says of a row. Several values (a workload's hostnames) are a list. */
  value: (row: T) => string | string[];
  /** Offered under Copy, as a list of this column's values: what the menu calls it, and what one line is ("image", "images"). */
  copy?: { label: string; what: [string, string] };
  /** In the CSV only: the table would be too wide with it. */
  csvOnly?: boolean;
}

const asText = (v: string | string[]) => (Array.isArray(v) ? v.join(" ") : v);

/** A column's values for a row, one per line to copy. */
export const linesOf = (v: string | string[]): string[] => (Array.isArray(v) ? v : [v]).filter(Boolean);

/** The rows whose text, in any column, holds every word typed. */
export function matching<T>(rows: T[], columns: TextColumn<T>[], term: string): T[] {
  const words = term.toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return rows;
  return rows.filter((r) => {
    const text = columns
      .map((c) => asText(c.value(r)))
      .join(" ")
      .toLowerCase();
    return words.every((w) => text.includes(w));
  });
}

/** A list as CSV rows: a heading and a line per row, with every column. */
export function csvOf<T>(rows: T[], columns: TextColumn<T>[]): string[][] {
  return [columns.map((c) => c.label), ...rows.map((r) => columns.map((c) => asText(c.value(r))))];
}

/** What Copy offers: each column that asks for it, with its values over the rows, in order and without repeats. */
export function copiesOf<T>(columns: TextColumn<T>[]): { label: string; what: [string, string]; lines: (rows: T[]) => string[] }[] {
  return columns.filter((c) => c.copy).map((c) => ({ ...c.copy!, lines: (rows: T[]) => [...new Set(rows.flatMap((r) => linesOf(c.value(r))))] }));
}
