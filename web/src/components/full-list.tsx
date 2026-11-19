// The whole of a list a row only shows the start of. A row that groups many
// things (the images a vulnerability is in, the repositories a package is used
// in, the workloads that run an image) names the first few and says "and 43
// more"; that count opens this: every one of them in a table, without leaving the
// page, with a filter, any column copied as a list (one value per line, to paste
// into a ticket or a chat) and a CSV that carries more than the table shows.
//
// One dialog for the whole app (FullListProvider, in App.tsx), opened through
// useFullList(): a list's rows are drawn by the hundred, so a link in every row
// must cost nothing until it is clicked.

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { Button, Dialog, Link, Table, useKumoToastManager } from "@cloudflare/kumo";
import { copiesOf, csvOf, linesOf, matching, num, plural, type TextColumn } from "../lib.ts";
import { DialogHeader, ErrorState, Loading, NoRows } from "./ui.tsx";
import { SearchBox } from "./search.tsx";
import { CopyMenu, DownloadCsvButton, downloadCsv, type CopyItem } from "./selection.tsx";

export interface FullListColumn<T> extends TextColumn<T> {
  /** How the table draws it, when plain text isn't enough (a link, a badge). */
  cell?: (row: T) => ReactNode;
  className?: string;
}

export interface FullList<T> {
  title: string;
  description?: ReactNode;
  /** What one row is: "image", "images". */
  noun: [string, string];
  columns: FullListColumn<T>[];
  /** The rows, when the page has them all, or how to ask for them. */
  rows: T[] | (() => Promise<T[]>);
  keyOf: (row: T) => string;
  /** The CSV's file name, without the extension. */
  file: string;
}

/** Rows drawn at once; a longer list grows by this many. Copying and the CSV always take every row that matches. */
const SHOWN = 100;

/** What Copy offers for a list: each column that asks for it, over the rows `rows` gives when it is chosen. */
export function copyItemsOf<T>(rows: () => T[] | Promise<T[]>, columns: TextColumn<T>[]): CopyItem[] {
  return copiesOf(columns).map((c) => ({ label: c.label, run: async () => ({ lines: c.lines(await rows()), what: c.what }) }));
}

// The dialog holds a list of any row type; each caller's columns keep its own.
type AnyList = FullList<any>;
const Opener = createContext<((list: AnyList) => void) | null>(null);

/** Opens a list in full. Stable, so a table given it isn't drawn again for it. */
export function useFullList(): <T>(list: FullList<T>) => void {
  const open = useContext(Opener);
  if (!open) throw new Error("useFullList() outside FullListProvider");
  return open as <T>(list: FullList<T>) => void;
}

export function FullListProvider({ children }: { children: ReactNode }) {
  const [list, setList] = useState<AnyList | null>(null);
  const open = useCallback((next: AnyList) => setList(next), []);
  return (
    <Opener.Provider value={open}>
      {children}
      <Dialog.Root open={!!list} onOpenChange={(o: boolean) => !o && setList(null)}>
        <Dialog size="xl" className="flex max-h-[calc(100vh-6rem)] flex-col p-6 sm:w-[75vw]">
          {list && <FullListView key={list.title} list={list} />}
        </Dialog>
      </Dialog.Root>
    </Opener.Provider>
  );
}

function FullListView({ list }: { list: AnyList }) {
  const given = Array.isArray(list.rows) ? list.rows : null;
  const [rows, setRows] = useState<unknown[] | null>(given);
  const [error, setError] = useState<Error | null>(null);
  const [term, setTerm] = useState("");
  const [shown, setShown] = useState(SHOWN);
  const toasts = useKumoToastManager();

  const load = useCallback(() => {
    if (Array.isArray(list.rows)) return;
    let live = true;
    setError(null);
    list.rows().then(
      (r: unknown[]) => live && setRows(r),
      (e: Error) => live && setError(e),
    );
    return () => {
      live = false;
    };
  }, [list]);
  useEffect(load, [load]);

  const found = useMemo(() => matching(rows ?? [], list.columns, term), [rows, list, term]);
  const columns = list.columns.filter((c) => !c.csvOnly);
  const total = rows?.length ?? 0;
  return (
    <>
      <DialogHeader title={list.title} description={list.description} />
      {error ? (
        <ErrorState error={error} retry={load} />
      ) : !rows ? (
        <Loading />
      ) : (
        <>
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <SearchBox
              placeholder={`Filter these ${list.noun[1]}`}
              value={term}
              onChange={(t) => {
                setTerm(t);
                setShown(SHOWN);
              }}
            />
            <span className="grow text-sm text-kumo-subtle">
              {term ? `${num(found.length)} of ${plural(total, list.noun[0], list.noun[1])}` : plural(total, list.noun[0], list.noun[1])}
            </span>
            <CopyMenu items={copyItemsOf(() => found, list.columns)} label={term ? "Copy what's shown" : "Copy"} />
            <DownloadCsvButton
              onClick={() => {
                downloadCsv(list.file, csvOf(found, list.columns));
                toasts.add({ title: `Downloaded ${plural(found.length, list.noun[0], list.noun[1])}`, variant: "success" });
              }}
            />
          </div>
          <div className="min-h-0 overflow-auto rounded-md ring ring-kumo-line">
            {found.length ? (
              <Table layout="auto">
                <Table.Header variant="compact">
                  <Table.Row>
                    {columns.map((c) => (
                      <Table.Head key={c.label}>{c.label}</Table.Head>
                    ))}
                  </Table.Row>
                </Table.Header>
                <Table.Body>
                  {found.slice(0, shown).map((r) => (
                    <Table.Row key={list.keyOf(r)}>
                      {columns.map((c) => (
                        <Table.Cell key={c.label} className={c.className ?? "align-top text-sm"}>
                          {c.cell ? c.cell(r) : linesOf(c.value(r)).join(", ") || <span className="text-kumo-subtle">—</span>}
                        </Table.Cell>
                      ))}
                    </Table.Row>
                  ))}
                </Table.Body>
              </Table>
            ) : (
              <NoRows>Nothing here matches "{term}".</NoRows>
            )}
          </div>
          {found.length > shown && (
            <div className="mt-3 flex items-center justify-between gap-3 text-sm text-kumo-subtle">
              <span>
                Showing {num(shown)} of {num(found.length)}. Copy and the CSV take all of them.
              </span>
              <Button size="sm" variant="secondary" onClick={() => setShown(shown + SHOWN)}>
                Show {num(Math.min(SHOWN, found.length - shown))} more
              </Button>
            </div>
          )}
        </>
      )}
    </>
  );
}

/**
 * "and 43 more" as a link that opens the list in full. `list` is only called on the click, so a row doesn't build
 * its list to be drawn.
 */
export function MoreLink<T>({ children, list, className }: { children: ReactNode; list: () => FullList<T>; className?: string }) {
  const open = useFullList();
  return (
    <Link
      variant="plain"
      className={className}
      render={<button type="button" title="See them all, copy them or download a CSV" onClick={() => open(list())} />}
    >
      {children}
    </Link>
  );
}

const capital = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

/** A plain list of names in full: the rest of what a row names the first few of. */
export const namesList = (title: string, noun: [string, string], names: string[]): FullList<string> => ({
  title,
  noun,
  columns: [{ label: capital(noun[0]), value: (n) => n, copy: { label: capital(noun[1]), what: noun } }],
  rows: names,
  keyOf: (n) => n,
  file: `keelson-${noun[1].replace(/\s+/g, "-")}`,
});

/** After the first `shown` names of a list: "and 4 more", which opens them all. Nothing when the row names them all. */
export function MoreNames({ names, shown, title, noun }: { names: string[]; shown: number; title: string; noun: [string, string] }) {
  if (names.length <= shown) return null;
  return (
    <>
      {" "}
      <MoreLink className="whitespace-nowrap" list={() => namesList(title, noun, names)}>
        and {num(names.length - shown)} more
      </MoreLink>
    </>
  );
}
