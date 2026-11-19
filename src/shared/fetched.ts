// What a list in the web app shows while its next rows load. A list that is
// filtered on the server (a search box, a page number) asks again for every
// change; emptying it each time made typing in a large list feel stuck, so it
// keeps the rows it has, marked stale, until the new ones arrive. Rows of another
// list or another view never show through. Here, not in the web app, so it is tested.

/** What was last fetched, with the path it was asked for and the list it belongs to. */
export interface Fetched<T> {
  path: string | null;
  /** The list the answer belongs to, when that list keeps its rows while loading. */
  keep: string | null;
  data: T | null;
  error: Error | null;
}

/**
 * What to show for `path`: its own answer, or the previous answer of the same list (`keep`), marked stale. An error
 * belongs to the path it came from.
 */
export function shownFor<T>(last: Fetched<T>, path: string | null, keep: string | null): { data: T | null; error: Error | null; stale: boolean } {
  if (last.path === path) return { data: last.data, error: last.error, stale: false };
  const stale = path != null && keep != null && last.keep === keep && last.data != null;
  return { data: stale ? last.data : null, error: null, stale };
}
