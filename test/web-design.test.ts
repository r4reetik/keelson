// The web app keeps to Kumo where Kumo has the component (AGENTS.md, Web UI
// conventions). These read the source, so a hand-made stand-in fails here before it
// reaches a page: links are Kumo's Link, routed through the app by LinkProvider, and
// the screen shown before the app has a session is built from Kumo's parts too.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { shownFor, type Fetched } from "../src/shared/fetched.ts";
import { copiesOf, csvOf, matching, type TextColumn } from "../src/shared/lists.ts";

const WEB = "web/src";

function sources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? sources(join(dir, e.name)) : e.name.endsWith(".tsx") ? [join(dir, e.name)] : [],
  );
}

/** Every opening tag of an element in a file, whole, however many lines it spans. */
function tags(text: string, name: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(new RegExp(`<${name}[\\s>]`, "g"))) {
    let depth = 0;
    let i = m.index + name.length + 1;
    for (; i < text.length; i++) {
      if (text[i] === "{") depth++;
      else if (text[i] === "}") depth--;
      else if (text[i] === ">" && depth === 0) break;
    }
    out.push(text.slice(m.index, i + 1));
  }
  return out;
}

test("links are Kumo's Link, not anchors or buttons styled to look like one", () => {
  const handMade: string[] = [];
  for (const file of sources(WEB))
    for (const name of ["a", "button"])
      for (const tag of tags(readFileSync(file, "utf8"), name))
        if (/className=\{?["`][^"`]*\btext-kumo-link\b/.test(tag)) handMade.push(`${file}: ${tag.replace(/\s+/g, " ").slice(0, 100)}`);
  assert.deepEqual(handMade, [], "use <Link href> (or <Link render={<button …/>}> for an action) from @cloudflare/kumo");
});

test("Kumo's links route in-app hrefs through the app", () => {
  const app = readFileSync(join(WEB, "App.tsx"), "utf8");
  assert.match(app, /<LinkProvider component=\{AppLink\}>/);
});

test("the screen for an unreachable server is built from Kumo's parts", () => {
  const app = readFileSync(join(WEB, "App.tsx"), "utf8");
  const screen = app.slice(app.indexOf("function Unreachable("), app.indexOf("/** Status checks that fail"));
  for (const part of ["<LayerCard", "<Empty", "<Button", "<Wordmark"]) assert.ok(screen.includes(part), `uses ${part}`);
});

test("copying goes through copyText, which still works on a team server over plain HTTP", () => {
  // Browsers offer navigator.clipboard only on HTTPS and localhost; copyText falls back to a text field elsewhere.
  const direct = sources(WEB).filter((file) => !file.endsWith("selection.tsx") && readFileSync(file, "utf8").includes("navigator.clipboard"));
  assert.deepEqual(direct, [], "use copyText or CopyMenu from web/src/components/selection.tsx");
});

test("lists that offer row checkboxes act on the selection with the shared selection bar", () => {
  // Findings predates the shared bar and keeps its own, with bulk triage; every other list uses SelectionBar.
  const own = sources(join(WEB, "pages")).filter((file) => {
    const text = readFileSync(file, "utf8");
    return /<Checkbox[\s>]/.test(text) && !text.includes("SelectionBar") && !file.endsWith("Findings.tsx") && !file.endsWith("Users.tsx");
  });
  assert.deepEqual(own, [], "pick rows with SelectRow and SelectPage, and act on them in SelectionBar");
});

test("the Images page's tables don't redraw when only the scan status changed", () => {
  // The shell refreshes the scan status every two seconds during a scan, and every page that reads the shell is drawn
  // again. Fifty rows of images cost about 90 ms each time on a real registry until the tables were memoized.
  const page = readFileSync(join(WEB, "pages/Images.tsx"), "utf8");
  for (const table of ["ImagesTable", "WorkloadsTable", "VulnerabilitiesTable", "ComponentsTable"])
    assert.match(page, new RegExp(`const ${table} = memo\\(`), `${table} is wrapped in memo`);
  // A memoized table only skips the redraw when its props are the same objects: the selection must be one.
  assert.match(
    readFileSync(join(WEB, "components/selection.tsx"), "utf8"),
    /return useMemo\(/,
    "useSelection returns the same object until the selection changes",
  );
});

test("a list keeps its rows while the next ones load, and never shows another list's", () => {
  // Emptying the table and drawing fifty rows again for every pause in typing is what made search feel stuck.
  const last: Fetched<string[]> = { path: "/api/images/components?q=open", keep: "all|components", data: ["openssl"], error: null };
  assert.deepEqual(shownFor(last, "/api/images/components?q=open", "all|components"), { data: ["openssl"], error: null, stale: false });
  assert.deepEqual(
    shownFor(last, "/api/images/components?q=opens", "all|components"),
    { data: ["openssl"], error: null, stale: true },
    "the same list with another search keeps its rows, marked stale",
  );
  assert.equal(shownFor(last, "/api/images/vulnerabilities?q=opens", "all|vulnerabilities").data, null, "another tab's rows don't show through");
  assert.equal(shownFor(last, "/api/images/components?q=opens", "e:2|components").data, null, "nor another view's");
  assert.equal(shownFor(last, "/api/overview", null).data, null, "a page that doesn't ask to keep rows starts empty, as before");
  assert.equal(shownFor(last, null, "all|components").stale, false);
  const failed: Fetched<string[]> = { ...last, error: new Error("no") };
  assert.equal(shownFor(failed, "/api/images/components?q=opens", "all|components").error, null, "an error belongs to the search it came from");
});

test("lists the server searches use the shared search box", () => {
  // The box waits for a pause in typing, never rewrites what is being typed, and shows that a search is running. A
  // plain input bound to the address asked the server on every key, and lost keys while the list was drawn.
  const box = readFileSync(join(WEB, "components/search.tsx"), "utf8");
  assert.match(box, /setTimeout\(\(\) => ask\(term\), SEARCH_PAUSE_MS\)/, "a search waits for a pause in typing");
  assert.match(box, /role="status" aria-label="Searching"/, "and says so while it runs");
  for (const page of ["Images.tsx", "Dependencies.tsx"]) {
    const text = readFileSync(join(WEB, "pages", page), "utf8");
    assert.match(text, /<SearchBox\s/, `${page} searches through SearchBox`);
    assert.match(text, /\{ keep: tab \}/, `${page} keeps its rows while the next ones load`);
    assert.match(text, /useDeferredValue\(/, `${page} draws new rows at low priority, so typing isn't held up`);
  }
  // Any page whose list is paged on the server and searched there.
  const typedIntoAddress = sources(join(WEB, "pages")).filter((file) => {
    const text = readFileSync(file, "utf8");
    return /offset=|"offset"/.test(text) && tags(text, "Input").some((tag) => /params\.get\("q"\)/.test(tag));
  });
  assert.deepEqual(typedIntoAddress, [], "a list searched on the server takes its search from SearchBox");
});

test("a list in full is filtered, copied a column at a time and exported with more than the table shows", () => {
  interface Image {
    name: string;
    hosts: string[];
    digest: string;
  }
  const columns: TextColumn<Image>[] = [
    { label: "Image", value: (i) => i.name, copy: { label: "Images", what: ["image", "images"] } },
    { label: "Hostnames", value: (i) => i.hosts, copy: { label: "Hostnames", what: ["hostname", "hostnames"] } },
    { label: "Digest", value: (i) => i.digest, csvOnly: true },
  ];
  const rows: Image[] = [
    { name: "registry/web:1.4.2", hosts: ["shop.example", "www.shop.example"], digest: "sha256:a1" },
    { name: "registry/api:2.0", hosts: [], digest: "sha256:b2" },
    { name: "registry/web:1.4.1", hosts: ["shop.example"], digest: "sha256:c3" },
  ];
  assert.deepEqual(matching(rows, columns, "  "), rows, "nothing typed leaves the list as it is");
  assert.deepEqual(
    matching(rows, columns, "WEB shop").map((r) => r.name),
    ["registry/web:1.4.2", "registry/web:1.4.1"],
    "every word typed, in any column, whatever its case",
  );
  assert.deepEqual(
    matching(rows, columns, "sha256:b2").map((r) => r.name),
    ["registry/api:2.0"],
    "found by a column only the CSV shows",
  );
  assert.deepEqual(csvOf(rows.slice(0, 2), columns), [
    ["Image", "Hostnames", "Digest"],
    ["registry/web:1.4.2", "shop.example www.shop.example", "sha256:a1"],
    ["registry/api:2.0", "", "sha256:b2"],
  ]);
  const copies = copiesOf(columns);
  assert.deepEqual(
    copies.map((c) => c.label),
    ["Images", "Hostnames"],
    "a column is offered under Copy only when it says so",
  );
  assert.deepEqual(copies[1].lines(rows), ["shop.example", "www.shop.example"], "one value per line, each once, none for a row that has none");
});

test("a row that names the first few of a group opens the rest", () => {
  // "and 43 more" as plain text left no way to see or copy the other 43 without an export.
  const plain: string[] = [];
  for (const file of sources(WEB)) {
    if (file.endsWith("full-list.tsx")) continue;
    const lines = readFileSync(file, "utf8").split("\n");
    lines.forEach((line, n) => {
      // The count written into a string: text can't be clicked.
      if (/and \$\{num\([^`]*\)\} more/.test(line)) plain.push(`${file}:${n + 1}`);
      // The count in JSX: it is a MoreLink's own text.
      if (/and \{num\(.*\)\} more/.test(line) && !lines.slice(Math.max(0, n - 2), n + 1).some((l) => /<MoreLink[\s>]/.test(l))) plain.push(`${file}:${n + 1}`);
    });
  }
  assert.deepEqual(plain, [], "say how many more there are with MoreLink or MoreNames (web/src/components/full-list.tsx), which open them all");
  const dialog = readFileSync(join(WEB, "components/full-list.tsx"), "utf8");
  assert.match(dialog, /<CopyMenu /, "the list in full copies a column as lines");
  assert.match(dialog, /downloadCsv\(list\.file, csvOf\(found, list\.columns\)\)/, "and downloads every column as CSV");
  assert.match(readFileSync(join(WEB, "App.tsx"), "utf8"), /<FullListProvider>/, "one dialog for the app, not one per row");
});
