// The web app keeps to Kumo where Kumo has the component (AGENTS.md, Web UI
// conventions). These read the source, so a hand-made stand-in fails here before it
// reaches a page: links are Kumo's Link, routed through the app by LinkProvider, and
// the screen shown before the app has a session is built from Kumo's parts too.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

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
