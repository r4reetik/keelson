// What the Data coverage table says about a source that couldn't be read: a
// missing scanner is worded for how Keelson runs and is never blamed on the
// platform or its credential.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { coverageFix, coverageNeed, isScannerTool, SCANNER_TOOLS, toolNeed } from "../src/shared/tools.ts";
import { GITHUB_SOURCES } from "../src/providers/github/sources.ts";
import { AWS_SOURCES } from "../src/providers/aws/sources.ts";

describe("a scanner's data source", () => {
  test("in the Docker image, Syft, Grype and Grant are said to be in it, Trivy and Amass not yet", () => {
    for (const key of ["syft", "grype", "grant"] as const) {
      const need = toolNeed(key, "docker");
      assert.match(need, /which the Docker image includes/, key);
      assert.doesNotMatch(need, /not in the Docker image/, key);
    }
    assert.match(toolNeed("trivy", "docker"), /isn't in the Docker image yet: mount its binary/);
    assert.match(toolNeed("amass", "docker"), /isn't in the Docker image yet/);
  });

  test("from a clone, it says nothing about the Docker image", () => {
    for (const key of Object.keys(SCANNER_TOOLS) as (keyof typeof SCANNER_TOOLS)[]) {
      const need = toolNeed(key, "source");
      assert.doesNotMatch(need, /Docker/, key);
      assert.match(need, new RegExp(`on the PATH, or its path in ${SCANNER_TOOLS[key].variable}`), key);
    }
    assert.match(toolNeed("grype", "source"), /about 3 GB/);
  });

  test("is fixed by installing the scanner, not by replacing the credential", () => {
    // A scan from before the image carried Syft kept the old words; the page words it again.
    const stored = { key: "syft", permission: "Syft installed where Keelson runs: on the PATH, or its path in KEELSON_SYFT (not in the Docker image yet)" };
    assert.deepEqual(coverageFix(stored), { kind: "tool", tool: "syft" });
    assert.match(coverageNeed(stored, "docker")!, /which the Docker image includes/);
    assert.equal(coverageFix({ key: "manifests", permission: "Repository permissions → Contents: Read-only" }).kind, "credential");
    assert.equal(coverageFix({ key: "kev", permission: "None: a public file, read from www.cisa.gov without a credential" }).kind, "none");
    assert.equal(coverageFix({ key: "registryNetwork", permission: "A connection to the account's ECR registry hosts" }).kind, "none");
    assert.equal(coverageFix({ key: "dns" }).kind, "network");
  });

  test("providers' registries take the scanners' words from one place", () => {
    for (const [key, source] of [...Object.entries(GITHUB_SOURCES), ...Object.entries(AWS_SOURCES)])
      if (isScannerTool(key)) assert.equal(source.permission, toolNeed(key), key);
    assert.match(GITHUB_SOURCES.syft.permission, /included in the Docker image/);
  });
});
