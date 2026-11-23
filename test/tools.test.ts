// What the Data coverage table says about a source that couldn't be read: a
// missing scanner is worded for how Keelson runs and is never blamed on the
// platform or its credential.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { coverageFix, coverageNeed, isScannerTool, notInstalled, SCANNER_TOOLS, scannerMissing, toolNeed, unreadableSentence } from "../src/shared/tools.ts";
import { GITHUB_SOURCES } from "../src/providers/github/sources.ts";
import { AWS_SOURCES } from "../src/providers/aws/sources.ts";

describe("a scanner's data source", () => {
  test("in the Docker image, every scanner is said to be in it", () => {
    for (const key of Object.keys(SCANNER_TOOLS) as (keyof typeof SCANNER_TOOLS)[]) {
      const need = toolNeed(key, "docker");
      assert.match(need, /which the Docker image includes/, key);
      assert.doesNotMatch(need, /not in the Docker image/, key);
    }
  });

  test("a scanner said to be in the image is fetched into it, and one fetched is said to be", () => {
    const dockerfile = readFileSync(new URL("../Dockerfile", import.meta.url), "utf8");
    const fetched = new Set([...dockerfile.matchAll(/^\s*fetch (\w+) /gm)].map((m) => m[1]));
    for (const [key, tool] of Object.entries(SCANNER_TOOLS)) assert.equal(fetched.has(key), tool.inImage, key);
    for (const key of fetched) assert.ok(isScannerTool(key), `${key} is fetched but Keelson doesn't know it as a scanner`);
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
    assert.deepEqual(coverageFix(stored), { kind: "tool", tool: "syft", missing: true });
    assert.match(coverageNeed(stored, "docker")!, /which the Docker image includes/);
    assert.equal(coverageFix({ key: "manifests", permission: "Repository permissions → Contents: Read-only" }).kind, "credential");
    assert.equal(coverageFix({ key: "kev", permission: "None: a public file, read from www.cisa.gov without a credential" }).kind, "none");
    assert.equal(coverageFix({ key: "registryNetwork", permission: "A connection to the account's ECR registry hosts" }).kind, "none");
    assert.equal(coverageFix({ key: "dns" }).kind, "network");
  });

  test("a page with nothing to show says how to get the scanner, not to replace the credential", () => {
    // The Dependencies page's empty state, from a scan made before the image carried Syft.
    const syft = {
      key: "syft",
      label: "Software bill of materials (Anchore Syft)",
      provider: "github" as const,
      permission: "Syft installed where Keelson runs: on the PATH, or its path in KEELSON_SYFT (not in the Docker image yet)",
    };
    const inDocker = unreadableSentence(syft, "docker");
    assert.match(inDocker, /^Keelson can't read software bill of materials \(Anchore Syft\)\. It needs Syft, which the Docker image includes/);
    assert.doesNotMatch(inDocker, /credential|Accounts page|not in the Docker image/);
    const fromClone = unreadableSentence(syft, "source");
    assert.match(fromClone, /Syft installed on the machine Keelson runs on/);
    assert.doesNotMatch(fromClone, /Docker|credential/);

    const contents = {
      key: "manifests",
      label: "Manifest and lock files",
      provider: "github" as const,
      permission: "Repository permissions → Contents: Read-only",
    };
    assert.match(unreadableSentence(contents, "docker"), /replace the GitHub App on the Accounts page/);
    assert.match(unreadableSentence({ key: "dns", label: "Public DNS lookups" }), /reach the internet over HTTPS/);
  });

  test("a scanner that ran and failed says why, and isn't said to need installing", () => {
    // The Images page said Trivy needed installing in the image after Trivy itself had failed on one image.
    const failed = {
      key: "trivy",
      label: "Packages, vulnerabilities and stored credentials in container images (Aqua Trivy)",
      permission: toolNeed("trivy"),
      message: "Trivy's database couldn't be downloaded: connection refused",
    };
    assert.deepEqual(coverageFix(failed), { kind: "tool", tool: "trivy", missing: false });
    assert.equal(coverageNeed(failed, "docker"), undefined);
    assert.equal(
      unreadableSentence(failed, "docker"),
      "Keelson can't read packages, vulnerabilities and stored credentials in container images (Aqua Trivy): Trivy's database couldn't be downloaded: connection refused. Then scan again.",
    );

    // What every scan says when the scanner isn't there, in its own words, and a gap from before messages were kept.
    for (const name of ["Syft", "Grype", "Grant", "Trivy", "Amass"]) {
      const missing = { key: name.toLowerCase(), permission: "", message: notInstalled(name) };
      assert.ok(scannerMissing(missing), name);
      assert.match(coverageNeed(missing, "source") ?? "", /installed on the machine Keelson runs on/, name);
    }
    assert.ok(scannerMissing({ message: undefined }));
  });

  test("providers' registries take the scanners' words from one place", () => {
    for (const [key, source] of [...Object.entries(GITHUB_SOURCES), ...Object.entries(AWS_SOURCES)])
      if (isScannerTool(key)) assert.equal(source.permission, toolNeed(key), key);
    assert.match(GITHUB_SOURCES.syft.permission, /included in the Docker image/);
  });
});
