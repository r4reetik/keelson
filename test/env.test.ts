// Settings from the environment, the defaults that depend on where Keelson runs,
// and the image, which is the only way Keelson ships.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { defaultDataDir, defaultHost, env, installKind } from "../src/env.ts";
import { networkUrls } from "../src/main.ts";
import { devHost } from "../scripts/dev-host.ts";

const read = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

describe("settings from the environment", () => {
  test("are KEELSON_* variables, and empty counts as unset", () => {
    assert.equal(env("PORT", { KEELSON_PORT: "5000" }), "5000");
    assert.equal(env("PORT", { KEELSON_PORT: "" }), undefined);
    assert.equal(env("PORT", {}), undefined);
  });

  test("KEELSON_INSTALL=docker is the Docker image; anything else runs from a clone", () => {
    assert.equal(installKind({ KEELSON_INSTALL: "docker" }), "docker");
    assert.equal(installKind({}), "source");
  });

  test("the Docker image listens on every interface unless told otherwise", () => {
    assert.equal(defaultHost({}), "127.0.0.1");
    assert.equal(defaultHost({ KEELSON_INSTALL: "docker" }), "0.0.0.0");
    assert.equal(defaultHost({ KEELSON_INSTALL: "docker", KEELSON_HOST: "127.0.0.1" }), "127.0.0.1");
    assert.match(read("Dockerfile"), /KEELSON_INSTALL=docker/);
  });

  test("the data folder is ~/.keelson, KEELSON_DATA_DIR, or /data in the Docker image", () => {
    assert.equal(defaultDataDir("/home/me", {}), join("/home/me", ".keelson"));
    assert.equal(defaultDataDir("/home/me", { KEELSON_DATA_DIR: "/srv/keelson" }), "/srv/keelson");
    assert.equal(defaultDataDir("/home/me", { KEELSON_INSTALL: "docker" }), "/data");
    assert.equal(defaultDataDir("/home/me", { KEELSON_INSTALL: "docker", KEELSON_DATA_DIR: "/srv/keelson" }), "/srv/keelson");
  });
});

describe("sharing Keelson with the local network", () => {
  const interfaces = {
    lo0: [{ address: "127.0.0.1", family: "IPv4", internal: true }],
    en0: [
      { address: "fe80::1", family: "IPv6", internal: false },
      { address: "192.168.1.20", family: "IPv4", internal: false },
    ],
    en7: [{ address: "10.0.0.5", family: "IPv4", internal: false }],
    bridge0: [{ address: "192.168.1.20", family: "IPv4", internal: false }],
  } as unknown as NodeJS.Dict<import("node:os").NetworkInterfaceInfo[]>;

  test("a server on every interface lists the addresses other machines open, once each", () => {
    assert.deepEqual(networkUrls("0.0.0.0", 4317, interfaces), ["http://192.168.1.20:4317", "http://10.0.0.5:4317"]);
    assert.deepEqual(networkUrls("::", 8080, interfaces), ["http://192.168.1.20:8080", "http://10.0.0.5:8080"]);
  });

  test("a server on this machine only, or on one address, lists none", () => {
    assert.deepEqual(networkUrls("127.0.0.1", 4317, interfaces), []);
    assert.deepEqual(networkUrls("192.168.1.20", 4317, interfaces), []);
  });

  test("npm run dev -- --host shares on every interface, or on the address it is given", () => {
    assert.equal(devHost(["--mock"]), null);
    assert.equal(devHost(["--mock", "--host"]), "0.0.0.0");
    assert.equal(devHost(["--host", "--mock"]), "0.0.0.0");
    assert.equal(devHost(["--host", "192.168.1.20"]), "192.168.1.20");
    assert.equal(devHost(["--host=192.168.1.20", "--mock"]), "192.168.1.20");
  });

  test("the dev servers and the mock take the address from KEELSON_HOST, so the page and its API are shared together", () => {
    assert.match(read("scripts/dev.ts"), /KEELSON_HOST: host/);
    assert.match(read("web/vite.config.ts"), /process\.env\.KEELSON_HOST/);
    assert.match(read("dev/mock/server.ts"), /env\("HOST"\) \|\| "127\.0\.0\.1"/);
  });
});

describe("the image, the only way Keelson ships", () => {
  test("nothing is published to npm", () => {
    const pkg = JSON.parse(read("package.json"));
    assert.equal(pkg.name, "keelson");
    assert.equal(pkg.private, true, "private stops an accidental npm publish");
    const wf = read(".github/workflows/release.yml");
    assert.doesNotMatch(wf, /npm publish|NPM_TOKEN|registry\.npmjs\.org/);
    assert.match(wf, /images: ghcr\.io\/\$\{\{ github\.repository \}\}\n/);
  });

  test("the image keeps the node user's uid, so volumes from earlier images stay readable", () => {
    assert.match(read("Dockerfile"), /adduser -u 1000 /);
  });

  test("the image installs every library Node's own Alpine image does, and checks the binary starts", () => {
    // Without libatomic, Node 26 can't load and the container exits at once (CI caught it).
    const dockerfile = read("Dockerfile");
    assert.match(dockerfile, /apk add --no-cache libatomic libstdc\+\+/);
    assert.match(dockerfile, /RUN node --version/);
  });

  test("the image carries Syft, Grype and Grant, checked against their published sums for both platforms", () => {
    const dockerfile = read("Dockerfile");
    for (const tool of ["SYFT", "GRYPE", "GRANT"]) {
      assert.match(dockerfile, new RegExp(`${tool}_VERSION=\\d+\\.\\d+\\.\\d+ `), `${tool}'s version is pinned`);
      for (const arch of ["AMD64", "ARM64"]) assert.match(dockerfile, new RegExp(`${tool}_${arch}=[0-9a-f]{64}`), `${tool} has a sum for ${arch}`);
      assert.ok(dockerfile.includes(`fetch ${tool.toLowerCase()} "$${tool}_VERSION" "$${tool}_AMD64" "$${tool}_ARM64"`), `${tool} is fetched`);
    }
    assert.match(dockerfile, /sha256sum -c -/);
    assert.ok(dockerfile.includes("COPY --from=anchore /out/ /usr/local/bin/"));
    assert.ok(dockerfile.includes("syft version >/dev/null && grype version >/dev/null && grant version >/dev/null"));
  });

  test("runtime dependencies are plain JavaScript, since the image's build stage runs on the build machine's platform", () => {
    const deps = Object.keys(JSON.parse(read("package.json")).dependencies);
    for (const dep of deps) {
      const meta = JSON.parse(read(`node_modules/${dep}/package.json`));
      assert.ok(!meta.gypfile && !meta.scripts?.install && !meta.scripts?.postinstall, `${dep} builds native code`);
      assert.ok(!meta.optionalDependencies, `${dep} may pull in a platform-specific package`);
    }
  });
});

test("the former name is gone, except where history keeps it", () => {
  // Released changelog sections must match what each release shipped, and a shipped migration can't change.
  const name = ["edge", "watch"].join("");
  const history = new Set(["CHANGELOG.md", "src/store/db.ts"]);
  let files: string[] = [];
  try {
    files = execFileSync("git", ["grep", "-I", "-l", "-i", name], { cwd: new URL("..", import.meta.url), encoding: "utf8" })
      .split("\n")
      .filter(Boolean);
  } catch (e) {
    if ((e as { status?: number }).status !== 1) throw e; // 1: nothing found
  }
  assert.deepEqual(
    files.filter((f) => !history.has(f)),
    [],
  );
  const changelog = read("CHANGELOG.md");
  const unreleased = changelog.slice(changelog.indexOf("## Unreleased"), changelog.indexOf("\n## ", changelog.indexOf("## Unreleased") + 1));
  assert.doesNotMatch(unreleased, new RegExp(name, "i"), "new changelog notes say Keelson");
});
