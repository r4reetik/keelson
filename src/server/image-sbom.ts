// An image's software bill of materials, written from what Keelson kept of
// Trivy's scan: every package with its version, type, license and package URL,
// the operating system and runtimes the image is built on, and the known
// vulnerabilities of each. CycloneDX 1.6 (with its vulnerabilities section) and
// SPDX 2.3, both as JSON, so other tools can read what the image is made of.
//
// The documents are built here rather than by running Trivy again: that would
// pull the image a second time, and everything they hold is already stored.

import { createHash } from "node:crypto";
import { imageName, type ImageRow, type ImageScan } from "../shared/images.ts";

export const SBOM_FORMATS = { cyclonedx: "cdx.json", spdx: "spdx.json" } as const;
export type SbomFormat = keyof typeof SBOM_FORMATS;

/** A stable ID from a text, in the shape of a UUID: the same image gives the same document ID. */
function uuidOf(text: string): string {
  const h = createHash("sha256").update(text).digest("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

/** The image's own package URL: pkg:oci/<name>@<digest>?repository_url=<registry/repository>. */
function ociPurl(image: ImageRow): string {
  const name = image.repository.split("/").pop() ?? image.repository;
  const version = image.digest ? `@${encodeURIComponent(image.digest)}` : "";
  const tag = image.tags[0] ? `&tag=${encodeURIComponent(image.tags[0])}` : "";
  return `pkg:oci/${name}${version}?repository_url=${encodeURIComponent(imageName(image))}${tag}`;
}

const SEVERITY: Record<string, string> = { critical: "critical", high: "high", medium: "medium", low: "low", unknown: "unknown" };

/** CycloneDX 1.6: components, and the vulnerabilities that affect them. */
export function cyclonedx(image: ImageRow, scan: ImageScan): unknown {
  const root = `image:${imageName(image)}@${image.digest ?? image.tags[0] ?? ""}`;
  const refOf = (p: { type: string; name: string; version: string }) => p.type && `pkg:${p.type}/${p.name}@${p.version}`;
  const seen = new Set<string>();
  const components: Record<string, unknown>[] = [];
  if (scan.os)
    components.push({
      type: "operating-system",
      "bom-ref": `os:${scan.os.family}@${scan.os.name}`,
      name: scan.os.family,
      version: scan.os.name,
      properties: [{ name: "keelson:end-of-life", value: String(scan.os.eol) }],
    });
  for (const r of scan.runtimes)
    components.push({
      type: "platform",
      "bom-ref": `runtime:${r.name}@${r.version}`,
      name: r.name,
      version: r.version,
      properties: [
        ...(r.eol == null ? [] : [{ name: "keelson:end-of-life", value: String(r.eol) }]),
        ...(r.latest ? [{ name: "keelson:latest-in-release-line", value: r.latest }] : []),
      ],
    });
  for (const p of scan.packages) {
    const ref = p.purl ?? refOf(p);
    if (seen.has(ref)) continue;
    seen.add(ref);
    components.push({
      type: "library",
      "bom-ref": ref,
      name: p.name,
      version: p.version,
      ...(p.purl ? { purl: p.purl } : {}),
      ...(p.licenses.length ? { licenses: p.licenses.map((name) => ({ license: { name } })) } : {}),
      properties: [
        { name: "keelson:package-type", value: p.type },
        { name: "keelson:from", value: p.layer === "os" ? "operating system" : "application" },
        ...(p.base ? [{ name: "keelson:layer", value: "base image" }] : []),
        ...(p.path ? [{ name: "keelson:recorded-in", value: p.path }] : []),
      ],
    });
  }
  const purlOf = new Map(scan.packages.map((p) => [`${p.type}|${p.name}|${p.version}`, p.purl ?? refOf(p)]));
  const vulns = new Map<string, { v: ImageScan["vulns"][number]; refs: Set<string> }>();
  for (const v of scan.vulns) {
    const ref = purlOf.get(`${v.type}|${v.pkg}|${v.version}`) ?? refOf({ type: v.type, name: v.pkg, version: v.version });
    const e = vulns.get(v.id) ?? { v, refs: new Set<string>() };
    e.refs.add(ref);
    vulns.set(v.id, e);
  }
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: `urn:uuid:${uuidOf(root)}`,
    version: 1,
    metadata: {
      timestamp: scan.scannedAt,
      tools: {
        components: [
          { type: "application", name: "trivy", ...(scan.trivy ? { version: scan.trivy } : {}) },
          { type: "application", name: "keelson" },
        ],
      },
      component: {
        type: "container",
        "bom-ref": root,
        name: imageName(image),
        version: image.tags[0] ?? image.digest ?? "",
        purl: ociPurl(image),
        ...(image.digest?.startsWith("sha256:") ? { hashes: [{ alg: "SHA-256", content: image.digest.slice(7) }] } : {}),
      },
    },
    components,
    dependencies: [{ ref: root, dependsOn: components.map((c) => c["bom-ref"]) }],
    vulnerabilities: [...vulns.values()].map(({ v, refs }) => ({
      id: v.id,
      ...(v.url ? { source: { name: "Trivy", url: v.url } } : {}),
      ratings: [{ severity: SEVERITY[v.severity], ...(v.cvss != null ? { score: v.cvss, method: "CVSSv3" } : {}) }],
      ...(v.title ? { description: v.title } : {}),
      ...(v.fixedIn ? { recommendation: `Upgrade ${v.pkg} to ${v.fixedIn}` } : {}),
      affects: [...refs].map((ref) => ({ ref })),
      properties: [
        { name: "keelson:known-exploited", value: String(v.kev) },
        { name: "keelson:status", value: v.status },
      ],
    })),
  };
}

/** SPDX 2.3: the image and its packages, each contained in the image. */
export function spdx(image: ImageRow, scan: ImageScan): unknown {
  const name = `${imageName(image)}${image.tags[0] ? `:${image.tags[0]}` : ""}`;
  const idOf = (text: string) => `SPDXRef-${createHash("sha256").update(text).digest("hex").slice(0, 16)}`;
  const root = "SPDXRef-image";
  const seen = new Set<string>();
  const packages: Record<string, unknown>[] = [
    {
      SPDXID: root,
      name: imageName(image),
      versionInfo: image.tags[0] ?? image.digest ?? "",
      downloadLocation: "NOASSERTION",
      filesAnalyzed: false,
      primaryPackagePurpose: "CONTAINER",
      externalRefs: [{ referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: ociPurl(image) }],
      ...(image.digest?.startsWith("sha256:") ? { checksums: [{ algorithm: "SHA256", checksumValue: image.digest.slice(7) }] } : {}),
    },
  ];
  const add = (key: string, pkg: Record<string, unknown>) => {
    if (seen.has(key)) return;
    seen.add(key);
    packages.push({ SPDXID: idOf(key), downloadLocation: "NOASSERTION", filesAnalyzed: false, licenseConcluded: "NOASSERTION", ...pkg });
  };
  if (scan.os) add(`os|${scan.os.family}|${scan.os.name}`, { name: scan.os.family, versionInfo: scan.os.name, primaryPackagePurpose: "OPERATING-SYSTEM" });
  for (const r of scan.runtimes) add(`runtime|${r.name}|${r.version}`, { name: r.name, versionInfo: r.version, primaryPackagePurpose: "APPLICATION" });
  for (const p of scan.packages)
    add(`${p.type}|${p.name}|${p.version}`, {
      name: p.name,
      versionInfo: p.version,
      primaryPackagePurpose: "LIBRARY",
      licenseDeclared: p.licenses.length ? p.licenses.join(" AND ") : "NOASSERTION",
      ...(p.purl ? { externalRefs: [{ referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: p.purl }] } : {}),
      ...(p.base ? { comment: "Came with the base image." } : {}),
    });
  return {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name,
    documentNamespace: `https://keelson.invalid/spdx/${uuidOf(`${name}@${image.digest ?? ""}`)}`,
    creationInfo: { created: scan.scannedAt.replace(/\.\d+Z$/, "Z"), creators: [`Tool: trivy${scan.trivy ? `-${scan.trivy}` : ""}`, "Tool: keelson"] },
    packages,
    relationships: [
      { spdxElementId: "SPDXRef-DOCUMENT", relationshipType: "DESCRIBES", relatedSpdxElement: root },
      ...packages.slice(1).map((p) => ({ spdxElementId: root, relationshipType: "CONTAINS", relatedSpdxElement: p.SPDXID })),
    ],
  };
}

export const sbomOf = (format: SbomFormat, image: ImageRow, scan: ImageScan): unknown => (format === "spdx" ? spdx(image, scan) : cyclonedx(image, scan));
