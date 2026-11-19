// Which container images a repository's workflows build and push, read from the
// workflow files Keelson already fetches for the SBOM. It links a repository to
// the images it produces, so a vulnerable image can be traced to the code that
// builds it and to where it runs.
//
// Workflows name images in a handful of ways: docker/metadata-action's `images`,
// docker/build-push-action's `tags`, and `docker build -t`, `docker tag` and
// `docker push` in scripts, usually through variables. Variables set in the file
// are filled in; a registry that comes from a login step, a secret or a variable
// kept in GitHub's settings stays unknown, and the image is then matched by its
// repository's name alone. The result is a reading of text, not of what a run
// did: links made this way are shown as coming from a workflow.

import { parseImageRef, type ImageBuildLink, type RegistryKind } from "../../../shared/images.ts";

export type BuildRef = Omit<ImageBuildLink, "repo">;

const UNKNOWN = "\u0000";
const ECR = "\u0001";
const ACR = "\u0002";
const EXPR = /\$\{\{\s*([^}]+?)\s*\}\}/g;
const SHELL_VAR = /\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g;

/** The images each workflow in `files` pushes. `repo` is "org/name". */
export function imageBuilds(files: Map<string, string>, repo: string): BuildRef[] {
  const out = new Map<string, BuildRef>();
  const [owner, name] = repo.toLowerCase().split("/");
  for (const [path, text] of files) {
    if (!/^\.github\/workflows\/[^/]+\.ya?ml$/.test(path)) continue;
    const lines = text.split("\n");
    const hasEcr = /uses:\s*["']?aws-actions\/amazon-ecr-login@/.test(text);
    const hasAcr = /uses:\s*["']?aliyun\/acr-login@/.test(text);
    // Variables the file sets itself, wherever (workflow, job or step `env`): the first value wins.
    const vars = new Map<string, string>();
    for (const line of lines) {
      const m = /^\s*([A-Za-z_][A-Za-z0-9_]*):\s*(\S.*?)\s*$/.exec(line);
      if (m && /^[A-Z][A-Z0-9_]*$/.test(m[1]) && !vars.has(m[1])) vars.set(m[1], unquote(m[2]));
    }
    const resolve = (value: string, depth = 0): string => {
      if (depth > 4) return UNKNOWN;
      return value
        .replace(EXPR, (_all, expr: string) => {
          const e = expr.trim();
          if (e === "github.repository") return `${owner}/${name}`;
          if (e === "github.repository_owner") return owner;
          if (e === "github.event.repository.name") return name;
          const env = /^env\.([A-Za-z_][A-Za-z0-9_]*)$/.exec(e);
          if (env) return vars.has(env[1]) ? resolve(vars.get(env[1])!, depth + 1) : UNKNOWN;
          // A login step's registry: Amazon ECR's when the workflow signs in to it, Alibaba Cloud's likewise.
          if (/^steps\.[\w-]+\.outputs\.registry$/.test(e)) return hasEcr ? ECR : hasAcr ? ACR : UNKNOWN;
          return UNKNOWN;
        })
        .replace(SHELL_VAR, (_all, v: string) => (vars.has(v) ? resolve(vars.get(v)!, depth + 1) : UNKNOWN));
    };
    const add = (raw: string) => {
      // docker/metadata-action also takes "name=ghcr.io/org/app,enable=true".
      const named = /(?:^|,)name=([^,]+)/.exec(raw);
      const value = resolve(unquote(named ? named[1] : raw)).trim();
      if (!value) return;
      // Everything after the name (a tag or a digest) may hold variables: only the name matters.
      const at = value.split("@")[0];
      const slash = at.lastIndexOf("/");
      const colon = at.indexOf(":", slash + 1);
      const image = (colon > 0 ? at.slice(0, colon) : at).toLowerCase();
      const parts = image.split("/");
      let registry: string | null = null;
      let kind: RegistryKind | null = null;
      if ([UNKNOWN, ECR, ACR].includes(parts[0]) && parts.length > 1) {
        kind = parts[0] === ECR ? "ecr" : parts[0] === ACR ? "acr" : hasEcr && !hasAcr ? "ecr" : hasAcr && !hasEcr ? "acr" : null;
        parts.shift();
        const repository = parts.join("/");
        if (!/^[a-z0-9]+([._/-]+[a-z0-9]+)*$/.test(repository)) return;
        out.set(`${kind}|${repository}`, { registry, kind, repository, workflow: path });
        return;
      }
      if (image.includes(UNKNOWN) || image.includes(ECR) || image.includes(ACR)) return;
      const ref = parseImageRef(image);
      if (!ref) return;
      registry = ref.registry;
      out.set(`${registry}|${ref.repository}`, { registry, kind, repository: ref.repository, workflow: path });
    };

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const key = /^(\s*)(?:-\s*)?(images|tags):\s*(.*)$/.exec(line);
      if (key) {
        const inline = key[3].trim();
        // A block ("|", ">") or a list on the lines below, indented further than the key.
        const values = inline && !/^[|>][+-]?$/.test(inline) ? inline.split(",") : [];
        if (!values.length || /^[|>]/.test(inline))
          for (let j = i + 1; j < lines.length; j++) {
            const indent = /^(\s*)\S/.exec(lines[j]);
            if (!indent) continue;
            if (indent[1].length <= key[1].length) break;
            values.push(lines[j].trim().replace(/^-\s*/, ""));
          }
        // Tags that come from the metadata step are that step's `images`, read above.
        for (const v of key[2] === "images" && inline.includes("name=") ? [inline] : values) if (!/steps\.[\w-]+\.outputs\.(tags|labels)/.test(v)) add(v);
        continue;
      }
      for (const m of line.matchAll(/\bdocker\s+(?:image\s+)?push\s+(?:--[\w-]+\s+)*(["']?[^\s"';|&]+)/g)) add(m[1]);
      for (const m of line.matchAll(/\bdocker\s+(?:buildx\s+)?build\b[^|;&]*?(?:\s-t|\s--tag)[ =](["']?[^\s"';|&]+)/g)) add(m[1]);
      for (const m of line.matchAll(/\bdocker\s+tag\s+\S+\s+(["']?[^\s"';|&]+)/g)) add(m[1]);
    }
  }
  return [...out.values()].sort((a, b) => a.repository.localeCompare(b.repository));
}

const unquote = (s: string) =>
  s
    .trim()
    .replace(/\s+#.*$/, "")
    .replace(/^(["'])(.*)\1$/, "$2");
