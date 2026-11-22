// What is wired into the group from outside: webhooks that deliver over plain
// HTTP or without checking who receives them, deploy keys that can push, and
// deploy tokens that can write and never expire.

import { defineChecks } from "./define.ts";
import type { GitlabHook } from "../types.ts";

const WRITES = /^write_/;

export default defineChecks(
  {
    "GLH-001": {
      category: "Secrets",
      severity: "medium",
      docs: "https://docs.gitlab.com/user/project/integrations/webhooks/",
      requires: ["groupHooks", "projectHooks"],
      title: "Webhook delivers over plain HTTP",
      why: "Each delivery carries commit messages, branch names, people's names and email addresses, and the secret token that proves it came from GitLab. Over HTTP, anyone on the path reads all of it and can forge deliveries to whatever the webhook triggers.",
      fix: "1. Open the webhook under the group's or the project's Settings → Webhooks. 2. Change its URL to https://. 3. Set a Secret token, and have the receiver check it.",
    },
    "GLH-002": {
      category: "TLS & HTTPS",
      severity: "low",
      docs: "https://docs.gitlab.com/user/project/integrations/webhooks/",
      requires: ["groupHooks", "projectHooks"],
      title: "Webhook doesn't verify the receiver's certificate",
      why: "With SSL verification off, GitLab sends each delivery, with its secret token, to whoever answers at that address. Someone who can redirect the connection receives them all.",
      fix: "In the webhook's settings (Settings → Webhooks), turn on Enable SSL verification. If the receiver uses a certificate from your own authority, an administrator can add that authority to the instance.",
    },
    "GLH-003": {
      category: "Identity & access",
      severity: "low",
      docs: "https://docs.gitlab.com/user/project/deploy_keys/",
      requires: ["deployKeys"],
      title: "Deploy key can push to the project",
      why: "A deploy key belongs to no person and isn't covered by two-factor authentication. One with write access lets whoever holds the private key (a build server, a backup, an old laptop) push code.",
      fix: "1. Open the project's Settings → Repository → Deploy keys. 2. If the key only fetches code, edit it and turn off Grant write permissions to this key. 3. Remove keys nobody can name an owner for.",
    },
    "GLH-004": {
      category: "Secrets",
      severity: "low",
      docs: "https://docs.gitlab.com/user/project/deploy_tokens/",
      requires: ["deployTokens"],
      title: "Deploy token can write and never expires",
      why: "A deploy token is a username and password for the project's repository, registry or packages, held by whatever was given it. One that can write and has no expiry keeps working for as long as nobody remembers it, wherever it has been copied.",
      fix: "1. Open the project's Settings → Repository → Deploy tokens. 2. Revoke the token and create one with an expiry date and only the read scopes it needs. 3. Where something must write, give it a date and renew it.",
    },
  },
  ({ inv, d }, report) => {
    const hooks = (list: GitlabHook[], zone: string | null, name: string, link: string) => {
      if (!list.length) return;
      const plain = list.filter((h) => h.endpoint.startsWith("http://"));
      if (!plain.length) report("GLH-001", { zone, resource: name, pass: true, link });
      for (const h of plain)
        report("GLH-001", { zone, resource: `${name}:${h.endpoint}`, pass: false, detail: `The webhook to ${h.endpoint} isn't encrypted`, link });
      // Without TLS there is no certificate to check: the first finding covers that webhook.
      const secure = list.filter((h) => h.endpoint.startsWith("https://"));
      const blind = secure.filter((h) => !h.verifiesTls);
      if (secure.length && !blind.length) report("GLH-002", { zone, resource: name, pass: true, link });
      for (const h of blind)
        report("GLH-002", { zone, resource: `${name}:${h.endpoint}`, pass: false, detail: `The webhook to ${h.endpoint} accepts any certificate`, link });
    };
    if (inv.hooks) hooks(inv.hooks, null, inv.login, d.group("hooks"));
    for (const p of inv.projects) {
      if (p.archived) continue;
      if (p.hooks) hooks(p.hooks, p.name, p.name, d.project(p.name, "hooks"));
      if (p.deployKeys?.length) {
        const link = d.project(p.name, "settings/repository");
        const writers = p.deployKeys.filter((k) => k.canPush);
        if (!writers.length) report("GLH-003", { zone: p.name, resource: p.name, pass: true, link });
        for (const k of writers)
          report("GLH-003", { zone: p.name, resource: `${p.name}:${k.title}`, pass: false, detail: `The key "${k.title}" has write access`, link });
      }
      if (p.deployTokens?.length) {
        const link = d.project(p.name, "settings/repository");
        const lasting = p.deployTokens.filter((t) => !t.expiresAt && t.scopes.some((s) => WRITES.test(s)));
        if (!lasting.length) report("GLH-004", { zone: p.name, resource: p.name, pass: true, link });
        for (const t of lasting)
          report("GLH-004", {
            zone: p.name,
            resource: `${p.name}:${t.name}`,
            pass: false,
            detail: `The token "${t.name}" has ${t.scopes.filter((s) => WRITES.test(s)).join(", ")} and no expiry date`,
            link,
          });
      }
    }
  },
);
