// What is wired into the organization from outside: webhooks that deliver over
// plain HTTP, and deploy keys that can push.

import { defineChecks } from "./define.ts";
import type { GiteaHook } from "../types.ts";

export default defineChecks(
  {
    "TEH-001": {
      category: "Secrets",
      severity: "medium",
      docs: "https://docs.gitea.com/usage/webhooks",
      requires: ["orgHooks", "repoHooks"],
      title: "Webhook delivers over plain HTTP",
      why: "Each delivery carries commit messages, branch names, people's names and email addresses, and the header that proves it came from Gitea. Over HTTP, anyone on the path reads all of it and can replay or forge deliveries to whatever the webhook triggers.",
      fix: "1. Open the webhook under the organization's or the repository's Settings → Webhooks. 2. Change its Target URL to https://. 3. Set a Secret, and have the receiver check the signature.",
    },
    "TEH-002": {
      category: "Identity & access",
      severity: "low",
      docs: "https://docs.gitea.com/usage/access-control/permissions",
      requires: ["deployKeys"],
      title: "Deploy key can push to the repository",
      why: "A deploy key belongs to no person, never expires and isn't covered by two-factor authentication. One with write access lets whoever holds the private key (a build server, a backup, an old laptop) push code.",
      fix: "1. Open the repository's Settings → Deploy Keys. 2. If the key only fetches code, delete it and add it again without Enable Write Access. 3. Remove keys nobody can name an owner for.",
    },
  },
  ({ inv, d }, report) => {
    const plain = (hooks: GiteaHook[]) => hooks.filter((h) => h.active && h.endpoint.startsWith("http://"));
    if (inv.hooks) {
      const bad = plain(inv.hooks);
      if (!bad.length && inv.hooks.length) report("TEH-001", { resource: inv.login, pass: true, link: d.org("settings/hooks") });
      for (const h of bad)
        report("TEH-001", {
          resource: `${inv.login}:${h.endpoint}`,
          pass: false,
          detail: `The organization's webhook to ${h.endpoint} isn't encrypted`,
          link: d.org("settings/hooks"),
        });
    }
    for (const r of inv.repos) {
      if (r.archived) continue;
      if (r.hooks?.length) {
        const bad = plain(r.hooks);
        if (!bad.length) report("TEH-001", { zone: r.name, resource: r.name, pass: true, link: d.repo(r.name, "settings/hooks") });
        for (const h of bad)
          report("TEH-001", {
            zone: r.name,
            resource: `${r.name}:${h.endpoint}`,
            pass: false,
            detail: `${r.name}'s webhook to ${h.endpoint} isn't encrypted`,
            link: d.repo(r.name, "settings/hooks"),
          });
      }
      if (!r.deployKeys?.length) continue;
      const writers = r.deployKeys.filter((k) => !k.readOnly);
      if (!writers.length) report("TEH-002", { zone: r.name, resource: r.name, pass: true, link: d.repo(r.name, "settings/keys") });
      for (const k of writers)
        report("TEH-002", {
          zone: r.name,
          resource: `${r.name}:${k.title}`,
          pass: false,
          detail: `The key "${k.title}" has write access`,
          link: d.repo(r.name, "settings/keys"),
        });
    }
  },
);
