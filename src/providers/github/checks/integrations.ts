// What else can reach the organization's code: webhooks that skip certificate
// checks or send over plain HTTP, deploy keys that can push, and other GitHub
// Apps that can change every repository. Keelson's own App is left out.

import { active, defineChecks } from "./define.ts";
import type { GithubHook } from "../types.ts";

/** Permissions that let an App change code, workflows or settings. */
const CHANGES_CODE = new Set(["administration", "contents", "workflows", "actions", "organization_administration", "secrets", "environments"]);

export default defineChecks(
  {
    "GHK-001": {
      category: "TLS & HTTPS",
      severity: "medium",
      docs: "https://docs.github.com/en/webhooks/using-webhooks/creating-webhooks",
      requires: ["orgHooks", "repoHooks"],
      title: "Webhook doesn't verify the receiver's certificate",
      why: "SSL verification is off, so anyone who can intercept the traffic can pose as the receiver and read every event GitHub sends, including code changes and who made them.",
      fix: "Open the webhook in Settings → Webhooks, choose Enable SSL verification, and give the receiver a valid certificate.",
    },
    "GHK-002": {
      category: "TLS & HTTPS",
      severity: "medium",
      docs: "https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks",
      requires: ["orgHooks", "repoHooks"],
      title: "Webhook sends events over plain HTTP",
      why: "Events, with commit messages, branch names and who pushed what, cross the internet unencrypted, and the signature header can be replayed.",
      fix: "Change the webhook's Payload URL to https:// and make sure the receiver serves HTTPS.",
    },
    "GHK-003": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys#deploy-keys",
      requires: ["deployKeys"],
      title: "Deploy key can push to the repository",
      why: "A deploy key with write access isn't tied to a person, doesn't expire and isn't covered by two-factor authentication. Whoever holds the private key can push, and it usually sits on a server.",
      fix: "In the repository's Settings → Deploy keys, remove the key and add it again without Allow write access, or replace it with a GitHub App that has only the access it needs.",
    },
    "GHK-004": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://docs.github.com/en/apps/using-github-apps/reviewing-and-modifying-installed-github-apps",
      requires: ["installations"],
      title: "GitHub App can change every repository",
      why: "The App can write code, workflows or settings in every repository, including ones created later. If the vendor or its keys are compromised, so is all of your code.",
      fix: "Under the organization's Settings → GitHub Apps, open the App's Configure page and choose Only select repositories, or remove it if nobody uses it.",
    },
  },
  ({ inv, d }, report) => {
    const hooks: [GithubHook, string | null, string][] = [
      ...(inv.hooks ?? []).map((h): [GithubHook, string | null, string] => [h, null, d.settings("hooks")]),
      ...active(inv).flatMap((r) => (r.hooks ?? []).map((h): [GithubHook, string | null, string] => [h, r.name, d.repo(r.name, "settings/hooks")])),
    ];
    // A hook list that couldn't be read skips both checks (requires), so a partial list is never judged.
    for (const [h, zone, link] of hooks) {
      if (!h.active || !h.endpoint) continue;
      const resource = `${zone ?? inv.login} webhook ${h.id} → ${h.endpoint}`;
      report("GHK-001", { zone, resource, pass: !h.insecureSsl, detail: h.insecureSsl ? "SSL verification is off" : "", link });
      const http = h.endpoint.startsWith("http:");
      report("GHK-002", { zone, resource, pass: !http, detail: http ? `Sends to ${h.endpoint}` : "", link });
    }
    report.passIfNone("GHK-001", inv.login);
    report.passIfNone("GHK-002", inv.login);

    for (const r of active(inv))
      for (const k of r.deployKeys ?? [])
        report("GHK-003", {
          zone: r.name,
          resource: `${r.name} key ${k.title}`,
          pass: k.readOnly,
          detail: k.readOnly ? "" : "Write access",
          link: d.repo(r.name, "settings/keys"),
        });
    report.passIfNone("GHK-003", inv.login);

    for (const app of inv.apps ?? []) {
      if (app.appId === inv.appId) continue;
      const writes = app.writes.filter((w) => CHANGES_CODE.has(w));
      report("GHK-004", {
        zone: null,
        resource: app.slug,
        pass: app.selection !== "all" || !writes.length,
        detail: app.selection === "all" && writes.length ? `All repositories, can write ${writes.join(", ")}` : "",
        link: d.settings("installations"),
      });
    }
    if (inv.apps) report.passIfNone("GHK-004", inv.login);
  },
);
