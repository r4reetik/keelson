// What leaves the organization: repositories the instance shows to anyone who
// can reach it, without signing in, and private repositories it pushes to
// another server after every change.

import { defineChecks } from "./define.ts";

export default defineChecks(
  {
    "TER-001": {
      category: "Attack surface",
      severity: "medium",
      docs: "https://docs.gitea.com/administration/config-cheat-sheet",
      requires: ["repos", "anonymous"],
      title: "Repository can be read without signing in",
      why: "The repository is public and the instance answers requests that carry no sign-in, so anyone who can reach the instance reads the code, its history and whatever was ever committed to it. On an instance the internet reaches, that is everyone.",
      fix: "1. If the code isn't meant for everyone, make the repository private under its Settings → Danger Zone, or set the organization's visibility to Limited or Private. 2. To require sign-in for the whole instance, its administrator sets REQUIRE_SIGNIN_VIEW = true under [service] in app.ini.",
    },
    "TER-002": {
      category: "Attack surface",
      severity: "low",
      docs: "https://docs.gitea.com/usage/repo-mirror",
      requires: ["repos", "pushMirrors"],
      title: "Private repository is pushed to another server",
      why: "A push mirror sends every change to another server with a credential stored in the repository's settings. The code is then only as private as the copy, and nobody who reviews access here sees who can read it there.",
      fix: "1. Open the repository's Settings → Repository → Mirror Settings. 2. Check that the copy is one your organization controls and is private there. 3. Remove the mirror if nobody uses it.",
    },
  },
  ({ inv, d }, report) => {
    const instance = hostOf(inv.base);
    for (const r of inv.repos) {
      if (r.visibility === "public" && inv.anonymous != null)
        report("TER-001", {
          zone: r.name,
          resource: r.name,
          pass: !inv.anonymous,
          confidence: "confirmed",
          detail: inv.anonymous ? `${instance} hands ${inv.login}/${r.name} to a request without a sign-in` : "",
          link: d.repo(r.name, "settings"),
        });
      if (r.visibility === "public" || !r.pushMirrors) continue;
      // A mirror to the same instance stays behind the same sign-in.
      const elsewhere = r.pushMirrors.filter((h) => h !== instance);
      report("TER-002", {
        zone: r.name,
        resource: r.name,
        pass: !elsewhere.length,
        detail: elsewhere.length ? `${r.name} is ${r.visibility} and is pushed to ${elsewhere.join(", ")}` : "",
        link: d.repo(r.name, "settings"),
      });
    }
  },
);

function hostOf(address: string): string {
  try {
    return new URL(address).host.toLowerCase();
  } catch {
    return address;
  }
}
