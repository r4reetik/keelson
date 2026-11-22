// Who can reach an organization's repositories and how they sign in: members
// without two-factor authentication, how many owners there are, teams other
// than the owners' that administer every repository, and people outside the
// organization who were given their own access to a repository.

import { defineChecks, owners } from "./define.ts";

/** More owners than this is worth a look: each one's sign-in opens everything. */
const MANY_OWNERS = 5;
const DOCS = "https://docs.gitea.com/usage/access-control/permissions";

export default defineChecks(
  {
    "TEI-001": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://docs.gitea.com/administration/config-cheat-sheet",
      requires: ["members", "twoFactor"],
      title: "Member signs in without two-factor authentication",
      why: "A reused or phished password is then all it takes to read and change every repository that person can reach. For an owner, that is all of them, with the organization's settings and webhooks.",
      fix: "1. Ask the person to turn it on under their Settings → Security → Two-Factor Authentication. 2. To require it for everyone, the instance's administrator can set TWO_FACTOR_AUTH = enforced under [security] in app.ini (Gitea 1.24 and later).",
    },
    "TEI-002": {
      category: "Identity & access",
      severity: "low",
      docs: DOCS,
      requires: ["teams"],
      title: "Many people own the organization",
      why: "An owner can change every repository, every team and every webhook, and delete the organization. Each owner's password, token and laptop is a way in to all of it.",
      fix: "1. Open the organization's Teams page and the Owners team. 2. Keep the people who run the organization, and move the others to a team with the access they use.",
    },
    "TEI-003": {
      category: "Identity & access",
      severity: "medium",
      docs: DOCS,
      requires: ["teams"],
      title: "A team other than the owners administers every repository",
      why: "Administering a repository means changing its branch rules, webhooks, deploy keys and collaborators. A team with that on every repository, including ones created later, is a second set of owners that nobody reviews as one.",
      fix: "1. Open the team under the organization's Teams page. 2. Give it the repositories it works on instead of All repositories, or lower its access to Write.",
    },
    "TEI-004": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://docs.gitea.com/usage/access-control/permissions",
      requires: ["members", "collaborators"],
      title: "Someone outside the organization can change a repository",
      why: "A collaborator added to one repository isn't in any team, so they aren't removed when teams are reviewed or when a contract ends. With write access they push code; as an administrator they also change its branch rules, webhooks and deploy keys.",
      fix: "1. Open the repository's Settings → Collaborators. 2. Remove the person, lower them to Read, or add them to the organization and a team so their access is reviewed with everyone else's.",
    },
  },
  ({ inv, d }, report) => {
    const who = owners(inv);
    if (inv.members && inv.noTwoFactor) {
      const without = new Set(inv.noTwoFactor);
      const owning = new Set(who ?? []);
      for (const login of inv.members)
        report("TEI-001", {
          resource: login,
          pass: !without.has(login),
          severity: without.has(login) && owning.has(login) ? "high" : undefined,
          detail: without.has(login) ? (owning.has(login) ? `${login} owns the organization and has no second factor` : `${login} has no second factor`) : "",
          link: d.user(login),
        });
    }
    if (who)
      report("TEI-002", {
        resource: inv.login,
        pass: who.length <= MANY_OWNERS,
        detail: who.length > MANY_OWNERS ? `${who.length} owners: ${who.slice(0, 8).join(", ")}${who.length > 8 ? "…" : ""}` : "",
        link: d.org("teams"),
      });
    for (const t of inv.teams ?? []) {
      if (t.permission === "owner") continue;
      const wide = t.permission === "admin" && t.allRepos;
      report("TEI-003", {
        resource: t.name,
        pass: !wide,
        detail: wide
          ? `${t.name} administers all repositories${t.members ? `: ${t.members.length} ${t.members.length === 1 ? "member" : "members"}` : ""}`
          : "",
        link: d.org(`teams/${encodeURIComponent(t.name)}`),
      });
    }
    for (const r of inv.repos) {
      if (r.archived || !r.outsiders) continue;
      const changing = r.outsiders.filter((o) => o.permission === "write" || o.permission === "admin" || o.permission === "owner");
      if (!changing.length) report("TEI-004", { zone: r.name, resource: r.name, pass: true, link: d.repo(r.name, "settings/collaboration") });
      for (const o of changing) {
        const admin = o.permission !== "write";
        report("TEI-004", {
          zone: r.name,
          resource: `${r.name}:${o.login}`,
          pass: false,
          severity: admin ? undefined : "low",
          detail: `${o.login} isn't a member of ${inv.login} and ${admin ? "administers" : "can push to"} ${r.name}`,
          link: d.repo(r.name, "settings/collaboration"),
        });
      }
    }
  },
);
