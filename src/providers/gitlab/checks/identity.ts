// The group's own settings and who runs it: whether everyone must sign in with
// two-factor authentication, how many owners there are, and whether projects
// can be shared with groups outside it.

import { defineChecks } from "./define.ts";
import { OWNER } from "../types.ts";

/** More owners than this is worth a look: each one's sign-in opens everything. */
const MANY_OWNERS = 5;

export default defineChecks(
  {
    "GLG-001": {
      category: "Identity & access",
      severity: "high",
      docs: "https://docs.gitlab.com/security/two_factor_authentication/",
      requires: ["group"],
      title: "Group doesn't require two-factor authentication",
      why: "Anyone in the group can sign in with a password alone. A reused or phished password is then enough to read and change every project that person can reach, and for an owner that is all of them.",
      fix: "1. Open the group's Settings → General → Permissions and group features. 2. Turn on All users in this group must set up two-factor authentication, with a short grace period. 3. On your own instance, an administrator can require it for everyone under Admin → Settings → General → Sign-in restrictions.",
    },
    "GLG-002": {
      category: "Identity & access",
      severity: "low",
      docs: "https://docs.gitlab.com/user/permissions/",
      requires: ["members"],
      title: "Many people own the group",
      why: "An owner can change every project, every member's role and every setting, and delete the group. Each owner's password, token and laptop is a way in to all of it.",
      fix: "1. Open the group's Manage → Members and filter by the Owner role. 2. Keep the people who run the group, and lower the others to Maintainer or Developer.",
    },
    "GLG-003": {
      category: "Identity & access",
      severity: "low",
      docs: "https://docs.gitlab.com/user/project/members/sharing_projects_groups/",
      requires: ["group"],
      title: "Projects can be shared with groups outside this one",
      why: "A project's maintainer can invite another group to it, and every member of that group then has the access it was given. Nobody who reviews this group's members sees them, and they stay when a contract ends.",
      fix: "1. Open the group's Settings → General → Permissions and group features. 2. Turn on Projects in this group cannot be shared with other groups. 3. Add outside people as members of this group instead, so their access is reviewed with everyone else's.",
    },
  },
  ({ inv, d }, report) => {
    if (inv.group) {
      report("GLG-001", {
        resource: inv.login,
        pass: inv.group.requireTwoFactor,
        detail: inv.group.requireTwoFactor ? "" : "Members can sign in with a password alone",
        link: d.group("edit"),
      });
      report("GLG-003", {
        resource: inv.login,
        pass: inv.group.shareLock,
        detail: inv.group.shareLock ? "" : "A maintainer can share a project with any other group",
        link: d.group("edit"),
      });
    }
    if (inv.members) {
      const owners = inv.members.filter((m) => m.level >= OWNER).map((m) => m.username);
      report("GLG-002", {
        resource: inv.login,
        pass: owners.length <= MANY_OWNERS,
        detail: owners.length > MANY_OWNERS ? `${owners.length} owners: ${owners.slice(0, 8).join(", ")}${owners.length > 8 ? "…" : ""}` : "",
        link: d.group("group_members"),
      });
    }
  },
);
