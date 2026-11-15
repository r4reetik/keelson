// Identity & access on GitHub: two-factor authentication for every member, what
// members can do in every repository by default, who can publish, copy, delete or
// give away code, and how many people hold the Owner role.

import { defineChecks } from "./define.ts";

const MAX_OWNERS = 3;

export default defineChecks(
  {
    "GID-001": {
      category: "Identity & access",
      severity: "high",
      docs: "https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization",
      requires: ["orgSettings"],
      attackPath: true,
      title: "Organization doesn't require two-factor authentication",
      why: "Members can sign in with a password alone. A phished or reused password then gives someone your code, your Actions secrets and whatever those workflows deploy to.",
      fix: "1. Open the organization's Settings → Authentication security. 2. Tick Require two-factor authentication for everyone. Members without it are removed until they set it up, so tell them first.",
    },
    "GID-002": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/setting-base-permissions-for-an-organization",
      requires: ["orgSettings"],
      title: "Every member can change every repository",
      why: "The base permission is Write or Admin, so every member can push to every repository, including ones they have nothing to do with. One stolen login reaches all of your code.",
      fix: "Under Settings → Member privileges, set Base permissions to Read or No permission, and give teams write access to the repositories they work on.",
    },
    "GID-003": {
      category: "Identity & access",
      severity: "low",
      docs: "https://docs.github.com/en/organizations/managing-organization-settings/restricting-repository-creation-in-your-organization",
      requires: ["orgSettings"],
      title: "Members can create public repositories",
      why: "Anyone in the organization can publish code under its name, and a repository meant to be private can be created public by mistake.",
      fix: "Under Settings → Member privileges → Repository creation, untick Public. Owners can still create public repositories.",
    },
    "GID-004": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://docs.github.com/en/organizations/managing-peoples-access-to-your-organization-with-roles/roles-in-an-organization",
      requires: ["members"],
      title: "Too many organization owners",
      why: "Every owner can change any setting, delete repositories, read every secret's name and add Apps with access to all code. Each extra owner widens what a stolen login can do.",
      fix: "Keep two or three owners for break-glass access. Under People, change everyone else's role to Member and give their teams the access they need.",
    },
    "GID-005": {
      category: "Identity & access",
      severity: "low",
      docs: "https://docs.github.com/en/organizations/managing-organization-settings/managing-the-forking-policy-for-your-organization",
      requires: ["orgSettings"],
      title: "Members can fork private repositories",
      why: "A fork of a private repository can live in a personal account, outside the organization's settings, and stays with the person after they leave.",
      fix: "Under Settings → Member privileges, untick Allow forking of private repositories, or allow it only within the organization where your plan offers that.",
    },
    "GID-006": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://docs.github.com/en/organizations/managing-organization-settings/restricting-repository-visibility-changes-in-your-organization",
      requires: ["orgSettings"],
      title: "Members can make private repositories public",
      why: "A member with admin access to a repository can make it public in two clicks, publishing its code and its whole history, including any secret ever committed. Only owners should be able to do that.",
      fix: "Under the organization's Settings → Member privileges → Repository visibility change, untick Allow members to change repository visibilities for this organization.",
    },
    "GID-007": {
      category: "Identity & access",
      severity: "low",
      docs: "https://docs.github.com/en/organizations/managing-organization-settings/setting-permissions-for-deleting-or-transferring-repositories",
      requires: ["orgSettings"],
      title: "Members can delete or transfer repositories",
      why: "A member with admin access to a repository, or someone with their login, can delete it or transfer it to an account outside the organization, taking the code, issues and settings with it.",
      fix: "Under the organization's Settings → Member privileges → Repository deletion and transfer, untick Allow members to delete or transfer repositories for this organization.",
    },
  },
  ({ inv, d }, report) => {
    const o = inv.org;
    const where = { zone: null, resource: inv.login };
    if (o?.twoFactorRequired != null)
      report("GID-001", {
        ...where,
        pass: o.twoFactorRequired,
        detail: o.twoFactorRequired ? "" : "Two-factor authentication is optional",
        link: d.settings("security"),
      });
    if (o?.defaultRepoPermission) {
      const wide = o.defaultRepoPermission === "write" || o.defaultRepoPermission === "admin";
      report("GID-002", {
        ...where,
        pass: !wide,
        severity: o.defaultRepoPermission === "admin" ? "high" : undefined,
        detail: wide ? `Base permission is ${o.defaultRepoPermission}` : "",
        link: d.settings("member_privileges"),
      });
    }
    if (o?.membersCanCreatePublicRepos != null)
      report("GID-003", {
        ...where,
        pass: !o.membersCanCreatePublicRepos,
        detail: o.membersCanCreatePublicRepos ? "Members can create public repositories" : "",
        link: d.settings("member_privileges"),
      });
    if (o?.membersCanForkPrivateRepos != null)
      report("GID-005", {
        ...where,
        pass: !o.membersCanForkPrivateRepos,
        detail: o.membersCanForkPrivateRepos ? "Forking of private repositories is allowed" : "",
        link: d.settings("member_privileges"),
      });
    if (o?.membersCanChangeVisibility != null)
      report("GID-006", {
        ...where,
        pass: !o.membersCanChangeVisibility,
        detail: o.membersCanChangeVisibility ? "Repository admins who aren't owners can change visibility" : "",
        link: d.settings("member_privileges"),
      });
    if (o?.membersCanDeleteRepos != null)
      report("GID-007", {
        ...where,
        pass: !o.membersCanDeleteRepos,
        detail: o.membersCanDeleteRepos ? "Repository admins who aren't owners can delete or transfer repositories" : "",
        link: d.settings("member_privileges"),
      });
    if (inv.owners)
      report("GID-004", {
        ...where,
        pass: inv.owners.length <= MAX_OWNERS,
        detail: inv.owners.length > MAX_OWNERS ? `${inv.owners.length} owners: ${inv.owners.slice(0, 8).join(", ")}${inv.owners.length > 8 ? "…" : ""}` : "",
        link: d.owners,
      });
  },
);
