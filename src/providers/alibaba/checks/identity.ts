// RAM: the main account's AccessKey, users' sign-in and AccessKeys, the password
// policy and the account's security settings for RAM users (MFA at sign-in, users
// managing their own AccessKeys), administrators, and who roles trust. Alibaba Cloud's counterpart of AWS's
// IAM checks, with the same wording and severities where the two match.

import { defineChecks, accountOf, date, days } from "./define.ts";
import { GLOBAL } from "../types.ts";

const KEY_MAX_AGE_DAYS = 90;
const IDLE_DAYS = 90;
const MIN_PASSWORD_LENGTH = 14;

export default defineChecks(
  {
    "LID-001": {
      category: "Identity & access",
      severity: "critical",
      docs: "https://www.alibabacloud.com/help/en/ram/use-cases/ensure-security-of-alibaba-cloud-resources",
      requires: ["identity"],
      title: "Main account has an AccessKey",
      why: "The main account (root) can do everything in Alibaba Cloud, and no policy limits its AccessKey. Anyone who obtains it, from a laptop, a script or a CI variable, owns the account. Alibaba Cloud recommends that the main account have no AccessKey at all.",
      fix: "1. Move whatever uses the main account's AccessKey to a RAM user with only the permissions it needs (for Keelson, the read-only policy from the Add accounts flow). 2. Sign in as the main account, open AccessKey management, and disable, then delete, its AccessKeys.",
    },
    "LID-013": {
      category: "Identity & access",
      severity: "critical",
      docs: "https://www.alibabacloud.com/help/en/account/user-guide/enable-the-account-protection-feature",
      requires: ["accountSecurity"],
      title: "Main account has no MFA",
      why: "The main account can do everything, including closing the account and every RAM user's access. With a password alone, one phished or reused password hands all of it over.",
      fix: "Sign in as the main account, open Security Settings, and bind a virtual MFA device or a passkey. Keep the recovery details somewhere only the account's owners can reach.",
    },
    "LID-002": {
      category: "Identity & access",
      severity: "high",
      docs: "https://www.alibabacloud.com/help/en/ram/user-guide/bind-an-mfa-device-to-a-ram-user",
      requires: ["ramUsers"],
      title: "RAM user can sign in to the console without MFA",
      why: "The user's console password is the only thing protecting their access. A reused or phished password is enough to sign in. When the account requires MFA at sign-in, a user without a device is asked to bind one at their next sign-in, so whoever signs in first with the password, the user or an attacker, binds it.",
      fix: "Bind an MFA device to the user in RAM → Users → the user → Authentication, or have them bind one now. Then require MFA at sign-in for every user under RAM → Settings → Security Settings.",
    },
    "LID-014": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://www.alibabacloud.com/help/en/ram/user-guide/manage-security-settings-of-ram-users",
      requires: ["securityPreference"],
      title: "RAM users can create their own AccessKeys",
      why: "Any RAM user, or anyone holding their console session, can create an AccessKey for themselves. The key works without MFA and outside any sign-in network limits, lasts until someone deletes it, and nobody reviewed it being made.",
      fix: "In RAM → Settings → Security Settings → RAM user security settings, turn off Manage AccessKeys. Administrators then create keys for the program users that need them.",
    },
    "LID-015": {
      category: "Identity & access",
      severity: "low",
      docs: "https://www.alibabacloud.com/help/en/ram/user-guide/create-a-ram-user",
      requires: ["ramUsers"],
      title: "RAM user is used both by a person and by programs",
      why: "The user signs in to the console and also has an active AccessKey. Alibaba Cloud recommends separate users for people and programs: the key skips the person's MFA, it is copied into scripts tied to someone who will leave, and the person's access can't be reviewed apart from what the programs need.",
      fix: "Create a RAM user with OpenAPI access only for the program, give it only the permissions the program needs, move the program to its AccessKey, and delete the person's AccessKey.",
    },
    "LID-003": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://www.alibabacloud.com/help/en/ram/user-guide/create-an-accesskey-pair",
      requires: ["ramUsers"],
      title: "AccessKey is older than 90 days",
      why: "Long-lived AccessKeys end up in scripts, CI variables and laptops. The longer one lives, the more places it has been copied to, and the longer a leaked copy stays useful.",
      fix: "Create a new AccessKey for the user, move whatever uses the old one over to it, then disable and delete the old one. Where possible, use a RAM role instead (an ECS instance RAM role, or OIDC from CI).",
    },
    "LID-004": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://www.alibabacloud.com/help/en/ram/user-guide/view-the-accesskey-pairs-of-a-ram-user",
      requires: ["ramUsers"],
      title: "AccessKey unused for 90 days",
      why: "An AccessKey nobody uses is still a working credential. If it leaked, nobody would notice it being used.",
      fix: "Disable the AccessKey in RAM → Users → the user → AccessKey, wait to see if anything breaks, then delete it.",
    },
    "LID-005": {
      category: "Identity & access",
      severity: "low",
      docs: "https://www.alibabacloud.com/help/en/ram/user-guide/manage-console-logon-settings-for-a-ram-user",
      requires: ["ramUsers"],
      title: "Console password unused for 90 days",
      why: "A console sign-in that nobody uses is a password that can still be guessed or phished, with no owner watching for it.",
      fix: "Turn off console access for the user in RAM → Users → the user → Authentication, or delete the user if nobody needs it.",
    },
    "LID-006": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://www.alibabacloud.com/help/en/ram/user-guide/configure-a-password-policy-for-ram-users",
      requires: ["passwordPolicy", "ramUsers"],
      title: "Password policy is weak",
      why: "RAM users who sign in to the console choose their own passwords. Without a minimum length, reuse prevention or a lockout after failed attempts, short or recycled passwords are accepted and can be guessed.",
      fix: "In RAM → Settings → Security Settings → Password Strength, require at least 14 characters, prevent reuse of recent passwords and lock users out after a few failed attempts in an hour.",
    },
    "LID-007": {
      category: "Identity & access",
      severity: "high",
      docs: "https://www.alibabacloud.com/help/en/ram/product-overview/best-practices-for-identity-and-access-control",
      requires: ["ramUsers", "ramPolicies"],
      title: "Administrator has a long-lived AccessKey",
      why: "This RAM user can do anything in the account, and has an AccessKey that works until someone deletes it. A key leaked from a laptop or a CI variable gives an attacker the whole account.",
      fix: "Use a RAM role for administrative work (assumed with the user's console sign-in and MFA, or from CI through OIDC), then delete the user's AccessKeys. If a tool needs a key, give it its own user with only the permissions it needs.",
    },
    "LID-008": {
      category: "Identity & access",
      severity: "critical",
      docs: "https://www.alibabacloud.com/help/en/ram/user-guide/edit-the-trust-policy-of-a-ram-role",
      requires: ["ramRoles"],
      title: "RAM role can be assumed by any Alibaba Cloud account",
      why: "The role's trust policy lets the principal \"*\" assume it without a condition. Anyone with an Alibaba Cloud account can get the role's permissions in yours.",
      fix: 'Open the role in RAM → Roles → Trust Policy and replace "*" with the accounts or services that should assume it. Add a condition on sts:ExternalId for a vendor\'s account.',
    },
    "LID-009": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://www.alibabacloud.com/help/en/ram/user-guide/policy-structure-and-syntax",
      requires: ["ramPolicies"],
      title: "Custom policy allows every action on every resource",
      why: "The policy is a second AdministratorAccess under another name. Whoever it is attached to is an administrator, which reviews that look for AdministratorAccess will miss.",
      fix: "Open the policy in RAM → Permissions → Policies and narrow its actions and resources to what its users need, or detach it and use AdministratorAccess where full access is intended.",
    },
    "LID-010": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://www.alibabacloud.com/help/en/ram/user-guide/edit-the-trust-policy-of-a-ram-role",
      requires: ["ramRoles"],
      title: "RAM role trusts an Alibaba Cloud account outside the entity without a condition",
      why: "Another company's Alibaba Cloud account can assume this role with nothing but its own permissions. If that account is a vendor's, any of the vendor's other customers may be able to make it act on your account; if it is an old partner or a forgotten account, it still has the access.",
      fix: "1. Open the role in RAM → Roles → Trust Policy. 2. If the other account is one of yours, add it to this entity in Keelson. 3. If it is a vendor's, add a condition that requires the external ID they gave you (sts:ExternalId). 4. If nobody uses the role any more, delete it.",
    },
  },
  ({ inv, d, related }, report) => {
    const g = { zone: GLOBAL };
    // Keelson's own key being the main account's is known without the report; the report says whether it has others.
    const rootKeys = Math.max(inv.root?.accessKeys ?? 0, inv.rootKey ? 1 : 0);
    if (inv.root || inv.rootKey)
      report("LID-001", {
        ...g,
        resource: "main account",
        pass: !rootKeys,
        detail: inv.rootKey
          ? "The AccessKey Keelson was given belongs to the main account, not to a RAM user"
          : rootKeys
            ? `${rootKeys} AccessKey${rootKeys === 1 ? "" : "s"}`
            : "",
        link: d.accessKeys,
      });
    if (inv.root)
      report("LID-013", { ...g, resource: "main account", pass: inv.root.mfa, detail: inv.root.mfa ? "" : "No MFA device is bound", link: d.accessKeys });

    const pref = inv.securityPreference;
    if (pref)
      report("LID-014", {
        ...g,
        resource: "RAM security settings",
        pass: !pref.usersManageKeys,
        detail: pref.usersManageKeys ? "Every RAM user may manage their own AccessKeys" : "",
        link: d.securitySettings,
      });
    // With MFA required at sign-in, a user without a device binds one at their next sign-in: a password alone still gets
    // in once, so it stays a finding, one step lower.
    const mandatory = pref?.mfaAtLogin === "mandatory";
    const admins = new Map((inv.admins ?? []).filter((a) => a.kind === "user").map((a) => [a.name, a.via]));
    for (const u of inv.users ?? []) {
      const link = d.user(u.name);
      if (u.console && u.mfa != null) {
        // An administrator behind a password alone is the whole account behind a password alone.
        const via = inv.admins && !u.mfa ? admins.get(u.name) : undefined;
        const why = [
          via ? `Administrator through ${via}, signing in with a password only` : "",
          !u.mfa && mandatory ? "The account requires MFA at sign-in, so the next sign-in with this password binds a device" : "",
          !u.mfa && pref?.mfaAtLogin === "adaptive" ? "The account asks for MFA only when a sign-in looks unusual" : "",
        ].filter(Boolean);
        report("LID-002", {
          ...g,
          resource: u.name,
          pass: u.mfa,
          severity: u.mfa ? undefined : via ? (mandatory ? "high" : "critical") : mandatory ? "medium" : undefined,
          detail: why.join(". "),
          evidence: via
            ? {
                chain: [
                  { label: "Console sign-in", value: `${u.name} has a password and no MFA device` },
                  { label: "Administrator access", value: `through ${via}` },
                ],
              }
            : null,
          link,
        });
      }
      if (u.console) {
        const idle = days(u.lastLoginAt ?? u.createdAt, inv.now);
        report("LID-005", {
          ...g,
          resource: u.name,
          pass: idle == null || idle < IDLE_DAYS,
          detail: u.lastLoginAt ? `Last signed in ${date(u.lastLoginAt)}` : `Never signed in since ${date(u.createdAt)}`,
          link,
        });
      }
      const active = (u.keys ?? []).filter((k) => k.active);
      if (u.console != null && u.keys)
        report("LID-015", {
          ...g,
          resource: u.name,
          pass: !(u.console && active.length),
          detail:
            u.console && active.length
              ? `Console sign-in${u.lastLoginAt ? ` (last ${date(u.lastLoginAt)})` : ""} and ${active.length} active AccessKey${active.length === 1 ? "" : "s"}`
              : "",
          link,
        });
      for (const k of active) {
        const resource = `${u.name} (key …${k.hint})`;
        const age = days(k.createdAt, inv.now);
        report("LID-003", { ...g, resource, pass: age == null || age <= KEY_MAX_AGE_DAYS, detail: `Created ${date(k.createdAt)}`, link });
        const idle = days(k.lastUsedAt ?? k.createdAt, inv.now);
        report("LID-004", {
          ...g,
          resource,
          pass: idle == null || idle < IDLE_DAYS,
          detail: k.lastUsedAt ? `Last used ${date(k.lastUsedAt)}` : `Never used since it was created on ${date(k.createdAt)}`,
          link,
        });
      }
      if (inv.admins && u.keys && admins.has(u.name))
        report("LID-007", {
          ...g,
          resource: u.name,
          pass: !active.length,
          detail: active.length ? `Administrator through ${admins.get(u.name)}, with ${active.length} active AccessKey${active.length === 1 ? "" : "s"}` : "",
          evidence: active.length
            ? {
                chain: [
                  { label: "Administrator access", value: `${u.name} through ${admins.get(u.name)}` },
                  ...active.map((k) => ({
                    label: `AccessKey …${k.hint}`,
                    value: `created ${date(k.createdAt)}, ${k.lastUsedAt ? `last used ${date(k.lastUsedAt)}` : "never used"}`,
                  })),
                ],
              }
            : null,
          link,
        });
    }
    if (inv.admins && inv.users) report.passIfNone("LID-007", "account", GLOBAL);

    // The policy only governs RAM users who have a console password.
    if (inv.passwordPolicy !== undefined && inv.users?.some((u) => u.console)) {
      const p = inv.passwordPolicy;
      const weak = p
        ? [
            p.minLength < MIN_PASSWORD_LENGTH ? `minimum length ${p.minLength}` : null,
            p.reusePrevention ? null : "old passwords can be reused",
            p.maxLoginAttempts ? null : "no lockout after failed sign-ins",
          ].filter(Boolean)
        : [];
      report("LID-006", {
        ...g,
        resource: "password policy",
        pass: !!p && !weak.length,
        detail: p ? weak.join(", ") : "No password policy could be found, so Alibaba Cloud's default applies: 8 characters, no reuse prevention",
        link: d.securitySettings,
      });
    }

    for (const r of inv.roles ?? []) {
      if (r.serviceLinked) continue;
      const anyone = r.trust.some((t) => t.kind === "anyone" && !t.conditional);
      report("LID-008", {
        ...g,
        resource: r.name,
        pass: !anyone,
        detail: anyone ? `The trust policy allows the principal "*" without a condition${r.admin ? ", and the role has administrator access" : ""}` : "",
        link: d.role(r.name),
      });
    }
    if (inv.roles) report.passIfNone("LID-008", "account", GLOBAL);

    // Which accounts belong to the entity is only known once every Alibaba Cloud account in it has been scanned.
    if (inv.roles && !related.unknown.includes("alibabaAccounts")) {
      const ours = new Set([inv.accountId, ...(related.alibabaAccounts ?? [])]);
      for (const r of inv.roles) {
        if (r.serviceLinked) continue;
        const outside = r.trust.filter((t) => t.kind === "account" && accountOf(t.principal) && !ours.has(accountOf(t.principal)!));
        if (!outside.length) continue;
        const open = outside.filter((t) => !t.conditional);
        const accounts = [...new Set(open.map((t) => accountOf(t.principal)))];
        report("LID-010", {
          ...g,
          resource: r.name,
          pass: !open.length,
          severity: open.length && r.admin ? "high" : undefined,
          detail: open.length
            ? `Account${accounts.length === 1 ? "" : "s"} ${accounts.join(", ")} can assume it without a condition${r.admin ? ", and the role has administrator access" : ""}`
            : "",
          link: d.role(r.name),
        });
      }
      report.passIfNone("LID-010", "account", GLOBAL);
    }

    for (const p of inv.policies ?? [])
      report("LID-009", {
        ...g,
        resource: p.name,
        // An unattached policy grants nothing yet.
        pass: !(p.fullAdmin && p.attachments > 0),
        detail: p.fullAdmin ? `Allows "*" on "*", attached to ${p.attachments} ${p.attachments === 1 ? "identity" : "identities"}` : "",
        link: d.policies,
      });
    if (inv.policies) report.passIfNone("LID-009", "account", GLOBAL);
  },
);
