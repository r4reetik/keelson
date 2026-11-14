// Who can do what. Every user has one role, and each role can do everything the
// one before it can, and more. The server checks a route's permission
// (requirePermission in src/server/middleware.ts); the web hides what a role
// can't do. Both read this table, so they can't disagree.

export const ROLES = ["viewer", "analyst", "manager", "admin"] as const;
export type Role = (typeof ROLES)[number];

/** What a change needs. Reading needs only a signed-in user: every role sees every page. */
export type Permission = "triage" | "scan" | "accounts" | "checks" | "settings" | "users";

/** The lowest role that has each permission. */
export const PERMISSION_ROLE: Record<Permission, Role> = {
  triage: "analyst",
  scan: "analyst",
  accounts: "manager",
  checks: "manager",
  settings: "admin",
  users: "admin",
};

/** What each permission lets someone do, as the end of "can't …". */
export const PERMISSION_TEXT: Record<Permission, string> = {
  triage: "triage findings",
  scan: "run scans",
  accounts: "connect or change accounts and entities",
  checks: "turn checks off or change their severity",
  settings: "change Keelson's settings",
  users: "manage users",
};

export const ROLE_INFO: Record<Role, { label: string; summary: string }> = {
  viewer: { label: "Viewer", summary: "Sees every page, and exports findings and reports. Changes nothing." },
  analyst: { label: "Analyst", summary: "Also triages findings (status, owner, due date, notes) and runs scans." },
  manager: {
    label: "Manager",
    summary: "Also connects and removes accounts, replaces credentials, edits entities and their alerts, and turns checks off or changes their severity.",
  },
  admin: { label: "Admin", summary: "Also adds and removes users, changes their roles, and changes Keelson's settings." },
};

export const isRole = (v: unknown): v is Role => typeof v === "string" && (ROLES as readonly string[]).includes(v);

export const can = (role: Role, permission: Permission): boolean => ROLES.indexOf(role) >= ROLES.indexOf(PERMISSION_ROLE[permission]);

/** Why a request was refused, fit to show the user. */
export const refusal = (role: Role, permission: Permission): string =>
  `Your role (${ROLE_INFO[role].label}) can't ${PERMISSION_TEXT[permission]}. Ask an admin to change your role on the Users page.`;
