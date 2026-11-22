// Who can do what. Every user has one role, and each role can do everything the
// one before it can, and more. The server checks a route's permission
// (requirePermission in src/server/middleware.ts); the web hides what a role
// can't do. Both read this table, so they can't disagree.
//
// An admin can also limit a user to some entities (src/store/users.ts): they then
// see and change only those entities' accounts, and none of the changes that reach
// every entity (INSTANCE_WIDE). Admins always see every entity.

export const ROLES = ["viewer", "analyst", "manager", "admin"] as const;
export type Role = (typeof ROLES)[number];

/** What a change needs. Reading needs only a signed-in user: every role sees every page. */
export type Permission = "triage" | "scan" | "accounts" | "checks" | "settings" | "networks" | "users";

/** The lowest role that has each permission. */
export const PERMISSION_ROLE: Record<Permission, Role> = {
  triage: "analyst",
  scan: "analyst",
  accounts: "manager",
  checks: "manager",
  settings: "admin",
  networks: "admin",
  users: "admin",
};

/** What each permission lets someone do, as the end of "can't …". */
export const PERMISSION_TEXT: Record<Permission, string> = {
  triage: "triage findings",
  scan: "run scans",
  accounts: "connect or change accounts and entities",
  checks: "turn checks off or change their severity",
  settings: "change Keelson's settings",
  networks: "see or change the networks Keelson's requests go through",
  users: "manage users",
};

export const ROLE_INFO: Record<Role, { label: string; summary: string }> = {
  viewer: { label: "Viewer", summary: "Sees every page, and exports findings and reports. Changes nothing." },
  analyst: { label: "Analyst", summary: "Also triages findings (status, owner, due date, notes) and runs scans." },
  manager: {
    label: "Manager",
    summary: "Also connects and removes accounts, replaces credentials, edits entities and their alerts, and turns checks off or changes their severity.",
  },
  admin: {
    label: "Admin",
    summary: "Also adds and removes users, changes their roles, and changes Keelson's settings and the networks its requests go through.",
  },
};

export const isRole = (v: unknown): v is Role => typeof v === "string" && (ROLES as readonly string[]).includes(v);

export const can = (role: Role, permission: Permission): boolean => ROLES.indexOf(role) >= ROLES.indexOf(PERMISSION_ROLE[permission]);

/**
 * Changes that reach every entity at once. Someone limited to some entities can't make them, whatever their role:
 * check overrides apply to every account, and settings, networks and users belong to the whole instance.
 */
export const INSTANCE_WIDE: readonly Permission[] = ["checks", "settings", "networks", "users"];

/** Who is asking: their role, and the entities they are limited to (null for every entity). */
export interface Access {
  role: Role;
  entities: number[] | null;
}

/** The user's role has this permission, and it doesn't reach past the entities they are limited to. */
export const allowed = (user: Access, permission: Permission): boolean => can(user.role, permission) && !(user.entities && INSTANCE_WIDE.includes(permission));

/** Why a request was refused, fit to show the user. */
export const refusal = (user: Access, permission: Permission): string =>
  can(user.role, permission)
    ? `You can only see some entities, so you can't ${PERMISSION_TEXT[permission]}: that applies to every entity. Ask an admin.`
    : `Your role (${ROLE_INFO[user.role].label}) can't ${PERMISSION_TEXT[permission]}. Ask an admin to change your role on the Users page.`;
