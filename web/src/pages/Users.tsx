// User management, for admins: who can sign in and what each person can do.
// New people and password resets get a one-time password, shown once here, which
// the admin hands over and the person replaces when they first sign in.

import { useState } from "react";
import { Badge, Button, Dialog, DropdownMenu, Input, Select, Table, useKumoToastManager } from "@cloudflare/kumo";
import { CopyIcon, DotsThreeIcon, KeyIcon, PlusIcon, TrashIcon, UserSwitchIcon } from "@phosphor-icons/react";
import { ago, api, plural, ROLE_INFO, ROLES, useApi, withArticle, type OneTimePasswordResponse, type Role, type UserRow, type UsersResponse } from "../lib.ts";
import { Card, DialogHeader, FormGrid, ListCard, Page, PageState } from "../components/ui.tsx";
import { useShell } from "../shell.tsx";

const TITLE = "Users";
const DESCRIPTION = "Who can sign in to Keelson, and what each person can do. Roles apply to every entity and account.";
const ROLE_ITEMS = Object.fromEntries(ROLES.map((r) => [r, ROLE_INFO[r].label])) as Record<Role, string>;

type Modal = { kind: "add" } | { kind: "password"; result: OneTimePasswordResponse; reset: boolean } | { kind: "remove"; user: UserRow } | null;

export function UsersPage() {
  const { session } = useShell();
  const { data, error, loading, reload } = useApi<UsersResponse>("/api/users");
  const toasts = useKumoToastManager();
  const [modal, setModal] = useState<Modal>(null);

  if (!session.authRequired)
    return (
      <Page title={TITLE} description={DESCRIPTION}>
        <Card title="Sign-in is off">
          <p className="text-sm text-kumo-subtle">
            Keelson runs with <code className="text-kumo-default">KEELSON_AUTH=none</code>, so the proxy in front of it decides who gets in, and everyone it
            lets through is an admin. Remove that setting to sign in with the users here.
          </p>
        </Card>
        <RolesCard />
      </Page>
    );
  if (error || !data) return <PageState title={TITLE} description={DESCRIPTION} error={error} loading={loading} empty={false} retry={reload} />;

  const users = data.users;
  const admins = users.filter((u) => u.role === "admin").length;
  const me = session.user?.id;
  const act = async (fn: () => Promise<unknown>, done?: string) => {
    try {
      await fn();
      await reload();
      if (done) toasts.add({ title: done, variant: "success" });
      return true;
    } catch (e) {
      toasts.add({ title: "Couldn't save", description: (e as Error).message, variant: "error" });
      return false;
    }
  };
  const setRole = (u: UserRow, role: Role) =>
    act(() => api(`/api/users/${u.id}`, { method: "PATCH", body: { role } }), `${u.username} is now ${withArticle(ROLE_INFO[role].label)}`);
  const resetPassword = async (u: UserRow) => {
    try {
      const result = await api<OneTimePasswordResponse>(`/api/users/${u.id}/password`, { method: "POST", body: {} });
      await reload();
      setModal({ kind: "password", result, reset: true });
    } catch (e) {
      toasts.add({ title: "Couldn't reset the password", description: (e as Error).message, variant: "error" });
    }
  };

  return (
    <Page
      title={TITLE}
      description={DESCRIPTION}
      actions={
        <Button variant="primary" icon={<PlusIcon />} onClick={() => setModal({ kind: "add" })}>
          Add user
        </Button>
      }
    >
      <ListCard footer={<span>{plural(users.length, "user")}</span>}>
        <Table layout="auto">
          <Table.Header variant="compact">
            <Table.Row>
              <Table.Head>User</Table.Head>
              <Table.Head>Role</Table.Head>
              <Table.Head className="whitespace-nowrap">Last sign-in</Table.Head>
              <Table.Head>Added</Table.Head>
              <Table.Head className="w-12">
                <span className="sr-only">Options</span>
              </Table.Head>
            </Table.Row>
          </Table.Header>
          <Table.Body>
            {users.map((u) => {
              const lastAdmin = u.role === "admin" && admins < 2;
              return (
                <Table.Row key={u.id}>
                  <Table.Cell className="max-w-72">
                    <div className="flex min-w-0 items-center gap-2">
                      <span className="truncate font-medium text-kumo-default">{u.name || u.username}</span>
                      {u.id === me && <Badge variant="neutral">You</Badge>}
                      {u.mustChangePassword && <Badge variant="outline">One-time password</Badge>}
                    </div>
                    {u.name && <div className="truncate text-sm text-kumo-subtle">{u.username}</div>}
                  </Table.Cell>
                  <Table.Cell className="whitespace-nowrap">{ROLE_INFO[u.role].label}</Table.Cell>
                  <Table.Cell className="whitespace-nowrap text-kumo-subtle">{u.lastLoginAt ? ago(u.lastLoginAt) : "Never"}</Table.Cell>
                  <Table.Cell className="whitespace-nowrap text-kumo-subtle">
                    {ago(u.createdAt)}
                    {u.createdBy ? ` by ${u.createdBy}` : ""}
                  </Table.Cell>
                  <Table.Cell>
                    <DropdownMenu>
                      <DropdownMenu.Trigger
                        render={<Button variant="ghost" size="sm" shape="square" icon={<DotsThreeIcon weight="bold" />} aria-label={`${u.username} options`} />}
                      />
                      <DropdownMenu.Content align="end">
                        <DropdownMenu.Sub>
                          <DropdownMenu.SubTrigger icon={UserSwitchIcon}>Change role</DropdownMenu.SubTrigger>
                          <DropdownMenu.SubContent>
                            {ROLES.map((r) => (
                              <DropdownMenu.Item key={r} disabled={r === u.role || (lastAdmin && r !== "admin")} onClick={() => void setRole(u, r)}>
                                {ROLE_INFO[r].label}
                                {r === u.role ? " (current)" : ""}
                              </DropdownMenu.Item>
                            ))}
                          </DropdownMenu.SubContent>
                        </DropdownMenu.Sub>
                        <DropdownMenu.Item icon={KeyIcon} disabled={u.id === me} onClick={() => void resetPassword(u)}>
                          {u.id === me ? "Reset password (use your menu)" : "Reset password"}
                        </DropdownMenu.Item>
                        <DropdownMenu.Separator />
                        <DropdownMenu.Item
                          icon={TrashIcon}
                          variant="danger"
                          disabled={u.id === me || lastAdmin}
                          onClick={() => setModal({ kind: "remove", user: u })}
                        >
                          {u.id === me ? "Remove (ask another admin)" : lastAdmin ? "Remove (the only admin)" : "Remove user"}
                        </DropdownMenu.Item>
                      </DropdownMenu.Content>
                    </DropdownMenu>
                  </Table.Cell>
                </Table.Row>
              );
            })}
          </Table.Body>
        </Table>
      </ListCard>

      <RolesCard />

      {modal?.kind === "add" && (
        <AddUserDialog
          taken={users.map((u) => u.username)}
          onClose={() => setModal(null)}
          onAdded={async (result) => {
            await reload();
            setModal({ kind: "password", result, reset: false });
          }}
        />
      )}
      {modal?.kind === "password" && <PasswordDialog result={modal.result} reset={modal.reset} onClose={() => setModal(null)} />}
      {modal?.kind === "remove" && (
        <RemoveDialog
          user={modal.user}
          onClose={() => setModal(null)}
          onConfirm={() => act(() => api(`/api/users/${modal.user.id}`, { method: "DELETE", body: {} }), `${modal.user.username} removed`)}
        />
      )}
    </Page>
  );
}

/** What each role can do, so an admin can choose. */
function RolesCard() {
  return (
    <Card title="Roles" description="From least to most access: each role can do everything the one before it can, and more. Every role sees every page.">
      <dl className="grid grid-cols-1 gap-x-6 gap-y-4 sm:grid-cols-2 xl:grid-cols-4">
        {ROLES.map((r) => (
          <div key={r} className="min-w-0">
            <dt className="text-sm font-medium text-kumo-default">{ROLE_INFO[r].label}</dt>
            <dd className="m-0 text-sm text-kumo-subtle">{ROLE_INFO[r].summary}</dd>
          </div>
        ))}
      </dl>
    </Card>
  );
}

function AddUserDialog({ taken, onClose, onAdded }: { taken: string[]; onClose: () => void; onAdded: (r: OneTimePasswordResponse) => void }) {
  const [username, setUsername] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState<Role>("viewer");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const clash = taken.includes(username.trim().toLowerCase());
  return (
    <Dialog.Root open onOpenChange={(o: boolean) => !o && onClose()}>
      <Dialog size="lg" className="p-6">
        <DialogHeader
          title="Add user"
          description="Keelson makes a one-time password for them. Give it to them yourself; they choose their own password when they first sign in."
        />
        <form
          className="flex flex-col gap-4"
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            setErr(null);
            try {
              onAdded(await api<OneTimePasswordResponse>("/api/users", { method: "POST", body: { username, name, role } }));
            } catch (x) {
              setErr((x as Error).message);
              setBusy(false);
            }
          }}
        >
          <FormGrid>
            <Input
              autoFocus
              className="w-full"
              label="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="off"
              autoCapitalize="none"
              spellCheck={false}
              variant={clash ? "error" : "default"}
              error={clash ? `${username.trim().toLowerCase()} already has an account.` : (err ?? undefined)}
              description={clash || err ? undefined : "What they sign in with. An email address works."}
            />
            <Input className="w-full" label="Name (optional)" value={name} onChange={(e) => setName(e.target.value)} autoComplete="off" />
          </FormGrid>
          <Select className="w-full" label="Role" hideLabel={false} value={role} onValueChange={(v) => setRole(v as Role)} items={ROLE_ITEMS} />
          <p className="-mt-2 text-sm text-kumo-subtle">{ROLE_INFO[role].summary}</p>
          <div className="flex justify-end gap-2">
            <Dialog.Close
              render={(p) => (
                <Button {...p} variant="secondary">
                  Cancel
                </Button>
              )}
            />
            <Button type="submit" variant="primary" loading={busy} disabled={!username.trim() || clash}>
              Add user
            </Button>
          </div>
        </form>
      </Dialog>
    </Dialog.Root>
  );
}

/** The one-time password, shown once: Keelson keeps only its hash. */
function PasswordDialog({ result, reset, onClose }: { result: OneTimePasswordResponse; reset: boolean; onClose: () => void }) {
  const toasts = useKumoToastManager();
  const u = result.user;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(result.password);
      toasts.add({ title: "One-time password copied", variant: "success" });
    } catch {
      toasts.add({ title: "Couldn't copy", description: "Select the password and copy it instead.", variant: "error" });
    }
  };
  return (
    <Dialog.Root open onOpenChange={(o: boolean) => !o && onClose()}>
      <Dialog size="lg" className="p-6">
        <DialogHeader
          title={reset ? `New password for ${u.username}` : `${u.username} added as ${withArticle(ROLE_INFO[u.role].label)}`}
          description={`Give ${u.name || u.username} this one-time password, and their username, ${u.username}. It's shown only now. When they sign in with it, they choose their own.${reset ? " They've been signed out everywhere." : ""}`}
        />
        <div className="flex items-center gap-2 rounded-md border border-kumo-hairline bg-kumo-base p-3">
          <code className="min-w-0 flex-1 truncate font-mono text-base text-kumo-default select-all">{result.password}</code>
          <Button variant="secondary" size="sm" icon={<CopyIcon />} onClick={() => void copy()}>
            Copy
          </Button>
        </div>
        <div className="mt-6 flex justify-end">
          <Button variant="primary" onClick={onClose}>
            Done
          </Button>
        </div>
      </Dialog>
    </Dialog.Root>
  );
}

function RemoveDialog({ user, onClose, onConfirm }: { user: UserRow; onClose: () => void; onConfirm: () => Promise<boolean> }) {
  const [busy, setBusy] = useState(false);
  return (
    <Dialog.Root open onOpenChange={(o: boolean) => !o && onClose()}>
      <Dialog size="base" className="p-6">
        <DialogHeader
          title={`Remove ${user.username}?`}
          description="They're signed out at once and can't sign in again. Their triage changes stay in each finding's timeline under their username."
        />
        <div className="mt-6 flex justify-end gap-2">
          <Dialog.Close
            render={(p) => (
              <Button {...p} variant="secondary">
                Cancel
              </Button>
            )}
          />
          <Button
            variant="destructive"
            loading={busy}
            onClick={async () => {
              setBusy(true);
              if (await onConfirm()) onClose();
              else setBusy(false);
            }}
          >
            Remove user
          </Button>
        </div>
      </Dialog>
    </Dialog.Root>
  );
}
