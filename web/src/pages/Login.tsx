// Before the app: creating the admin account when Keelson is new, signing in,
// and replacing a one-time password. Changing your password later uses the same
// form, in a dialog from the user menu.

import { useState, type ReactNode } from "react";
import { Banner, Button, Dialog, Input, LayerCard, SensitiveInput, useKumoToastManager } from "@cloudflare/kumo";
import { XCircleIcon } from "@phosphor-icons/react";
import { api, ROLE_INFO, type SessionUser } from "../lib.ts";
import { Wordmark } from "../components/brand.tsx";
import { DialogHeader, FormGrid } from "../components/ui.tsx";

/** Kept in step with MIN_PASSWORD in src/server/passwords.ts; the server checks it too. */
const MIN_PASSWORD = 12;

/** Runs a request for a form, keeping its busy state and error. */
function useSubmit(run: () => Promise<void>) {
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      await run();
    } catch (x) {
      setErr((x as Error).message);
      setBusy(false);
    }
  };
  return { err, busy, submit };
}

function AuthCard({
  title,
  description,
  children,
  onSubmit,
}: {
  title: string;
  description?: ReactNode;
  children: ReactNode;
  onSubmit: (e: React.FormEvent) => void;
}) {
  return (
    <div className="flex min-h-full items-center justify-center bg-kumo-canvas px-4 py-10">
      <form onSubmit={onSubmit} className="w-full max-w-md">
        <div className="mb-6 flex justify-center">
          <Wordmark />
        </div>
        <LayerCard>
          <LayerCard.Secondary>
            <h1 className="m-0 text-base font-medium">{title}</h1>
          </LayerCard.Secondary>
          <LayerCard.Primary className="flex flex-col gap-4">
            {description && <p className="text-sm text-kumo-subtle">{description}</p>}
            {children}
          </LayerCard.Primary>
        </LayerCard>
      </form>
    </div>
  );
}

const ErrorBanner = ({ err }: { err: string | null }) => (err ? <Banner variant="error" size="sm" icon={<XCircleIcon weight="fill" />} title={err} /> : null);

/** A new password typed twice, with the length rule shown before it's broken. */
function NewPassword({
  value,
  confirm,
  onChange,
  onConfirm,
}: {
  value: string;
  confirm: string;
  onChange: (v: string) => void;
  onConfirm: (v: string) => void;
}) {
  const short = value.length > 0 && value.length < MIN_PASSWORD;
  const mismatch = confirm.length > 0 && confirm !== value;
  return (
    <FormGrid>
      <SensitiveInput
        className="w-full"
        label="New password"
        value={value}
        onChange={(e: React.ChangeEvent<HTMLInputElement>) => onChange(e.target.value)}
        autoComplete="new-password"
        description={`At least ${MIN_PASSWORD} characters. A few words make a good one.`}
        variant={short ? "error" : "default"}
      />
      <SensitiveInput
        className="w-full"
        label="Repeat it"
        value={confirm}
        onChange={(e: React.ChangeEvent<HTMLInputElement>) => onConfirm(e.target.value)}
        autoComplete="new-password"
        variant={mismatch ? "error" : "default"}
        error={mismatch ? "The two passwords are different." : undefined}
      />
    </FormGrid>
  );
}

const passwordReady = (p: string, confirm: string) => p.length >= MIN_PASSWORD && p === confirm;

/** First open: whoever opens Keelson first creates the admin. Off this machine that needs the setup code from the log. */
export function SignupPage({ codeRequired, onDone }: { codeRequired: boolean; onDone: () => void }) {
  const [username, setUsername] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [code, setCode] = useState("");
  const { err, busy, submit } = useSubmit(async () => {
    await api("/api/setup", { method: "POST", body: { username, name, password, code } });
    onDone();
  });
  const ready = username.trim() && passwordReady(password, confirm) && (!codeRequired || code.trim());
  return (
    <AuthCard
      title="Create the admin account"
      description="Keelson is new here. The admin connects accounts, adds the people who use Keelson and chooses what each of them can do."
      onSubmit={submit}
    >
      {codeRequired && (
        <Input
          className="w-full"
          label="Setup code"
          placeholder="XXXX-XXXX-XXXX"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          autoComplete="off"
          spellCheck={false}
          description={
            <>
              Keelson printed it when it started. In Docker: <code className="text-kumo-default">docker logs keelson</code>
            </>
          }
        />
      )}
      <FormGrid>
        <Input
          className="w-full"
          label="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoComplete="username"
          autoCapitalize="none"
          spellCheck={false}
          description="What you sign in with. An email address works."
        />
        <Input className="w-full" label="Name (optional)" value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" />
      </FormGrid>
      <NewPassword value={password} confirm={confirm} onChange={setPassword} onConfirm={setConfirm} />
      <ErrorBanner err={err} />
      <Button type="submit" variant="primary" loading={busy} disabled={!ready}>
        Create admin account
      </Button>
    </AuthCard>
  );
}

export function LoginPage({ onDone }: { onDone: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const { err, busy, submit } = useSubmit(async () => {
    await api("/api/login", { method: "POST", body: { username, password } });
    onDone();
  });
  return (
    <AuthCard title="Sign in" onSubmit={submit}>
      <Input
        className="w-full"
        label="Username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
        autoComplete="username"
        autoCapitalize="none"
        spellCheck={false}
        autoFocus
      />
      <SensitiveInput
        className="w-full"
        label="Password"
        value={password}
        onChange={(e: React.ChangeEvent<HTMLInputElement>) => setPassword(e.target.value)}
        autoComplete="current-password"
      />
      <ErrorBanner err={err} />
      <Button type="submit" variant="primary" loading={busy} disabled={!username.trim() || !password}>
        Sign in
      </Button>
      <p className="text-sm text-kumo-subtle">Forgot your password? An admin can give you a new one-time password from the Users page.</p>
    </AuthCard>
  );
}

/** The fields for changing a password, shared by the forced page and the dialog. */
function usePasswordChange(onDone: () => void) {
  const [current, setCurrent] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const form = useSubmit(async () => {
    await api("/api/me/password", { method: "PUT", body: { current, password } });
    onDone();
  });
  return { current, setCurrent, password, setPassword, confirm, setConfirm, ready: !!current && passwordReady(password, confirm), ...form };
}

/** After signing in with a one-time password from an admin: nothing else until it's replaced. */
export function ChangePasswordPage({ user, onDone }: { user: SessionUser; onDone: () => void }) {
  const f = usePasswordChange(onDone);
  const signOut = async () => {
    await api("/api/logout", { method: "POST", body: {} }).catch(() => {});
    onDone();
  };
  return (
    <AuthCard
      title="Choose your password"
      description={`You signed in as ${user.username} (${ROLE_INFO[user.role].label}) with a one-time password. Choose your own to continue.`}
      onSubmit={f.submit}
    >
      <SensitiveInput
        className="w-full"
        label="One-time password"
        value={f.current}
        onChange={(e: React.ChangeEvent<HTMLInputElement>) => f.setCurrent(e.target.value)}
        autoComplete="current-password"
      />
      <NewPassword value={f.password} confirm={f.confirm} onChange={f.setPassword} onConfirm={f.setConfirm} />
      <ErrorBanner err={f.err} />
      <div className="flex justify-end gap-2">
        <Button type="button" variant="secondary" onClick={() => void signOut()}>
          Sign out
        </Button>
        <Button type="submit" variant="primary" loading={f.busy} disabled={!f.ready}>
          Save password
        </Button>
      </div>
    </AuthCard>
  );
}

export function ChangePasswordDialog({ onClose }: { onClose: () => void }) {
  const toasts = useKumoToastManager();
  const f = usePasswordChange(() => {
    toasts.add({ title: "Password changed", description: "You're still signed in here, and signed out everywhere else.", variant: "success" });
    onClose();
  });
  return (
    <Dialog.Root open onOpenChange={(o: boolean) => !o && onClose()}>
      <Dialog size="lg" className="p-6">
        <DialogHeader title="Change password" description="Your other sessions are signed out when you save." />
        <form onSubmit={f.submit} className="flex flex-col gap-4">
          <SensitiveInput
            className="w-full"
            label="Current password"
            value={f.current}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) => f.setCurrent(e.target.value)}
            autoComplete="current-password"
          />
          <NewPassword value={f.password} confirm={f.confirm} onChange={f.setPassword} onConfirm={f.setConfirm} />
          <ErrorBanner err={f.err} />
          <div className="flex justify-end gap-2">
            <Dialog.Close
              render={(p) => (
                <Button {...p} variant="secondary">
                  Cancel
                </Button>
              )}
            />
            <Button type="submit" variant="primary" loading={f.busy} disabled={!f.ready}>
              Save password
            </Button>
          </div>
        </form>
      </Dialog>
    </Dialog.Root>
  );
}
