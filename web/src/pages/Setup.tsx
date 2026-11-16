// Before any account is connected: the Overview says what Keelson does and how to
// start, and links to adding accounts on the Accounts page, where the platform
// choice and its steps live. Other pages that need an account say so in one line.
// A role that can't connect accounts is told who can.

import { Button, Link } from "@cloudflare/kumo";
import { EyeIcon, HardDrivesIcon, LockKeyIcon, PlusIcon } from "@phosphor-icons/react";
import { Card, NoRows, Page } from "../components/ui.tsx";
import { navigate, providerList } from "../lib.ts";
import { useShell } from "../shell.tsx";

/** Opens the Accounts page with its Add accounts dialog. */
export const ADD_ACCOUNTS = "/accounts?add=1";

export function GetStarted() {
  const { can } = useShell();
  const add = can("accounts");
  const assurances = [
    [EyeIcon, "Read-only", "Keelson never changes anything in your accounts."],
    [HardDrivesIcon, "Stays here", "Results and credentials stay on the machine Keelson runs on."],
    [LockKeyIcon, "No telemetry", "It talks to your platforms, and checks your own hostnames for takeovers (you can turn that off)."],
  ] as const;
  return (
    <Page title="Overview" description={`Keelson scans your configuration on ${providerList()} for security problems, then tracks each one until it's fixed.`}>
      <Card
        title="Connect your first account"
        footer={
          add ? (
            <Button variant="primary" icon={<PlusIcon />} onClick={() => navigate(ADD_ACCOUNTS)}>
              Add accounts
            </Button>
          ) : undefined
        }
      >
        <p className="text-sm text-kumo-subtle">
          {add
            ? "Choose a platform, create a credential there with the steps Keelson shows, and pick the accounts to scan. The first scan starts as soon as you add them, and findings show up here."
            : "Nothing is connected yet. An admin or a manager connects accounts; once they do, findings show up here."}
        </p>
        <dl className="mt-4 grid grid-cols-1 gap-x-6 gap-y-4 sm:grid-cols-3">
          {assurances.map(([Icon, title, text]) => (
            <div key={title} className="flex gap-3">
              <Icon className="mt-0.5 h-4 w-4 shrink-0 text-kumo-subtle" aria-hidden />
              <div className="min-w-0">
                <dt className="text-sm font-medium text-kumo-default">{title}</dt>
                <dd className="m-0 text-sm text-kumo-subtle">{text}</dd>
              </div>
            </div>
          ))}
        </dl>
      </Card>
    </Page>
  );
}

/** For pages that need an account, before there is one. */
export function NoAccountsYet() {
  const { can } = useShell();
  return (
    <NoRows>
      {can("accounts") ? (
        <>
          No accounts yet.{" "}
          <Link variant="plain" href={ADD_ACCOUNTS}>
            Add accounts
          </Link>{" "}
          to see this page.
        </>
      ) : (
        "No accounts yet. An admin or a manager connects them."
      )}
    </NoRows>
  );
}
