// GitHub Actions policy for the whole organization: what the GITHUB_TOKEN can do
// by default, whether a workflow can approve its own pull request, which
// third-party actions may run, what workflows started by a fork's pull request
// get, and whether public repositories can send jobs to the organization's own
// machines. Skipped when Actions is off for every repository.

import { active, type dash, defineChecks } from "./define.ts";
import type { Report } from "../../../core/checks/define.ts";
import type { GithubInventory, GithubRepo, SelfHostedRunner } from "../types.ts";

/** How each fork pull request approval policy reads in a finding. */
const APPROVAL: Record<string, string> = {
  first_time_contributors_new_to_github: "only accounts new to GitHub wait for a maintainer's approval",
  first_time_contributors: "only first-time contributors wait for a maintainer's approval",
  all_external_contributors: "every outside contributor waits for a maintainer's approval",
};

/**
 * The self-hosted runners a public repository can send jobs to: its own, and those of every organization group that
 * public repositories may use and that includes it. Null when a group's repositories couldn't be read.
 */
export function publicRunners(inv: GithubInventory, r: GithubRepo): { runners: SelfHostedRunner[]; groups: string[]; restricted: boolean } | null {
  if (!inv.runnerGroups || !inv.runners || !r.runners) return null;
  const groups = inv.runnerGroups.filter((g) => g.allowsPublic && (g.visibility === "all" || g.visibility === "selected"));
  if (groups.some((g) => g.visibility === "selected" && !g.repos)) return null;
  const reach = groups.filter((g) => g.visibility === "all" || g.repos!.includes(r.name));
  const fromGroups = inv.runners.filter((x) => reach.some((g) => g.id === x.groupId));
  const used = reach.filter((g) => fromGroups.some((x) => x.groupId === g.id));
  return {
    runners: [...r.runners, ...fromGroups],
    groups: used.map((g) => g.name),
    // Only named workflows may use those groups, and the repository has none of its own.
    restricted: r.runners.length === 0 && used.length > 0 && used.every((g) => g.restrictedToWorkflows),
  };
}

export default defineChecks(
  {
    "GAC-001": {
      category: "Deployments",
      severity: "medium",
      docs: "https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token",
      requires: ["actions"],
      title: "Workflows get a token that can write by default",
      why: "Every workflow run gets a GITHUB_TOKEN that can push code, create releases and change issues, even when it only builds or tests. A compromised action or a script injection then changes the repository.",
      fix: "Under the organization's Settings → Actions → General → Workflow permissions, choose Read repository contents and packages permissions. Give a workflow more with a permissions block where it needs it.",
    },
    "GAC-002": {
      category: "Deployments",
      severity: "medium",
      docs: "https://docs.github.com/en/organizations/managing-organization-settings/disabling-or-limiting-github-actions-for-your-organization#preventing-github-actions-from-creating-or-approving-pull-requests",
      requires: ["actions"],
      title: "Workflows can approve pull requests",
      why: "A workflow can approve a pull request, including one it opened. That satisfies a required review with no person involved, so the review rule protects nothing against a compromised workflow.",
      fix: "Under the organization's Settings → Actions → General → Workflow permissions, untick Allow GitHub Actions to create and approve pull requests.",
    },
    "GAC-003": {
      category: "Deployments",
      severity: "low",
      docs: "https://docs.github.com/en/organizations/managing-organization-settings/disabling-or-limiting-github-actions-for-your-organization#allowing-select-actions-and-reusable-workflows-to-run",
      requires: ["actions"],
      title: "Any third-party action can run",
      why: "Workflows can use any action from any author. An action runs with the workflow's token and secrets, so one compromised action reaches every repository that uses it.",
      fix: "Under the organization's Settings → Actions → General → Policies, choose Allow enterprise, and select non-enterprise, actions and reusable workflows. Allow actions created by GitHub, verified creators and the ones you name.",
    },
    "GAC-004": {
      category: "Deployments",
      severity: "high",
      docs: "https://docs.github.com/en/organizations/managing-organization-settings/disabling-or-limiting-github-actions-for-your-organization#enabling-workflows-for-private-repository-forks",
      requires: ["forkPrs"],
      attackPath: true,
      title: "Pull requests from forks of private repositories get secrets or a write token",
      why: "A workflow started by a pull request from a fork runs the fork's version of the workflow. Anyone who can fork a private repository can then read every secret the workflow can reach, or use its token to change the repository, before anyone reviews the change.",
      fix: "Under the organization's Settings → Actions → General, in the section for forks of private repositories, untick Send write tokens to workflows from pull requests and Send secrets to workflows from pull requests. If fork pull requests must run workflows, also tick Require approval for fork pull request workflows.",
    },
    "GAC-005": {
      category: "Deployments",
      severity: "high",
      docs: "https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security",
      requires: ["runners", "repoRunners"],
      attackPath: true,
      title: "Public repository can run jobs on self-hosted runners",
      why: "A pull request to a public repository can change its workflows to run anything on your own machines, which sit inside your network with whatever credentials they hold. A runner that isn't ephemeral also keeps what the job left behind for the next job, including a backdoor.",
      fix: "1. Move the runners into a runner group that public repositories can't use: under the organization's Settings → Actions → Runner groups, untick Allow public repositories. 2. Remove runners added to the public repository itself, under its Settings → Actions → Runners. 3. If a public repository needs them, use ephemeral runners, limit the group to named workflows, and under Settings → Actions → General choose Require approval for all external contributors.",
    },
  },
  ({ inv, d }, report) => {
    const a = inv.actions;
    if (a?.enabledRepos === "none") return;
    forkPrs(inv, report, d.settings("actions"));
    runners(inv, report, d);
    if (!a) return;
    const where = { zone: null, resource: inv.login, link: d.settings("actions") };
    if (a.defaultWorkflowPermissions)
      report("GAC-001", {
        ...where,
        pass: a.defaultWorkflowPermissions !== "write",
        detail: a.defaultWorkflowPermissions === "write" ? "Default GITHUB_TOKEN permissions: read and write" : "",
      });
    if (a.canApprovePullRequests != null)
      report("GAC-002", { ...where, pass: !a.canApprovePullRequests, detail: a.canApprovePullRequests ? "Actions can create and approve pull requests" : "" });
    if (a.allowedActions)
      report("GAC-003", {
        ...where,
        pass: a.allowedActions !== "all",
        detail: a.allowedActions === "all" ? "All actions and reusable workflows are allowed" : "",
      });
  },
);

type ReportFn = Report<"GAC-004" | "GAC-005">;

function forkPrs(inv: GithubInventory, report: ReportFn, link: string): void {
  const p = inv.forkPrs?.private;
  if (!p) return;
  const given = [p.secrets && "secrets and variables", p.writeTokens && "a token that can write"].filter(Boolean);
  const open = p.runs && given.length > 0;
  report("GAC-004", {
    zone: null,
    resource: inv.login,
    pass: !open,
    // A maintainer must approve each run first: still a way in, but not one that needs no one.
    severity: open && p.needsApproval ? "medium" : undefined,
    detail: open
      ? `Workflows from fork pull requests get ${given.join(" and ")}${p.needsApproval ? ", after a maintainer approves the run" : ", with no approval"}`
      : "",
    link,
  });
}

function runners(inv: GithubInventory, report: ReportFn, d: ReturnType<typeof dash>): void {
  const approval = inv.forkPrs?.approval ?? null;
  for (const r of active(inv).filter((x) => x.visibility === "public")) {
    const reach = publicRunners(inv, r);
    if (!reach) continue;
    const n = reach.runners.length;
    const where = { zone: r.name, resource: r.name };
    if (!n) {
      report("GAC-005", { ...where, pass: true, link: d.repo(r.name, "settings/actions/runners") });
      continue;
    }
    const persistent = reach.runners.some((x) => !x.ephemeral);
    const unapproved = approval != null && approval !== "all_external_contributors";
    const names = reach.runners.slice(0, 5).map((x) => x.name);
    const parts = [
      `${n} self-hosted runner${n === 1 ? "" : "s"}: ${names.join(", ")}${n > 5 ? "…" : ""}`,
      reach.groups.length ? `group${reach.groups.length === 1 ? "" : "s"} ${reach.groups.join(", ")}` : "",
      persistent ? "not ephemeral" : "",
      reach.restricted ? "limited to named workflows" : "",
      approval ? (APPROVAL[approval] ?? "") : "",
    ].filter(Boolean);
    report("GAC-005", {
      ...where,
      pass: false,
      severity: reach.restricted ? "medium" : persistent && unapproved ? "critical" : undefined,
      detail: parts.join("; "),
      link: reach.groups.length ? d.settings("actions/runner-groups") : d.repo(r.name, "settings/actions/runners"),
    });
  }
}
