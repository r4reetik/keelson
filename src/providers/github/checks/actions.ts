// GitHub Actions policy for the whole organization: what the GITHUB_TOKEN can do
// by default, whether a workflow can approve its own pull request, and which
// third-party actions may run. Skipped when Actions is off for every repository.

import { defineChecks } from "./define.ts";

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
  },
  ({ inv, d }, report) => {
    const a = inv.actions;
    if (!a || a.enabledRepos === "none") return;
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
