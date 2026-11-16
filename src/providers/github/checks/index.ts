// Every GitHub check module, in the order they run. Adding one: write it with
// defineChecks (./define.ts), list it here, and add a failing case to
// test/github-cases.ts.

import identity from "./identity.ts";
import branches from "./branches.ts";
import codeSecurity from "./code-security.ts";
import actions from "./actions.ts";
import integrations from "./integrations.ts";
import pages from "./pages.ts";
import releases from "./releases.ts";
import dependencies from "./dependencies.ts";
import type { CheckModule } from "../../../core/checks/define.ts";

export const GITHUB_MODULES = [identity, branches, codeSecurity, actions, integrations, pages, releases, dependencies] as const;

type IdsOf<M> = M extends CheckModule<infer Id, infer _C, infer _S> ? Id : never;
export type GithubCheckId = IdsOf<(typeof GITHUB_MODULES)[number]>;
