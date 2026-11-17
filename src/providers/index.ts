// The provider registry. Everything that depends on the platform an account is on
// looks its provider up here.

import { cloudflare } from "./cloudflare.ts";
import { vercel } from "./vercel/index.ts";
import { aws } from "./aws/index.ts";
import { alibaba } from "./alibaba/index.ts";
import { github } from "./github/index.ts";
import { internet } from "./internet/index.ts";
import type { ProviderId } from "../shared/providers.ts";
import type { Provider } from "./types.ts";

export const PROVIDER: Record<ProviderId, Provider> = { cloudflare, vercel, aws, alibaba, github, internet };
export type { Provider };
