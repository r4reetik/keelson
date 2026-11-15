// Reading AWS policy documents for what checks need, and nothing more: whether a
// resource policy lets anyone in, which other accounts it lets in, whether a bucket
// refuses plain HTTP, and whether an identity's policies let it give itself more
// access. Callers keep only these conclusions; no document is ever stored.

export interface Statement {
  Effect?: string;
  Action?: string | string[];
  NotAction?: string | string[];
  Resource?: string | string[];
  Principal?: string | Record<string, string | string[]>;
  Condition?: Record<string, Record<string, unknown>>;
}

export const list = <T>(v: T | T[] | undefined): T[] => (v == null ? [] : Array.isArray(v) ? v : [v]);

/** The statements of a policy given as JSON text (resource policies) or URL-encoded JSON (IAM). Empty when it can't be read. */
export function statementsOf(policy: string | null | undefined): Statement[] {
  if (!policy) return [];
  for (const text of [policy, safeDecode(policy)]) {
    try {
      const doc = JSON.parse(text);
      return list(doc?.Statement as Statement | Statement[]);
    } catch {
      /* try the next form */
    }
  }
  return [];
}

const safeDecode = (s: string) => {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
};

const hasCondition = (s: Statement) => !!s.Condition && Object.keys(s.Condition).length > 0;
const principals = (s: Statement): string[] =>
  s.Principal === "*" ? ["*"] : s.Principal && typeof s.Principal === "object" ? Object.values(s.Principal).flatMap((v) => list(v)) : [];

/**
 * A resource policy lets anyone in: an Allow for the principal "*" with no condition. A condition (a source account, an
 * organization, an address) narrows who can use it, so it isn't counted, which can miss a condition that narrows nothing.
 */
export const allowsAnyone = (policy: string | null | undefined): boolean =>
  statementsOf(policy).some((s) => s.Effect === "Allow" && !hasCondition(s) && principals(s).includes("*"));

/** The 12-digit accounts an Allow names, other than `self`: as an ID or in the ARN of a root, user or role. */
export function otherAccounts(policy: string | null | undefined, self: string): string[] {
  const out = new Set<string>();
  for (const s of statementsOf(policy)) {
    if (s.Effect !== "Allow" || !s.Principal || typeof s.Principal !== "object") continue;
    for (const p of list(s.Principal.AWS)) {
      const id = /^(\d{12})$|^arn:aws[a-z-]*:(?:iam|sts)::(\d{12}):/.exec(p)?.slice(1).find(Boolean);
      if (id && id !== self) out.add(id);
    }
  }
  return [...out].sort();
}

/** A bucket policy refuses requests that don't use TLS: a Deny on aws:SecureTransport "false". */
export const deniesPlainHttp = (policy: string | null | undefined): boolean =>
  statementsOf(policy).some(
    (s) =>
      s.Effect === "Deny" &&
      Object.entries(s.Condition ?? {}).some(
        ([op, claims]) => /^Bool$/i.test(op) && list(claims?.["aws:SecureTransport"] as string | string[]).some((v) => String(v).toLowerCase() === "false"),
      ),
  );

/** Each of these lets an identity give itself, or another identity it controls, more access on its own. */
const SINGLE = [
  "iam:CreatePolicyVersion",
  "iam:SetDefaultPolicyVersion",
  "iam:AttachUserPolicy",
  "iam:AttachGroupPolicy",
  "iam:AttachRolePolicy",
  "iam:PutUserPolicy",
  "iam:PutGroupPolicy",
  "iam:PutRolePolicy",
  "iam:AddUserToGroup",
  "iam:CreateAccessKey",
  "iam:CreateLoginProfile",
  "iam:UpdateLoginProfile",
  "iam:UpdateAssumeRolePolicy",
];
/** With iam:PassRole, each of these runs code as any role: a new instance, function, stack or job. */
const WITH_PASS_ROLE = [
  "ec2:RunInstances",
  "lambda:CreateFunction",
  "cloudformation:CreateStack",
  "glue:CreateDevEndpoint",
  "glue:CreateJob",
  "codebuild:CreateProject",
  "sagemaker:CreateNotebookInstance",
  "datapipeline:CreatePipeline",
];

/** Whether an action pattern in a policy ("iam:Put*", "iam:*") covers an action. */
const covers = (pattern: string, action: string) =>
  new RegExp(
    `^${pattern
      .replace(/[.+^${}()|[\]\\]/g, "\\$&")
      .replace(/\*/g, ".*")
      .replace(/\?/g, ".")}$`,
    "i",
  ).test(action);

/**
 * The ways a set of identity policies lets their holder escalate: single actions, or iam:PassRole with a way to run code.
 * Only Allows without a condition on a wildcard resource count, so a policy scoped to named resources isn't reported.
 * Statements that allow everything are left to the administrator checks.
 */
export function escalationPaths(st: Statement[]): string[] {
  const allowed = st.filter((s) => s.Effect === "Allow" && !hasCondition(s) && list(s.Resource).some((r) => r.includes("*"))).flatMap((s) => list(s.Action));
  if (allowed.some((a) => a === "*" || a === "*:*")) return [];
  const has = (action: string) => allowed.some((p) => covers(p, action));
  const out = SINGLE.filter(has);
  if (has("iam:PassRole")) for (const a of WITH_PASS_ROLE) if (has(a)) out.push(`iam:PassRole with ${a}`);
  return out;
}
