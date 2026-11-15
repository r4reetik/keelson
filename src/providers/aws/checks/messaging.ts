// Messaging: SNS topics and SQS queues whose policies let anyone in, SNS
// deliveries over plain HTTP, Amazon MQ brokers and MSK (Kafka) clusters reachable
// from the internet or without authentication, and EventBridge buses that accept
// events from any account.

import { defineChecks } from "./define.ts";

export default defineChecks(
  {
    "AMQ-001": {
      category: "Attack surface",
      severity: "high",
      docs: "https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-use-cases.html",
      requires: ["sns"],
      title: "SNS topic lets anyone publish or subscribe",
      why: 'The topic policy allows "*" without a condition, so any AWS account can send messages to everything subscribed, or subscribe and receive what you publish.',
      fix: 'In SNS → the topic → Access policy, remove the statement for "*" or add a condition that names the source (aws:SourceAccount, aws:SourceArn) or your organization (aws:PrincipalOrgID).',
    },
    "AMQ-002": {
      category: "TLS & HTTPS",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/sns/latest/dg/sns-http-https-endpoint-as-subscriber.html",
      requires: ["sns"],
      title: "SNS delivers messages over plain HTTP",
      why: "Messages, and any data in them, cross the internet unencrypted to the subscriber, where anyone on the path can read or change them.",
      fix: "Subscribe the endpoint again with an https:// URL, confirm the new subscription, and delete the http one.",
    },
    "AMQ-003": {
      category: "Attack surface",
      severity: "high",
      docs: "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-basic-examples-of-sqs-policies.html",
      requires: ["sqs"],
      title: "SQS queue lets anyone send or read messages",
      why: 'The queue policy allows "*" without a condition, so any AWS account can put messages your consumers will act on, or read and delete the ones meant for them.',
      fix: 'In SQS → the queue → Access policy, remove the statement for "*" or add a condition (aws:SourceArn for an SNS topic or S3 bucket, aws:PrincipalOrgID for your organization).',
    },
    "AMQ-004": {
      category: "Attack surface",
      severity: "high",
      docs: "https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/amazon-mq-security.html",
      requires: ["mq"],
      attackPath: true,
      title: "Amazon MQ broker is publicly accessible",
      why: "The broker and its web console have public addresses, so only its users' passwords keep the internet from your messages.",
      fix: "Public accessibility can't be changed in place: create a private broker in your VPC, move producers and consumers to it, and delete the public one.",
    },
    "AMQ-005": {
      category: "Attack surface",
      severity: "high",
      docs: "https://docs.aws.amazon.com/msk/latest/developerguide/msk-authentication.html",
      requires: ["msk"],
      title: "Kafka cluster accepts unauthenticated or unencrypted clients",
      why: "Clients can connect without proving who they are, or in plain text, so anyone who reaches the brokers can read and write every topic, or watch the traffic.",
      fix: "In MSK → the cluster → Properties → Security settings, turn on IAM, SASL/SCRAM or TLS client authentication and turn off unauthenticated access; set encryption between clients and brokers to TLS only. Turn off public access unless clients outside AWS need it.",
    },
    "AMQ-006": {
      category: "Attack surface",
      severity: "high",
      docs: "https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-bus-perms.html",
      requires: ["eventBuses"],
      title: "EventBridge event bus accepts events from any account",
      why: 'The bus policy allows "*" without a condition, so any AWS account can put events that your rules then act on: start workflows, invoke functions, send notifications.',
      fix: "In EventBridge → Event buses → the bus → Permissions, name the accounts that may send events, or add an aws:PrincipalOrgID condition for your organization.",
    },
  },
  ({ inv, d }, report) => {
    for (const r of inv.regions) {
      for (const t of r.topics ?? [])
        report("AMQ-001", {
          zone: r.name,
          resource: t.name,
          pass: !t.public,
          detail: t.public ? 'The topic policy allows "*"' : "",
          link: d.console(r.name, "sns/v3", `/topic/arn:aws:sns:${r.name}:${inv.accountId}:${t.name}`),
        });
      for (const s of r.httpSubscriptions ?? [])
        report("AMQ-002", {
          zone: r.name,
          resource: `${s.topic} → ${s.host || "http endpoint"}`,
          pass: false,
          detail: `Delivers to http://${s.host}`,
          link: d.console(r.name, "sns/v3", "/subscriptions"),
        });
      if (r.httpSubscriptions && r.topics?.length) report.passIfNone("AMQ-002", "subscriptions", r.name);
      for (const q of r.queues ?? [])
        report("AMQ-003", {
          zone: r.name,
          resource: q.name,
          pass: !q.public,
          detail: q.public ? 'The queue policy allows "*"' : "",
          link: d.console(r.name, "sqs/v3", `/queues/${encodeURIComponent(`https://sqs.${r.name}.amazonaws.com/${inv.accountId}/${q.name}`)}`),
        });
      for (const b of r.brokers ?? [])
        report("AMQ-004", {
          zone: r.name,
          resource: b.name,
          pass: !b.public,
          detail: b.public ? `${b.engine} broker with a public address` : "",
          link: d.console(r.name, "amazon-mq", "/brokers"),
        });
      for (const k of r.kafka ?? []) {
        const gaps = [
          k.unauthenticated && "unauthenticated clients",
          k.plaintext && "plain-text connections",
          k.public && "connections from the internet",
        ].filter(Boolean);
        report("AMQ-005", {
          zone: r.name,
          resource: k.name,
          pass: !k.unauthenticated && !k.plaintext,
          severity: k.public && k.unauthenticated ? "critical" : !k.unauthenticated && k.plaintext ? "medium" : undefined,
          detail: k.unauthenticated || k.plaintext ? `Accepts ${gaps.join(", ")}` : "",
          link: d.console(r.name, "msk", "/clusters"),
        });
      }
      for (const b of r.eventBuses ?? [])
        report("AMQ-006", {
          zone: r.name,
          resource: b.name,
          pass: !b.public,
          detail: b.public ? 'The bus policy allows "*"' : "",
          link: d.console(r.name, "events", `eventbus/${encodeURIComponent(b.name)}`),
        });
    }
  },
);
