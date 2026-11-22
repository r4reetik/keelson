# Security policy

## Supported versions

Security fixes go into the latest minor release. Upgrade to it before reporting, if you can.

| Version | Supported |
|---|---|
| 0.4.x | Yes |
| < 0.4 | No |

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[**Report a vulnerability**](https://github.com/r4reetik/keelson/security/advisories/new) form
(Security → Advisories) rather than in a public issue. Include the version,
how to reproduce it, and the impact. You'll get an acknowledgement within three working days,
and we'll agree a disclosure date with you once a fix is ready. Reporters are credited in the advisory unless they'd rather not be.

A false positive or missed finding in a check is not a vulnerability; use the
[false positive template](https://github.com/r4reetik/keelson/issues/new?template=false_positive.yml) for those.

## Threat model

Keelson holds the credentials of the platforms you connect (Cloudflare API tokens, Vercel access tokens,
AWS access keys, Alibaba Cloud AccessKeys, GitHub App private keys, a Shodan API key), and a database describing accounts' configuration, including member email addresses. It is designed to:

- **Only read.** The scanner issues GET requests, plus Cloudflare GraphQL analytics queries (GraphQL is sent
  as POST, as Cloudflare requires, and only ever queries). Use a Cloudflare token with read permissions;
  Keelson never needs anything else. Vercel can't issue read-only tokens, so a Vercel token can do what its
  user's role allows: Keelson still only sends GET requests to Vercel, and tests fail on anything else.
  Scanning container images pulls them from your registries with a registry login that expires within hours:
  three ECR read actions on AWS and one registry permission on Alibaba Cloud, each optional. Trivy, which reads the
  images, gets that login for the one registry host and never an account's own credential.
  For AWS, give the access key's user only the managed SecurityAudit policy; Keelson sends signed GET requests,
  and to services whose APIs only accept POST (CloudTrail, KMS, ECS and others) only the read actions it names
  (Describe, List, Get). The client refuses any other action before sending it, and tests fail on anything else.
  For Alibaba Cloud, give a RAM user the custom policy Keelson shows, which names only the read actions it sends.
  Every request is a signed GET, but Alibaba Cloud's APIs also accept GET for changes, so the client refuses any
  action that isn't a Describe, List or Get named in that policy before sending it, and tests fail on anything else.
  Keelson never asks for an object in an OSS bucket or a secret's value, which Alibaba Cloud's ReadOnlyAccess policy
  would allow.
  For GitHub, register the App with read-only permissions. On each scan Keelson signs a short-lived JWT with the
  App's private key and sends one POST to GitHub, for an installation token limited to the read permissions it
  needs, so a token Keelson holds can't write even if the App can. Every other request is GET, and tests fail on
  anything else.
- **Never read secret values.** Vercel environment variables are listed without their values; drain and
  webhook URLs are stored without their paths, query strings or headers. AWS policy documents are reduced to
  what they allow and Lambda environment variables are dropped as the answer is read; neither is stored. Instance
  start-up scripts (user data) are scanned for credentials in memory and dropped: only the kind of credential found
  is stored, never the script or the value. The same holds for Alibaba Cloud: RAM and OSS policy documents are
  reduced to what they allow, Function Compute environment variables, instance start-up scripts and launch templates
  are scanned in memory and dropped, an ALB rule's header condition keeps only the header's name, and of an AccessKey
  ID only the last four characters are kept. GitHub secret scanning alerts are read with `hide_secret` and the value
  field is dropped regardless; GitHub webhook URLs keep only their scheme and host, and deploy keys only their title.
- **Contact only what it needs.** Besides the APIs of the platforms you connect and public DNS, the optional takeover check
  sends one GET to your own hostnames that point at known cloud providers, and the update check reads
  GitHub's public list of releases once a day, sending nothing about the installation. Both can be turned off in Settings.
  Sonar, when you add it to an entity, sends that entity's domain names to crt.sh and Shodan and its public addresses
  to Shodan, with GET requests, and nothing to its hosts. A Shodan key travels only to `api.shodan.io`, in the request's
  address as Shodan requires, and never into a log line or an error. Of Shodan's answers, only ports, products,
  versions, vulnerability IDs and the entity's own hostnames are stored. When OWASP Amass is installed where Keelson
  runs, Sonar also runs it, passive and limited to the entity's domains: Amass sends the domain names to its own data
  sources and public DNS, and nothing to the entity's hosts. It runs
  with no Keelson setting or credential in its environment, its database is deleted after each scan, and its engine
  listens on port 4000 while it runs. Set `KEELSON_AMASS=off` to never run it.
  Secrets found in rules, such as hard-coded header values, and in plain-text Worker or Pages variables are
  never stored or shown; only their name (and, for headers, length) is.
- **Keep secrets local.**
  - Tokens are stored in `<data-dir>/credentials.json` with mode 0600, keyed by a random ID. The database
    only holds that ID. Each account is scanned only with the token it was added with, and a token no
    account uses any more is deleted.
  - Tokens are never returned by the API or written to logs.
  - A GitLab or Gitea instance's address is entered by whoever connects it (a manager or an admin), and Keelson then sends
    GET requests to that address from where it runs, never following a redirect. Like any connector to a server
    you name, that lets those roles make Keelson ask a host on its own network for `/api/v1/…`; give the roles
    to people you would let do that.
  - The password of a network's proxy (the Networks page) is stored the same way, and never returned or logged
    either. A certificate added to a network is trusted only for requests sent through that network. Adding it
    lets that network read those requests, credentials included, as it can for any machine whose TLS it
    inspects: add only your own organization's.
  - Removing an account deletes its scans, findings and triage. Copies of the database made before
    upgrades (`<data-dir>/backups/`, the newest three) keep older data until they're replaced.
  - Webhook URLs are treated as secrets as well.
- **Resist browser-based attacks.**
  - Host-header allowlisting stops DNS rebinding when sign-in is off on loopback, and the setup code stops a rebound page from creating the first admin.
  - Same-origin JSON is required for state changes (CSRF).
  - A strict Content-Security-Policy, framing denied.
  - CSV exports are protected against formula injection.
- **Require authentication.**
  - Everyone signs in with their own account, and the server checks their role (viewer, analyst, manager, admin) on every change. A user an admin limited to some entities can't read or change anything in another entity; it answers as if it didn't exist. Creating the first admin from anywhere but the machine Keelson runs on needs the one-time setup code from its log. Sign-in can only be turned off by declaring an authenticating proxy with `KEELSON_AUTH=none`.
  - Sessions are HttpOnly, SameSite=Strict cookies.
  - Passwords are stored as scrypt hashes. Sign-in and setup-code attempts are rate-limited per IP and overall.

Out of scope: an attacker who can already read the data directory or run code as the same user.
