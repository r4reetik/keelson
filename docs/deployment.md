# Deployment

Keelson ships as one container image, `ghcr.io/r4reetik/keelson`, for `linux/amd64` and `linux/arm64`. Inside is a
single Node.js process with an embedded SQLite database, on Alpine Linux. It needs Docker (or any OCI runtime:
Podman, containerd, ECS, Kubernetes), and outbound HTTPS to `api.cloudflare.com` and `cloudflare-dns.com`. It also contacts, unless turned off in
Settings: your own hostnames that point at cloud providers (the takeover check, over HTTPS then HTTP),
`api.github.com` (the update check), and any Slack or webhook URL you configure for alerts.

## On your own machine

```bash
docker run -d --name keelson -p 127.0.0.1:4317:4317 \
  -v keelson-data:/data \
  ghcr.io/r4reetik/keelson:0.10
docker logs keelson
```

Open http://localhost:4317 and create the admin account. It asks for the setup code that `docker logs keelson`
shows: inside the container Keelson listens on every interface and can't tell that your browser is on the same
machine. Publishing the port on `127.0.0.1` keeps Keelson reachable from this machine only.

To keep your data in a folder rather than a Docker volume, mount the folder and run as your own user, so the files
stay yours: `--user "$(id -u):$(id -g)" -v ~/.keelson:/data`.

## For a team, with Docker

```yaml
# compose.yaml
services:
  keelson:
    # The release line: compatible updates only. See upgrading.md.
    image: ghcr.io/r4reetik/keelson:0.10
    restart: unless-stopped
    ports:
      - "4317:4317"
    volumes:
      - keelson-data:/data

volumes:
  keelson-data:
```

```bash
docker compose up -d
docker compose logs keelson
```

The image runs as an unprivileged user, stores everything in `/data`, and has a health check on `/api/health`.

### The first admin, and everyone else

Until someone has an account, Keelson shows a page to create the admin. From any machine but the one Keelson runs
on, that page asks for the setup code Keelson prints when it starts (`docker compose logs keelson`), so whoever
reaches the address first can't take it over. The code works once; a restart before the admin exists prints a new
one. Create the admin before you share the address.

The admin then adds people on the **Users** page, choosing a role for each (viewer, analyst, manager or admin; the
[README](../README.md#users-and-roles) says what each can do). Keelson gives each new person a one-time password,
shown once, for the admin to hand over; the person chooses their own password when they first sign in. Resetting a
password works the same way and signs that person out everywhere. Keelson always keeps at least one admin.

## Behind Cloudflare Access

If you already use Cloudflare Zero Trust, put Keelson behind a Cloudflare Tunnel and an Access application,
and let Access do the sign-in:

You can keep Keelson's own sign-in on behind Access, so each person still has a role. Or let Access be the only
sign-in:

1. Run Keelson with `KEELSON_AUTH=none` and `KEELSON_TRUST_PROXY=1`, reachable only from the tunnel
   (for example `ports: ["127.0.0.1:4317:4317"]`, or no published port and `cloudflared` on the same network).
2. Create a public hostname on the tunnel pointing at `http://keelson:4317`.
3. Create an Access application for that hostname, with a policy that allows only the people who should see
   your security findings.

`KEELSON_AUTH=none` turns off Keelson's own sign-in: there are no users, everyone Access lets through is an admin,
and triage changes aren't recorded under anyone's name. Never expose the port anywhere else.

If Keelson itself listens on `127.0.0.1` (`KEELSON_HOST=127.0.0.1` with host networking, or running from a clone)
with sign-in off, it only answers requests addressed to `localhost`, which blocks DNS-rebinding attacks. Add the
public hostname with `KEELSON_ALLOWED_HOSTS=keelson.example.com`.

## Behind another reverse proxy

Terminate TLS at the proxy and set `KEELSON_TRUST_PROXY=1` so session cookies are marked `Secure` and sign-in rate
limits apply to the client's address. Keelson takes that address from the last
`X-Forwarded-For` entry, the one your proxy adds, so the proxy must append to the header (Caddy, nginx's
`$proxy_add_x_forwarded_for` and most others do). With Caddy:

```
keelson.example.com {
  reverse_proxy 127.0.0.1:4317
}
```

## Configuration

| Flag | Environment | Default | |
|---|---|---|---|
| `--port` | `KEELSON_PORT` | `4317` | Port to listen on |
| `--host` | `KEELSON_HOST` | `0.0.0.0` (`127.0.0.1` from a clone) | Address to bind. Off loopback, creating the first admin needs the setup code |
| `--data-dir` | `KEELSON_DATA_DIR` | `/data` (`~/.keelson` from a clone) | Database and stored tokens |
| `--trust-proxy` | `KEELSON_TRUST_PROXY=1` | off | Trust `X-Forwarded-*` from your reverse proxy |
| `--no-open` | | | Don't open a browser (the image always passes it) |
| `--reset-password <user>` | | | Give a user a one-time password and exit, without starting the server |
| | `KEELSON_AUTH=none` | | No sign-in: an authenticating proxy decides who gets in, and everyone is an admin |
| | `KEELSON_ALLOWED_HOSTS` | | Extra names for this machine when Keelson listens on loopback, comma-separated |
| | `KEELSON_LOG=json` | text | Log one JSON object per line, for log collectors |
| | `KEELSON_UPDATE_CHECK=off` | on | Never check GitHub for new releases, whatever Settings say |

Flags are for the command, so in a container they mean running it there: `docker exec keelson node dist/bin.js
--reset-password <username>`.

Everything else (users and their roles, scan schedule, retention, SLAs, the takeover probe, accounts, entities and
alert destinations) is set in the web app and stored in the database.

## Data, backups and upgrades

The data directory holds:

- `keelson.db`, with `keelson.db-wal` and `keelson.db-shm` next to it while it runs: users (with scrypt hashes of
  their passwords, never the passwords), accounts, scans, findings, triage and settings (SQLite).
- `credentials.json`: the tokens and access keys. The database only holds a reference to each.
- `backups/`: copies of the database from before each upgrade that changed it, the newest three.

All of them are readable by the owning user only. Back up the whole directory; a copy taken while Keelson
is stopped is complete. Treat it like the tokens themselves. Scans older than the retention period (Settings →
Scans) are pruned automatically, along with the triage of findings no scan reports any more.

Upgrading is pulling the new image and recreating the container; Keelson copies the database to `backups/` before
migrating it. Release lines, automatic updates and rolling back are covered in [upgrading.md](upgrading.md).

## Operating it

- **Logs** go to standard output (warnings and errors to standard error): `docker logs keelson`. `KEELSON_LOG=json` writes one JSON object per line.
- **Passwords:** each person changes their own from the menu under their name; an admin resets anyone else's from
  the Users page. If nobody can sign in as an admin, `docker exec keelson node dist/bin.js --reset-password
  <username>` prints a one-time password. Sessions are kept in memory, so a restart signs everyone out.
- **Removing an account** (Accounts → the account's menu → Remove) deletes its scans, findings and triage.
  Older copies remain in `backups/` until newer upgrades replace them.
- **Uninstalling:** remove the container and its volume (`docker rm -f keelson && docker volume rm
  keelson-data`), or the folder you mounted at `/data`. Nothing is stored anywhere else. Revoke the tokens and access keys at each provider too.
- `PORT` is read when `KEELSON_PORT` isn't set, for platforms that assign one.

## Running from a clone

For working on Keelson itself, see [CONTRIBUTING.md](../CONTRIBUTING.md). `npm ci && npm run build && npm start` runs the
same server on Node.js 26 LTS, listening on `127.0.0.1` with its data in `~/.keelson`; on loopback, creating the
admin needs no setup code. That is for development; the image is the supported way to run Keelson, and the only one released.
