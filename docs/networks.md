# Networks

Some platforms only answer from inside a company's network: a GitHub organization with an IP allow list, an AWS
policy tied to a source address, a container registry with an access list. That network is reached through a zero
trust client (Netskope, Cloudflare WARP, Zscaler) or a VPN (OpenVPN, WireGuard, Tailscale), and some of them inspect
TLS, so every certificate Keelson sees is re-signed by the company's own authority.

The **Networks** page (under Manage, for admins) is where you tell Keelson about them, and which one each platform's
requests go through.

A platform you host yourself is the plainest case: a Gitea instance at an address that only resolves inside the
office network, with a certificate from the company's own authority. Add a network with that certificate (and the
proxy into the office network, if Keelson runs outside it), and choose it for Gitea.

## What a network is

A network is one or both of:

- **A proxy to send requests through**: an HTTP proxy (it must allow `CONNECT` to port 443), the same over TLS, or
  SOCKS5, with an optional username and password.
- **A certificate to trust**: the root certificate the network signs with when it inspects TLS, as PEM. It is
  trusted only for requests sent through that network, on top of the public authorities, never for the rest of
  Keelson.

Keelson does not run a VPN or zero trust client itself. A tunnel changes the routes of the whole machine, so it
couldn't be chosen per platform, and it needs privileges the Docker image doesn't have. Every product can either
offer a proxy, or already steers the machine's traffic and only needs its certificate trusted:

| Network | How Keelson gets a route in |
|---|---|
| Netskope | Where the Netskope Client runs on Keelson's machine, it already steers Keelson's requests: no proxy, only your tenant's root certificate. Without the client, your tenant's explicit proxy address, and the certificate. |
| Cloudflare WARP | Put the Cloudflare One Client in **Local proxy mode**. It listens on `127.0.0.1:40000` as a SOCKS5 and HTTP proxy. Add your organization's root certificate if it inspects TLS. |
| Zscaler | Like Netskope: Client Connector on the machine needs only the certificate; otherwise the proxy address for your cloud, and the certificate. |
| OpenVPN, WireGuard | Neither has a proxy of its own. Run a VPN client beside Keelson that also offers an HTTP or SOCKS5 proxy into the tunnel, and enter that proxy. If everything should go through the VPN, connect the machine itself and add nothing here. |
| Tailscale | Run `tailscaled` in userspace networking mode with its SOCKS5 and HTTP proxies on, and enter that address. |
| Anything else | Any HTTP or SOCKS5 proxy that leads into the network, and its certificate if it inspects TLS. |

The form shows these steps for the kind you pick, and fills in the usual address.

In Docker, `127.0.0.1` is the container itself. To reach a proxy on the host, run the container on the host's
network, or run the proxy (or the VPN client that offers it) as a container beside Keelson and use its service name:

```yaml
services:
  keelson:
    # as in docs/deployment.md
  office-vpn:
    image: <a VPN client image that offers an HTTP or SOCKS5 proxy>
    # its own settings: the VPN profile, and the proxy's port
```

The network's proxy is then `office-vpn` and the port that image listens on. Choose that image as carefully as any
other software that carries your traffic.

## Which network a platform uses

Under **Which network each platform uses**, each platform is set to one of:

- **Default**: whatever the Default row says.
- **This machine's own connection**: no network, whatever the default is.
- **A network** from the list.

**Default** itself is this machine's own connection until you choose a network for it. Besides the platforms set
to Default, it carries what Keelson reads for itself: CISA's catalog, support dates, AWS's address ranges, the
scanners' vulnerability databases, update checks and alerts.

A platform's network applies to every request of its scans, to adding an account (verifying the credential, listing
its accounts), and to pulling its container images. Changes apply from the next scan. A removed network's platforms
follow the default again.

## Testing a network

**Test** (in a network's menu, and in the form before saving) sends one request to each platform through the
network (for a platform you host, to each instance a connected account is on), without any credential, and one to Cloudflare's trace page to read the address requests come out at. That
address is the one to add to a platform's allow list. A platform that answers anything, even "unauthorized", was
reached.

Before each scan through a network, Keelson asks the platform one thing the same way. If the network itself is
what fails (its proxy is down or refuses the sign-in, or a certificate isn't trusted because the network's own is
missing), the scan stops at once and says so, rather than finishing with every source unread.

## What is stored, and who sees it

- A proxy's password is kept with your platform credentials (`credentials.json` in the data folder, mode 0600). The
  database holds only its ID. No page, API answer, log line or error shows it.
- Certificates are public. The page shows who each one names, until when it is valid and its SHA-256 fingerprint.
  A private key is refused.
- Only admins see or change networks. Someone limited to some entities never does: networks belong to the whole
  installation.

## Limits

- Chosen per platform, not per account or entity: every account of a platform goes the same way.
- A proxy is used for HTTPS and HTTP requests. DNS lookups Sonar and Amass make themselves, and Amass's own
  requests, use the machine's resolver and connection.
- Trivy, Grype and the other scanners get the proxy and the certificates through their environment (`HTTPS_PROXY`,
  `SSL_CERT_FILE`). On macOS, Go programs read certificates from the system keychain instead of `SSL_CERT_FILE`, so
  a certificate that only Keelson knows isn't trusted by them there; in the Docker image and on Linux it is.
- AWS and Alibaba Cloud name a host per service and region, and one that doesn't exist means the service isn't
  offered there. A proxy only says that it couldn't connect, so Keelson asks the machine's own resolver whether the
  name exists, and believes "no" only from a resolver that resolves public names. Where the machine can't resolve
  public names at all, those services are coverage gaps instead of being read as not offered.
- Proxies set for the whole process (`HTTPS_PROXY` in the container's environment) aren't used by Keelson's own
  requests, only passed to the scanners it runs, as before. Add the proxy as a network and make it the default.
