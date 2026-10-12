# HTTPS

Signalith serves its web UI, API and agent ingest over HTTPS by default. Passwords,
sessions, the ingest token and events never cross the network in clear text, and there
is nothing to set up: the server makes its own certificate the first time it starts.

- [What happens by default](#what-happens-by-default)
- [Trust the certificate](#trust-the-certificate)
- [Agents and syslog](#agents-and-syslog)
- [Use your own certificate](#use-your-own-certificate)
- [Behind a reverse proxy](#behind-a-reverse-proxy)
- [Upgrading from plain HTTP](#upgrading-from-plain-http)
- [Settings](#settings)
- [Troubleshooting](#troubleshooting)

## What happens by default

With `server.tls.mode: auto` (the default), the first start creates a small certificate
authority for this server, **Signalith Local CA (*hostname*)**, valid for 10 years, and a
server certificate signed by it, valid for 397 days. Signalith renews the server
certificate by itself 30 days before it expires, with the same CA, so nothing has to be
trusted again. Both use ECDSA P-256 keys.

The server certificate covers:

- the host in `server.public_url`,
- this machine's host name and full DNS name,
- its IP addresses (not loopback or link-local ones),
- `localhost`, `127.0.0.1` and `::1`,
- every name in `server.tls.names`,
- every address entered under **Agents send to** on the **Add data** page. Signalith adds
  it to the certificate when it builds the agent setup, and keeps the 32 most recent ones.

The files are kept in the `tls` folder of Signalith's state folder (`SIGNALITH_STATE_DIR`,
or else the folder that holds `lookups.dir`):

| Install | Folder |
| --- | --- |
| Linux (systemd unit) | `/var/lib/signalith/tls` |
| Windows service | `C:\ProgramData\Signalith\tls` |
| Docker quick start | `/var/lib/signalith/tls` in the `signalith-data` volume |
| Anything else | `tls` next to the `lookups` folder, by default next to `signalith.yaml` |

`ca.pem` is the CA certificate to trust; `server.pem` is the certificate being served.
The keys (`ca.key`, `server.key`) are readable by Signalith's user only. Back up the folder
with the rest of Signalith's data: if `ca.key` is lost, the next start makes a new CA, and
browsers and agents have to trust that one instead.

When Signalith starts it logs the CA file, its SHA-256 fingerprint, the names the
certificate covers and when it expires:

```
level=INFO msg="HTTPS certificate from Signalith's own certificate authority; ..." ca_file=/var/lib/signalith/tls/ca.pem ca_sha256=3A:F1:... names=siem,siem.example.com,192.168.1.20,localhost,127.0.0.1,::1 expires=2027-11-13
```

### One port for HTTPS and plain HTTP

Signalith keeps one port (8080 by default) and looks at the first byte each client sends
to tell HTTPS from plain HTTP, so old `http://` bookmarks and agents still reach it:

- A browser asking for a page over `http://` is sent to the same address over `https://`.
- Signing in, HTTP Basic credentials and session cookies are refused over plain HTTP
  (403, with a message to use `https://`). A password is never accepted in clear text.
- Agents sending events over plain HTTP are accepted or refused (426) by
  `server.tls.plaintext_ingest`; see [Upgrading from plain HTTP](#upgrading-from-plain-http).

Over HTTPS, browsers are told to use HTTPS only for this site (HSTS), and the session
cookie is `__Host-signalith_session`, which browsers only send over HTTPS.

## Trust the certificate

Until your computer trusts Signalith's CA, browsers show a warning such as "Your connection
is not private". Trust the CA once on each computer you use Signalith from; there is
nothing to do again when the server certificate is renewed.

**1. Get the CA certificate.** Any of these:

- On the sign-in page, click **Download the server certificate** (`signalith-ca.crt`).
- Download `https://<server>:8080/api/tls/ca.pem`; it needs no sign-in.
- Copy `ca.pem` from the server's `tls` folder (see above).

**2. Check it is the right one.** Its SHA-256 fingerprint must match the `ca_sha256` in
Signalith's log, or the fingerprint on the **Add data** page:

```sh
openssl x509 -in signalith-ca.crt -noout -fingerprint -sha256
```

On Windows, `certutil -dump signalith-ca.crt` prints it as `Cert Hash(sha256)` (the same
hex digits, in lower case and without colons).

**3. Trust it.**

Windows, for every user of the computer, in an elevated PowerShell:

```powershell
Import-Certificate -FilePath .\signalith-ca.crt -CertStoreLocation Cert:\LocalMachine\Root
```

or for your user only, without administrator rights: `certutil -user -addstore Root signalith-ca.crt`.
Edge and Chrome use the Windows store; restart the browser afterwards.

macOS:

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain signalith-ca.crt
```

Safari and Chrome use the keychain; restart the browser afterwards.

Linux, Debian and Ubuntu:

```sh
sudo cp signalith-ca.crt /usr/local/share/ca-certificates/signalith-ca.crt
sudo update-ca-certificates
```

Linux, RHEL, Fedora and similar:

```sh
sudo cp signalith-ca.crt /etc/pki/ca-trust/source/anchors/signalith-ca.crt
sudo update-ca-trust
```

Chrome and Chromium on Linux keep their own list; add it there too (the `certutil` here
comes from `libnss3-tools` or `nss-tools`):

```sh
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "Signalith Local CA" -i signalith-ca.crt
```

Firefox, on any system: **Settings > Privacy & Security > Certificates > View
Certificates > Authorities > Import**, choose the file and tick **Trust this CA to identify
websites**.

Command-line tools take the file directly, for example
`curl --cacert signalith-ca.crt -u admin https://siem.example.com:8080/api/health`.

Signalith's CA only ever signs certificates for this one server; it cannot be used to
read your traffic to other sites unless someone takes `ca.key` from the server. If you
would rather not add a CA, [use your own certificate](#use-your-own-certificate).

## Agents and syslog

The Fluent Bit setup on the **Add data** page checks the server's certificate:

- The configuration sends with `tls On` and `tls.verify On`, with `tls.ca_file` set to
  Signalith's CA (`/etc/fluent-bit/signalith-ca.pem` on Linux,
  `C:\Program Files\fluent-bit\conf\signalith-ca.pem` on Windows) and `tls.vhost` set to
  the server's name when agents send to a name rather than an IP address.
- One of the steps saves the CA next to the configuration. The page shows the certificate,
  its fingerprint, and **Download** and **Copy** buttons.
- The steps also make the configuration readable only by root (Linux) or SYSTEM and
  Administrators (Windows), since it holds the ingest token.

When the certificate comes from a CA the agent's system already trusts (see
[Use your own certificate](#use-your-own-certificate)), there is no CA file to save.

Syslog over TLS (`syslog.tls`, port 6514 in new configs) uses the same certificate. In
**Add data > Syslog**, the rsyslog and syslog-ng setups send over TLS when it is on, with
the CA to save on each server. For other devices, give them `ca.pem` the way their manual
describes, or use UDP or TCP.

## Use your own certificate

To serve a certificate from your company's CA or a public one, set:

```yaml
server:
  tls:
    mode: files
  tls_cert: /etc/signalith/tls/server.pem  # the certificate, then the rest of its chain
  tls_key: /etc/signalith/tls/server.key
```

Relative paths are relative to `signalith.yaml`. Signalith checks the pair when it starts
(`signalith validate` too) and reloads the files within a minute of them changing, so a
renewal needs no restart. Syslog over TLS uses the same certificate.

What agents get depends on the chain:

- A certificate from a CA every system already trusts: agents need no CA file, and the
  sign-in page offers nothing to download.
- A certificate from a private CA, with that CA's certificate at the end of `tls_cert`:
  Add data and the sign-in page offer that CA, as for Signalith's own.
- A private CA that is not in the file: the agent steps ask you to save the CA you got
  from whoever issued the certificate.

The certificate must cover the address agents send to. If it does not, the Add data page
says so and names what it covers.

## Behind a reverse proxy

If a reverse proxy (nginx, Caddy, IIS, a load balancer) adds HTTPS in front of Signalith,
you can keep Signalith on HTTPS too: point the proxy at `https://` and trust Signalith's CA
in the proxy, or simply forward the plain connection to the same port and list the proxy
under `server.trusted_proxies`.

To have Signalith speak plain HTTP to the proxy instead, turn HTTPS off and keep the port
private to the proxy:

```yaml
server:
  listen: 127.0.0.1:8080              # only the proxy on this machine reaches it
  public_url: https://siem.example.com
  tls:
    mode: off
  trusted_proxies: [127.0.0.1]
```

The proxy must send `X-Forwarded-Proto: https`. Signalith believes that header only from
the addresses in `server.trusted_proxies`; from anyone else it is ignored, since any
client can send it. With it, Signalith sends HSTS and uses the HTTPS-only session cookie.
For nginx:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    client_max_body_size 20m;
}
```

With `mode: off`, `server.listen` reachable from other machines and no
`server.trusted_proxies`, `signalith validate` and the **Health** page warn that passwords
and events cross the network unencrypted.

## Upgrading from plain HTTP

Earlier versions served plain HTTP unless `server.tls_cert` was set. Nothing breaks when
you upgrade:

- **A config without `server.tls` and without `tls_cert`** (the usual case, and the Docker
  quick start) gets `mode: auto` on the same port. An `http://` `public_url` is read as
  `https://` with the same host and port (the file is not changed). Browsers on old
  `http://` bookmarks are redirected, and are signed out once, since the session cookie
  changes. Agents set up for `http://` keep sending: for these configs
  `plaintext_ingest` is `allow`.
- **A config with `tls_cert`** gets `mode: files` and works as before.
- **A config without `tls_cert` whose `public_url` is `https://`** was behind a proxy that
  adds HTTPS, so it gets `mode: off` and works as before.

While agents still send over plain HTTP, the **Health** page names them (by address) and
says how to move them over:

1. On **Add data**, build the agent setup again. It now sends to `https://` and checks
   the server with Signalith's CA.
2. Put the CA and the new configuration on each agent and restart it.
3. When the Health page no longer lists any agent, add this to `signalith.yaml` and
   restart Signalith:

   ```yaml
   server:
     tls:
       mode: auto
       plaintext_ingest: deny
   ```

New configs from `signalith init` and `install.ps1` already have `mode: auto` and
`plaintext_ingest: deny`.

Scripts that used `http://` with a user name and password are refused (403) until they
use `https://`; give them the CA, for example `curl --cacert ca.pem`.

## Settings

| Setting | Default | Meaning |
| --- | --- | --- |
| `server.tls.mode` | `auto` | `auto`: Signalith makes and renews its own certificate. `files`: `server.tls_cert` and `tls_key`. `off`: plain HTTP, only behind a reverse proxy that adds HTTPS |
| `server.tls.names` | none | Extra host names or IP addresses for the `auto` certificate, such as a DNS alias or the address a NAT or Docker publishes |
| `server.tls.plaintext_ingest` | `deny` (`allow` for configs from before HTTPS was the default) | Whether agents may still send events over plain HTTP |
| `server.trusted_proxies` | none | IPs or CIDRs of reverse proxies whose `X-Forwarded-Proto` header is believed |
| `server.tls_cert`, `server.tls_key` | none | Your certificate (with its chain) and key, for `mode: files` |
| `syslog.tls` | off (`init` sets `0.0.0.0:6514`) | Syslog over TLS, with the same certificate |
| `SIGNALITH_STATE_DIR` | the folder holding `lookups.dir` | Where the `tls` folder is kept |

## Troubleshooting

**The browser still warns after trusting the CA.** Restart the browser. Check you trusted
the CA (`signalith-ca.crt`), not the server certificate, and that you open Signalith by a
name or address the certificate covers (it is listed in the startup log). To add a name,
put it under `server.tls.names` and restart Signalith, or enter it under **Agents send to**
on Add data.

**An agent logs `certificate verify failed` or a name mismatch.** The CA file is missing
from the path in `tls.ca_file`, or the agent sends to an address the certificate does not
cover. Build the setup again on Add data with the address the agent uses; that adds the
address to the certificate.

**An agent gets 426 Upgrade Required.** It sends over plain HTTP and
`plaintext_ingest` is `deny`. Give it a new configuration from Add data.

**Signalith cannot write its certificate.** The error names the folder. Give Signalith's
user write access to it, or set `SIGNALITH_STATE_DIR` to a folder it can write.
