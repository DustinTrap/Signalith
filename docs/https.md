# HTTPS

Signalith serves its web UI, API and agent ingest over HTTPS by default. Passwords,
sessions, the ingest token and events never cross the network in clear text, and there
is nothing to set up: the server makes its own certificate the first time it starts.

- [What happens by default](#what-happens-by-default)
- [Trust the certificate](#trust-the-certificate)
- [Names the certificate can cover](#names-the-certificate-can-cover)
- [Agents and syslog](#agents-and-syslog)
- [Use your own certificate](#use-your-own-certificate)
- [Behind a reverse proxy](#behind-a-reverse-proxy)
- [Upgrading from plain HTTP](#upgrading-from-plain-http)
- [Settings](#settings)
- [Troubleshooting](#troubleshooting)

Every HTTPS setting described here can also be changed on the **Settings** page
(**Configure > Settings**, the **HTTPS** card), without editing `signalith.yaml`: see
[Settings page](#on-the-settings-page) below.

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
- every address entered under **Agents send to** (or **Devices send to**) on the **Add
  data** page. Signalith adds it once you have entered it (not while you type), and keeps
  the 32 most recent ones.

The CA can only sign names for this server, not for other websites; see
[Names the certificate can cover](#names-the-certificate-can-cover).

The files are kept in the `tls` folder of Signalith's state folder (`SIGNALITH_STATE_DIR`,
or else the folder that holds `lookups.dir`):

| Install | Folder |
| --- | --- |
| Linux (systemd unit) | `/var/lib/signalith/tls` |
| Windows service | `C:\ProgramData\Signalith\tls` |
| Docker quick start | `/var/lib/signalith/tls` in the `signalith-data` volume |
| Anything else | `tls` next to the `lookups` folder, by default next to `signalith.yaml` |

`ca.pem` is the CA certificate to trust; `server.pem` is the certificate being served.
The keys (`ca.key`, `server.key`) are readable by Signalith's user only. Treat `ca.key`
like a password: whoever has it can make certificates that computers trusting the CA
accept for this server's names. Keep it out of backups that many people can read. If it
is lost, the next start makes a new CA, and browsers and agents have to trust that one
instead.

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
- Agents sending events over plain HTTP are accepted or refused by
  `server.tls.plaintext_ingest`; see [Upgrading from plain HTTP](#upgrading-from-plain-http).
  A refused batch gets 503, so the agent keeps it and sends it again later.

Over HTTPS, browsers are told to use HTTPS only for this site (HSTS), and the session
cookie is `__Host-signalith_session`, which browsers only send over HTTPS. HSTS is not sent
for `localhost` or an IP address: it would apply to every port of that host, so other
tools on `http://localhost` would stop working in that browser.

## Trust the certificate

Until your computer trusts Signalith's CA, browsers show a warning such as "Your connection
is not private". Trust the CA once on each computer you use Signalith from; there is
nothing to do again when the server certificate is renewed.

**1. Get the CA certificate.** Any of these:

- On the sign-in page, click **Download the server certificate**. It saves Signalith's CA
  certificate as `signalith-ca.crt` in your Downloads folder.
- Download `https://<server>:8080/api/tls/ca.pem`; it needs no sign-in.
- Copy `ca.pem` from the server's `tls` folder (see above).

**2. Check it is the right one.** The browser warning means the download itself could
come from someone in the middle, so compare it with what the server says, read on the
server rather than over that same connection. On the computer you downloaded it to:

```sh
openssl x509 -in ~/Downloads/signalith-ca.crt -noout -fingerprint -sha256
```

On Windows, `certutil -dump "$env:USERPROFILE\Downloads\signalith-ca.crt"` prints it as
`Cert Hash(sha256)` (the same hex digits, in lower case and without colons).

It must match the `ca_sha256` Signalith logs when it starts. On the server:

| Install | Command |
| --- | --- |
| Docker quick start, in the Signalith folder | `docker compose -f deploy/docker/docker-compose.yml logs signalith \| grep ca_sha256` (PowerShell: `... logs signalith \| Select-String ca_sha256`) |
| Linux (systemd) | `journalctl -u signalith \| grep ca_sha256`, or `openssl x509 -in /var/lib/signalith/tls/ca.pem -noout -fingerprint -sha256` |
| Windows service | `Select-String ca_sha256 C:\ProgramData\Signalith\signalith.log`, or `certutil -dump C:\ProgramData\Signalith\tls\ca.pem` |

Once one computer trusts the CA, the fingerprint on the **Add data** page is a fine check
for the others: that page is then reached over a connection the browser has checked.

**3. Trust it.** The commands below expect the file in your Downloads folder.

Windows, for every user of the computer, in an elevated PowerShell:

```powershell
Import-Certificate -FilePath "$env:USERPROFILE\Downloads\signalith-ca.crt" -CertStoreLocation Cert:\LocalMachine\Root
```

or for your user only, without administrator rights:
`certutil -user -addstore Root "$env:USERPROFILE\Downloads\signalith-ca.crt"`.
Edge and Chrome use the Windows store; restart the browser afterwards.

macOS:

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/Downloads/signalith-ca.crt
```

Safari and Chrome use the keychain; restart the browser afterwards.

Linux, Debian and Ubuntu:

```sh
sudo cp ~/Downloads/signalith-ca.crt /usr/local/share/ca-certificates/signalith-ca.crt
sudo update-ca-certificates
```

Linux, RHEL, Fedora and similar:

```sh
sudo cp ~/Downloads/signalith-ca.crt /etc/pki/ca-trust/source/anchors/signalith-ca.crt
sudo update-ca-trust
```

Chrome and Chromium on Linux keep their own list; add it there too (the `certutil` here
comes from `libnss3-tools` or `nss-tools`):

```sh
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "Signalith Local CA" -i ~/Downloads/signalith-ca.crt
```

Firefox, on any system: **Settings > Privacy & Security > Certificates > View
Certificates > Authorities > Import**, choose the file and tick **Trust this CA to identify
websites**.

Command-line tools take the file directly, for example
`curl --cacert signalith-ca.crt -u admin https://siem.example.com:8080/api/health`.

Signalith's CA only ever signs certificates for this one server. It is also limited to
this server's names and private network addresses (see below), so even someone who took
`ca.key` from the server could not use it to read your traffic to other websites. If you
would rather not add a CA, [use your own certificate](#use-your-own-certificate).

## Names the certificate can cover

Computers that trust a CA accept every certificate it signs, so Signalith's CA is made
with limits (X.509 name constraints) that browsers, Fluent Bit and other TLS clients
enforce. It can only sign:

- the names and addresses this server had when the CA was made: its host name, full DNS
  name and IP addresses, the `server.public_url` host and `server.tls.names`;
- names that only mean something on a private network: `localhost`, and names ending in
  `.local`, `.localdomain`, `.internal`, `.intranet`, `.lan`, `.home`, `.home.arpa`,
  `.corp` or `.private`;
- private, shared and loopback addresses: `10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `::1`, `fc00::/7`
  and `fe80::/10`.

Entering another name under **Agents send to** says so, and Health lists any name in
`signalith.yaml` the certificate leaves out. To use such a name, either:

- [use your own certificate](#use-your-own-certificate) for it, or
- put it under `server.tls.names`, stop Signalith, delete the `tls` folder and start
  Signalith again. That makes a new CA that includes the name; every browser and agent
  then has to trust the new CA (get it again from the sign-in page or Add data).

## Agents and syslog

The Fluent Bit setup on the **Add data** page checks the server's certificate:

- The configuration sends with `tls On` and `tls.verify On`, with `tls.ca_file` set to
  Signalith's CA (`/etc/fluent-bit/signalith-ca.pem` on Linux,
  `C:\Program Files\fluent-bit\conf\signalith-ca.pem` on Windows).
- When agents send to a name rather than an IP address, it also sets `tls.vhost` to that
  name and `tls.verify_hostname On`, so the agent checks the certificate is for this
  server and not just from a CA it trusts. That needs Fluent Bit 3.1 or later, which the
  install steps get. (Fluent Bit cannot check an IP address against a certificate; with
  Signalith's own CA, which signs nothing else, checking the CA is enough.)
- One of the steps saves the CA next to the configuration. The page shows its fingerprint,
  **Download** and **Copy** buttons, and the certificate itself under **Show certificate**.
- The steps also make the configuration readable only by root (Linux) or SYSTEM and
  Administrators (Windows), since it holds the ingest token. On Windows they do the same
  for the agent's buffer in `C:\ProgramData\fluent-bit`, which holds Security log events
  until they are sent.

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
says so and names what it covers. Agents sending to a name check that the certificate is
for that name (`tls.verify_hostname`), so a certificate for another site, even one from
the same CA, is refused.

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

A `signalith.yaml` from before HTTPS was the default (no `server.tls` section) and without
`server.trusted_proxies` also believes `X-Forwarded-Proto: https` from this machine and
private networks, so a proxy set up the way older versions described keeps working. The
**Health** page then names the proxy; add it under `server.trusted_proxies` and restart.

## Upgrading from plain HTTP

Earlier versions served plain HTTP unless `server.tls_cert` was set. Nothing breaks when
you upgrade:

- **A config without `server.tls` and without `tls_cert`** (the usual case) gets
  `mode: auto` on the same port. An `http://` `public_url` is read as
  `https://` with the same host and port (`:80` when it had no port); the file is not
  changed, and the **Health** page asks you to change it. Browsers on old `http://`
  bookmarks are redirected, and are signed out once, since the session cookie changes.
  Agents set up for `http://` keep sending: for these configs `plaintext_ingest` is
  `allow`.
- **A config with `tls_cert`** gets `mode: files` and works as before.
- **A config without `tls_cert` whose `public_url` is `https://`** was behind a proxy that
  adds HTTPS, so it gets `mode: off` and works as before.
- **The Docker quick start** has HTTPS set in its own files now. Updating it also brings
  generated passwords and a secured OpenSearch; see
  [Upgrading the Docker quick start](../README.md#upgrading-the-docker-quick-start).

While agents still send over plain HTTP, the **Health** page names them (by address, and
by the host names in their events) and says how to move them over:

1. On **Add data**, build the agent setup again. It now sends to `https://` and checks
   the server with Signalith's CA.
2. Put the CA and the new configuration on each agent and restart it.
3. When the Health page no longer lists any agent, add this to `signalith.yaml`, change
   `public_url` to `https://` if it still says `http://`, and restart Signalith:

   ```yaml
   server:
     tls:
       mode: auto
       plaintext_ingest: deny
   ```

   An agent you missed is then turned away with 503: it keeps its events and sends them
   again, and the Health page names it, until it gets a new configuration.

New configs from `signalith init` and `install.ps1` already have `mode: auto` and
`plaintext_ingest: deny`.

Scripts that used `http://` with a user name and password are refused (403) until they
use `https://`; give them the CA, for example `curl --cacert ca.pem`.

## Settings

| Setting | Default | Meaning |
| --- | --- | --- |
| `server.tls.mode` | `auto` | `auto`: Signalith makes and renews its own certificate. `files`: `server.tls_cert` and `tls_key`. `off`: plain HTTP, only behind a reverse proxy that adds HTTPS |
| `server.tls.names` | none | Extra host names or IP addresses for the `auto` certificate, such as a DNS alias or the address a NAT or Docker publishes. Best set before the first start (see [Names the certificate can cover](#names-the-certificate-can-cover)) |
| `server.tls.plaintext_ingest` | `deny` (`allow` for configs from before HTTPS was the default) | Whether agents may still send events over plain HTTP |
| `server.trusted_proxies` | none | IPs or CIDRs of reverse proxies whose `X-Forwarded-Proto` header is believed |
| `server.tls_cert`, `server.tls_key` | none | Your certificate (with its chain) and key, for `mode: files` |
| `syslog.tls` | off (`init` sets `0.0.0.0:6514`) | Syslog over TLS, with the same certificate |
| `SIGNALITH_STATE_DIR` | the folder holding `lookups.dir` | Where the `tls` folder is kept |

### On the Settings page

The **HTTPS** card of the **Settings** page has the same settings: **HTTPS** (`mode`),
**Extra certificate names**, **Certificate file** and **Key file** (used only with your
own certificate files), **Agents on plain HTTP** and **Trusted reverse proxies**. What
is saved there wins over `signalith.yaml` (see [the Settings page](settings.md)); an
`http://` public address saved there is read as `https://` and the page offers to change
it, as for `signalith.yaml`.

- **Agents on plain HTTP** and **Trusted reverse proxies** apply as soon as they are
  saved.
- The mode, the extra names and the certificate files apply after a restart, which the
  page does in place. The certificate keeps coming from the same certificate authority,
  so nothing has to be trusted again; a restart with new names gives a certificate that
  has them, and a name taken out of the list leaves the certificate at the next restart.
- A public address saved on the page joins the certificate at once, as one entered on
  **Add data** does. A name Signalith's own CA may not sign is shown as a warning on the
  page.
- Turning HTTPS off or on moves the page between `http://` and `https://` on the same
  port, so you sign in again there; going between Signalith's own certificate and your
  files asks first, since agents set up to check one do not trust the other. A
  certificate that cannot be loaded or made stops the restart before anything stops.
- Below the settings, **In use now** shows the mode in use, the names the certificate
  covers and the CA's fingerprint, with a link to download the CA.

## Troubleshooting

**The browser still warns after trusting the CA.** Restart the browser. Check you trusted
`signalith-ca.crt`, the file the sign-in page's **Download the server certificate** link
saves (or `ca.pem` from the server), not `server.pem`. Check too that you open Signalith
by a name or address the certificate covers (it is listed in the startup log). To add a
name, enter it under **Agents send to** on Add data, or put it under `server.tls.names`
and restart Signalith; see [Names the certificate can cover](#names-the-certificate-can-cover).

**An agent logs `certificate verify failed`.** The CA file is missing from the path in
`tls.ca_file`, or the agent sends to an address the certificate does not cover. Enter the
address the agent uses under **Agents send to** on Add data, which adds it to the
certificate, and put the new configuration on the agent.

**An agent logs `unknown configuration property 'tls.verify_hostname'`.** Its Fluent Bit
is older than 3.1. Update Fluent Bit with the install step on Add data.

**An agent gets 503 and the Health page says it was turned away.** It sends over plain HTTP
while `plaintext_ingest` is `deny`, or with the old example token from an earlier Docker
quick start. It keeps its events and retries; give it a new configuration from Add data.

**Signalith cannot write its certificate.** The error names the folder. Give Signalith's
user write access to it, or set `SIGNALITH_STATE_DIR` to a folder it can write.
