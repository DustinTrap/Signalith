# Server settings

Admins change how the server runs on the **Settings** page: the public address,
the web address and certificate, the OpenSearch connection, search limits, syslog,
the detection scheduler, the AI assistant and more, without editing
`signalith.yaml` on the server. Each setting says where its value comes from, and
whether it applies at once or after a restart, which the page does for you.

Users, directory sign-in, agent tokens, threat intel feeds and data retention keep
their own pages; the Settings page links to them.

Only admins see the page (under **Configure**, or type "settings" in the
**Jump to** box with Ctrl+K). Viewers and analysts do not see it, and its API
answers them `403`.

## Using the page

The page has one card per section (General, Web server, OpenSearch, Search,
Syslog, Detections, AI assistant, Threat intel) and **About this server**. On a
wide screen a list of the sections stays on the left; on a phone the cards
follow one another.

Each setting has its name, what it does, and a quiet note on where its value
comes from:

- **From signalith.yaml**, or nothing for a built-in default (an empty box shows
  what empty means, such as "When empty: 12h").
- **Changed here by ann, 2h ago**, with **Reset** to take it off the page.
- A lock and **Set by SIGNALITH_…** when an environment variable sets it. The box
  cannot be changed; change the variable where Signalith's environment is set.

Changes wait until you save them. A bar at the bottom says how many are not
saved yet, with **Discard** and **Save changes**; leaving the page or closing the
tab with unsaved changes asks first. When something cannot be saved, nothing is
saved: each setting with a problem says what is wrong, and the cursor moves to
the first one.

Changes that are hard to undo ask before they are saved, and say what will happen:
a new listen address, OpenSearch address or index prefix, skipping OpenSearch's
certificate check, turning the detection scheduler off, and allowing threat intel
feeds from this computer.

The public address may be left empty: it is then worked out from the listen
address, and the page shows what it works out to.

Turning syslog on is two settings in the **Syslog** card (UDP and TCP address,
such as `0.0.0.0:514`), then a restart. The **Add data** page's syslog steps send
you there.

## Where changes are kept

Changes made on the page are written to `settings.yaml` in the lookups folder
(`/var/lib/signalith/lookups/settings.yaml` on Linux,
`C:\ProgramData\Signalith\lookups\settings.yaml` on Windows, the `lookups` volume in
Docker), never to `signalith.yaml`, which is often read-only. Set
`SIGNALITH_SETTINGS_FILE` to keep it somewhere else.

The file holds only the settings changed on the page, each with who changed it and
when. Signalith rewrites it whole on every save, through a temporary file and a
rename, readable only by its own account (mode 0600), since it can hold passwords
and API keys. When `signalith settings reset` runs as root, the file keeps the
owner it had, so the service can still read it.

```yaml
settings:
  opensearch.index_prefix:
    value: siem2
    changed_by: ann
    changed_at: 2026-10-12T18:52:32Z
  opensearch.password:
    secret: the-password
    sent_to: https://opensearch.corp.example:9200
    changed_by: ann
    changed_at: 2026-10-12T18:52:32Z
```

## Which value wins

1. An **environment variable**, such as `SIGNALITH_LISTEN` or
   `SIGNALITH_OPENSEARCH_PASSWORD`. The page shows these settings locked, with the
   variable's name: change them where Signalith's environment is set (for example
   `docker-compose.yml` or the service's settings), then restart it.
2. The **Settings page**.
3. **`signalith.yaml`**.
4. The **built-in default**.

Every setting on the page shows which of these its value comes from, and
**Reset** takes it off the page, so `signalith.yaml` or the default applies again.

## Applying changes

Settings marked **applies at once** take effect when you save: the public address,
the sign-out time, the default time range and events per search, the quiet data
source time, the most findings per run, and the AI assistant. A new public address
waits for the restart when the listen address or the certificate also changes, so
agents set up meanwhile are not sent to an address nothing answers yet.

The others are saved and wait for a restart. A banner at the top of the page
names what is waiting (**What changes** lists the value in use and the saved
one) and has a **Restart now** button. While Signalith restarts, the banner
shows its progress; the page reloads when Signalith is back, or moves to the new
address when the web address changed, and you stay signed in. If the new
settings cannot work, the banner says why and what to change. Signalith restarts
itself inside the same process: it stops its components (web handlers, OpenSearch
client, syslog receiver, detection scheduler, feed downloader and the rest) and
builds them again from the saved settings. This works the same under Docker,
systemd, a Windows service or a terminal. People stay signed in, and requests that
arrive during the few milliseconds of the switch wait for it.

### Protection against locking yourself out

Before anything stops, a restart checks that the new settings can work:

- the new web address can be listened on;
- the certificate and key files load;
- OpenSearch answers with the new address, username and password (within 10
  seconds);
- new syslog addresses can be listened on.

If one of these fails, nothing changes: Signalith keeps running with the settings
in use, and the page says what failed and what to change. If the new components then
fail to start anyway, Signalith goes back to the previous settings and says so.

When the web address moves, the old address keeps answering for 30 seconds, so the
page there can send you to the new one. Check the **public address** too: agents
are told to send there, and the page warns when its port is not the one Signalith
listens on (right only behind a proxy or a port forward).

Settings saved on the page never keep Signalith from starting. If the settings
file cannot be read, or Signalith cannot start with the settings in it (for
example, the saved web address is taken), it starts with `signalith.yaml` alone,
logs why, and shows it at the top of the Settings page and in
`signalith validate`.

### If you are locked out anyway

On the server:

```
signalith settings list               # what was changed on the page, by whom and when
signalith settings reset server.listen
signalith settings reset              # every change made on the page
```

then restart the service (`systemctl restart signalith`, `Restart-Service Signalith`
or `docker compose restart signalith`). Passwords and keys are never printed.

## Passwords and API keys

The OpenSearch password and the AI assistant's API key are never shown or sent back
to the browser; the page only says whether one is set.

- A saved one shows as **Saved, hidden**. **Replace** opens a box to type a new
  one (**Keep saved** closes it again), and **Remove** removes it when you save.
- A password is only ever sent to the address it was entered for (its scheme, host
  and port). To point Signalith at another OpenSearch or AI provider, enter the
  password or key again, or clear it; the page refuses to save otherwise. A password
  from `signalith.yaml` or the environment is likewise only sent to the address set
  there.

**Test connection** checks OpenSearch with the values on the form, saved or not,
and says plainly what is wrong: nothing answers, wrong password, a certificate that
is not trusted, HTTP on an HTTPS port, or not an OpenSearch at all. **Test** for the
AI assistant asks the model one fixed question ("failed logins in the last 24
hours") and shows the query it wrote. A result is marked out of date as soon as
one of the settings it used changes.

## Exporting settings

**Download settings as YAML**, in **About this server**, downloads the page's
settings in the format of `signalith.yaml`, for a second server or a backup.
Passwords and keys are left out, and settings that belong to this server only (its
addresses and certificate files) are marked. A public address worked out from the
listen address is left empty, so the other server works out its own.

**About this server** also shows the version, platform and how long Signalith has
been running, where its files and folders are, and **Reset all**, which takes every
change off the page.

## Not on this page

| Setting | Where instead |
| --- | --- |
| `retention.days` | The data retention page. |
| `auth.admin_user`, `auth.admin_password_hash` | `signalith.yaml` and `signalith passwd` only: the built-in admin is the break-glass account, so no page can lock everyone out. |
| `auth.ldap` | The Users page sets up directory sign-in. |
| `auth.users_file`, `intel.feeds_file`, `detections.dir`, `dashboards.dir`, `lookups.dir` | `signalith.yaml`: pages save into these files and folders, and the lookups folder holds the Settings page's own file. The page shows where they are. |
| `ingest.tokens` | Add data. The page shows how many there are. |
| `intel.feeds` | The Threat intel page. |

## Audit log

Every save, test and restart is logged with `audit=true`, who did it and from which
address. Values of settings are logged; passwords and keys never are (they show as
`(changed)` or `(none)`).

| Message | Fields |
| --- | --- |
| `settings saved` | `by`, `client`, `changes` (`key=value` pairs), `reset`, `cleared`, `reset_all`, `applied_now`, `after_restart`, `file` |
| `settings tested` | `by`, `client`, `what` (`opensearch` or `assistant`), the address, `ok` |
| `restart requested` | `by`, `client`, `pending` |
| `restarted with the saved settings` | `by`, `client`, `settings`, `took_ms` |
| `restart failed` | `by`, `client`, `settings`, `rolled_back`, `reason` |

```
level=INFO msg="settings saved" audit=true by=ann client=10.0.0.12 changes="opensearch.index_prefix=siem2 opensearch.password=(changed) search.max_events=5000" applied_now=search.max_events after_restart=opensearch.password,opensearch.index_prefix
level=ERROR msg="restart failed" audit=true by=ann client=10.0.0.12 settings=server.listen rolled_back=false reason="Signalith cannot listen on 0.0.0.0:443 (bind: permission denied). Signalith kept running with the previous settings. Choose another address or port."
```

## API

Every route is for admins. Requests from a browser that change something must come
from the Signalith page itself.

| Route | What it does |
| --- | --- |
| `GET /api/settings` | Every setting by section, with its value, source, whether it is locked, applies at once or after a restart, and is waiting for one; what is waiting; the last restart; paths and version |
| `PUT /api/settings` | Saves changes: `{"values": {key: value}, "clear": [keys], "reset": [keys], "reset_all": false}` |
| `POST /api/settings/test/opensearch` | Tests OpenSearch with `{"values": {...}}` over the saved settings |
| `POST /api/settings/test/assistant` | Tests the AI assistant the same way |
| `POST /api/settings/restart` | Restarts with the saved settings; answers 202 at once |
| `GET /api/settings/export` | `{"yaml": "...", "filename": "signalith-settings.yaml"}`; `?download=1` downloads the file |

One setting in `GET /api/settings`:

```json
{"key": "opensearch.password", "label": "Password", "type": "secret",
 "help": "Only sent to the address it was entered for.",
 "value": null, "set": true, "sent_to": "https://opensearch.corp.example:9200",
 "source": {"kind": "page", "by": "ann", "at": "2026-10-12T18:57:24Z"},
 "env": "SIGNALITH_OPENSEARCH_PASSWORD", "locked": false,
 "apply": "restart", "dangerous": false, "pending": true,
 "reset_to": {"value": null, "set": false, "source": "default"}}
```

A save with problems saves nothing and answers 400 with each problem by setting:

```json
{"error": "Nothing was saved. Fix the settings marked below.",
 "fields": {"server.listen": "Must be host:port, for example 0.0.0.0:8080",
            "syslog.tls": "Needs “Certificate file” and “Key file”; syslog over TLS uses the same certificate as the web UI"},
 "problems": []}
```

A restart answers at once, then `GET /api/settings` shows how it went under
`restart.last`:

```json
{"restarting": true, "pending": ["server.listen"], "listen_changed": true,
 "new_listen": "0.0.0.0:9443", "go_to": "https://siem.corp.example:9443/"}
```

```json
{"available": true, "in_progress": false, "needed": true,
 "last": {"at": "2026-10-12T18:54:45Z", "by": "ann", "ok": false, "keys": ["opensearch.url"],
          "error": "OpenSearch did not answer with the new settings: Nothing answered at 10.0.0.9:9200. Check that OpenSearch is running, and the address and port. Signalith kept running with the previous settings.",
          "took_ms": 1}}
```

While the components are being switched, a request that waits more than 30 seconds
is answered `503` with `{"code": "restarting"}` and `Retry-After: 5`.
