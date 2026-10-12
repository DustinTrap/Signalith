# Signalith

An open-source SIEM for Windows and Linux, inspired by Splunk Enterprise Security.
Signalith stores events in [OpenSearch](https://opensearch.org), collects them with
[Fluent Bit](https://fluentbit.io), and adds the security layer on top: a pipe-based
query language that reads like SPL, plain-English questions that become queries, a
visual query builder, CIM-style data models, scheduled detections with a findings
queue for triage, Sigma rule import, a MITRE ATT&CK coverage map, risk-based
alerting with asset and identity context, threat intel feeds matched against your
events, a security posture dashboard plus dashboards you build from queries, and
investigation cases that collect findings, notes, searches and evidence in one place.
Response actions and playbooks come next.

The server is a single Go binary with the web UI embedded. It runs as a Windows
service or a systemd unit.

> Status: Phase 3 (ES depth) is complete; Phase 4 has started with investigation cases. See the [roadmap](#roadmap).

## Quick start

### Docker (evaluation)

```sh
docker compose -f deploy/docker/docker-compose.yml up -d
```

Open http://localhost:8080 and sign in as `admin` with the password set in
`deploy/docker/docker-compose.yml` (change it first).
To update, run `git pull` and then the same command. It rebuilds Signalith from the
new code each time. After a reboot both containers start again by themselves once
Docker is running; in Docker Desktop turn on Settings > General > "Start Docker
Desktop when you sign in".

### Linux

1. Install OpenSearch 2.x ([instructions](https://opensearch.org/docs/latest/install-and-configure/install-opensearch/index/)).
2. Install Signalith:
   ```sh
   sudo install -m 0755 signalith-linux-amd64 /usr/local/bin/signalith
   sudo useradd --system --no-create-home signalith
   sudo signalith init -c /etc/signalith/signalith.yaml -opensearch http://127.0.0.1:9200
   sudo chown -R signalith /etc/signalith
   sudo cp deploy/systemd/signalith.service /etc/systemd/system/
   sudo systemctl enable --now signalith
   ```
   `init` prints the admin password once.

### Windows

1. Install OpenSearch 2.x for Windows ([instructions](https://opensearch.org/docs/latest/install-and-configure/install-opensearch/windows/)).
2. In an elevated PowerShell, from the folder holding `signalith.exe` and `deploy\windows\install.ps1`:
   ```powershell
   .\install.ps1 -OpenSearchUrl http://127.0.0.1:9200
   ```
   This writes `C:\ProgramData\Signalith\signalith.yaml`, installs the **Signalith** service and starts it.

### Send data

Open **Add data** in the UI, pick Linux or Windows, and follow the three steps: install
Fluent Bit, paste the generated configuration, restart it. The configuration already
contains the server address and ingest token. For firewalls, switches and other network
devices, pick **Syslog** (see [Syslog](#syslog)).

Agents on other machines must send to an address they can reach, such as
`http://192.168.1.20:8080`, not `localhost`. Enter it under **Agents send to** on that page
(or set `server.public_url` or `SIGNALITH_PUBLIC_URL`), and allow the port, 8080 by default,
through this computer's firewall.

Supported sources in Phase 1:

| Source | Data model |
| --- | --- |
| Windows Security log: 4624, 4625 logons | Authentication |
| Windows Security log: 4688 process creation | Endpoint |
| Windows Security log: 4720, 4726 accounts; 4728, 4732, 4756 group changes | Change |
| Sysmon: event 1 process create, event 3 network connection | Endpoint, Network_Traffic |
| Linux sshd, sudo, su (auth.log, secure, or journald) | Authentication |
| Linux useradd, userdel, usermod, gpasswd | Change |
| Syslog from any device (see below), including CEF | Authentication, Change, Network_Traffic or Other |
| Anything else | Other (searchable by text and fields) |

#### Syslog

Firewalls, switches, routers, appliances and servers without an agent can send syslog.
Point them at this server's address on **UDP or TCP port 514** (or the TLS port, if
you set `syslog.tls`). `signalith init` turns UDP and TCP 514 on; the Docker quick start
publishes port 514 too.

Open **Add data** and pick **Syslog** for copy-ready setup for rsyslog, syslog-ng, Cisco IOS
and ASA, Palo Alto, FortiGate, pfSense and OPNsense, UniFi and Windows, with this server's
address filled in. Send the test message it shows and watch it arrive on the same page.
When syslog is off, the page gives the steps to turn it on for this system.
By hand, forwarding a Linux server's logs with rsyslog is one line in
`/etc/rsyslog.d/90-signalith.conf`, then a restart of rsyslog:

```
*.* @@siem.example.com:514
```

`@@` sends over TCP; a single `@` sends over UDP. Signalith reads RFC 5424 and RFC 3164
syslog (including the usual variations, such as Cisco IOS, IOS XR, NX-OS and ASA), and
**CEF** (Common Event Format) from security products, mapped to CIM fields like `src`,
`dest`, `dest_port`, `user` and `action`. Forwarded sshd, sudo, su and user-management messages
land in Authentication and Change like agent data, so the built-in detections apply.
Events have `sourcetype=syslog` (or `cef`), `host` from the message, `dvc` set to the
sender's address, and `facility` and `severity`. The event time is the one in the message,
unless it is more than a week old (or older than any event category is kept) or more than a day
ahead; then it is the time Signalith received the message, and the device's own time is
kept in `device_time`.

To accept syslog only from known senders, list them under `syslog.allow`:

```yaml
syslog:
  udp: 0.0.0.0:514
  tcp: 0.0.0.0:514
  allow: [10.0.0.0/8, 192.0.2.10]
```

Over UDP the sender address can be forged, so for trusted senders use TCP or TLS, and
restrict the port with a firewall as well. The Windows installer limits its firewall
rules to the `syslog.allow` senders.

Ports below 1024 need extra permission on Linux. The systemd unit grants it; when
running Signalith another way, use a port such as `0.0.0.0:1514`. When devices send to a
different port than Signalith listens on, because Docker or a firewall forwards it, set
`syslog.public_port` so Add data shows the right one (the Docker quick start listens on
5514 and sets it to 514). The **Health** page (and `/api/health`, under `syslog`) shows the
listeners, how many messages were received, dropped, not written and rejected, and the
most recent senders.

### Sign in and users

The web UI has its own sign-in page. Sessions end after `auth.session_timeout` without
activity (12 hours by default) or when you sign out; tick **Keep me signed in** to stay
signed in for up to 7 days. Ten wrong passwords for one account from one address within
15 minutes lock that account out for that address for 15 minutes (with wider limits per
address and per account; see [docs/users.md](docs/users.md#signing-in)). Scripts and API
clients can keep using HTTP Basic auth with the same username and password.

Admins add people on the **Users** page and give each one a role: **Viewer** (look,
search, change nothing), **Analyst** (also triage findings, work investigations, build
dashboards) or **Admin** (also detections, feeds, lists, data collection and users).
New users get a temporary password they replace at their first sign-in. People can
also sign in with their **Active Directory or LDAP** account, with their role coming
from their groups; set it up and test it on the same page. The `admin` account from
`signalith.yaml` stays as a break-glass account that always works. See
[docs/users.md](docs/users.md).

## Configuration

Everything lives in one YAML file (`/etc/signalith/signalith.yaml` or
`C:\ProgramData\Signalith\signalith.yaml`). `signalith init` writes a working one, and
`signalith validate` checks it and lists every problem with the setting to fix.
Unknown keys are rejected, so typos do not silently do nothing.

| Setting | Default | Meaning |
| --- | --- | --- |
| `server.listen` | `127.0.0.1:8080` | Address the UI and API bind to |
| `server.public_url` | from `listen` | URL agents use (scheme, host and port); goes into generated agent configs |
| `server.tls_cert`, `server.tls_key` | none | Serve HTTPS |
| `opensearch.url` | `http://127.0.0.1:9200` | Event store |
| `opensearch.username`, `opensearch.password` | none | OpenSearch credentials |
| `opensearch.index_prefix` | `signalith` | Indices are `<prefix>-<datamodel>-YYYY.MM.DD` |
| `search.default_earliest` | `-24h` | Time range when a query sets none |
| `retention.days` | `90` | Days of events to keep (`0` keeps everything) until a default policy is saved on the Data retention page |
| `retention.interval` | `1h` | How often retention policies are enforced |
| `retention.archive_dir` | `archive` next to `lookups.dir` | Folder for archived days |
| `retention.default`, `retention.policies.<category>` | none | Policies that override the page; see [Data retention](#data-retention) |
| `retention.guard` | on, 85%, 7 days | Disk guard: `enabled`, `max_disk_percent`, `min_days` |
| `auth.admin_user`, `auth.admin_password_hash` | `admin` | The built-in admin, a break-glass account; change its password with `signalith passwd` |
| `auth.session_timeout` | `12h` | Sign the web UI out after this long without activity ("Keep me signed in" lasts up to 7 days) |
| `auth.users_file` | `users.json` in `lookups.dir` | Where users added on the Users page are kept; directory settings go in `directory.json` next to it |
| `auth.ldap` | none | Active Directory or LDAP sign-in, when you would rather not set it up on the Users page; see [docs/users.md](docs/users.md#setting-it-in-signalithyaml) |
| `ingest.tokens` | one generated | Tokens agents send as `Authorization: Bearer` |
| `syslog.udp`, `syslog.tcp` | off (`init` sets `0.0.0.0:514`) | Addresses to receive syslog on; empty turns a listener off. See [Syslog](#syslog) |
| `syslog.tls` | off | Address for syslog over TLS, such as `0.0.0.0:6514`; uses `server.tls_cert` and `server.tls_key` |
| `syslog.allow` | any sender | Sender IPs or CIDRs allowed to send syslog; others are dropped and counted |
| `syslog.public_port` | the listen port | Port devices send UDP and TCP syslog to, when it is forwarded to the listen port; shown on Add data |
| `detections.dir` | `detections` | Folder for custom and edited detections, relative to the config file |
| `detections.scheduler` | `true` | Run detections on schedule; turn off on extra servers sharing one OpenSearch |
| `detections.max_findings_per_run` | `100` | Cap on findings one run can raise |
| `lookups.dir` | `lookups` | Folder for `assets.csv` and `identities.csv`, relative to the config file |
| `intel.feeds` | none | Threat intel feeds kept in this file (read-only on the page); most people add feeds on the **Threat intel** page instead. See [Threat intel](#threat-intel). Nothing is fetched until a feed is added |
| `intel.feeds[].name`, `.url` | required | Feed name (shown as the indicator source) and its http(s) address |
| `intel.feeds[].kind`, `.collection` | `url` | `taxii` reads a TAXII 2.1 collection: `url` is the API root and `collection` the collection ID |
| `intel.feeds[].format` | `lines` | `lines` (one per line, `#` comments), `csv` (with `column:`, a header name or number), `stix` (STIX 2.1 bundle) or `auto` to detect |
| `intel.feeds[].type` | `auto` | `auto` detects each value, or `ip`, `cidr`, `domain`, `url`, `hash`, `md5`, `sha1`, `sha256`, `email` |
| `intel.feeds[].interval`, `.max_age` | `1h`, `7d` | How often to download; how long indicators last when downloads keep failing |
| `intel.feeds[].weight` | `1` | Multiplies the risk a match adds (0 to 10) |
| `intel.feeds[].headers`, `.username`, `.password` | none | Request headers and HTTP basic sign-in for feeds that need a key; values may use `${ENV_VAR}` |
| `intel.feeds[].tags`, `.description`, `.enabled` | none, `true` | Labels added to every indicator, and on/off |
| `intel.feeds_file` | `<lookups.dir>/intel_feeds.yaml` | Where feeds added on the page are saved, with their API keys (file mode 0600) |
| `intel.allow_loopback_feeds` | `false` | Allow feed downloads from this machine (`127.0.0.1`, `::1`), for a feed server on the same host |
| `dashboards.dir` | `dashboards` | Folder for custom dashboards, one YAML file each, relative to the config file |
| `dashboards.stale_after` | `2h` | How long a host and source type can be quiet before the posture dashboard lists it as stopped |
| `assistant.provider` | off | Optional AI model for **Ask**: `anthropic`, or `openai` for any OpenAI-compatible API (OpenAI, Ollama, LM Studio, vLLM) |
| `assistant.url`, `assistant.model`, `assistant.api_key` | per provider | Endpoint, model name and key; `anthropic` defaults to `claude-sonnet-5-5` |

Secrets can come from the environment instead: `SIGNALITH_OPENSEARCH_PASSWORD`,
`SIGNALITH_ADMIN_PASSWORD`, `SIGNALITH_INGEST_TOKEN`, `SIGNALITH_LDAP_BIND_PASSWORD` (for
`auth.ldap` in this file only; directory sign-in set up on the Users page keeps its own) (also
`SIGNALITH_OPENSEARCH_URL`, `SIGNALITH_LISTEN`, `SIGNALITH_PUBLIC_URL`, `SIGNALITH_DETECTIONS_DIR`,
`SIGNALITH_LOOKUPS_DIR`, `SIGNALITH_DASHBOARDS_DIR`, `SIGNALITH_USERS_FILE`,
`SIGNALITH_INTEL_FEEDS_FILE`, `SIGNALITH_ARCHIVE_DIR`, `SIGNALITH_ASSISTANT_API_KEY`, and `SIGNALITH_SYSLOG_UDP` and
`SIGNALITH_SYSLOG_TCP`, where `off` turns the listener off).

## Detections and findings

A detection is a query that runs on a schedule. Each row it returns becomes a
**finding** in the queue, like a notable event in Splunk ES. Signalith ships 21
detections mapped to MITRE ATT&CK (brute force, password spray, encoded PowerShell,
Office spawning shells, shadow copy deletion, credential dumping, privileged group
changes and more, plus two risk incident rules); 19 are on by default.

- **Findings** is the triage queue: filter by status, severity, owner or entity;
  assign, change status and disposition, comment, and update many at once. Each
  finding shows the result that fired, its entities, triage guidance, its full
  history, and a **View contributing events** link that opens the exact search.
- **Detections** lists every rule with its last run. Edit one in the form, **Test**
  it to see which findings it would raise, or **Run now**. Editing a built-in saves
  your version and keeps the original to revert to. Any search can become a detection
  with **Save as detection** on the Search page.
- **Import Sigma rule** converts a [Sigma](https://github.com/SigmaHQ/sigma) rule to a
  Signalith query and lists anything it had to approximate. Imported rules start
  disabled so you can test them first.
- **ATT&CK coverage** shows the Enterprise matrix with techniques covered by enabled
  detections, by disabled ones, and gaps.

Detections are YAML files, so they can live in Git. See
[docs/detections.md](docs/detections.md) for the format.

## Investigations

A **case** groups the findings that belong to one incident with the work done on it,
like an investigation in Splunk ES. Open the **Investigations** tab to see open cases.

- Start a case with **New case**, or select findings on the Findings page and choose
  **Add to case**. A finding belongs to one case; adding it to another moves it. The
  case takes the highest urgency of its findings and collects their users, hosts and
  IPs as **entities**, each a click away from a search.
- The **timeline** holds notes, searches and events. **Add a search** (or **Add to
  case** on the Search page) runs the query and keeps a snapshot of its first 50 rows,
  so the case still shows what you saw after the events age out. In search results,
  click a cell and choose **Pin this event to a case** to keep the full event.
- Set status, severity and owner as you work. When you resolve or close a case, write
  a resolution and optionally close all of its open findings with one disposition.

Cases are stored in OpenSearch in the `<prefix>_cases` index, and every change is
recorded with who made it.

## Risk and context

Signalith does risk-based alerting the way Splunk ES does. Most detections add
**risk** to the users and systems in their results instead of (or as well as)
raising a finding. Risk adds up per object, and two risk incident detections raise
one finding when an object crosses a total of 100 in 24 hours, or trips three ATT&CK
tactics from three detections in a week. Many weak signals about one user become
one alert, and noisy rules (new services, scheduled tasks, discovery commands) stop
flooding the queue.

- **Risk** lists the users and systems with the most risk, with a bar per score, the
  number of detections and tactics, and the asset or identity context. Click one to
  see every detection that added risk, oldest first.
- **Assets & identities** takes two CSV files, like the ES asset and identity
  lookups. Upload them on that page, or put them in `lookups.dir` (they reload within
  a minute). Every bad line is reported and nothing is saved until the file is clean.
  Download the current file from the same page to edit it.

```csv
host,ip,cidr,owner,priority,category,bunit,location
web1|web1.corp.local,10.0.1.10,,web team,critical,web|pci,ecommerce,dc1
,,10.20.0.0/16,it,low,workstation,,office
```

```csv
identity,name,email,manager,priority,category,bunit,watchlist
alice|CORP\alice|alice@corp.local,Alice Ng,alice@corp.local,bob,high,admin,it,true
```

Use `|` between several values in one cell. Hosts match by short name or FQDN,
IPs exactly or by the most specific CIDR, and users with or without `DOMAIN\` or
`@domain`. Priority is `low`, `medium`, `high` or `critical`.

Context changes three things:

- **Risk scores** are multiplied by the object's priority: critical ×2, high ×1.5,
  medium ×1, low ×0.5. A watchlisted user counts at least ×1.5.
- **Urgency** on each finding starts at its severity, goes up one level when a
  critical asset or watchlisted user is involved, and down one level when every
  known entity is low priority. The queue shows and filters by urgency.
- **`| enrich`** in any search adds `<field>_priority`, `_owner`, `_category` and more
  next to each user, host and IP field.

Risk events are stored under the Risk data model (`datamodel=Risk`) in
`<prefix>-risk-YYYY.MM.DD` indices, which ordinary searches leave out.

## Threat intel

Like the ES threat intelligence framework, Signalith matches events against
**indicators**: IP addresses and IPv4 networks, domains, URLs, MD5/SHA-1/SHA-256
file hashes and email addresses.

- **Feeds** are added on the **Threat intel** page with **Add feed**: pick free
  feeds from the built-in catalog (abuse.ch, Spamhaus, Emerging Threats and more),
  paste the address of any list, CSV or STIX file, or connect a TAXII 2.1 server
  such as MISP or OpenCTI and pick a collection. **Test** downloads the feed and
  shows what it holds (format, indicator types, samples) before you save, and a new
  feed downloads at once. Feeds can also be listed under `intel.feeds` in
  signalith.yaml; those show on the page as read-only. Nothing is fetched until you
  add one.
- **Downloads** run on the server with the detection scheduler, every feed on its
  own interval. The server needs outbound HTTPS to each feed; proxy settings come
  from `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`. An indicator that disappears from
  a feed is removed at the next download; if a feed keeps failing, its indicators
  expire after `max_age`. Turning a feed off removes its indicators; deleting one
  removes them, or keeps them until they age out if you choose.
- **Manual indicators**: add one on the **Threat intel** page or upload a CSV
  (`value,type,description,weight,expires,tags`) or plain list. Every bad line is
  reported and nothing is saved until the file is clean.
- **Matching**: the built-in **Threat intel match** detection (`threat-activity`)
  runs every 5 minutes, raises one finding per indicator and system a day, and adds
  60 risk times the indicator's weight to the system and user involved. In Search,
  `| threatmatch` keeps only matching events and `| intel` adds
  `<field>_intel_source`, `_intel_type`, `_intel_weight` and `_intel_description`
  columns to any result.

Feeds added on the page are saved in `lookups/intel_feeds.yaml` (set
`intel.feeds_file` to move it). To keep feeds in signalith.yaml instead, for example
when it is managed by configuration tools (check each provider's terms; values may
use `${ENV_VAR}` so keys stay out of the file):

```yaml
intel:
  feeds:
    - name: feodo-tracker          # botnet C2 servers, abuse.ch
      url: https://feodotracker.abuse.ch/downloads/ipblocklist.txt
      weight: 1.5
    - name: urlhaus                # malware download URLs, abuse.ch
      url: https://urlhaus.abuse.ch/downloads/text_recent/
      type: url
    - name: our-cti                # a collection on your own TAXII 2.1 server
      kind: taxii
      url: https://cti.example.com/taxii2/api1/
      collection: 91a7b528-80eb-42ed-a74d-c6fbd5a26116
      username: signalith
      password: ${CTI_PASSWORD}
```

See [docs/threat-intel.md](docs/threat-intel.md) for the catalog, formats, TAXII,
download safety rules, matching details and the API.

## Dashboards

The **Dashboards** tab opens on the built-in **Security posture** dashboard, like the
Splunk ES Security Posture and executive summary views. Pick a time range (last hour
to 30 days) and, if you like, auto-refresh. It shows:

- **Key indicators** compared with the previous period of the same length: open
  findings by urgency, new findings, findings closed, mean time to triage, mean time
  to resolve, and events ingested.
- **Findings over time by urgency**, **top detections firing** (findings and risk
  events), **top risk objects** and **ATT&CK tactics seen**.
- **Events by data model** and **by source type** over time.
- **Detection health**: how many detections are enabled, which ones failed on their
  last run, which enabled ones matched nothing in 30 days, and which hosts stopped
  sending (quiet for `dashboards.stale_after`).

**Custom dashboards** are panels of queries shown as a single value (optionally with
the change from the previous period), a table, bars, or a line or area chart. Build
one with **New dashboard**, then **Add panel**: ask a question in plain English and
the query is written for you, or write it, and preview before saving. On the Search
page, **Add to dashboard** turns the current search into a panel. Panels can be
edited, reordered and removed in the UI; they run in parallel and a failing panel
shows its error without breaking the others.

Each custom dashboard is a YAML file in `dashboards.dir`, so dashboards can be
reviewed and shared in Git. Files dropped into the folder show up without a restart.

```yaml
id: auth-watch
title: Authentication watch
time_range: 24h
panels:
  - title: Failed logons
    query: datamodel=Authentication action=failure | stats count
    viz: single
    compare: true
  - title: Logons over time
    query: datamodel=Authentication | timechart count by action
    viz: area
```

See [docs/dashboards.md](docs/dashboards.md) for every option and the API.

## Data retention

Admins set how long data is kept on the **Data retention** page. It lists every
category with its size on disk, the days it holds and its policy:

- each data model (Authentication, Endpoint, Network traffic, Change),
- Other events,
- Risk events,
- Findings,
- Investigations,
- Threat intel, which is managed by its feeds.

Each event category can have its own policy, or use the default policy:

- **Keep**: how many days stay searchable (0 keeps them forever).
- **Size cap**: the most disk the category may use. Its oldest days are deleted
  first.
- **Compact after**: makes old days read-only and merges them into one segment, so
  they take less space and memory.
- **Archive before deleting**: writes each day to a compressed, checksummed file
  first. You can restore it later from the page or with `signalith archive restore`.

Findings and investigations can be set to delete resolved and closed ones after a
number of days. Open ones are never deleted, and neither are findings that belong to
an investigation that is kept. Before you save, the dialog shows exactly which days
the change deletes, archives or compacts, including days already due, and asks
before deleting anything. Saving applies the change at once, with no restart.
Restoring archived days shows how full the disk will be first.

The **disk guard**, on by default, deletes the oldest event days when OpenSearch's
disk passes 85% and spares the last 7 days. This keeps OpenSearch from reaching 95%,
where it makes every index read-only and ingest stops. It deletes only when that
helps: if other files fill the disk, it keeps your history and the page says to add
space. A server upgraded while its OpenSearch disk is already above 85% trims old
days at its first run. To avoid that, set `retention.guard` in signalith.yaml first.

Retention runs every hour on the server with the detection scheduler; other servers
show the page read-only. It never deletes today's data or indices that are not
Signalith daily indices. The page keeps the last 200 actions with the reason for each.

Page settings are saved in `retention.yaml` in `lookups.dir`. Anything set under
`retention` in signalith.yaml is read-only on the page, except `retention.days`,
which is the default only until you save a default on the page:

```yaml
retention:
  days: 90
  policies:
    authentication: {keep_days: 365, compact_after_days: 14}
    endpoint: {keep_days: 30, max_size_gb: 500, archive: true}
    cases: {keep_days: 1095}
  guard: {enabled: true, max_disk_percent: 85, min_days: 7}
```

See [docs/retention.md](docs/retention.md) for more:

- how each rule works,
- the archive format and restores,
- compliance examples such as keeping 90 days searchable and a year archived,
- running more than one server,
- the API.

## Writing queries

```
datamodel=Authentication action=failure earliest=-24h
| stats count, dc(user) as users by src
| where count > 20
| sort -count
```

Ways to build one without memorizing syntax:

- **Ask in plain English.** Type a question above the query box, such as
  *top 10 users with failed logins today*, *users who logged in to more than 3 hosts*
  or *powershell spawned by winword on dc01*. Signalith writes the query, runs it, and
  lists how it read each phrase, so you can see why the query looks the way it does
  and edit it. The built-in translator works offline and knows the data models, CIM
  field names, common Windows and Linux tools, time ranges, counting, top and rare
  values, thresholds and charts, and recognizes names from your asset and identity
  lists. Words it does not understand are listed rather than guessed at.
- **Query builder.** Pick the data, add conditions, choose events, a table or a chart. The query text is written as you click, and typing in the text updates the builder when it can represent the query.
- **Fields sidebar.** Click a field for its top values; click a value to filter on it.
- **Click any result cell** to filter to it, exclude it, count by that field, or chart it over time.
- **Autocomplete** for fields, commands and functions as you type.
- **Explain** turns any query into plain-English steps and shows the OpenSearch request it runs.
- **AI model (optional).** For questions the translator only partly understands, set
  `assistant.provider` and Signalith asks the model instead, or always when you tick
  **Use AI**. Only the question and the field list are sent, never your events, and
  the model's query is checked by the parser before you see it. Point
  `assistant.url` at a local Ollama or LM Studio server to keep everything on site:

  ```yaml
  assistant:
    provider: openai
    url: http://localhost:11434/v1
    model: llama3.1
  ```
- **Starter hunts** on the empty search page cover brute force, new accounts, encoded PowerShell and more.

From the shell: `signalith query "datamodel=Authentication | top user"` or add
`-explain` to see the compiled request, and `signalith ask "failed logins from
203.0.113.9 today"` prints the query for a question. The full reference is in
[docs/query-language.md](docs/query-language.md).

## Architecture

```
Fluent Bit agents ──HTTP──▶ signalith (Go) ──REST──▶ OpenSearch
 (Windows, Linux)            ingest, parse,          events by data model and day
syslog devices ──UDP/TCP──▶  query compiler,
                             web UI and API ◀── analyst browser
```

| Path | What it holds |
| --- | --- |
| `cmd/signalith` | CLI and server entry point, Windows service |
| `internal/query` | Query language lexer, parser, canonical printer, builder model |
| `internal/search` | Compiles queries to OpenSearch DSL and runs remaining commands in memory |
| `internal/ingest` | Fluent Bit record parsing for Windows and Linux, index template |
| `internal/syslog` | Syslog receiver (UDP, TCP, TLS), RFC 5424, RFC 3164 and CEF parsing |
| `internal/datamodel` | Authentication, Endpoint, Network_Traffic, Change, Risk, Other |
| `internal/agents` | Fluent Bit configuration generator |
| `internal/detect` | Detection format, built-in content, scheduler, Sigma converter, ATT&CK catalog |
| `internal/findings` | Findings model and its OpenSearch store |
| `internal/assets` | Asset and identity lists: CSV parsing, matching, priority |
| `internal/risk` | Risk event store |
| `internal/intel` | Threat intel indicators, feed parsing (lines, CSV, STIX, format detection), the feed catalog, TAXII 2.1, guarded downloads and feeds managed on the page |
| `internal/retention` | Retention policies, planner, disk guard, archives and restores |
| `internal/dashboards` | Security posture metrics, custom dashboard files, parallel panel runner |
| `internal/nlq` | Plain-English question to query translator |
| `internal/assistant` | Optional AI model client (Anthropic, OpenAI-compatible) |
| `internal/config` | YAML config, validation, password hashing |
| `internal/auth` | Web UI sign-in sessions and the failed sign-in limit |
| `internal/users` | Roles, local users, Active Directory and LDAP sign-in and its tests |
| `internal/api` | REST API, the role of every route, query explanations |
| `web/static` | Browser UI (plain JavaScript, no build step) |
| `deploy/` | Docker Compose, systemd unit, Windows installer script |

## Building

Requires Go 1.24 or newer.

```sh
go test ./...
go build -o signalith ./cmd/signalith                         # Linux
GOOS=windows GOARCH=amd64 go build -o signalith.exe ./cmd/signalith  # Windows
```

## Roadmap

1. **Search foundation**: agents, parsing, data models, query language, builder, installers.
2. **Detect and triage**: scheduled detections in Sigma or Signalith queries, throttling, a findings queue, ATT&CK coverage.
3. **ES depth**: risk-based alerting, asset and identity context, threat intel feeds, posture dashboards, and plain-English to query.
4. **Respond and scale**: investigation cases, response actions, playbooks, multi-node deployments.

## License

[Apache 2.0](LICENSE). See [NOTICE](NOTICE) for third-party data.

## Trademarks

Signalith is an independent open-source project. It is not affiliated with,
endorsed by or sponsored by Splunk or Cisco, and contains no Splunk code.
Splunk, Splunk Enterprise Security and SPL are trademarks of Splunk LLC; they are
named here only to describe what Signalith works like. OpenSearch, Fluent Bit,
Sigma and MITRE ATT&CK are trademarks of their respective owners.
