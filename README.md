# Signalith

An open-source SIEM for Windows and Linux, modeled on Splunk Enterprise Security.
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
contains the server address and ingest token.

Supported sources in Phase 1:

| Source | Data model |
| --- | --- |
| Windows Security log: 4624, 4625 logons | Authentication |
| Windows Security log: 4688 process creation | Endpoint |
| Windows Security log: 4720, 4726 accounts; 4728, 4732, 4756 group changes | Change |
| Sysmon: event 1 process create, event 3 network connection | Endpoint, Network_Traffic |
| Linux sshd, sudo, su (auth.log, secure, or journald) | Authentication |
| Linux useradd, userdel, usermod, gpasswd | Change |
| Anything else | Other (searchable by text and fields) |

### Sign in

The web UI has its own sign-in page. Sessions end after `auth.session_timeout` without
activity (12 hours by default) or when you sign out; tick **Keep me signed in** to stay
signed in for up to 7 days. Ten wrong passwords from one address within 15 minutes lock
that address out for 15 minutes. Scripts and API clients can keep using HTTP Basic auth
with the same username and password.

## Configuration

Everything lives in one YAML file (`/etc/signalith/signalith.yaml` or
`C:\ProgramData\Signalith\signalith.yaml`). `signalith init` writes a working one, and
`signalith validate` checks it and lists every problem with the setting to fix.
Unknown keys are rejected, so typos do not silently do nothing.

| Setting | Default | Meaning |
| --- | --- | --- |
| `server.listen` | `127.0.0.1:8080` | Address the UI and API bind to |
| `server.public_url` | from `listen` | URL agents use; goes into generated agent configs |
| `server.tls_cert`, `server.tls_key` | none | Serve HTTPS |
| `opensearch.url` | `http://127.0.0.1:9200` | Event store |
| `opensearch.username`, `opensearch.password` | none | OpenSearch credentials |
| `opensearch.index_prefix` | `signalith` | Indices are `<prefix>-<datamodel>-YYYY.MM.DD` |
| `search.default_earliest` | `-24h` | Time range when a query sets none |
| `retention.days` | `90` | Days of events to keep; `0` keeps everything |
| `auth.admin_user`, `auth.admin_password_hash` | `admin` | Sign-in; change with `signalith passwd` |
| `auth.session_timeout` | `12h` | Sign the web UI out after this long without activity ("Keep me signed in" lasts up to 7 days) |
| `ingest.tokens` | one generated | Tokens agents send as `Authorization: Bearer` |
| `detections.dir` | `detections` | Folder for custom and edited detections, relative to the config file |
| `detections.scheduler` | `true` | Run detections on schedule; turn off on extra servers sharing one OpenSearch |
| `detections.max_findings_per_run` | `100` | Cap on findings one run can raise |
| `lookups.dir` | `lookups` | Folder for `assets.csv` and `identities.csv`, relative to the config file |
| `intel.feeds` | none | Threat intel feeds to download; see [Threat intel](#threat-intel). Nothing is fetched unless listed |
| `intel.feeds[].name`, `.url` | required | Feed name (shown as the indicator source) and its http(s) address |
| `intel.feeds[].format` | `lines` | `lines` (one per line, `#` comments), `csv` (with `column:`, a header name or number) or `stix` (STIX 2.1 bundle) |
| `intel.feeds[].type` | `auto` | `auto` detects each value, or `ip`, `cidr`, `domain`, `url`, `hash`, `md5`, `sha1`, `sha256`, `email` |
| `intel.feeds[].interval`, `.max_age` | `1h`, `7d` | How often to download; how long indicators last when downloads keep failing |
| `intel.feeds[].weight` | `1` | Multiplies the risk a match adds (0 to 10) |
| `intel.feeds[].headers`, `.tags`, `.description`, `.enabled` | none, `true` | Request headers (values may use `${ENV_VAR}` for API keys), labels, and on/off |
| `dashboards.dir` | `dashboards` | Folder for custom dashboards, one YAML file each, relative to the config file |
| `dashboards.stale_after` | `2h` | How long a host and source type can be quiet before the posture dashboard lists it as stopped |
| `assistant.provider` | off | Optional AI model for **Ask**: `anthropic`, or `openai` for any OpenAI-compatible API (OpenAI, Ollama, LM Studio, vLLM) |
| `assistant.url`, `assistant.model`, `assistant.api_key` | per provider | Endpoint, model name and key; `anthropic` defaults to `claude-sonnet-5-5` |

Secrets can come from the environment instead: `SIGNALITH_OPENSEARCH_PASSWORD`,
`SIGNALITH_ADMIN_PASSWORD`, `SIGNALITH_INGEST_TOKEN` (also `SIGNALITH_OPENSEARCH_URL`,
`SIGNALITH_LISTEN`, `SIGNALITH_DETECTIONS_DIR`, `SIGNALITH_LOOKUPS_DIR`, `SIGNALITH_DASHBOARDS_DIR`,
`SIGNALITH_ASSISTANT_API_KEY`).

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

- **Feeds** listed under `intel.feeds` in signalith.yaml are downloaded on their
  interval by the server running the detection scheduler. Nothing is fetched until
  you add one. Proxy settings come from `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`.
  An indicator that disappears from a feed is removed at the next download; if a
  feed keeps failing, its indicators expire after `max_age`. Disabling or removing a
  feed removes its indicators.
- **Manual indicators**: add one on the **Threat intel** page or upload a CSV
  (`value,type,description,weight,expires,tags`) or plain list. Every bad line is
  reported and nothing is saved until the file is clean.
- **Matching**: the built-in **Threat intel match** detection (`threat-activity`)
  runs every 5 minutes, raises one finding per indicator and system a day, and adds
  60 risk times the indicator's weight to the system and user involved. In Search,
  `| threatmatch` keeps only matching events and `| intel` adds
  `<field>_intel_source`, `_intel_type`, `_intel_weight` and `_intel_description`
  columns to any result.

Copy-paste examples (free public feeds; check each provider's terms, and some ask for
a free key, which you send with `headers`):

```yaml
intel:
  feeds:
    - name: feodo-tracker          # botnet C2 servers, abuse.ch
      url: https://feodotracker.abuse.ch/downloads/ipblocklist.txt
      weight: 1.5
    - name: urlhaus                # malware download URLs, abuse.ch
      url: https://urlhaus.abuse.ch/downloads/csv_recent/
      format: csv
      column: url
      type: url
    - name: malwarebazaar          # malware SHA-256 hashes, abuse.ch
      url: https://bazaar.abuse.ch/export/txt/sha256/recent/
      type: sha256
    - name: et-compromised         # compromised hosts, Proofpoint Emerging Threats
      url: https://rules.emergingthreats.net/blockrules/compromised-ips.txt
      type: ip
      interval: 12h
```

See [docs/threat-intel.md](docs/threat-intel.md) for formats, STIX, matching details
and the API.
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
                             query compiler,
                             web UI and API ◀── analyst browser
```

| Path | What it holds |
| --- | --- |
| `cmd/signalith` | CLI and server entry point, Windows service |
| `internal/query` | Query language lexer, parser, canonical printer, builder model |
| `internal/search` | Compiles queries to OpenSearch DSL and runs remaining commands in memory |
| `internal/ingest` | Fluent Bit record parsing for Windows and Linux, index template |
| `internal/datamodel` | Authentication, Endpoint, Network_Traffic, Change, Risk, Other |
| `internal/agents` | Fluent Bit configuration generator |
| `internal/detect` | Detection format, built-in content, scheduler, Sigma converter, ATT&CK catalog |
| `internal/findings` | Findings model and its OpenSearch store |
| `internal/assets` | Asset and identity lists: CSV parsing, matching, priority |
| `internal/risk` | Risk event store |
| `internal/intel` | Threat intel indicators, feed parsing (lines, CSV, STIX) and downloads |
| `internal/dashboards` | Security posture metrics, custom dashboard files, parallel panel runner |
| `internal/nlq` | Plain-English question to query translator |
| `internal/assistant` | Optional AI model client (Anthropic, OpenAI-compatible) |
| `internal/config` | YAML config, validation, password hashing |
| `internal/auth` | Web UI sign-in sessions and the failed sign-in limit |
| `internal/api` | REST API, query explanations |
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
