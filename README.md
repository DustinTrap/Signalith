# Signalith

An open-source SIEM for Windows and Linux, modeled on Splunk Enterprise Security.
Signalith stores events in [OpenSearch](https://opensearch.org), collects them with
[Fluent Bit](https://fluentbit.io), and adds the security layer on top: a pipe-based
query language that reads like SPL, a visual query builder, CIM-style data models,
scheduled detections with a findings queue for triage, Sigma rule import, a
MITRE ATT&CK coverage map, and risk-based alerting with asset and identity context.
Threat intel and investigations come in later phases.

The server is a single Go binary with the web UI embedded. It runs as a Windows
service or a systemd unit.

> Status: Phase 3 (risk and context), in progress. See the [roadmap](#roadmap).

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
| `ingest.tokens` | one generated | Tokens agents send as `Authorization: Bearer` |
| `detections.dir` | `detections` | Folder for custom and edited detections, relative to the config file |
| `detections.scheduler` | `true` | Run detections on schedule; turn off on extra servers sharing one OpenSearch |
| `detections.max_findings_per_run` | `100` | Cap on findings one run can raise |
| `lookups.dir` | `lookups` | Folder for `assets.csv` and `identities.csv`, relative to the config file |

Secrets can come from the environment instead: `SIGNALITH_OPENSEARCH_PASSWORD`,
`SIGNALITH_ADMIN_PASSWORD`, `SIGNALITH_INGEST_TOKEN` (also `SIGNALITH_OPENSEARCH_URL`,
`SIGNALITH_LISTEN`, `SIGNALITH_DETECTIONS_DIR`, `SIGNALITH_LOOKUPS_DIR`).

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

## Writing queries

```
datamodel=Authentication action=failure earliest=-24h
| stats count, dc(user) as users by src
| where count > 20
| sort -count
```

Ways to build one without memorizing syntax:

- **Query builder.** Pick the data, add conditions, choose events, a table or a chart. The query text is written as you click, and typing in the text updates the builder when it can represent the query.
- **Fields sidebar.** Click a field for its top values; click a value to filter on it.
- **Click any result cell** to filter to it, exclude it, count by that field, or chart it over time.
- **Autocomplete** for fields, commands and functions as you type.
- **Explain** turns any query into plain-English steps and shows the OpenSearch request it runs.
- **Starter hunts** on the empty search page cover brute force, new accounts, encoded PowerShell and more.

From the shell: `signalith query "datamodel=Authentication | top user"` or add
`-explain` to see the compiled request. The full reference is in
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
| `internal/config` | YAML config, validation, password hashing |
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
3. **ES depth** (in progress): risk-based alerting and asset and identity context are in; threat intel feeds, posture dashboards and plain-English to query are next.
4. **Respond and scale**: investigation cases, response actions, playbooks, multi-node deployments.

## License

[Apache 2.0](LICENSE). See [NOTICE](NOTICE) for third-party data.
