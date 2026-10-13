# Sample data

Sample data fills Signalith with a realistic week of security activity for a
fictional company, with a handful of attacks hidden in it, so you can try the
SIEM on data that makes detections fire, fills the triage queue, builds risk on
users and hosts, matches threat intel and lights up the dashboards. Load it in
one click, look around, and remove it in one click when you are done.

Everything is made up and safe to load on any network:

- the company is fictional and its domain is `corp.example` (a reserved
  documentation name, RFC 6761);
- its own hosts use private `10.x` addresses;
- every external address is from the documentation ranges `192.0.2.0/24`,
  `198.51.100.0/24` and `203.0.113.0/24` (RFC 5737), so no real host is ever
  named or contacted;
- the generator is deterministic and offline — it reads nothing from the
  network or disk.

Every document the sample writes carries a hidden marker holding the load's ID,
so removal deletes exactly the sample data and nothing else. The marker is kept
out of search results and field lists, so it never clutters what you see.

## Load and remove it

**In the browser (admins):** open **Add data** under Collect. The **Try it with
sample data** card loads a week of activity, shows progress, lists things to
try, and removes it again behind a confirm. While it loads, detections run over
the week so findings and risk appear at once.

**From the shell** (or in Docker):

```sh
signalith sample-data load               # a full week (tens of thousands of events)
signalith sample-data load -size small   # a lighter set, quicker to load
signalith sample-data status             # whether it is loaded, and the counts
signalith sample-data remove             # take all of it out

# In Docker:
docker compose -f deploy/docker/docker-compose.yml exec signalith signalith sample-data load
```

Loading twice is refused: remove the set first, then load again. Loading and
removing are logged as admin actions, run in the background, and one at a time.

## What it contains

- **A fictional organisation:** about 50 users and 40 hosts — finance, IT and
  operations workstations, a few Linux servers (web, app, database, jump host),
  two domain controllers and a file server.
- **A week of background activity** with a working-hours and weekday rhythm:
  sign-ins, process starts, network connections, firewall traffic and DNS
  lookups — ordinary noise for the attacks to hide in, plus a couple of benign
  look-alikes to practise closing as false positives.
- **An OT flavour:** an engineering workstation, two HMIs and three PLCs, with
  the HMIs polling the PLCs over Modbus (TCP 502) and writing to a historian.
  It is all normal; no detection targets OT, it just shows the plant floor in
  the data.
- **Context and intel:** sample assets and identities (with priorities,
  categories and a watchlist entry) merged into your lists without touching your
  own, and a few sample threat-intel indicators (a C2 address, a beaconing
  address, a credential-dumping tool hash and two look-alike domains).
- **A sample investigation** grouping the most serious findings, so you have a
  case to open and practise on.

Two sizes load the same attacks; only the volume of background activity differs.
Use **small** for a quick look or a slower machine, **standard** for a full week.

## A guided tour of the attacks

Five stories are woven into the week. Four are real intrusions designed so that
every built-in detection that can fire does; the fifth is benign activity that
trips detections as false positives.

| Story | What happens | Detections it fires |
| --- | --- | --- |
| **SSH brute force from the internet** | An external host (`203.0.113.45`) password-sprays SSH on the database server `db-01`, breaks the account `bob.okafor`, logs in as root and reads `/etc/shadow`. | auth-brute-force, auth-password-spray, auth-brute-force-success, auth-ssh-root-login, auth-sudo-failures, auth-shadow-file-access, threat-activity |
| **Phishing to credential theft and C2** | A finance workstation (`ws-fin-07`, Alice Nguyen) opens a malicious invoice that launches encoded PowerShell, downloads a tool with `certutil`, dumps credentials with Mimikatz, runs discovery, installs persistence and beacons to a C2 that is in the sample intel. | endpoint-office-child-shell, endpoint-encoded-powershell, endpoint-lolbin-download, endpoint-credential-dumping, endpoint-discovery-burst, endpoint-scheduled-task, endpoint-service-created, network-shell-port, threat-activity |
| **Hidden admin account on the domain controller** | On `dc-01` the attacker creates `svc-helpdesk` and adds it to Domain Admins, then deletes a stale contractor account. | change-account-created, change-admin-group-add |
| **Ransomware preparation on the file server** | Using the stolen domain-admin account, the attacker reaches `file-01` over SMB and deletes the volume shadow copies and recovery configuration. | endpoint-shadow-copy-delete |
| **Benign activity that looks malicious** | IT fetching a tool with `certutil`, and a backup job using encoded PowerShell — false positives to close as benign. | endpoint-lolbin-download, endpoint-encoded-powershell (as false positives) |

As those detections fire, several of them add **risk** to the users and hosts
involved. That accumulated risk then raises two more findings on its own:

- **risk-threshold-exceeded** — a user or host passed the risk threshold;
- **risk-multiple-tactics** — risk from several ATT&CK tactics on one entity.

So 20 of the 22 built-in detections fire from the sample.

### Detections that do not fire

Two built-in detections are **off by default**, so they do not fire — but the
sample includes data that would fire them the moment you turn them on, on the
**Detections** page:

- **change-account-deleted** — the contractor account the domain-persistence
  story deletes would fire it.
- **network-remote-admin-port** — the SMB connection the ransomware story makes
  from the workstation to the file server (port 445) would fire it. It is off by
  default because it needs tuning for your own admin tools.

Everything else fires at least once.

## How removal works

Removal deletes exactly what the load wrote, by the hidden marker, and leaves
everything else alone:

- the sample **events**, across every data model, by the marker;
- the sample **risk events**;
- the **findings** the backfill raised (marked), plus the risk-threshold and
  risk-multiple-tactics findings the live scheduler may have raised from sample
  entities while the sample was loaded (matched by entity and time range, so
  your own findings are untouched);
- the sample **investigation**; and, for any case of your own that holds a
  sample finding, the sample finding is unlinked, and the case is deleted only
  if it held nothing else;
- the sample **threat intel** (source `sample`);
- the sample **asset and identity** entries (tagged with the `Sample data`
  business unit); your own entries with the same keys were never overwritten and
  are kept.

Your own data, detections, intel feeds and lists are never changed. After
removal the server is back exactly as it was.

## Notes

- The sample stays out of **source health** on the dashboards, because it is
  loaded and removed all at once and would otherwise show as a source that goes
  stale the moment you remove it.
- The `sample` name is reserved: you cannot create a threat-intel feed called
  `sample`, and the feed sync never removes sample indicators.
- All events fall within the last six days, ending a few minutes before you
  load, so they sit inside the default seven-day maximum event age. If your
  server keeps events for fewer days, the oldest background may be dropped; the
  attacks (the last four days) still land.
- In a cluster, the bookkeeping file that records what is loaded lives on the
  server you load from, so load, check status and remove from the same server.
  The data itself is in OpenSearch and visible everywhere.
