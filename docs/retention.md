# Data retention

Signalith keeps events in daily OpenSearch indices, one per data category and day
(`<prefix>-endpoint-2026.10.12`). Retention policies decide, for each category:

- how many days it stays searchable,
- how large it may grow,
- when old days are compacted to save space,
- whether days are archived to files before they are deleted.

Findings and investigations have their own policy. A **disk guard** keeps
OpenSearch from filling its disk.

Set everything on the **Data retention** page under Configure (admins only): select a
category to change its policy, or edit the default policy and the disk guard under
**Defaults**. The dialog shows what saving would delete, archive or compact before you
save, and asks again before anything is deleted. Changes apply at once: saving starts
a retention run, with no restart. The same settings can be written in
`signalith.yaml` instead (see [Settings in signalith.yaml](#settings-in-signalithyaml)).

## Categories

| Category | ID | Stored in | Policy |
| --- | --- | --- | --- |
| Authentication | `authentication` | `<prefix>-authentication-YYYY.MM.DD` | Event policy |
| Endpoint | `endpoint` | `<prefix>-endpoint-YYYY.MM.DD` | Event policy |
| Network traffic | `network_traffic` | `<prefix>-network_traffic-YYYY.MM.DD` | Event policy |
| Change | `change` | `<prefix>-change-YYYY.MM.DD` | Event policy |
| Other events | `other` | `<prefix>-other-YYYY.MM.DD` | Event policy; listed once it has data or a policy |
| Risk events | `risk` | `<prefix>-risk-YYYY.MM.DD` | Event policy |
| Findings | `findings` | `<prefix>_findings` | Delete closed findings after N days |
| Investigations | `cases` | `<prefix>_cases` | Delete closed cases after N days |
| Threat intel | `intel` | `<prefix>_intel` | Managed by feeds: indicators expire through each feed's `max_age` |

Days are UTC days, the same days the index names use.

## Event policies

| Setting | Meaning |
| --- | --- |
| **Keep** (`keep_days`) | Days a category stays searchable. `0` keeps it forever. A day is deleted once it is more than `keep_days` days old, so `90` keeps today and the 90 days before it |
| **Size cap** (`max_size_gb`) | Largest the category may be, in GB (1 GB = 2^30 bytes) of disk, replicas included. Over the cap, its oldest days are deleted until it fits. `0` means no cap |
| **Compact after** (`compact_after_days`) | Days after which a day is made read-only and force-merged to one segment. `0` never compacts. Must be less than `keep_days` |
| **Archive before deleting** (`archive`) | Write each day to a compressed file before deleting it, so it can be restored later |

A category without its own policy uses the **default policy**. Until you save a
default on the page, the default is `retention.days` from signalith.yaml (90 days,
nothing else), which is exactly how retention worked before policies existed.

**Compaction** makes old days smaller and cheaper to search: fewer segments,
deleted documents purged, and less memory for OpenSearch. Today and yesterday are
never compacted. A compacted day is read-only. If an agent sends events for that
day later, OpenSearch rejects them and the server logs "some events were
rejected". So set **Compact after** above the longest time your agents can be
offline. For laptops that may be away for a week, use 14 or more.

**Size caps** are checked after `keep_days`. They never delete today's data or a
restored day. If only those are left and the category is still over its cap, the
page says so.

## Findings and investigations

The policy for **Findings** and **Investigations** has one setting, `keep_days`. It
is off by default, which keeps them forever. When it is set, retention deletes only
the ones that are **resolved or closed** and have not changed for more than
`keep_days` days. New, in-progress and pending items are never deleted, whatever
their age.

Findings that belong to an open investigation are kept too, so an open case never loses
its findings. A case keeps its own notes, search snapshots and pinned events, so it
outlives the event days it came from. If the open cases cannot be listed, no
findings are deleted in that run.

## The disk guard

OpenSearch protects itself when a data disk fills up. At 85% (the low watermark) it
stops placing new replica shards on the node. At 90% (the high watermark) it moves
shards away from the node. At 95% (the flood stage) it makes every index with a
shard on that node read-only, and ingest stops until space is freed. The page counts
the indices OpenSearch has blocked this way.

The disk guard acts first. When the fullest OpenSearch data disk is above
**Max disk use** (default 85%), it deletes the oldest event days, in any category,
until the disk is back under the limit:

- It counts what the policies already delete before deleting more.
- It never deletes the last **Min days** days (default 7), today, or restored days.
- It never touches findings, cases or threat intel.
- A category set to archive is archived first, as usual.

Disk use is `(total - available) / total`, the same formula OpenSearch's watermarks
use. So space used by other files on the same disk counts too.

If OpenSearch has already reached the flood stage, the guard still frees space.
Blocked indices can still be read and deleted, so they are archived (when the policy
says so) and deleted as usual. Compaction waits until OpenSearch lifts the block,
which it does by itself once disk use falls below the high watermark.

The guard is **on by default**, including on servers upgraded from an earlier
version. A server whose OpenSearch disk is already above 85% deletes its oldest days
(older than 7 days) at the first run after the upgrade. To prevent this, turn the
guard off or raise its limit (up to 94%) before upgrading, by setting `retention.guard`
in signalith.yaml.

The guard runs with every retention run. Between runs it also checks the disk every
5 minutes and starts a run when the disk passes the limit. If the guard has deleted
everything it may and the disk is still over the limit, the page says so. In that
case, add disk space, lower **Min days** or the policies' **Keep**, or look for other
data on the same disk. The guard then waits for the next scheduled run instead of
checking every 5 minutes.

## Archives

With **Archive before deleting** on, each day is archived and checked before its
index is deleted:

1. The index is made read-only, so the copy is complete.
2. Every event is written to `<index>.ndjson.gz`, one `{"_id": ..., "_source": ...}`
   per line, then flushed to disk with fsync.
3. A manifest `<index>.json` is written beside it, with the event count, file size,
   SHA-256 and creation time.
4. The file is read back and checked against the manifest. Its event count must also
   match the index's count.
5. Only then is the index deleted.

If anything fails (a full archive disk, a count that does not match, an OpenSearch
error), the index is kept and the error is listed in the run's history. The next run
tries again. Put the archive folder on a different disk from OpenSearch's data, so
that one full disk cannot stop both archiving and the disk guard.

Files are written with mode 0600 in a folder with mode 0700. If the same day is
archived again, the new copy gets its own ID, such as
`signalith-endpoint-2026.07.01.2`. This happens when late events recreate a deleted
day. A day that is already fully archived, such as a restored one, is not archived
twice.

The archive folder is `retention.archive_dir`, `SIGNALITH_ARCHIVE_DIR`, or an
`archive` folder next to `lookups.dir`. Docker images use
`/var/lib/signalith/archive`; mount a volume there to keep archives outside the
container. Archives are plain gzip and JSON, so `zcat file.ndjson.gz | head` works
and any tool can read them. Move older files to cheaper storage as you like:
retention never deletes archive files.

Example manifest:

```json
{
  "format": "signalith-archive/1",
  "id": "signalith-endpoint-2026.07.01",
  "index": "signalith-endpoint-2026.07.01",
  "category": "endpoint",
  "day": "2026-07-01",
  "docs": 1840221,
  "file": "signalith-endpoint-2026.07.01.ndjson.gz",
  "bytes": 211630580,
  "index_bytes": 1073741824,
  "sha256": "ace69f8245...",
  "created": "2026-10-04T03:00:12Z"
}
```

### Restoring

On the page, open **Archive**, select days and choose **Restore**. You can also
use the CLI on the server:

```sh
signalith archive list
signalith archive verify signalith-endpoint-2026.07.01
signalith archive restore -keep-days 30 signalith-endpoint-2026.07.01
```

A restore works like this:

- It checks the whole file against its manifest first, so a damaged file restores
  nothing.
- It writes the events back into their original index, so ordinary searches over
  that day find them again.
- Each event keeps its original ID, so restoring the same day twice does not
  duplicate anything. An interrupted restore can be run again to finish.
- A restored day stays searchable for the days you choose (14 by default, up to
  365). Retention, the size cap and the disk guard leave it alone until then. After
  that, the category's policy applies again and the day is deleted without being
  archived a second time.

Restores from the page run in the background, one at a time, and never during a
retention run.

## Compliance examples

**Keep 90 days searchable and 1 year archived.** Set the default policy to keep 90
days and turn **Archive before deleting** on. Each day is archived when it turns 91
days old. Signalith never deletes archive files. To keep a year in all, delete each
day's files once the day is a year old. That is about 275 days after the file was
written:

```sh
find /var/lib/signalith/archive -type f -mtime +275 -delete
```

Each manifest records the day it holds (`day`). Use it instead of file times if
your policy must be exact to the day.

**Keep authentication events for a year, everything else for 30 days.** Set the
default to 30 days and give **Authentication** its own policy of 365 days.

**Keep endpoint data under 500 GB.** Give **Endpoint** a 500 GB size cap. Add
`keep_days` as well if you also need a time limit.

**Keep closed investigations for 3 years.** Give **Investigations** a policy of 1095
days. Open cases are never deleted.

## Runs and history

Retention runs every hour (`retention.interval`) on the server that runs the
detection scheduler. It also runs when settings are saved, when **Run now** is
pressed, and when the disk guard trips. The first scheduled run is 2 minutes after
the server starts.

Each run plans first and then acts. The preview in the page's dialogs uses the same
planner, so what it shows is what the next run does. Deletions run oldest day first,
then compactions.

Retention only touches indices named `<prefix>-<category>-YYYY.MM.DD` with a known
category and a valid date, plus the findings and cases indices. Anything else under
the prefix is listed as unmanaged and left alone. Today's and future-dated days are
never deleted, and today and yesterday are never compacted. Only one run or restore
happens at a time.

The page keeps the last 200 actions (what was deleted, archived or compacted, why,
how much space it freed, and who made the change behind it), plus the last run's
totals and errors. Every action is also logged by the server.

## Settings in signalith.yaml

The page saves its settings in `retention.yaml` in the `lookups.dir` folder (mode
0600). Run history goes in `retention_history.json` beside it. You can edit
`retention.yaml` by hand. The server notices the change at the next run. If the
file has a mistake, runs pause and the page shows the error until it is fixed.

Anything set under `retention` in signalith.yaml wins over the page and is shown
there as "From signalith.yaml", read-only. Use this for settings that must not be
changed from the UI:

```yaml
retention:
  days: 90                 # default keep_days until a default is set (0 = forever)
  interval: 1h             # how often to enforce, 5m to 24h
  archive_dir: /srv/signalith-archive
  default:                 # replaces days; the page can no longer change the default
    keep_days: 90
    archive: true
  policies:
    authentication:
      keep_days: 365
      compact_after_days: 7
    endpoint:
      keep_days: 30
      max_size_gb: 500
    findings:
      keep_days: 365       # resolved or closed findings
    cases:
      keep_days: 1095      # resolved or closed investigations
  guard:
    enabled: true
    max_disk_percent: 85   # 50 to 94
    min_days: 7
```

| Key | Default | Meaning |
| --- | --- | --- |
| `retention.days` | `90` | Default `keep_days` for event categories without a policy, until a default is saved on the page |
| `retention.interval` | `1h` | How often policies are enforced (5m to 24h) |
| `retention.archive_dir` | `archive` next to `lookups.dir` | Archive folder; relative paths are relative to signalith.yaml. `SIGNALITH_ARCHIVE_DIR` overrides it |
| `retention.default` | none | Default event policy: `keep_days`, `max_size_gb`, `compact_after_days`, `archive` |
| `retention.policies.<id>` | none | Policy for one category (IDs above). Findings and cases accept only `keep_days` |
| `retention.guard.enabled` | `true` | Disk guard on or off |
| `retention.guard.max_disk_percent` | `85` | Disk use the guard keeps OpenSearch under (50 to 94) |
| `retention.guard.min_days` | `7` | Days before today the guard never deletes |

`signalith validate` checks all of these and names each problem.

## More than one server

When several Signalith servers share one OpenSearch, only the one with
`detections.scheduler: true` runs retention on a schedule. Make retention changes on
that server. Each server keeps page settings in its own `lookups.dir`, and saving
settings or pressing **Run now** runs retention on the server where you did it,
with that server's settings and archive folder. Runs on different servers are not
coordinated. To pin the same policies everywhere, put them in signalith.yaml on
every server. On the other servers, the page reports that retention does not run on
a schedule there.

Archives are written on the server that runs retention, in its archive folder.
Restore from that server, or first copy the files into another server's archive
folder.

On a cluster with several data nodes, the guard follows the fullest data disk.
Deleting a day frees space on every node that held part of it, so the guard may
take a few passes, 5 minutes apart, to get under the limit.

## API

All routes need an admin. Request bodies reject unknown fields, so a typo is an
error rather than a setting that does nothing.

| Method and path | Body | Response |
| --- | --- | --- |
| `GET /api/retention` | | Categories with sizes, days and policies; the default; the guard and disk; the archive; the schedule; pending actions; the last run and recent actions |
| `PUT /api/retention/policies/{id}` | `{"keep_days":30,"max_size_gb":0,"compact_after_days":7,"archive":true}` | `{"category","policy","source":"ui","run_started"}` |
| `DELETE /api/retention/policies/{id}` | | Back to the default: `{"category","policy","source","run_started"}` |
| `PUT /api/retention/default` | A policy | `{"policy","source":"ui","run_started"}` |
| `PUT /api/retention/guard` | `{"enabled":true,"max_disk_percent":85,"min_days":7}` | The guard plus `source` and `run_started` |
| `POST /api/retention/preview` | `{"category":"endpoint","policy":{...}}`, `{"category":"endpoint","policy":null}`, `{"default":{...}}` or `{"guard":{...}}` | What the change would do beyond the current settings: `summary`, `steps`, `records`, `deletes_data`, `guard`, `notes` |
| `POST /api/retention/run` | | `202 {"started":true}`; `409` while a run or restore is going |
| `GET /api/retention/archive` | | Archived days, with whether each is searchable and its latest restore |
| `POST /api/retention/archive/restore` | `{"ids":["signalith-endpoint-2026.07.01"],"keep_days":14}` | `202 {"restores":[...]}` with each restore's state |

Errors:

- An invalid setting returns `400` with `error`, `problems` and `fields` (the
  settings at fault).
- A setting that comes from signalith.yaml returns `409`.
- An unknown category or archive ID returns `404`.
