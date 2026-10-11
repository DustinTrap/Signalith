# Detections

A detection is a Signalith query that runs on a schedule. Every row the query
returns becomes a finding, unless the throttle says the same thing was already
raised recently.

## Where detections live

- **Built-in detections** ship inside the binary (`internal/detect/builtin`).
- **Custom and edited detections** are YAML files in `detections.dir`
  (default: a `detections` folder next to the config file; `/var/lib/signalith/detections`
  for the systemd unit and Docker image). One file per detection, named `<id>.yaml`.
- A file whose `id` matches a built-in **overrides** it. Delete the file, or click
  **Revert to built-in**, to go back.

You can edit detections in the UI or drop YAML files into the folder and restart.
`signalith validate` checks every file and reports problems with the field to fix;
a broken file is skipped at startup and logged, so it never stops the server.

## Format

```yaml
id: auth-brute-force                    # 3-64 lowercase letters, digits, - or _
title: Brute force against $dest$ from $src$   # $field$ is filled from the result row
description: One source failed to log on to a system many times.
query: |
  datamodel=Authentication action=failure
  | stats count, dc(user) as users by src, dest
  | where count >= 10
schedule: 5m          # how often it runs: s, m, h, d or w
lookback: 15m         # how far back each run searches
severity: medium      # informational, low, medium, high, critical
mitre: [T1110]        # ATT&CK technique or sub-technique IDs
throttle:
  fields: [src, dest] # one finding per distinct src and dest...
  window: 1h          # ...per hour
enabled: true
tags: [authentication]
guidance: Check whether the source is internal and whether any attempt succeeded.
```

Rules of thumb:

- Do not put `earliest=` or `latest=` in the query; `lookback` sets the window.
- Make `lookback` at least as long as `schedule`, or events between runs are missed.
  A little overlap is fine; throttling keeps overlapping runs from raising duplicates.
- Without `throttle.fields`, the whole result row is the throttle key.
- Use `stats ... by` to raise one finding per entity instead of one per event.

## What a finding contains

The result row, the entities found in it (`user`, `src_user`, `src`, `src_host`,
`dest`, `dest_host`, `host`, `process_name`, `object`, `member`), the detection's
severity and ATT&CK techniques, and a drilldown search. For `stats` and `top`
detections the drilldown is the detection's filter plus the row's group-by values,
so **View contributing events** shows exactly the events behind that row.

Findings move through `new`, `in_progress`, `pending`, `resolved` and `closed`, with
an owner, a disposition (`true_positive`, `benign_true_positive`, `false_positive`,
`undetermined`), comments, and a history of every change. They are stored in the
OpenSearch index `<index_prefix>_findings`, which event searches never include.

## Sigma rules

**Import Sigma rule** on the Detections page (or `POST /api/detections/sigma`)
converts a rule and shows the result for review. Supported:

- Log sources `process_creation` (Endpoint), `network_connection` and `firewall`
  (Network_Traffic), `authentication` and Linux `auth` (Authentication). Other log
  sources search all data and say so.
- Sysmon and Windows Security field names, mapped to Signalith fields (`Image` to
  `process_path`, or `process_name` for `endswith` a file name; `CommandLine` to
  `process`; `TargetUserName` to `user`; `IpAddress` to `src`; and so on). Unmapped
  fields are searched as-is and listed as warnings.
- Modifiers `contains`, `startswith`, `endswith`, `all`, `windash`, `exists`; lists,
  `null`, keyword lists; conditions with `and`, `or`, `not`, parentheses,
  `1 of`, `all of`, `them` and `selection_*` patterns.

Not supported, and reported as an error: `re`, `base64`, `base64offset`, `cidr` and
other modifiers, aggregation conditions (`| count() > 10`), and escaped wildcards.

Imported rules start disabled with a 5 minute schedule and 10 minute lookback.

## API

| Method and path | Purpose |
| --- | --- |
| `GET /api/detections` | All detections with last-run state |
| `POST /api/detections` | Create (400 lists every problem) |
| `GET`, `PUT`, `DELETE /api/detections/{id}` | Read, save, delete or revert |
| `GET /api/detections/{id}/yaml` | Export as YAML |
| `POST /api/detections/test` | Run an unsaved detection; returns rows and titles, raises nothing |
| `POST /api/detections/{id}/run` | Run now and raise findings |
| `POST /api/detections/sigma` | Convert a Sigma rule (YAML body, or JSON `{"rule": "..."}`) |
| `GET /api/coverage` | ATT&CK matrix with coverage |
| `GET /api/findings?status=&severity=&owner=&detection=&q=&since=7d&limit=` | Queue |
| `GET`, `PATCH /api/findings/{id}` | Read; update status, owner, severity, disposition, comment |
| `POST /api/findings/bulk` | `{"ids": [...], "update": {...}}` |
| `POST /api/findings` | Raise a finding by hand |
| `GET /api/findings/summary` | Open counts by status and severity |
