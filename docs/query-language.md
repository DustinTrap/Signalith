# Signalith query language

A query is a **search** followed by zero or more **commands**, each after a `|`.
The search selects events; commands reshape the results. It reads like Splunk's SPL,
but it is Signalith's own language and does not claim SPL compatibility.

```
datamodel=Authentication action=failure earliest=-24h
| stats count, dc(user) as users by src
| where count > 20
| sort -count
| head 10
```

## Search

| Syntax | Meaning |
| --- | --- |
| `datamodel=Authentication` | Events of one data model: Authentication, Endpoint, Network_Traffic, Change, Other |
| `index=custom-*` | Search a different OpenSearch index pattern |
| `field=value` | Exact match, case-insensitive |
| `field=val*` | Wildcard match with `*` and `?` |
| `field=*` | The field has any value |
| `field!=value` | Does not match |
| `field>10`, `>=`, `<`, `<=` | Numeric (or text) comparison |
| `field IN (a, b, c)` | Any of several values |
| `word` or `"a phrase"` | Text anywhere in the raw event (`_raw`) |
| `NOT term`, `( ... )` | Negation and grouping |
| `a OR b` | Either. As in SPL, OR binds tighter than the implicit AND, so `x a OR b` means `x AND (a OR b)` |
| `earliest=-7d@d latest=now` | Time range; overrides the UI time picker |

Relative times: `-30s`, `-15m`, `-4h`, `-7d`, `-2w`, `-1mon`, `-1y`, optionally snapped
with `@d`, `@h`, `@w`. Absolute times are ISO 8601 (`2026-10-01T00:00:00Z`).

Quote values that contain spaces or symbols: `process_path="C:\Windows\System32\cmd.exe"`.
Inside quotes, `\"` is a quote and `\\` is one backslash; any other backslash is
kept as typed, so Windows paths work without doubling.

## Commands

| Command | Example | Notes |
| --- | --- | --- |
| `stats` | `stats count, dc(user) as users, avg(bytes) by src, dest` | Functions: `count`, `count(f)`, `dc(f)`, `sum(f)`, `avg(f)`, `min(f)`, `max(f)` |
| `timechart` | `timechart span=1h count by action` | One aggregation when splitting by a field; span picked automatically if omitted |
| `top` | `top limit=10 process_name by host` | Adds `count` and `percent` |
| `where` | `where count > 20 AND users >= 2` | AND binds tighter than OR here, as in most languages |
| `sort` | `sort -count, src` | `-` for descending |
| `head` | `head 20` | Also `limit` |
| `table` | `table _time, user, src` | Also `fields`; wildcards allowed |
| `rename` | `rename src as source_ip` | |

Columns produced by `stats` are referenced by name in later commands, for example
`sort -dc(user)` or `where avg(bytes) > 1000`.

## How queries run

- The search and any `where` commands that come before the first `stats`, `timechart`
  or `top` run inside OpenSearch, so they scale with the cluster.
- `stats` and `top` use composite aggregations and page through every group (up to
  50,000 groups, then results are marked truncated).
- Commands after that run in the Signalith server on the aggregated rows.
- An event search without `stats` returns the newest 100 events, or up to
  `search.max_events` when later commands need to sort or filter them all.

Use **Explain** in the UI, or `signalith query -explain "<query>"`, to see the plain-English
steps and the exact OpenSearch request.
