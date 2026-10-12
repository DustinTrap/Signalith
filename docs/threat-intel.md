# Threat intel

Signalith matches events against threat intel **indicators**, like the Splunk ES
threat intelligence framework. Indicators come from feeds that the server downloads,
from indicators you add by hand, and from uploaded lists.

## Indicators

| Type | Example | Matched against |
| --- | --- | --- |
| `ip` | `203.0.113.9` | `src`, `dest`, `src_ip`, `dest_ip` |
| `cidr` | `198.51.100.0/24` | The same fields, for any address in the network |
| `domain` | `evil.example` | `dest`, `dest_host`, `domain`, `query`, `url_domain`, and the host of `url` (with `| intel`) |
| `url` | `http://evil.example/a.exe` | `url` |
| `md5`, `sha1`, `sha256` | `d41d8cd9...` | `process_md5`, `process_sha1`, `process_sha256`, `process_hash`, `file_hash`, `hash`, `md5`, `sha1`, `sha256` |
| `email` | `ceo@spoofed.example` | `sender`, `recipient`, `src_user`, `user` |

Each indicator has a source (the feed name, or `manual`), description, weight,
tags, first and last seen times, and an optional expiry. The same value from two
feeds is two indicators, and a match lists every source.

Values are normalized: IPs and hashes are lower-cased and canonical, domains and
email addresses lower-cased, URL schemes and hosts lower-cased. Defanged values
such as `hxxp://evil[.]example` are accepted. Domain matches are exact, so
`evil.example` does not match `www.evil.example`; list both if you need both.

Sysmon process events get `process_md5`, `process_sha1` and `process_sha256` (lower
case) split out of `Hashes` at ingest, so hashes match exactly. Events ingested
before this version have only `process_hash`; `| intel` still reads it.

**Weight** multiplies the risk a match adds: 1 is normal, 2 doubles it, 0.5 halves
it, up to 10.

## Feeds

Feeds go in signalith.yaml. Nothing is downloaded unless a feed is listed.

```yaml
intel:
  feeds:
    - name: feodo-tracker
      url: https://feodotracker.abuse.ch/downloads/ipblocklist.txt
      tags: [botnet, c2]
      weight: 1.5
```

| Key | Default | Meaning |
| --- | --- | --- |
| `name` | required | 2-64 lowercase letters, digits, `-`, `_` or `.`; shown as the source. `manual` is reserved |
| `url` | required | http(s) address |
| `format` | `lines` | `lines`, `csv` or `stix` |
| `type` | `auto` | `auto`, `ip`, `cidr`, `domain`, `url`, `hash`, `md5`, `sha1`, `sha256` or `email`. Values of other types are skipped and counted |
| `column` | none | For `csv`: a header name or a column number starting at 1 |
| `interval` | `1h` | How often to download, at least `5m` |
| `max_age` | `7d` | How long indicators last if downloads keep failing |
| `weight` | `1` | Risk multiplier for matches |
| `description`, `tags` | none | Added to every indicator from the feed |
| `headers` | none | Sent with the download. Values may use `${ENV_VAR}`, so API keys stay out of the file |
| `enabled` | `true` | `false` stops the feed and removes its indicators |

### Formats

- **lines**: one indicator per line. Lines starting with `#`, `;` or `//` are
  comments. The first word is the indicator, so `1.2.3.0/24 ; SBL123` and
  `1.2.3.4 # note` work, and hosts files (`0.0.0.0 evil.example`) use the second word.
- **csv**: `column` picks the value, by number or header name. The header can be the
  first row, or the last `#` comment line before the data, which is how abuse.ch
  publishes its CSV files.
- **stix**: a STIX 2.1 bundle (`{"type": "bundle", "objects": [...]}`), a TAXII 2.1
  envelope (`{"objects": [...]}`) or an array of objects. Each `indicator` with a STIX
  pattern contributes every comparison it contains, such as
  `[ipv4-addr:value = '203.0.113.9']`, `[domain-name:value = '...']`,
  `[url:value = '...']`, `[file:hashes.'SHA-256' = '...']` and
  `[email-addr:value = '...']`. The indicator's name and description become the
  description, `indicator_types` and `labels` become tags, and `valid_until` becomes
  the expiry. Revoked and expired indicators and other pattern languages are skipped.

### Schedule and aging

The server with `detections.scheduler: true` downloads each enabled feed when it
starts (unless it downloaded it within the interval, which survives restarts in
`lookups.dir/intel_feeds.json`) and then every `interval`. Each download replaces the
feed's indicators: new ones are added, existing ones get a new last-seen time, and
ones no longer listed are removed. A failed download, or one with no valid
indicators, keeps the previous indicators and is retried within 15 minutes; if it
keeps failing, indicators expire `max_age` after the last good download. Expired
indicators stop matching at once and are deleted hourly.

Downloads honor `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`, are limited to 256 MB
and 2 million indicators, and time out after 5 minutes. The Threat intel page shows
each feed's last download, count, changes, skipped lines and last error, with
**Refresh now**.

### Free feeds

Copy what you need; check each provider's terms of use. Some providers ask for a
free API key; send it with `headers`.

```yaml
intel:
  feeds:
    # Botnet command-and-control servers
    - name: feodo-tracker
      url: https://feodotracker.abuse.ch/downloads/ipblocklist.txt
      weight: 1.5
    # Malware download URLs from the last 30 days
    - name: urlhaus
      url: https://urlhaus.abuse.ch/downloads/csv_recent/
      format: csv
      column: url
      type: url
    # Recent malware file hashes
    - name: malwarebazaar
      url: https://bazaar.abuse.ch/export/txt/sha256/recent/
      type: sha256
    # Compromised hosts
    - name: et-compromised
      url: https://rules.emergingthreats.net/blockrules/compromised-ips.txt
      type: ip
      interval: 12h
    # Your own platform (MISP, OpenCTI) exporting STIX 2.1
    - name: our-cti
      url: https://cti.example.com/export/signalith.json
      format: stix
      headers: {Authorization: "Bearer ${CTI_API_KEY}"}
```

## Manual indicators and uploads

Add one indicator on the Threat intel page, or upload a file:

```csv
value,type,description,weight,expires,tags
203.0.113.9,,Scanner seen in incident 42,2,30d,scanner|ssh
login-bank.example,domain,Phishing site,,2026-12-31,phishing
```

Only `value` is required; `type` is detected when empty. `expires` is a date, an
RFC 3339 time or a duration such as `30d`. A plain list with one value per line also
works. Every bad line is reported and nothing is saved unless the whole file is
valid. Uploads add to the manual indicators (a value already present is updated).
Delete manual indicators on the page; feed indicators come back with the next
download, so disable the feed instead.

## Matching

### The threat intel match detection

`threat-activity` is built in and enabled. Every 5 minutes it runs

```
* | threatmatch
| head 1000
```

over the last 10 minutes and raises one finding per indicator and target system per
24 hours, titled for example *Threat intel match on src 203.0.113.9 (feodo-tracker)*.
The finding's result has the matched field and value, the indicator, its sources,
weight and description. Risk is 60 times the indicator's weight, added to
`threat_target` (system) and `user`. It does nothing until there are indicators.
Matching is forward-looking; to check older events, search with a longer time range.

### threatmatch

`| threatmatch [fields]` keeps only events where a field equals an active indicator.
It runs inside OpenSearch: the server sends the indicator values as `terms` filters
(10,000 values per clause, upper- and lower-case for hashes) and IPv4 networks as
prefix filters, so events are never streamed through Signalith. It must come right
after the search. Up to about 800 network clauses are used (a /24 or /16 is one;
a /20 is 16); networks beyond that are matched only by `| intel`. IPv6 networks
match only with `| intel`.

Each event gets:

| Column | Meaning |
| --- | --- |
| `threat_match_field`, `threat_match_value` | The event field and value that matched (the highest-weight match if several did) |
| `threat_indicator`, `threat_type` | The indicator, such as the network the address is in |
| `threat_source` | Every source listing it |
| `threat_weight`, `threat_description` | From the strongest indicator |
| `threat_target` | The system on your side: the destination when the source matched, otherwise the source or reporting host |

### intel

`| intel [fields]` checks any result in the Signalith server and adds
`<field>_intel_source`, `<field>_intel_type`, `<field>_intel_weight` and
`<field>_intel_description` where a value is an indicator. It also matches URLs by
host against domain indicators and Sysmon `process_hash` lists. Use it after `stats`:

```
datamodel=Network_Traffic | stats count, sum(bytes) as bytes by dest | intel dest | where dest_intel_source=*
```

## Storage and scale

Indicators are stored in the `<prefix>_intel` OpenSearch index, which event searches
never read, and every server keeps the active ones in memory (about 200 bytes each),
reloading within a minute when another server changes them. A few hundred thousand
indicators are fine; the threatmatch filter for 200,000 IP indicators is a few
megabytes per search.

## API

| Method and path | Purpose |
| --- | --- |
| `GET /api/intel` | Counts by type and source, and every feed with its status |
| `POST /api/intel/feeds/{name}/refresh` | Download a feed now |
| `GET /api/intel/indicators?q=&type=&source=&limit=&offset=` | List indicators, newest first |
| `POST /api/intel/indicators` | Add one: `{"value": "...", "type": "auto", "description": "...", "weight": "1", "expires": "30d", "tags": []}` |
| `DELETE /api/intel/indicators/{id}` | Delete a manual indicator |
| `POST /api/intel/upload` | Add manual indicators from CSV or a list; returns `{"lines": [{"line", "msg"}]}` on errors |
| `GET /api/intel/lookup?value=` | Check one value against every indicator |
