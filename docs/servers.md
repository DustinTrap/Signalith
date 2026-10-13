# Servers

Several Signalith servers can share one OpenSearch, for example two servers
behind a load balancer. Each one is a whole Signalith: it serves the web pages,
receives agent and syslog data, and searches. They find each other through
OpenSearch, so there is nothing to connect between them.

One thing they do not all do: the **background jobs**. Exactly one server at a
time runs them. The **Servers** page shows which one.

## The Servers page

Open **Servers** in the navigation, under Health, or press Ctrl+K and type
"servers". The page is for admins. When something stops for everyone, such as no
server running detections or OpenSearch's disk being full, every signed-in person
sees a red banner at the top of every page, and the Health card in the sidebar
turns red.

The line above the list says how many servers there are, which one runs the jobs,
which version they run and how OpenSearch is doing. The page updates itself every
few seconds.

| Column | What it shows |
| --- | --- |
| Server | The server's name (`cluster.node_name`), **This server** on the one you are signed in to, and its address (`server.node_url`) |
| Status | **Running**, **Starting**, **Stopping**, **Stopped** (shut down on purpose), **Not answering** (no sign of life for 30 seconds), **Can't reach OpenSearch** (this server, while it cannot) or **Identity in use** (see [Identity](#identity)). Below it: how long it has been up, or when it was last seen, counted by the server that answered the page, so neither the other server's clock nor yours matters. A clock more than 2 seconds off is shown here too |
| Background jobs | **Runs jobs** on the server that runs them. **Standby** on a server that would take them over, or why it would not. **Doesn't run them** on a server that may not, with the reason |
| Version | The Signalith version it runs |

With one server, the page shows that server and nothing to set up. To add one, see
[Adding a server by hand](#adding-a-server-by-hand). Servers that run a version of
Signalith from before this one are not listed: they do not write a sign of life
(see [Upgrading servers you set up by hand](#upgrading-servers-you-set-up-by-hand)).

A server stopped on purpose stays in the list, after the running ones, as
**Stopped** with when it stopped, and is not counted. It leaves the list 7 days
after it stopped. A server that got a new identity shows up once under its new
identity and once, stopped, under its old one until then.

Alerts above the list appear only when something needs attention: amber when it
should be looked at, red when something is not running. Each one names the server
and says what to do. Problems another server finds with itself, such as a state
folder that was moved from another computer, are shown here too.

While this server cannot reach OpenSearch, it shows itself as **Can't reach
OpenSearch**, a red alert says so, and the other servers stay as it last saw them.

## The background jobs

These run on one server only:

- detections on their schedule,
- threat intel feed downloads,
- data retention, including the disk guard and archiving,
- index upgrades after a new version.

Searching, dashboards, investigations and receiving data work on every server.

**How they move.** The server that runs the jobs confirms every 10 seconds, in
OpenSearch, that it still does. If it stops confirming (it crashed, its computer
stopped, or it lost OpenSearch), another server takes the jobs over within about
40 seconds. When a server is stopped on purpose, it hands them over first, so
another server has them within seconds. Two servers do not run them at once: a
server that cannot confirm for 20 seconds stops its jobs by itself, on a timer of
its own, before anyone else may start them after 30 seconds. Detections and feed
downloads also check, before each run, that their server still runs the jobs.

**Which servers may run them.** Every server, unless **Run detections on schedule**
(`detections.scheduler`) is turned off on its Settings page. Leave it on: the
servers take turns by themselves. Turn it off only on a server that should never
run the jobs, for example one that only receives data.

**Changing retention and feeds.** Until settings are shared between servers, the
Data retention and Threat intel feed settings can be changed only on the server
that runs the jobs.

## When a server will not take over

Retention policies, threat intel feeds and custom detections are still kept in
files on each server. A server whose files differ from those of the server that
runs the jobs does not take the jobs over by itself: it would delete, download or
alert differently. The list shows it as **Standby** with "Won't take over" and the
reason, and an alert says what to copy:

| What differs | What to make the same |
| --- | --- |
| Retention policies | `retention.yaml` in the lookups folder, and `retention` in signalith.yaml |
| Threat intel feeds | `intel_feeds.yaml` in the lookups folder, and `intel` in signalith.yaml |
| Detections folder | The custom detection files in `detections.dir` |
| Archive folder | Only while a retention policy archives: every server must use one shared archive folder. Set `retention.archive_dir` to the same shared folder on each server. Signalith names the folder with a small file in it, `.signalith-archive-id`; leave it there |

Copy the files from the server that runs the jobs, then restart the server you
copied them to. The alert goes away within a minute.

If the server that runs the jobs stops while no other server may take over, a red
alert says that nothing runs detections, threat intel downloads or retention.
Start the server that ran them again, or fix the other server's files and restart
it.

## When OpenSearch's disk is full

When OpenSearch runs out of disk, it refuses new events. The page shows a red
alert, and the server that runs the jobs keeps only the **disk guard** running:
unless it was turned off on the Data retention page, it deletes the oldest days
until there is room. Detections and feed downloads wait. New events are stored
again by themselves once there is room; agents keep theirs until then. To make room
sooner, give OpenSearch more disk.

While the disk is full, servers cannot write their sign of life, so the list keeps
showing them as they were last seen instead of marking them all as not answering.

## Clocks

Detections are scheduled by the clock. The list warns when a server's clock is more
than 2 seconds off OpenSearch's. A server more than 30 seconds off leaves the jobs
to a server whose clock is right while one is up; a server on its own runs them
anyway, with the warning. Keep every server's clock in sync with NTP (Windows Time
on Windows).

## Identity

Each server keeps its identity in its state folder (`node.id`). Never copy a state
folder to another server, for example by cloning a virtual machine. Two servers with
one identity are found out within seconds. The one that started last stops (it
refuses to start), and the one that was running goes on and shows an alert. A
server that finds another one using its identity later shows **Identity in use**,
runs no jobs, and tells load balancers to send it nothing.

To give a server a new identity, stop it, delete `node.id` from its state folder
and start it again. In Docker the state folder is the data volume, and the image
has no shell, so:

```
docker compose stop signalith
docker run --rm -v docker_signalith-data:/d busybox rm /d/node.id
docker compose up -d
```

`docker volume ls` shows the volume's name (here `docker_signalith-data`).

**The state folder.** It is `SIGNALITH_STATE_DIR` when that is set; the systemd
unit and the Docker image set it to `/var/lib/signalith`. Otherwise it is the
folder that holds `lookups.dir`. It must be on a local disk, never on a network
share, and the service's user must be able to write in it. When the folder that
holds `lookups.dir` is on a network share or cannot be written, Signalith keeps its
identity in a local folder instead (`/var/lib/signalith` on Linux,
`C:\ProgramData\Signalith` on Windows) and says so in its log; set
`SIGNALITH_STATE_DIR` to choose. Servers that share `lookups.dir` on a network
share must each set their own `SIGNALITH_STATE_DIR`. On Docker Desktop and WSL
bind mounts, which may not lock files, Signalith starts with a warning.

## Adding a server by hand

Until servers can be added from the Servers page:

1. Install Signalith on the new computer as usual.
2. Give it the same OpenSearch settings as the first server: `opensearch.url`, its
   user and password, and `opensearch.index_prefix`.
3. Give it the same agent tokens (`ingest.tokens`), so agents can send to either
   server.
4. Copy the retention, feed and detection files listed above, so it can take the
   jobs over. Copy only those files: never `node.id` or the `cluster` folder. In
   Docker they are in the data volume; copy them into the new server's volume
   rather than copying the whole volume.
5. Set up the same users on its Users page: users and sign-in settings are still
   kept on each server.
6. Give it its own name with `cluster.node_name`. In Docker, set
   `SIGNALITH_NODE_NAME` in the compose file (it is `signalith-1` there), and set
   its address with `SIGNALITH_NODE_URL`, since a container cannot know it. Two
   running servers with one name get an amber alert.
7. Give the OpenSearch user the right to create, read and write
   `<prefix>_runtime` (or `<prefix>_*`), where the servers find each other.

When it starts, it appears on the Servers page of every server.

## Upgrading servers you set up by hand

Versions before this one do not take turns: each server with **Run detections on
schedule** on runs the jobs itself, so two of them run detections, threat intel
downloads and retention twice. They also do not appear on the Servers page.

The Servers page says this too, until an admin dismisses the note. When you
upgrade servers that share one OpenSearch, either:

- upgrade them all at the same time, or
- first turn off **Run detections on schedule** (`detections.scheduler: false`) on
  every server except one, upgrade them one by one, and turn it back on once all of
  them run this version.

## Load balancers: /readyz and /livez

Every server answers two addresses without signing in. They say nothing else about
the server.

| Address | Answer | Use it for |
| --- | --- | --- |
| `GET /readyz` | `200 {"ready":true}` when the server should get traffic; `503 {"ready":false,"reason":"…"}` when it should not | Load balancer health checks, Kubernetes readiness probes |
| `GET /livez` | `200 {"live":true}` while the process runs | Restarting a process that hangs, Kubernetes liveness probes |

The reasons `/readyz` gives:

| Reason | Meaning |
| --- | --- |
| `starting` | The server has not finished starting |
| `restarting` | It is applying changed settings; it answers again in a few seconds |
| `down` | It could not start, and tries again every 30 seconds; its log says why |
| `opensearch` | It cannot reach OpenSearch, or OpenSearch refuses its sign of life (the Servers page and the log say why) |
| `identity` | Another server uses its identity (see [Identity](#identity)) |
| `stopping` | It is shutting down and handing its jobs over. This takes up to a minute while jobs finish: the systemd unit allows 100 seconds, the compose file 90, and the Windows service waits 90 |

Do not use `/readyz` to restart a server: a server that waits for OpenSearch is
fine, and restarting it does not help. Use `/livez` for that.

HAProxy, for example, with each person kept on one server (see below):

```
backend signalith
    balance source
    option httpchk GET /readyz
    http-check expect status 200
    server siem-a 10.0.0.11:8080 check
    server siem-b 10.0.0.12:8080 check
```

When Signalith serves HTTPS (`server.tls_cert`), add `check-ssl` and the
certificate authority to check it with (`ca-file`) to each `server` line. A
Kubernetes container:

```yaml
readinessProbe:
  httpGet: { path: /readyz, port: 8080 }
livenessProbe:
  httpGet: { path: /livez, port: 8080 }
```

**Keep each person on one server.** A sign-in to the web pages is kept by the
server it was made on, so set the load balancer to send each person to the same
server (sticky sessions, or source address affinity). If that server stops, people
sign in again on the other one. Agents and syslog need no such setting: any server
takes any agent's data.
