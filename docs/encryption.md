# Encryption

Signalith keeps passwords and API keys: the OpenSearch password, ingest tokens, the
AI model's API key, the directory (Active Directory or LDAP) service account
password, and the keys and passwords of threat intel feeds. This page covers how
they and your events are protected:

| | What protects it | What you do |
| --- | --- | --- |
| **In transit** (on the network) | HTTPS and TLS | Turn on HTTPS: [docs/https.md](https.md) |
| **At rest** (on disk) | Signalith encrypts the passwords and keys it stores; disk encryption protects everything else | Back up the master key; turn on disk encryption |
| **In use** (in memory) | The service is locked down so other programs cannot read its memory | Nothing, or a confidential VM for more |

## In transit

Use HTTPS for the web UI and the API (agents send events over it, with the ingest
token), TLS for syslog where devices support it, `https://` for OpenSearch, and
`ldaps://` or StartTLS for directory sign-in. [docs/https.md](https.md) sets this
up. Signalith refuses to send the OpenSearch password over plain http to another
machine unless you allow it, and warns while certificate checks are off.

## At rest

### What Signalith encrypts

Every password and key Signalith stores in a file is encrypted:

| File | Encrypted values | Written by |
| --- | --- | --- |
| `signalith.yaml` | `opensearch.password`, `assistant.api_key`, `auth.ldap.bind_password`, each of `ingest.tokens`, and `intel.feeds[].password` and header values | You, `signalith init` and `signalith secrets`. The server never changes this file |
| `directory.json` (lookups folder) | The service account password of directory sign-in set up on the **Users** page | The server |
| `intel_feeds.yaml` (lookups folder) | Passwords and header values (API keys) of feeds added on the **Threat intel** page | The server |

An encrypted value looks like this:

```yaml
opensearch:
  password: enc:v1:9096cd23:zNhdzHvpeSnrdiqQHGOGMRlih2VUzUrwcOjWVF3w4lW1dAVcs-fPcn_nBiPB6wM
```

`9096cd23` is the id of the master key that encrypted it. A plain value still works:
paste a password into `signalith.yaml` and the server uses it, but `signalith
validate`, the server log and the **Health** page say so:

```
Warning: 1 password or key in signalith.yaml is stored as plain text (assistant.api_key). Run: signalith secrets encrypt
```

`signalith secrets encrypt` then encrypts it where it stands, keeping your comments
and layout:

```diff
-    api_key: sk-ant-PASTED-BY-HAND   # pasted in by hand
+    api_key: enc:v1:dea48fde:Nqfes8VQxocc4uRLZGjXal83RwCznSCgI0samMWNTPIlepfiZhj50zH8iGnwjRE1Ag   # pasted in by hand
```

The server encrypts the plain values in the files it writes itself (left by an
older version) when it starts, and logs it once:

```
level=INFO msg="encrypted the passwords and keys stored in a file" file=/var/lib/signalith/lookups/intel_feeds.yaml values=1
```

**Passwords in addresses.** A password written into an address cannot be encrypted
there, so Signalith counts it as plain text:

- In `opensearch.url` (`https://admin:secret@opensearch:9200`), `signalith secrets
  encrypt` takes it out of the address and writes it as `opensearch.username` and an
  encrypted `opensearch.password`.
- In `opensearch.proxy`, it is only reported: set the proxy with the
  `SIGNALITH_OPENSEARCH_PROXY` environment variable instead.
- A key in a feed's address (`https://feed.example/list?apikey=...`) is only
  reported: if the feed accepts it as a header, send it that way, since headers are
  encrypted.

Not encrypted, because they need not be:

- **User passwords** (the built-in admin's and those on the **Users** page) are
  stored as bcrypt hashes, which cannot be turned back into the password.
- **Environment variables** (`SIGNALITH_OPENSEARCH_PASSWORD` and the others) are used
  as they are and never written to a file, even when Signalith saves a file.
- A value written as `${ENV_VAR}` (in a feed in `signalith.yaml`) holds no secret.
- **Events**, in OpenSearch and in archives, are protected by disk encryption (below).

How: each value is encrypted with AES-256-GCM, under a key derived from the master
key for that setting alone. A value copied to another setting, or changed, does not
decrypt. A feed's password and header values in `signalith.yaml` are tied to the
header's name, not to the feed's: rename a feed as you like, but after renaming a
header (`X-API-Key` to `X-Auth-Key`) enter its value again. Header names ignore
case, so `x-api-key` is the same header.

### The master key

The master key is 32 random bytes. Signalith makes it the first time it stores a
password or key (`signalith init` does), and looks for it in this order:

1. `$CREDENTIALS_DIRECTORY/master.key`: a systemd credential (see below).
2. The file `SIGNALITH_MASTER_KEY_FILE` names, such as a Docker or Kubernetes secret.
3. `SIGNALITH_MASTER_KEY`: the key itself, in base64. It works, but other programs
   can sometimes read a program's environment (`docker inspect`, `/proc`), so
   Signalith warns while it is used.
4. The key file Signalith makes, `keys/master.key` (on Windows
   `keys\master.key.dpapi`), in the state folder (`SIGNALITH_STATE_DIR`, or the
   folder that holds the lookups folder), then next to `signalith.yaml`, then on
   Linux in `/var/lib/signalith`. For a config in `/etc` on Linux,
   `/var/lib/signalith` comes first, so the key is never made next to
   `signalith.yaml`, where a copy of `/etc` would carry both.

Where it ends up:

| Install | Master key |
| --- | --- |
| Linux (systemd) | `/var/lib/signalith/keys/master.key`, made by `signalith init` |
| Docker quick start | `/var/lib/signalith/keys/master.key`, in the `signalith-data` volume |
| Windows | `C:\ProgramData\Signalith\keys\master.key.dpapi` |
| Elsewhere | `keys/master.key` next to the lookups folder |

The key file can be read only by Signalith's own account: mode 0600 in a 0700
folder on Linux, and on Windows an access list of its own (SYSTEM, Administrators and
the service account, `NT SERVICE\Signalith`). On Windows the key is also encrypted
with DPAPI for the computer, so a copy of the file is useless on another computer.

On Linux, Signalith warns (in `signalith secrets status`, `signalith validate`, the
log and the **Health** page) when other accounts can read or change the key file,
such as a key restored from a backup with `cp`, and says how to fix it (`chmod 600`).
A key file it is not allowed to read is an error that names the file and the fix
(`sudo chown -R signalith /var/lib/signalith/keys`); Signalith never makes a second
key while there is one it cannot read.

A key file you make yourself holds one line of base64 (or hex), or the 32 bytes as
they are. Make one with `openssl rand -base64 32 > master.key`. A 32-character
passphrase is refused: typed text is far easier to guess than random bytes.

`signalith secrets status` shows where the key is and how every value is stored:

```
$ sudo signalith secrets status
Using the settings the signalith service is given (systemctl show signalith):
  SIGNALITH_ARCHIVE_DIR=/var/lib/signalith/archive
  SIGNALITH_DASHBOARDS_DIR=/var/lib/signalith/dashboards
  SIGNALITH_DETECTIONS_DIR=/var/lib/signalith/detections
  SIGNALITH_LOOKUPS_DIR=/var/lib/signalith/lookups
  SIGNALITH_STATE_DIR=/var/lib/signalith

Master key:    /var/lib/signalith/keys/master.key, key id 9096cd23

/etc/signalith/signalith.yaml
  opensearch.password  encrypted
  ingest.tokens[0]     encrypted

/var/lib/signalith/lookups/directory.json
  bind_password (service account password)  encrypted

/var/lib/signalith/lookups/intel_feeds.yaml
  feeds[legacy-cti] header X-API-Key  encrypted
  feeds[otx] password                 encrypted
  feeds[otx] header X-OTX-API-KEY     encrypted

6 encrypted, 0 plain text.
```

A command run by hand does not see the settings the service is given, so
`signalith secrets`, `signalith validate` and `signalith init` read them: on Linux
the systemd unit's `Environment=`, `EnvironmentFile=` and `LoadCredential=` lines,
and on Windows the Signalith service's `Environment` value in the registry. They
find the server's files and key that way (only folders, files and the master key
are taken, never other settings).

#### Keeping the key elsewhere

- **systemd credential**: systemd hands the key to the service when it starts, from
  a file only root can read, away from the service's own folder and from
  `/etc/signalith`. To move the key there:

  ```sh
  sudo signalith secrets status      # "Master key:" names the key file; with a "Previous key:" line, prune it first
  sudo systemctl stop signalith
  sudo install -d -m 0700 /etc/credstore
  sudo mv /var/lib/signalith/keys/master.key /etc/credstore/signalith-master.key
  sudo chown root:root /etc/credstore/signalith-master.key
  sudo sed -i 's|^# LoadCredential=|LoadCredential=|' /etc/systemd/system/signalith.service
  sudo systemctl daemon-reload
  sudo systemctl start signalith
  sudo signalith secrets status      # "Master key: /etc/credstore/signalith-master.key"
  ```

  `signalith secrets` commands use the same file. The service reads the key only
  when it starts, so after `rotate-master`, restart it and run `signalith secrets
  encrypt` once (for anything it saved in between) before `rotate-master -prune`;
  `-prune` waits for that restart. If the file is missing, the service does not start.
- **Docker or Kubernetes secret**: mount the key file into the container and set
  `SIGNALITH_MASTER_KEY_FILE` to its path; [Docker](#docker) below shows it with
  Docker Compose.
- **Windows, a key you can move**: the DPAPI-protected key works only on the
  computer that made it. To use a key file you can restore on another server, in a
  PowerShell opened as Administrator:

  ```powershell
  $exe = "$env:ProgramFiles\Signalith\signalith.exe"
  Stop-Service Signalith
  & $exe secrets decrypt          # values back to plain text, while the old key still works
  $key = New-Object byte[] 32
  [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)
  [IO.File]::WriteAllText("$env:ProgramData\Signalith\keys\master.key", [Convert]::ToBase64String($key))
  Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Signalith -Name Environment -Type MultiString `
    -Value 'SIGNALITH_MASTER_KEY_FILE=C:\ProgramData\Signalith\keys\master.key'
  & $exe secrets encrypt          # encrypted again, with the new key
  Remove-Item "$env:ProgramData\Signalith\keys\master.key.dpapi"
  Start-Service Signalith
  ```

  The new file takes the `keys` folder's access list (SYSTEM, Administrators and
  the service). Every `signalith` command, and `install.ps1` when you upgrade, reads
  the service's `Environment` value, so they all use this key.

### Docker

In the Docker quick start the key is `/var/lib/signalith/keys/master.key` in the
`signalith-data` volume, together with `directory.json` and `intel_feeds.yaml`. A
backup of the volume therefore holds both the key and the values it decrypts. Copy
the key out and keep it apart (in a password manager or a vault). From the
repository folder, in a shell or PowerShell:

```sh
docker compose -f deploy/docker/docker-compose.yml cp signalith:/var/lib/signalith/keys/master.key "$HOME/signalith-master.key"
```

If you back up the volume, keep the key out of it instead, as a Docker secret. In
`deploy/docker/docker-compose.override.yml`:

```yaml
services:
  signalith:
    environment:
      - SIGNALITH_MASTER_KEY_FILE=/run/secrets/signalith_master_key
    secrets: [signalith_master_key]
secrets:
  signalith_master_key:
    file: ./master.key
```

Put the key copied out above in `deploy/docker/master.key` (or make a new one with
`openssl rand -base64 32 > deploy/docker/master.key` before the first start). The
container's account (uid 65532) must be able to read it: `sudo chown 65532
deploy/docker/master.key && sudo chmod 0400 deploy/docker/master.key`. Git ignores
that file. Compose reads the override file by itself only when run from its folder
without `-f`, so from then on start Signalith with `cd deploy/docker` and `docker
compose up -d`. The copy left in the volume is then not used; `signalith secrets
status` notes it, and `docker run --rm -v docker_signalith-data:/data busybox rm
/data/keys/master.key` removes it (`docker volume ls` shows the volume's name).

`signalith.yaml` is mounted read-only in the container, so to encrypt a password
you pasted into it (as the warning on the **Health** page asks), run the command in
a container of its own that may write the file and uses the same volume, and so the
same key. From `deploy/docker`, in a shell or PowerShell:

```sh
docker compose run --rm --no-deps --user 0 -v "$PWD/signalith.yaml:/work/signalith.yaml" signalith secrets encrypt -c /work/signalith.yaml
docker compose restart signalith
```

`--user 0` lets it write a file that belongs to you rather than to the container's
account; a key it makes is given to the account of its folder, so the server can
read it. Any other `signalith secrets` command runs the same way.

### Backing up the key

Back up the key file, and keep the copy **apart** from backups of `signalith.yaml`
and the lookups folder: whoever has both can decrypt the passwords. A password
manager or a vault is a good place; the file is short text on Linux and Docker.
After `rotate-master`, back up the new key.

On Windows the `.dpapi` file can only be read on the same Windows installation, so a
copy helps when you restore that server (a VM snapshot or system backup), not on a
new one. Keep the passwords themselves in your vault too, or use a key file you can
move (above).

### Losing the key

Losing the key loses only the stored passwords and keys, never events, and the
server keeps running. Enter them again:

- In `signalith.yaml`, each value that cannot be decrypted is left out, as if it
  were not set, and the server log, `signalith validate` and the **Health** page
  name it with the command that replaces it:

  ```
  Warning: In signalith.yaml, ingest.tokens[0] is encrypted with master key c656730c, but no master key was found. Restore the master key it was encrypted with, or enter the value again; without that key only stored passwords and keys are lost, never events. Remove it from ingest.tokens and add a token with: signalith secrets set ingest.tokens. Signalith runs without it until then.
  ```

  Agents that send with that token are refused until it is replaced, and without
  `opensearch.password` OpenSearch refuses Signalith (the **Health** page shows
  it); the web pages, syslog and other tokens keep working.

  `signalith secrets set opensearch.password` (or `assistant.api_key`,
  `auth.ldap.bind_password`) replaces a value; for an ingest token, remove the line
  and add one with `signalith secrets set ingest.tokens`. While the file holds
  values encrypted with a key that is not found, `set` and `encrypt` stop rather
  than make a new key, since the key may only be elsewhere (such as in a variable
  the service has and your shell does not). When it really is lost, add `-new-key`
  to the first command: `sudo signalith secrets set opensearch.password -new-key`.
- **Directory sign-in** keeps running but cannot search for users until you enter
  the service account password again on the **Users** page, under **Directory
  sign-in**. The **Health** page and the log say so. Signalith does not try a wrong
  password, so the account is not locked out.
- A **threat intel feed** whose key cannot be decrypted stops downloading and shows
  why on the **Threat intel** page. For a feed added on the page, edit it and enter
  the key again; for one in `signalith.yaml`, replace the value with the plain one
  and run `signalith secrets encrypt`. Other feeds keep running.

`signalith secrets status` lists everything that cannot be decrypted.

### Changing the key

Change the master key when someone who could read it leaves, or when a copy may have
leaked:

```
$ sudo signalith secrets rotate-master
New master key dea48fde in /var/lib/signalith/keys/master.key.
Encrypted 2 values again in /etc/signalith/signalith.yaml
Encrypted 1 value again in /var/lib/signalith/lookups/directory.json
Encrypted 3 values again in /var/lib/signalith/lookups/intel_feeds.yaml
The previous key (9096cd23) is kept as /var/lib/signalith/keys/master.key.old, so files saved before now can still be read.
A running server picks up the new key by itself.
Next: back up the new key, then remove the previous one with: signalith secrets rotate-master -prune
```

Every file is written next to its place first and checked; if any cannot be put in
place, everything (the key included) is put back as it was and the command says
"Nothing was changed". The previous key is kept so that a file restored from an
older backup can still be read. When nothing needs it any more:

```
$ sudo signalith secrets rotate-master -prune
Removed the previous master key /var/lib/signalith/keys/master.key.old (key id 9096cd23).
Backups of files from before the rotation now need a backup of that key to be read.
```

`-prune` keeps the previous key, and says why, while a value still needs it (such
as a file restored from a backup; `signalith secrets encrypt` encrypts it with the
new key), while a value cannot be decrypted at all (it might need that key), or
while the previous key cannot be read. A key in `SIGNALITH_MASTER_KEY` cannot be
rotated by Signalith: change the variable yourself, or move the key to a file.

### Commands

| Command | What it does |
| --- | --- |
| `signalith secrets status [-c file]` | Where the master key is, and how each stored password or key is kept |
| `signalith secrets encrypt [-c file]` | Encrypts plain values (and values still under the previous key), changing nothing else in the files |
| `signalith secrets set <setting> [-c file]` | Stores `opensearch.password`, `assistant.api_key`, `auth.ldap.bind_password`, or another of `ingest.tokens`, encrypted. It asks twice without showing what you type, or reads one line from a pipe; for an ingest token, press Enter to have one made |
| `signalith secrets encrypt -new-key`, `set <setting> -new-key` | The same, making a new master key although the files hold values encrypted with one that is not found (when that key is lost) |
| `signalith secrets rotate-master [-c file]` | Makes a new master key and encrypts every stored value again with it |
| `signalith secrets rotate-master -prune [-c file]` | Removes the previous master key once nothing needs it |
| `signalith secrets decrypt [-c file]` | Writes every stored password and key as plain text again, before going back to an older version (below) |

All of them write each file whole through a temporary file (a crash never leaves
half a file) and keep its permissions and owner. When a file is a link, the file it
points to is written and the link stays.

### Going back to an older version

Versions of Signalith from before encryption cannot read encrypted values: they
would use the `enc:v1:...` text itself as the password, and for directory sign-in
repeated wrong passwords can lock the service account out. So before putting an
older version back, stop the server and write the values as plain text again:

```sh
sudo systemctl stop signalith
sudo signalith secrets decrypt
sudo install -m 0755 signalith-old-version /usr/local/bin/signalith
sudo systemctl start signalith
```

On Windows, in a PowerShell opened as Administrator, run `Stop-Service Signalith`
and `& "$env:ProgramFiles\Signalith\signalith.exe" secrets decrypt`, then the older
version's `install.ps1`. In Docker, run `docker compose stop signalith` and the
`secrets decrypt` command the way [Docker](#docker) shows, then build the older
version. If you skip this, enter the directory password and feed keys again in the
older version, or restore the files from a backup made before the upgrade. Going
forward again needs nothing: the new version encrypts them again.

### Disk encryption

The master key protects passwords and keys in copies of files: a backup, a support
ticket, a Git commit. Events, archives and the key itself are protected on the
server by encrypting its disks:

- **Windows**: BitLocker on the system drive and the drives holding OpenSearch data
  and archives (`manage-bde -on C:`, or Settings > Privacy & security > Device
  encryption).
- **Linux**: LUKS. Choose "encrypt" when installing the system, or use `cryptsetup
  luksFormat` for a data disk and put OpenSearch's data folder and the archive folder
  on it.
- **Docker Desktop**: its virtual disk lives on your computer's drive; encrypt that
  drive (BitLocker on Windows, FileVault on macOS).
- **Cloud servers**: Azure (managed disks) and Google Cloud encrypt disks by
  default; on AWS turn on "EBS encryption by default" for the region, or encrypt
  each volume. Make sure snapshots and backups are encrypted too.
- **OpenSearch snapshots and archives** you copy elsewhere need the same protection
  at their destination.

## In use

While it runs, the server holds decrypted passwords and keys in memory. Signalith
keeps them there:

- **Not printed**: logs, API replies and errors show `[redacted]` or `***` instead of
  passwords and keys.
- **No dumps**: on Linux the server turns off core dumps and marks itself
  not-dumpable when it starts, which also stops other programs running as the same
  account from reading its memory. A crash prints only the failing goroutine (unless
  `GOTRACEBACK` asks for more) and never writes a core file.
- **systemd unit** (`deploy/systemd/signalith.service`): no swap (`MemorySwapMax=0`),
  no core dumps (`LimitCORE=0`), private `/tmp`, other processes hidden, the system
  read-only, and only the system calls an ordinary service needs.
  `systemd-analyze security signalith` rates it 1.7 (OK).
- **Windows service**: runs as its own account, `NT SERVICE\Signalith`, not
  LocalSystem. Only Administrators and SYSTEM can read another account's memory.

What remains: an administrator or root on the server can read any process's memory.
Go cannot reliably wipe a value from memory once it is a string, so decrypted
passwords may stay in memory until it is reused (Signalith clears the master key and
decrypted bytes where it can).

To protect memory from the people who run the hardware too (a cloud provider, a
hosting company), run Signalith and OpenSearch on a **confidential VM**, where the
processor encrypts the VM's memory: Azure confidential VMs (DCasv5, ECasv5 and
DCesv5 series), Google Cloud Confidential VMs (N2D with AMD SEV, C3 with Intel TDX),
or AWS EC2 instances with AMD SEV-SNP (M6a, C6a, R6a). Nothing in Signalith needs to
change.

## Environment variables

| Variable | Meaning |
| --- | --- |
| `SIGNALITH_STATE_DIR` | Folder for files Signalith makes for itself, such as its master key (in `keys/`). Default: the folder that holds the lookups folder. The systemd unit and the Docker image set `/var/lib/signalith` |
| `SIGNALITH_MASTER_KEY_FILE` | A file holding the master key (32 bytes, or one line of base64 or hex) |
| `SIGNALITH_MASTER_KEY` | The master key itself, in base64. Weaker than a file; Signalith warns while it is used |
| `CREDENTIALS_DIRECTORY` | Set by systemd for `LoadCredential=`; Signalith reads `master.key` there |
