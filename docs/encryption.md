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

Not encrypted, because they need not be:

- **User passwords** (the built-in admin's and those on the **Users** page) are
  stored as bcrypt hashes, which cannot be turned back into the password.
- **Environment variables** (`SIGNALITH_OPENSEARCH_PASSWORD` and the others) are used
  as they are and never written to a file, even when Signalith saves a file.
- A value written as `${ENV_VAR}` (in a feed in `signalith.yaml`) holds no secret.
- **Events**, in OpenSearch and in archives, are protected by disk encryption (below).

How: each value is encrypted with AES-256-GCM, under a key derived from the master
key for that setting alone. A value copied to another setting, or changed, does not
decrypt.

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
   Linux in `/var/lib/signalith`.

Where it ends up:

| Install | Master key |
| --- | --- |
| Linux (systemd) | `/etc/signalith/keys/master.key`, made by `signalith init` |
| Docker quick start | `/var/lib/signalith/keys/master.key`, in the `signalith-data` volume |
| Windows | `C:\ProgramData\Signalith\keys\master.key.dpapi` |
| Elsewhere | `keys/master.key` next to the lookups folder |

The key file can be read only by Signalith's own account: mode 0600 in a 0700
folder on Linux, and on Windows an access list of its own (SYSTEM, Administrators and
the service account, `NT SERVICE\Signalith`). On Windows the key is also encrypted
with DPAPI for the computer, so a copy of the file is useless on another computer.

`signalith secrets status` shows where the key is and how every value is stored:

```
$ sudo signalith secrets status
Using the folders the signalith service is given (systemctl show signalith):
  SIGNALITH_ARCHIVE_DIR=/var/lib/signalith/archive
  SIGNALITH_DASHBOARDS_DIR=/var/lib/signalith/dashboards
  SIGNALITH_DETECTIONS_DIR=/var/lib/signalith/detections
  SIGNALITH_LOOKUPS_DIR=/var/lib/signalith/lookups
  SIGNALITH_STATE_DIR=/var/lib/signalith

Master key:    /etc/signalith/keys/master.key, key id 9096cd23

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

On Linux, `signalith secrets` reads the folders the systemd service is given, so it
finds the server's files when run by hand.

#### Keeping the key elsewhere

- **systemd credential**: uncomment `LoadCredential=master.key:/etc/signalith/keys/master.key`
  in the unit. systemd then hands the key to the service when it starts, in a folder
  only the service can read. `signalith secrets` commands use the same file. After
  `rotate-master`, restart the service.
- **Docker or Kubernetes secret**: create a key with `openssl rand -base64 32 >
  master.key`, mount it into the container, and set `SIGNALITH_MASTER_KEY_FILE` to
  its path. With Docker Compose, in a `docker-compose.override.yml` next to
  `docker-compose.yml`:

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

  The file must be readable by the container's user (uid 65532):
  `sudo chown 65532 master.key && chmod 0400 master.key`. A key file holds the 32
  bytes as they are, or one line of base64 or hex.
- **Windows, a key you can move**: the DPAPI-protected key works only on the
  computer that made it. To use a key file you can restore on another server, put
  one in `C:\ProgramData\Signalith\keys\master.key` and give the service its path:

  ```powershell
  Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Signalith -Name Environment -Type MultiString `
    -Value 'SIGNALITH_MASTER_KEY_FILE=C:\ProgramData\Signalith\keys\master.key'
  ```

  Values already encrypted with the old key need to be encrypted again: enter them
  again, or set `SIGNALITH_MASTER_KEY_FILE` only for a fresh install.

### Backing up the key

Back up the key file, and keep the copy **apart** from backups of `signalith.yaml`
and the lookups folder: whoever has both can decrypt the passwords. A password
manager or a vault is a good place; the file is short text on Linux and Docker.

On Windows the `.dpapi` file can only be read on the same Windows installation, so a
copy helps when you restore that server (a VM snapshot or system backup), not on a
new one. Keep the passwords themselves in your vault too, or use a key file you can
move (above).

### Losing the key

Losing the key loses only the stored passwords and keys, never events. Enter them
again:

- In `signalith.yaml`, the server does not start and names each value it cannot
  decrypt, with the command that replaces it:

  ```
  error: /etc/signalith/signalith.yaml: invalid configuration:
    - ingest.tokens[0] is encrypted with master key c656730c, but no master key was found. Restore the master key it was encrypted with, or enter the value again; without that key only stored passwords and keys are lost, never events. Remove it from ingest.tokens and add a token with: signalith secrets set ingest.tokens
  ```

  `signalith secrets set opensearch.password` (or `assistant.api_key`,
  `auth.ldap.bind_password`) replaces a value; for an ingest token, remove the line
  and add one with `signalith secrets set ingest.tokens`.
- **Directory sign-in** keeps running but cannot search for users until you enter
  the service account password again on the **Users** page, under **Directory
  sign-in**. The **Health** page and the log say so. Signalith does not try a wrong
  password, so the account is not locked out.
- A **threat intel feed** whose key cannot be decrypted stops downloading and shows
  why on the **Threat intel** page; edit the feed and enter the key again. Other
  feeds keep running.

`signalith secrets status` lists everything that cannot be decrypted.

### Changing the key

Change the master key when someone who could read it leaves, or when a copy may have
leaked:

```
$ sudo signalith secrets rotate-master
New master key dea48fde in /etc/signalith/keys/master.key.
Encrypted 2 values again in /etc/signalith/signalith.yaml
Encrypted 1 value again in /var/lib/signalith/lookups/directory.json
Encrypted 3 values again in /var/lib/signalith/lookups/intel_feeds.yaml
The previous key (9096cd23) is kept as /etc/signalith/keys/master.key.old, so files saved before now can still be read.
A running server picks up the new key by itself.
Next: back up the new key, then remove the previous one with: signalith secrets rotate-master -prune
```

Every file is written next to its place first and checked; if any cannot be put in
place, everything (the key included) is put back as it was and the command says
"Nothing was changed". The previous key is kept so that a file restored from an
older backup can still be read. When nothing needs it any more:

```
$ sudo signalith secrets rotate-master -prune
Removed the previous master key /etc/signalith/keys/master.key.old (key id 9096cd23).
Backups of files from before the rotation now need a backup of that key to be read.
```

`-prune` refuses while a value still needs the previous key (such as a file
restored from a backup) and says which; `signalith secrets encrypt` encrypts it
with the new key first. A key in `SIGNALITH_MASTER_KEY` cannot be rotated by
Signalith: change the variable yourself, or move the key to a file.

### Commands

| Command | What it does |
| --- | --- |
| `signalith secrets status [-c file]` | Where the master key is, and how each stored password or key is kept |
| `signalith secrets encrypt [-c file]` | Encrypts plain values (and values still under the previous key), changing nothing else in the files |
| `signalith secrets set <setting> [-c file]` | Stores `opensearch.password`, `assistant.api_key`, `auth.ldap.bind_password`, or another of `ingest.tokens`, encrypted. It asks twice without showing what you type, or reads one line from a pipe; for an ingest token, press Enter to have one made |
| `signalith secrets rotate-master [-c file]` | Makes a new master key and encrypts every stored value again with it |
| `signalith secrets rotate-master -prune [-c file]` | Removes the previous master key once nothing needs it |

All of them write each file whole through a temporary file (a crash never leaves
half a file) and keep its permissions and owner.

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
