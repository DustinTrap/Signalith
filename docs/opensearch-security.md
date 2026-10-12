# Securing OpenSearch

Signalith keeps every event, finding and investigation in OpenSearch, so anyone who
can reach OpenSearch can read or change them. This page sets OpenSearch up so that:

- it answers only over HTTPS, with a certificate from a small certificate authority
  (CA) of your own;
- nobody signs in with a password: Signalith signs in with a client certificate, and
  there are no built-in users and no anonymous access;
- Signalith's certificate may touch only Signalith's own indices (`signalith*`) and read
  the cluster's health.

The Docker quick start does all of this by itself. For OpenSearch installed on Linux or
Windows, `signalith opensearch-certs` makes the files and the steps below put them in
place.

Do not keep OpenSearch's demo security configuration. Its certificates, keys and
passwords (such as `admin`, and the `kirk` admin certificate) are published with
OpenSearch, so anyone can use them.

## Docker quick start

Nothing to do. Each `docker compose ... up` first runs a short setup step,
`signalith bootstrap-docker`, which:

- makes the CA and three certificates the first time (RSA 3072, valid 10 years): one for
  OpenSearch, one for Signalith (`CN=signalith,O=Signalith`) and an admin certificate
  (`CN=signalith-admin,O=Signalith`) that can change OpenSearch's security settings;
- keeps them in the `opensearch-certs` and `signalith-secrets` volumes, readable only by
  the container that uses them, and leaves them alone on later runs. If one is missing,
  damaged or due to expire within 30 days, it makes a new set; restart both then with
  `docker compose -f deploy/docker/docker-compose.yml restart opensearch signalith`;
- makes the first admin password and the agents' ingest token the same way.

OpenSearch runs with its security plugin on and the demo setup skipped. Its settings are
in `deploy/docker/opensearch/opensearch.yml`, and the users and roles in
`deploy/docker/opensearch/security/`: `config.yml` (certificate sign-in only),
`internal_users.yml` (empty), `roles.yml` (the `signalith_server` role) and
`roles_mapping.yml` (Signalith's certificate gets that role). OpenSearch publishes no
port; only Signalith reaches it, on the Docker network.

To look at OpenSearch yourself, use the admin certificate from inside its container:

```sh
docker compose -f deploy/docker/docker-compose.yml exec opensearch \
  curl -s --cacert config/certs/root-ca.pem --cert config/certs/admin.pem \
  --key config/certs/admin-key.pem "https://localhost:9200/_cat/indices?v"
```

OpenSearch reads the files in `security/` only when it first starts with its security
plugin on (that includes the first start after upgrading from an earlier quick start;
existing indices stay). If you change them later, for example to give `roles.yml`
another `index_prefix`, load them again:

```sh
docker compose -f deploy/docker/docker-compose.yml exec opensearch \
  bash plugins/opensearch-security/tools/securityadmin.sh -cd config/opensearch-security/ \
  -cacert config/certs/root-ca.pem -cert config/certs/admin.pem \
  -key config/certs/admin-key.pem -h localhost
```

## OpenSearch on Linux or Windows

Below, `<config>` is OpenSearch's config folder: `/etc/opensearch` for the Linux
packages, or the `config` folder where you unpacked OpenSearch on Windows (such as
`C:\opensearch\config`).

### 1. Make the certificates

On the Signalith server:

```sh
signalith opensearch-certs -out opensearch-pki
```

This is enough when OpenSearch runs on the same machine as Signalith. When it runs on
another machine, give its name with `-node` and every other name or address Signalith
uses to reach it with `-san`:

```sh
signalith opensearch-certs -out opensearch-pki -node search1 -san search1.example.com -san 10.0.0.5
```

The folder it writes holds:

| Path | For |
| --- | --- |
| `opensearch/certs/` | OpenSearch: the CA, its own certificate and key, and the admin certificate and key |
| `opensearch/opensearch-security/` | OpenSearch: `config.yml`, `internal_users.yml`, `roles.yml`, `roles_mapping.yml` |
| `opensearch/add-to-opensearch.yml` | Lines to add to `opensearch.yml` |
| `signalith/` | Signalith: the CA, its client certificate and key, and `add-to-signalith.yaml` |

The `*-key.pem` files are private keys. Copy them only where the steps say, and delete the
`opensearch-pki` folder when you are done.

Signalith uses indices named `signalith*`. If you set another `opensearch.index_prefix`,
change `index_patterns` in `opensearch-security/roles.yml` to match before step 4.

### 2. Put the files in place on the OpenSearch machine

1. Copy `opensearch/certs` to `<config>/certs`. On Linux, let only OpenSearch read it:
   ```sh
   sudo cp -r opensearch-pki/opensearch/certs /etc/opensearch/certs
   sudo chown -R opensearch:opensearch /etc/opensearch/certs
   sudo chmod 700 /etc/opensearch/certs && sudo chmod 600 /etc/opensearch/certs/*
   ```
2. Copy the four files in `opensearch/opensearch-security/` into
   `<config>/opensearch-security/`, replacing the ones there (keep a copy of the old ones).
3. Edit `<config>/opensearch.yml`: delete the block from
   `######## Start OpenSearch Security Demo Configuration ########` to
   `######## End OpenSearch Security Demo Configuration ########` if there is one, and any
   other line starting with `plugins.security.`. Then paste in the contents of
   `opensearch/add-to-opensearch.yml`. Leave `network.host` as it is when Signalith runs on
   the same machine (OpenSearch then listens on this machine only).
4. Restart OpenSearch: `sudo systemctl restart opensearch`, or on Windows restart its
   service (or `opensearch.bat`).

### 3. Load the security settings

If OpenSearch ran with its security plugin before, which the demo configuration does, it
keeps its users and roles in an index and does not read the files again. Load them once
with the admin certificate. On Linux:

```sh
sudo env OPENSEARCH_JAVA_HOME=/usr/share/opensearch/jdk \
  bash /usr/share/opensearch/plugins/opensearch-security/tools/securityadmin.sh \
  -cd /etc/opensearch/opensearch-security/ -cacert /etc/opensearch/certs/root-ca.pem \
  -cert /etc/opensearch/certs/admin.pem -key /etc/opensearch/certs/admin-key.pem -h localhost
```

On Windows, in PowerShell (change `C:\opensearch` to where OpenSearch is):

```powershell
$env:OPENSEARCH_JAVA_HOME = "C:\opensearch\jdk"
C:\opensearch\plugins\opensearch-security\tools\securityadmin.bat `
  -cd C:\opensearch\config\opensearch-security\ -cacert C:\opensearch\config\certs\root-ca.pem `
  -cert C:\opensearch\config\certs\admin.pem -key C:\opensearch\config\certs\admin-key.pem -h localhost
```

It ends with `Done with success`. The demo users, `admin` included, are gone from then
on. A new OpenSearch that never ran with its security plugin loads the files by itself on
first start; running this anyway does no harm.

The admin certificate can change every security setting. It is only needed for this
command, so keep `admin-key.pem` somewhere safe rather than on the server.

Check that OpenSearch now refuses everyone without a certificate. Both should print
`401` (on Windows, type `curl.exe` and use the Windows paths):

```sh
curl -s -o /dev/null -w '%{http_code}\n' --cacert /etc/opensearch/certs/root-ca.pem https://localhost:9200/
curl -s -o /dev/null -w '%{http_code}\n' --cacert /etc/opensearch/certs/root-ca.pem -u admin:admin https://localhost:9200/
```

### 4. Point Signalith at it

1. Copy the three `.pem` files in `signalith/` next to `signalith.yaml` and let only
   Signalith read them. On Linux:
   ```sh
   sudo cp opensearch-pki/signalith/opensearch-*.pem /etc/signalith/
   sudo chown signalith /etc/signalith/opensearch-*.pem
   sudo chmod 400 /etc/signalith/opensearch-*.pem
   ```
   On Windows, copy them to `C:\ProgramData\Signalith\`, which `install.ps1` lets only
   Administrators and SYSTEM (the service) read.
2. In `signalith.yaml`, set `opensearch:` as in `signalith/add-to-signalith.yaml`: the
   `https://` URL, `ca_file`, `cert_file` and `key_file`. Remove `username` and `password`
   if they are there. The URL's host must be a name or address the certificate covers;
   `add-to-signalith.yaml` lists them.
3. Run `signalith validate`, then restart Signalith. The **Health** page shows OpenSearch's
   status.

## Renewing

The certificates last 10 years. To replace them, run `signalith opensearch-certs` into a
new folder and repeat steps 2 and 4 (step 3 too if you changed the security files), then
restart OpenSearch and Signalith, since the CA is new as well.

## Other setups

- **A cluster of several nodes**: `opensearch-certs` makes a certificate for one node.
  For more, use your own CA, list every node's certificate subject in
  `plugins.security.nodes_dn`, and give Signalith a client certificate whose common name
  is `signalith` (or map yours to `signalith_server` in `roles_mapping.yml`).
- **Passwords instead of certificates**: Signalith can also sign in with
  `opensearch.username` and `opensearch.password` (or `SIGNALITH_OPENSEARCH_PASSWORD`, or
  `SIGNALITH_OPENSEARCH_PASSWORD_FILE`). It sends them over `https://` only, unless the
  OpenSearch is on the same machine. Give that user the `signalith_server` role from
  `roles.yml` rather than an admin role.
