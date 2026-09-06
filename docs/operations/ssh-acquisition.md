# Playbook: SSH acquisition

## Objective and prerequisites

Fetch explicitly named files from a saved, authorised POSIX SSH target and analyse
them offline. Complete [controller setup](controller-setup.md) and the actual host's
[container validation](containers.md) first.

The operator must know each absolute remote file path and be authorised to read it.
The adapter does not discover candidate files, walk remote directories or collect
general process, network, user or service telemetry. Python and the normal Ansible
module prerequisites must be available on the target.

## Register a target

Obtain the SSH host-key fingerprint through an independent trusted channel. For
example, an authorised target administrator can inspect its public host key:

```bash
ssh-keygen -E sha256 -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Initialise the local profile using a literal IPv4 address:

```bash
dacctl target init lab \
  --host 192.0.2.10 \
  --port 22 \
  --host-key-fingerprint SHA256:REPLACE_WITH_VERIFIED_FINGERPRINT
```

Initialisation checks the target key against the expected fingerprint and creates
encrypted credentials in a project-managed volume. Follow the interactive passphrase
prompt. Only the public key is printed; register it on a dedicated target account
with read access to the intended files.

Where suitable for the target configuration, limit the authorised public key with
OpenSSH restrictions. Ansible still needs to execute its own modules; avoid a forced
command that prevents normal file acquisition. Remote sudo is optional and should
only be granted when the selected paths require it.

```bash
dacctl target list
```

The profile records the name, IPv4 address, port, expected fingerprint and managed
volume reference. It does not store private key bytes or passwords in host metadata.

## Acquire named regular files

```bash
dacctl run ssh htb-malevolent-modmaker \
  --target lab \
  --user analyst \
  --remote-file /opt/evidence/artifact-one \
  --remote-file /opt/evidence/artifact-two \
  --output ./reports
```

Every operation creates a fresh rootless network namespace. A short-lived initialiser
applies the saved target-and-port allowlist before the unprivileged acquisition worker
runs. The acquisition worker cannot change the firewall. It uses strict host-key
checking; `run ssh` does not accept arbitrary hosts or `accept-new`.

The generated key stays inside managed storage. An encrypted key may require an
interactive passphrase. The physical host's SSH agent and SSH directory are not
forwarded.

## Explicit identity import or password prompt

To use an existing authorised key, import only that selected regular file:

```bash
dacctl run ssh htb-malevolent-modmaker \
  --target lab \
  --user analyst \
  --identity /absolute/path/to/selected_private_key \
  --remote-file /opt/evidence/artifact-one
```

The selected key is made available only to acquisition. It is not included in reports,
detector requests or analysis mounts. Do not supply an entire SSH directory.

For password authentication:

```bash
dacctl run ssh htb-malevolent-modmaker \
  --target lab \
  --user analyst \
  --ask-pass \
  --remote-file /opt/evidence/artifact-one
```

Passwords are entered interactively, never as CLI arguments or environment variables.

## Limits and elevation

```bash
dacctl run ssh htb-malevolent-modmaker \
  --target lab \
  --user analyst \
  --remote-file /opt/evidence/artifact-one \
  --max-file-size 32MiB \
  --max-total-size 64MiB \
  --max-files 5 \
  --connection-timeout 20 \
  --acquisition-timeout 600 \
  --timeout 5
```

The connection timeout covers each SSH connection attempt; the acquisition timeout
bounds the complete acquisition. Detector timeouts apply later in offline analysis.
Remote metadata is checked before transfer where possible, and fetched files are
rechecked and hashed when snapshotted.

Use `--become` only when the selected path requires elevated read access.
`--ask-become-pass` requires `--become` and requests an interactive prompt.
Elevation can cause Ansible to buffer remote content while determining checksums.

## Target behaviour and partial results

The core-owned playbook performs inspection and fetching. It does not install an
agent, execute an artefact or run pack code on the target. Ansible can stage transient
modules in the target account; normal Ansible cleanup applies.

Missing, linked, non-regular, inaccessible, oversized or unfetched paths become
acquisition issues. A failed transfer is never accepted merely because a residual
destination file exists. A changing target can race metadata and transfer; local
snapshot integrity checks remain authoritative.

Successfully acquired files are handed to a separate analysis container without
networking or credentials. A partial run can produce findings but returns `2`.
Total acquisition failure may produce no normal report. Temporary acquisition
workloads and namespaces are removed after use.

## Retention and retirement

Add `--retain-evidence` when later replay is required. Raw evidence stays in managed
storage and host exports contain only JSON and Markdown reports. Check the report's
source, target, requested display paths and acquisition issues.

Retire a local target explicitly:

```bash
dacctl target remove lab
```

Remove the corresponding public key from the remote account separately. Local volume
removal does not revoke a remote credential or guarantee secure erasure. For a changed
target or host key, verify the new identity independently and create a new profile;
do not weaken host-key checks.
