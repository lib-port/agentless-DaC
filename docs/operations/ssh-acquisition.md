# Playbook: SSH acquisition

## Objective

Fetch only explicitly named files from an authorized POSIX SSH host, snapshot them on
the controller, and run Malevolent ModMaker detections locally.

## Preconditions

- The core was installed with the `ssh` optional dependency.
- `ansible-playbook` and an OpenSSH client are available.
- The operator is authorized to read every requested remote path.
- Each remote path is an absolute POSIX path to an expected regular file.
- The target host key was verified through an appropriate independent channel.
- SSH-agent, private-key, or interactive password authentication is ready.
- Elevation requirements were determined before the run.

The adapter does not discover candidate files, walk remote directories, or collect
process, network, user, service, or log telemetry. The operator must know the paths.

## Preflight

Confirm tool versions and pack capability:

```bash
ansible-playbook --version
dacctl pack validate htb-malevolent-modmaker
dacctl pack list
```

With strict host-key checking, confirm that the target is already known when required:

```bash
ssh-keygen -F 10.10.10.10
```

An optional manual SSH test may be performed using the same user, port, and key. Do not
put a password in a command or environment variable.

## Procedure: SSH agent

When an authorized key is already loaded in the agent:

```bash
dacctl run ssh htb-malevolent-modmaker \
  --host 10.10.10.10 \
  --user htb \
  --remote-file /opt/evidence/artifact-one \
  --remote-file /opt/evidence/artifact-two \
  --output ./reports
```

The adapter forwards `SSH_AUTH_SOCK` but does not forward arbitrary caller environment
variables to Ansible.

## Procedure: explicit private key

```bash
dacctl run ssh htb-malevolent-modmaker \
  --host 10.10.10.10 \
  --user htb \
  --identity ~/.ssh/id_ed25519 \
  --remote-file /opt/evidence/artifact-one \
  --remote-file /opt/evidence/artifact-two \
  --output ./reports
```

The identity path must resolve to a regular controller-local file. Key content is never
copied into the ephemeral inventory or report.

## Procedure: interactive password

```bash
dacctl run ssh htb-malevolent-modmaker \
  --host 10.10.10.10 \
  --user htb \
  --ask-pass \
  --remote-file /opt/evidence/artifact-one \
  --output ./reports
```

Ansible prompts interactively. There is no `--password` option. Never redirect a
password into standard input or include it in a wrapper command.

## Host-key policy

The default policy is `strict`. An unknown or changed key stops acquisition. For an
authorized disposable lab host whose first-seen key cannot be preloaded, opt in once:

```bash
dacctl run ssh htb-malevolent-modmaker \
  --host 10.10.10.10 \
  --user htb \
  --host-key-policy accept-new \
  --remote-file /opt/evidence/artifact-one
```

`accept-new` accepts and records an unknown key but still rejects a changed known key.
It changes the controller's known-host state. Do not use it as a workaround for a key
mismatch; resolve unexpected key changes before retrying.

## Non-default port and connection timeout

```bash
dacctl run ssh htb-malevolent-modmaker \
  --host lab.example \
  --port 2222 \
  --user analyst \
  --connection-timeout 20 \
  --acquisition-timeout 600 \
  --remote-file /srv/evidence/sample.bin
```

The connection timeout must be from 1 through 300 seconds and controls each SSH
connection establishment. The acquisition timeout must be from 1 through 3,600 seconds
and bounds the complete Ansible process group, including inspection and transfer. Both
are separate from the detector timeout.

## Privilege escalation

Use elevation only when the SSH account cannot read a required path:

```bash
dacctl run ssh htb-malevolent-modmaker \
  --host 10.10.10.10 \
  --user htb \
  --become \
  --ask-become-pass \
  --remote-file /restricted/evidence/sample.bin
```

`--ask-become-pass` requires `--become`. Elevation broadens readable data and can cause
Ansible to buffer a remote file while determining its checksum. Reduce limits before an
elevated run and request the smallest possible file set.

## Transfer and detector limits

Apply limits exactly as for local acquisition:

```bash
dacctl run ssh htb-malevolent-modmaker \
  --host 10.10.10.10 \
  --user htb \
  --remote-file /opt/evidence/artifact-one \
  --max-file-size 32MiB \
  --max-total-size 64MiB \
  --max-files 5 \
  --timeout 5
```

Remote `stat` metadata is used to exclude ineligible files before fetch. Every inspection
and fetch result is recorded separately. A failed checksum or fetch outcome is rejected
even if Ansible left a residual destination file. The fetched copy is then subjected to
local limits and hashing again. A target can change a file between inspection and
transfer, so controller-side verification remains authoritative.

## Target-side behavior

The core-owned playbook performs `stat` and `fetch` operations. It does not run a pack
script, execute an artifact, install an agent, or create the evidence report remotely.
Ansible can use transient module staging on the remote account; normal Ansible cleanup
applies. Controller inventory, status files, fetch staging, and control paths live in an
owner-only temporary directory and are deleted when the adapter exits.

## Partial acquisition

The playbook continues across path-level conditions when the connection itself remains
usable. Missing, linked, non-regular, inaccessible, oversized, or unfetched paths become
acquisition issues. If at least one file succeeds, detections run on that subset and the
command returns `2`. If no regular remote artifact succeeds, the command stops with an
operational error and writes no normal run report.

## Completion criteria

- The report identifies source `ssh` and the intended host and port.
- Artifact display paths correspond only to explicitly requested paths.
- Acquisition issues are zero, or the result is labeled incomplete.
- No credential appears in the report, retained manifest, command history, or pack.
- `accept-new` and `become`, if used, are recorded as operator decisions.
- Retained evidence, if requested, is handled under the replay playbook.
