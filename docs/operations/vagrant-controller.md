# Playbook: disposable Vagrant controller

## Objective and boundary

Run Detection Goggles and Ansible in a disposable KVM virtual machine so Detection Pack
code, target credentials, and acquired artifacts do not execute or persist on the
physical controller host. Vagrant manages lifecycle; KVM/libvirt provides the isolation.

This profile is intentionally operational rather than a development environment. It
uploads one clean, committed source snapshot, disables synchronized folders, seals
outbound networking to one SSH target, and permits only rendered reports to return to
the host. It does not protect against a hypervisor escape, hostile host-side Vagrant
plugins or configuration, or an already compromised physical host.

## Supported host and prerequisites

The supported host is a bare-metal Debian 12 amd64 installation with hardware
virtualization enabled. Other distributions, architectures, Vagrant versions, and nested
virtualization are unsupported until they receive the complete physical-host validation
described below. The VM is configured for 2 vCPUs and 4 GiB RAM; leave additional CPU and
memory for the host and enough local storage for the box, guest disk, acquired evidence,
and reports.

Run from a trusted Git checkout. Wheel and source-distribution installations do not carry
the reviewed commit identity required by `scripts/vm-init`. On Debian 12, install the
host tools without the distribution's older `vagrant-libvirt` recommendation:

```bash
sudo apt-get update
sudo apt-get install --no-install-recommends \
  build-essential ebtables git libguestfs-tools libvirt-clients \
  libvirt-daemon-system libvirt-dev libxml2-dev libxslt1-dev openssh-client \
  pkg-config python3 python3-pip python3-venv qemu-system-x86 qemu-utils \
  ruby-dev vagrant zlib1g-dev
sudo systemctl enable --now libvirtd
sudo usermod --append --groups kvm,libvirt "$USER"
```

Log out of the physical host completely and log in again so the new group membership is
effective. Debian 12 supplies Vagrant 2.3.4. Do not install Debian 12's packaged
`vagrant-libvirt` 0.11.2; install the reviewed provider version into Vagrant instead:

```bash
vagrant plugin install vagrant-libvirt --plugin-version 0.12.2
```

Verify the exact supported toolchain before handling evidence:

```bash
. /etc/os-release
test "$ID" = debian && test "$VERSION_ID" = 12
test "$(dpkg --print-architecture)" = amd64
test "$(systemd-detect-virt)" = none
test -c /dev/kvm && test -r /dev/kvm && test -w /dev/kvm
virsh -c qemu:///system list
test "$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')" = 3.11
test "$(vagrant --version)" = "Vagrant 2.3.4"
test "$(vagrant plugin list | sed -n \
  's/^vagrant-libvirt (\([^,)]*\).*/\1/p')" = 0.12.2
```

If the final command does not match, inspect `vagrant plugin list` and correct the
installation. Proceed only when it lists one active `vagrant-libvirt` version and that
version is exactly `0.12.2`. Never run Vagrant or these project scripts as root.

The controller uses the official `debian/bookworm64` libvirt box at the exact version
and SHA-256 recorded in `scripts/vm-init`. Initialization checks the live box metadata
against that reviewed digest before Vagrant downloads or starts the box.

## Confirm the target host key

Obtain the SSH host-key fingerprint through a trusted channel that does not depend on
the new controller connection. For example, an authorized target administrator can run:

```bash
ssh-keygen -E sha256 -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Record the literal target IPv4 address, SSH port, and `SHA256:...` fingerprint. Hostnames
are deliberately not accepted because the sealed guest has no general DNS or network
access.

## Create and seal the controller

Commit and review every intended repository change. Initialization rejects staged,
unstaged, and untracked changes. Its `git archive` includes only committed paths, so
ignored artifacts and local credentials are not copied accidentally.

```bash
scripts/vm-init \
  --target-ip 192.0.2.10 \
  --target-port 22 \
  --host-key-fingerprint SHA256:REPLACE_WITH_VERIFIED_FINGERPRINT
```

Initialization performs these one-time operations in this order:

1. verifies Debian-host prerequisites, exact Vagrant/provider versions, box status, and
   the reviewed box checksum;
2. uploads a temporary `git archive` without mounting the host repository;
3. fully updates the guest and installs hash-pinned validation and runtime environments;
4. builds the project wheel, creates unprivileged user `dac`, makes application code
   root-owned, and records OS and Python package inventories;
5. enables the default-deny nftables policy before executing project or Detection Pack
   code, allowing egress only to the declared target and SSH port;
6. runs Ruff, pytest, pack validation/build, and Ansible syntax validation, then removes
   validation tooling from the guest;
7. disables forwarding, removes general passwordless sudo, deletes the host-side source
   archive, reboots the VM, and runs `scripts/vm-verify` after the reboot.

After sealing, outbound guest traffic is limited to the declared target and SSH port.
Changing targets requires destroying and rebuilding the VM.

If initialization fails before Vagrant is invoked, temporary state is removed and the
reported preflight problem can be corrected before retrying. After Vagrant has been
invoked, treat any failed provisioning, reboot, or verification as an incomplete
controller: run `scripts/vm-destroy`, revoke a target key if one was already registered,
fix the cause, and rebuild from a clean commit. Do not delete `.vagrant` state manually or
continue using a partially provisioned guest.

## Verify the sealed controller

Initialization performs verification automatically. Run it again after any host or guest
reboot and before acquiring evidence:

```bash
scripts/vm-verify
```

The command does not alter sealed configuration and returns nonzero unless the VM is
running and all of these conditions hold:

- the guest commit and sealed target configuration match `.vagrant/dac-vm.json`;
- the physical host still has the exact Vagrant and provider versions;
- no host-sharing filesystem or physical-host SSH agent is visible;
- application files and command wrappers are root-owned and not writable by `dac`;
- runtime locations are owner-only and the temporary validation environment is absent;
- OS and Python package inventories exist and nftables is active;
- the CLI, exact source-tree pack, and Ansible syntax checks succeed.

Provisioning checks the actual target allowlist rule when it enables nftables. The
physical-host release test additionally proves allowed and denied network behavior; an
active service alone is not evidence that an edited policy remains correct.

## Create and register the per-VM target key

Open an unprivileged controller shell and initialize its identity:

```bash
scripts/vm-shell
dac-key-init
```

`dac-key-init` verifies the scanned key against the preconfigured fingerprint and then
requires a non-empty passphrase for a new Ed25519 private key. The private key remains
inside the guest. If key generation is interrupted or an empty passphrase is entered,
destroy the VM rather than reusing its disk. Register the printed public key on a
dedicated, least-privileged target account. Where the source address is stable, prepend
restrictions similar to:

```text
from="CONTROLLER_EGRESS_ADDRESS",restrict ssh-ed25519 AAAA... dac-controller-...
```

`restrict` disables forwarding, PTY allocation, and user startup files while still
allowing the commands Ansible needs. Confirm compatibility with the target OpenSSH
version. Grant the account read access only to intended artifacts. Avoid remote sudo;
if it is unavoidable, constrain it on the target and use `--become` only for the named
run.

Start a guest-local agent for each operator session:

```bash
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/dac_target_ed25519
```

This agent exists inside the VM; the physical host's agent is never forwarded.

## Run an acquisition

From `scripts/vm-shell`, use the exact preconfigured IP and port:

```bash
dacctl run ssh htb-malevolent-modmaker \
  --host 192.0.2.10 \
  --port 22 \
  --user dac-reader \
  --remote-file /absolute/authorized/artifact-one \
  --remote-file /absolute/authorized/artifact-two \
  --identity ~/.ssh/dac_target_ed25519 \
  --host-key-policy strict
```

Reports remain under `/var/lib/detection-goggles/reports`; temporary acquisitions and
raw snapshots stay on the guest. For local-file mode, create or acquire files directly
under `/var/lib/detection-goggles/evidence` from within the isolated environment. There
is deliberately no raw-artifact host upload command.

The controller has no general DNS, HTTPS, package-index, or registry access after it is
sealed. Do not attempt to update Debian, install Python packages, install Detection Packs,
or change application code in place. A different commit, pack, dependency set, target,
box, or network policy requires a new controller.

## Export reports

Note the run ID printed by `dacctl`, leave the guest shell, and pull only its two rendered
reports:

```bash
scripts/vm-pull-report RUN_ID
```

The default destination is `reports/RUN_ID` on the host. The command refuses traversal,
links, files over 10 MiB, existing destinations, missing formats, and evidence paths. It
creates the exported files with mode `0600`. Report content remains untrusted: inspect it
with a non-executing text or JSON viewer and do not automatically render Markdown or
follow embedded links.

## Destroy and revoke

When the run is complete—or immediately after suspected compromise—destroy the guest:

```bash
scripts/vm-destroy
```

Remove the `dac-controller-...` public-key entry from the target account. VM destruction
removes the private key, evidence, report originals, and application environment. It does
not remove reports explicitly exported to the host.

Do not use VM snapshots as long-term rollback points containing credentials or evidence.
Recreate from the pinned box and reviewed commit instead.

If destruction fails, assume the guest disk and private key still exist. Revoke the
target public key immediately, restore libvirt access, inspect `vagrant status controller`,
and repeat `scripts/vm-destroy`. A successful message from that script is the lifecycle
signal that Vagrant destruction completed; it does not erase reports already exported.

For other failures, follow the
[VM-specific troubleshooting procedure](troubleshooting.md#disposable-controller-vm).

## Updating the profile

Treat base-box, lock-file, provisioning, and network-policy changes as security changes:

1. review an active official Debian libvirt box and its provider SHA-256;
2. update the matching version and digest in both `Vagrantfile` and `scripts/vm-init`;
3. on Debian 12 amd64 with CPython 3.11, update and validate every transitive dependency:

   ```bash
   scripts/vm-locks update
   git diff -- requirements/vm.lock requirements/vm-runtime.lock
   scripts/vm-locks check
   ```

4. review every resolved version and wheel digest, then run the repository validation
   suite and the physical-host procedure below;
5. destroy every old controller and build a new VM instead of upgrading it in place.

Never regenerate dependency hashes from an untrusted index or approve an update solely
because its digest changed consistently. `scripts/vm-locks` uses canonical PyPI, accepts
binary wheels only, and verifies installation with hashes; this establishes repeatability,
not package trust.

## Physical-host release validation

Before describing a profile revision as operationally validated, use a clean physical
Debian 12 amd64 test host and a controlled POSIX SSH target containing only synthetic,
non-sensitive fixtures:

1. install the host exactly as documented and record Debian, kernel, QEMU, libvirt,
   Vagrant, provider, box, commit, and Python dependency versions;
2. initialize the VM, run `scripts/vm-verify`, reboot with `vagrant reload controller`,
   and run `scripts/vm-verify` again;
3. confirm `dac-key-init` accepts the out-of-band target fingerprint and strict SSH to the
   allowlisted target succeeds;
4. confirm DNS, HTTPS, and a controlled second IPv4 destination fail from the guest while
   the target connection remains usable;
5. acquire a synthetic regular file, confirm the expected exit code, and export both
   reports with `scripts/vm-pull-report`;
6. confirm report traversal, symbolic-link, hard-link, oversize, missing-format, raw-data,
   and existing-destination attempts are rejected without publishing partial output;
7. confirm the host agent and shared mounts remain absent, record the domain UUID from
   `.vagrant/machines/controller/libvirt/id`, destroy the guest, confirm
   `virsh -c qemu:///system dominfo DOMAIN_UUID` fails, and revoke the public key.

Record failures as failures; do not relax a pin, firewall rule, host-key policy, export
check, or permission merely to complete the checklist. This repository's current nested
VirtualBox environment can run static checks but cannot satisfy this physical-host gate.
