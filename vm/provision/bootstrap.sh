#!/usr/bin/env bash
set -euo pipefail

readonly TARGET_IP=${1:-}
readonly TARGET_PORT=${2:-}
readonly TARGET_HOST_KEY=${3:-}
readonly EXPECTED_COMMIT=${4:-}
readonly SOURCE_ARCHIVE=/tmp/dac-source.tar
readonly APP_ROOT=/opt/detection-goggles
readonly RUNTIME_ROOT=/var/lib/detection-goggles
readonly VENV_ROOT=/opt/detection-goggles/.venv
readonly VALIDATION_VENV=/tmp/dac-validation-venv

fail() {
  printf 'controller bootstrap: %s\n' "$*" >&2
  exit 1
}

[[ "$(id -u)" == 0 ]] || fail "bootstrap must run as root"
[[ "$TARGET_IP" =~ ^[0-9.]+$ ]] || fail "target must be a literal IPv4 address"
[[ "$TARGET_PORT" =~ ^[0-9]+$ ]] || fail "target port must be numeric"
((TARGET_PORT >= 1 && TARGET_PORT <= 65535)) || fail "target port is out of range"
[[ "$TARGET_HOST_KEY" =~ ^SHA256:[A-Za-z0-9+/]{43}$ ]] || fail "host fingerprint is invalid"
[[ "$EXPECTED_COMMIT" =~ ^[0-9a-f]{40}$ ]] || fail "commit ID is invalid"
[[ -f "$SOURCE_ARCHIVE" && ! -L "$SOURCE_ARCHIVE" ]] || fail "source archive is missing"
[[ ! -e "$APP_ROOT" ]] || fail "application root already exists"
[[ -z "${SSH_AUTH_SOCK:-}" ]] || fail "host SSH-agent forwarding must remain disabled"
if findmnt --raw --noheadings \
  --types 9p,vboxsf,fuse.vmhgfs-fuse,virtiofs,nfs,nfs4 | grep -q .; then
  fail "a host-sharing filesystem is mounted in the controller"
fi

python3 - "$TARGET_IP" <<'PY' || fail "target must be a unicast IPv4 address"
import ipaddress
import sys

address = ipaddress.ip_address(sys.argv[1])
if address.version != 4 or address.is_multicast or address.is_unspecified:
    raise SystemExit(1)
PY

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -y full-upgrade
apt-get install -y --no-install-recommends \
  ca-certificates nftables openssh-client openssh-server python3 python3-pip python3-venv sudo
apt-get clean

python3 - "$SOURCE_ARCHIVE" <<'PY'
import pathlib
import sys
import tarfile

archive = pathlib.Path(sys.argv[1])
with tarfile.open(archive, mode="r:") as handle:
    members = handle.getmembers()
    if not members:
        raise SystemExit("source archive is empty")
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts:
            raise SystemExit(f"unsafe source archive path: {member.name}")
        if not path.parts or path.parts[0] != "detection-goggles":
            raise SystemExit(f"source archive path has an unexpected root: {member.name}")
        if not (member.isdir() or member.isfile()):
            raise SystemExit(f"source archive contains a non-regular member: {member.name}")
PY

tar --extract --file "$SOURCE_ARCHIVE" --directory /opt --no-same-owner --no-same-permissions
rm -f -- "$SOURCE_ARCHIVE"
printf '%s\n' "$EXPECTED_COMMIT" >"${APP_ROOT}/.deployed-commit"

python3 -m venv "$VALIDATION_VENV"
"${VALIDATION_VENV}/bin/python" -m pip install \
  --disable-pip-version-check \
  --require-hashes \
  --only-binary=:all: \
  --requirement "${APP_ROOT}/requirements/vm.lock"
"${VALIDATION_VENV}/bin/python" -m pip install \
  --disable-pip-version-check \
  --no-build-isolation \
  --no-deps \
  "$APP_ROOT"
wheel_output="$(mktemp -d /tmp/dac-wheel-build.XXXXXX)"
"${VALIDATION_VENV}/bin/python" -m build --wheel --no-isolation \
  --outdir "$wheel_output" "$APP_ROOT"
runtime_wheel="$(find "$wheel_output" -maxdepth 1 -type f \
  -name 'detection_goggles-*.whl' -print -quit)"
[[ -n "$runtime_wheel" && -f "$runtime_wheel" ]] || fail "core wheel build did not produce output"

python3 -m venv "$VENV_ROOT"
"${VENV_ROOT}/bin/python" -m pip install \
  --disable-pip-version-check \
  --require-hashes \
  --only-binary=:all: \
  --requirement "${APP_ROOT}/requirements/vm-runtime.lock"
"${VENV_ROOT}/bin/python" -m pip install \
  --disable-pip-version-check --no-deps "$runtime_wheel"
"${VENV_ROOT}/bin/python" -m pip uninstall --yes setuptools
"${VENV_ROOT}/bin/python" -m pip check

if ! id dac >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash dac
fi
passwd --lock dac >/dev/null
chmod 0700 /home/dac
install -d -o dac -g dac -m 0700 \
  "$RUNTIME_ROOT" \
  "${RUNTIME_ROOT}/cache" \
  "${RUNTIME_ROOT}/data" \
  "${RUNTIME_ROOT}/evidence" \
  "${RUNTIME_ROOT}/reports" \
  "${RUNTIME_ROOT}/tmp"

vagrant_home="$(getent passwd vagrant | cut -d: -f6)"
[[ -n "$vagrant_home" && -f "${vagrant_home}/.ssh/authorized_keys" ]] || \
  fail "Vagrant management authorized_keys was not found"
install -d -o dac -g dac -m 0700 /home/dac/.ssh
install -o dac -g dac -m 0600 \
  "${vagrant_home}/.ssh/authorized_keys" /home/dac/.ssh/authorized_keys

install -d -o root -g root -m 0755 /etc/detection-goggles
dpkg-query --show --showformat='${binary:Package}\t${Version}\n' | sort \
  >/etc/detection-goggles/os-packages.txt
chmod 0444 /etc/detection-goggles/os-packages.txt
cat > /etc/detection-goggles/controller.conf <<EOF
DAC_TARGET_IP=${TARGET_IP}
DAC_TARGET_PORT=${TARGET_PORT}
DAC_TARGET_HOST_KEY=${TARGET_HOST_KEY}
EOF
chmod 0644 /etc/detection-goggles/controller.conf
printf '%s\n' "$EXPECTED_COMMIT" >/etc/detection-goggles/commit
chmod 0444 /etc/detection-goggles/commit

install -o root -g root -m 0755 "${APP_ROOT}/vm/guest/dacctl" /usr/local/bin/dacctl
install -o root -g root -m 0755 "${APP_ROOT}/vm/guest/dac-key-init" /usr/local/bin/dac-key-init
install -o root -g root -m 0755 \
  "${APP_ROOT}/vm/guest/dac_export_report.py" /usr/local/bin/dac-export-report

chown -R root:root "$APP_ROOT"
chmod -R go-w "$APP_ROOT"

management_ip="${SSH_CLIENT%% *}"
if ! python3 - "$management_ip" <<'PY'
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit(1)
raise SystemExit(address.version != 4)
PY
then
  management_ip="$(ip -4 route show default | awk 'NR == 1 {print $3}')"
fi
[[ "$management_ip" =~ ^[0-9.]+$ ]] || fail "could not determine the libvirt management address"

cat >/etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
flush ruleset

table inet dac_filter {
  chain input {
    type filter hook input priority filter; policy drop;
    iifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    ip saddr ${management_ip} tcp dport 22 accept
    udp sport 67 udp dport 68 accept
  }

  chain forward {
    type filter hook forward priority filter; policy drop;
  }

  chain output {
    type filter hook output priority filter; policy drop;
    oifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    udp sport 68 udp dport 67 accept
    ip daddr ${TARGET_IP} tcp dport ${TARGET_PORT} accept
  }
}
EOF
chmod 0600 /etc/nftables.conf
nft --check --file /etc/nftables.conf
systemctl enable --now nftables
nft --numeric list chain inet dac_filter output | grep -Fq \
  "ip daddr ${TARGET_IP} tcp dport ${TARGET_PORT} accept"

run_as_dac() {
  runuser -u dac -- env \
    HOME=/home/dac \
    XDG_CACHE_HOME="${RUNTIME_ROOT}/cache" \
    XDG_DATA_HOME="${RUNTIME_ROOT}/data" \
    TMPDIR="${RUNTIME_ROOT}/tmp" \
    "$@"
}

cd "$APP_ROOT"
run_as_dac "${VALIDATION_VENV}/bin/ruff" check --no-cache .
run_as_dac "${VALIDATION_VENV}/bin/ruff" format --check --no-cache .
run_as_dac "${VALIDATION_VENV}/bin/pytest" -p no:cacheprovider
run_as_dac "${VENV_ROOT}/bin/dacctl" --pack-root "${APP_ROOT}/packs" \
  pack validate htb-malevolent-modmaker
pack_output="$(mktemp -d /tmp/dac-pack-build.XXXXXX)"
chown dac:dac "$pack_output"
run_as_dac "${VENV_ROOT}/bin/dacctl" --pack-root "${APP_ROOT}/packs" pack build \
  htb-malevolent-modmaker --output "$pack_output"
run_as_dac "${VENV_ROOT}/bin/ansible-playbook" --syntax-check \
  -i 'dac_target,' src/detection_goggles/ansible/fetch_files.yml
run_as_dac test ! -w "$APP_ROOT"
run_as_dac test ! -w /usr/local/bin/dacctl
rm -rf -- "$pack_output" "$wheel_output" "$VALIDATION_VENV"
"${VENV_ROOT}/bin/python" -m pip freeze --all \
  >/etc/detection-goggles/python-packages.txt
chmod 0444 /etc/detection-goggles/python-packages.txt

install -d -o root -g root -m 0755 /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/90-dac-controller.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no
AllowUsers vagrant dac
EOF
/usr/sbin/sshd -t
systemctl reload ssh

gpasswd --delete vagrant sudo >/dev/null 2>&1 || true
cat >/etc/sudoers.d/vagrant <<'EOF'
vagrant ALL=(root) NOPASSWD: /usr/sbin/shutdown, /usr/bin/systemctl poweroff, /usr/bin/systemctl reboot
EOF
chmod 0440 /etc/sudoers.d/vagrant
visudo -cf /etc/sudoers.d/vagrant >/dev/null
if sudo -l -U vagrant | grep -Eq 'NOPASSWD:[[:space:]]+ALL([[:space:]]|$)'; then
  fail "vagrant still has unrestricted passwordless sudo"
fi

printf '%s\n' \
  "Detection Goggles controller installed from ${EXPECTED_COMMIT}." \
  "The guest firewall now permits outbound traffic only to ${TARGET_IP}:${TARGET_PORT}."
