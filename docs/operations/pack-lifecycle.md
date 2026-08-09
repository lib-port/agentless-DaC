# Playbook: Detection Pack lifecycle

## Scope

This playbook covers operator installation and the maintainer's manual release process
for the sole first-party pack. External Detection Pack submissions and pull requests are
not accepted. GitHub Actions are not used.

## Inspect discoverable and available packs

List locally discoverable versions:

```bash
dacctl pack list
```

List registry entries:

```bash
dacctl pack available
```

Use a local registry during offline review:

```bash
dacctl pack available --registry ./registry/packs.yml
```

Validate a discovered pack by ID, exact version, or source path:

```bash
dacctl pack validate htb-malevolent-modmaker
dacctl pack validate htb-malevolent-modmaker@0.1.1
dacctl pack validate ./packs/htb-malevolent-modmaker
```

## Install from the registry

```bash
dacctl pack install htb-malevolent-modmaker
```

Pin an exact version when operational reproducibility requires it:

```bash
dacctl pack install htb-malevolent-modmaker@0.1.1
```

The installation fails if the version is incompatible with the core, the HTTPS download
exceeds its limit, the digest differs, the archive is unsafe, the embedded identity does
not match, or the same version is already installed.

## Install a local archive

First verify it against an inspected registry copy:

```bash
dacctl pack verify ./htb-malevolent-modmaker-0.1.1.tar.gz \
  --registry ./registry/packs.yml
```

Then install with the explicit digest:

```bash
dacctl pack install ./htb-malevolent-modmaker-0.1.1.tar.gz \
  --sha256 79083d7e291a4687edae28c91df153c652772899c483a34bc91ee47eeb732e1b
```

Do not accept a digest delivered only alongside an untrusted archive; compare it with an
independently obtained registry or release record.

## Build a source-tree pack

```bash
dacctl pack validate htb-malevolent-modmaker
dacctl pack build htb-malevolent-modmaker --output ./dist
```

The output directory may exist, but the builder refuses to overwrite the target archive.
It prints the archive path and SHA-256.

Run the tests embedded in the unpacked pack with the core and pytest installed:

```bash
pytest packs/htb-malevolent-modmaker/tests
```

## Maintainer release procedure

There is no automated validation or release workflow. The maintainer performs every
step locally.

### 1. Choose and apply the version

Use stable canonical `X.Y.Z` semantic versions for the pack independently of the core.
Prerelease and build suffixes are not part of the v1 pack contract. Update:

- `pack.yml` pack version;
- `registry/packs.yml` version, archive name, URL, and release tag;
- versioned commands or digests in documentation when present.

Changing detection behavior, metadata with operational meaning, pack tests, or shipped
documentation changes the archive and therefore requires a new digest. Use an
appropriate version increase rather than replacing an already published archive.

### 2. Validate source and tests

```bash
ruff check .
ruff format --check .
pytest
dacctl pack validate htb-malevolent-modmaker
ansible-playbook --syntax-check -i 'dac_target,' \
  src/detection_goggles/ansible/fetch_files.yml
python -m build
```

Review the pack tree and confirm it contains no live malware, challenge answers,
credentials, flags, decrypted victim data, bytecode, or unexpected files.

### 3. Build twice

Use two empty directories:

```bash
PACK_VERSION="0.1.1"
dacctl pack build htb-malevolent-modmaker --output ./dist-a
dacctl pack build htb-malevolent-modmaker --output ./dist-b
cmp "./dist-a/htb-malevolent-modmaker-${PACK_VERSION}.tar.gz" \
  "./dist-b/htb-malevolent-modmaker-${PACK_VERSION}.tar.gz"
```

Any byte difference blocks release until explained.

### 4. Record the digest

```bash
PACK_VERSION="0.1.1"
sha256sum "./dist-a/htb-malevolent-modmaker-${PACK_VERSION}.tar.gz"
```

Put that exact lowercase digest in `registry/packs.yml` and any version-specific install
example. Rebuild only if a file inside the pack changed; registry and root documentation
are not part of the pack archive.

### 5. Verify registry consistency

```bash
PACK_VERSION="0.1.1"
dacctl pack verify "./dist-a/htb-malevolent-modmaker-${PACK_VERSION}.tar.gz" \
  --registry ./registry/packs.yml
```

Run the complete test suite again because a digest mismatch is a release-blocking test.

### 6. Smoke-test installation

Use an empty temporary destination and the recorded digest:

```bash
PACK_VERSION="0.1.1"
PACK_SHA256="replace-with-recorded-lowercase-sha256"
dacctl pack install "./dist-a/htb-malevolent-modmaker-${PACK_VERSION}.tar.gz" \
  --destination-root ./release-smoke/packs \
  --sha256 "${PACK_SHA256}"
dacctl pack validate \
  "./release-smoke/packs/htb-malevolent-modmaker/${PACK_VERSION}"
```

Run its self-contained tests from the installed version directory, then run one clean
fixture through `dacctl run files`.

### 7. Prepare release files

From a staging directory containing only the final archive:

```bash
PACK_VERSION="0.1.1"
PACK_ARCHIVE="htb-malevolent-modmaker-${PACK_VERSION}.tar.gz"
sha256sum "${PACK_ARCHIVE}" > SHA256SUMS
sha256sum --check SHA256SUMS
```

Manually create the GitHub release with the exact `release_tag` recorded in the registry
and upload the archive plus `SHA256SUMS`. Do not mutate or replace those assets after
publication.

### 8. Post-release verification

After publication:

```bash
PACK_VERSION="0.1.1"
dacctl pack available
dacctl pack install "htb-malevolent-modmaker@${PACK_VERSION}" \
  --destination-root ./release-download-smoke
```

Confirm the installed identity and run a clean fixture. Preserve the local validation
record, both build digests, final registry, tag, and release asset checksum.

## Version selection and rollback

When multiple versions are installed, an unversioned ID resolves to the newest version
compatible with the core from the first trusted root containing that pack ID.
Operational procedures that require stable behavior should always use an exact reference
such as `htb-malevolent-modmaker@0.1.1`.

There is no uninstall or automatic rollback command. Keep prior immutable versions when
rollback is a requirement. Removal is a manual operator action after resolving the exact
versioned directory.
