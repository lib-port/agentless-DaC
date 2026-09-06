# Playbook: Detection Pack lifecycle

## Scope

Manage independently versioned first-party packs using the container workflow.
External Detection Pack submissions and pull requests are not accepted. Validation,
archive preparation and publication are manual; the GitHub workflows handle mirroring
and completed-run retention.

Pack code is executable and must be trusted before use. A matching archive digest
proves consistency with expected metadata, not that the code is safe.

## Inspect and validate

```bash
dacctl pack list
dacctl pack validate htb-malevolent-modmaker
dacctl pack validate htb-malevolent-modmaker@0.1.2
dacctl pack validate ./packs/htb-malevolent-modmaker
dacctl pack available --registry ./registry/packs.yml
```

The source-tree pack is an explicitly known source input. Detection execution always
uses the selected pack inside the container workflow; an explicit source path is
admitted read-only and does not authorise native execution.

Installed packs live in managed storage. The launcher rejects `--destination-root`
instead of writing installed pack code into arbitrary host directories. Exact versions
can be selected with `pack-id@version`.

## Install a local archive

Verify a trusted archive against an inspected registry copy:

```bash
dacctl pack verify ./htb-malevolent-modmaker-0.1.2.tar.gz \
  --registry ./registry/packs.yml
dacctl pack install ./htb-malevolent-modmaker-0.1.2.tar.gz \
  --sha256 5bbac3d60c288865b37afc4a3e7e34aa33d3d421376ec02f4ce31d565023f57b
```

A local install requires an explicit lowercase SHA-256. Do not trust a digest obtained
only alongside an untrusted archive. Installation validates the pack, compatibility,
identity and archive structure before admitting it to managed storage.

Unsafe paths, links, devices, duplicate archive entries, excessive expanded size and
excessive member counts are rejected. An already installed identical version is not
silently overwritten.

If the archive exactly matches the pack already bundled in the immutable image,
installation verifies its digest and content and reports that it is already available.
It does not create a duplicate managed installation. The same identity with different
content is rejected.

## Install a published registry version

```bash
dacctl pack available
dacctl pack install htb-malevolent-modmaker@0.1.2
```

These commands require the registry and matching immutable release asset to have
actually been published. A registry entry in a checkout is not evidence of publication.

Network downloads run in a separate disposable workload with no evidence or target
credential mounts. Registry and archive URLs require credential-free HTTPS and bounded
downloads. The archive digest must match registry metadata before installation.

## Build and validate a release

Run the container suite, including the pack's synthetic tests:

```bash
scripts/container-build
scripts/container-test
scripts/container-verify
dacctl pack validate htb-malevolent-modmaker
```

Do not substitute host `pytest` or directly invoke detector entrypoints. Runtime or
integration failures remain release blockers until resolved or explicitly recorded as
unvalidated work. Live network validation is additional to offline verification; see
[the container playbook](containers.md).

Choose a canonical stable `X.Y.Z` pack version independently of the core. A change
to shipped code, metadata, tests or documentation changes the archive and requires an
appropriate new version and digest. Update the manifest, registry identity/URL/tag and
versioned documentation together.

Build twice into different directories:

```bash
dacctl pack build htb-malevolent-modmaker --output ./dist-a
dacctl pack build htb-malevolent-modmaker --output ./dist-b
cmp ./dist-a/htb-malevolent-modmaker-0.1.2.tar.gz \
  ./dist-b/htb-malevolent-modmaker-0.1.2.tar.gz
sha256sum ./dist-a/htb-malevolent-modmaker-0.1.2.tar.gz
```

The builder refuses an existing archive name and must not publish a partial file on
failure. Host archive export is limited to 20 MiB, separately from the 64 MiB download
limit and expanded-archive limits. Confirm byte-for-byte equality, record the final
digest in `registry/packs.yml`, and verify it:

```bash
dacctl pack verify ./dist-a/htb-malevolent-modmaker-0.1.2.tar.gz \
  --registry ./registry/packs.yml
```

Inspect the pack tree for restricted artefacts, credentials, live malware, generated
bytecode and unexpected files. Every pack archive must include its own licence.

## Smoke-test and publish

Use a fresh managed installation state when validating an unpublished version. Install
the final archive with its recorded digest, validate the exact version, and run a clean
synthetic fixture through `dacctl run files`. Do not edit an installed immutable version
or bypass duplicate-version rejection.

Prepare a checksum record from a staging directory containing the final archive:

```bash
sha256sum htb-malevolent-modmaker-0.1.2.tar.gz > SHA256SUMS
sha256sum --check SHA256SUMS
```

Manually create the GitHub release with the exact registry tag and upload the archive
plus `SHA256SUMS`. Published assets are immutable. Afterwards, verify registry listing
and installation by exact ID/version through a fresh managed environment. Preserve
the validation results, host/runtime versions, image IDs, build digests, final registry,
tag and release checksum.

## Version selection

Use an exact reference such as `htb-malevolent-modmaker@0.1.2` when a recorded
procedure depends on rule behaviour. Keep earlier trusted immutable versions when
rollback is required. The CLI has no automatic rollback or pack uninstall command;
do not remove unrelated Podman volumes to reset an installation.
