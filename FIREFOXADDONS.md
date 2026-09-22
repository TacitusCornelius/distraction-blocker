# Firefox and LibreWolf release

This repository ships a Firefox-compatible Manifest V2 adapter in
`extension/firefox/`. Version 1.9.2 uses the same shared core as Chromium and
has a stable Gecko add-on ID. The browser extension is only one part of the
installation: the Ubuntu root service and native-messaging host are required
for enforcement.

## Production distribution

Use Mozilla's AMO self-distribution channel for production Firefox and
LibreWolf installs. This keeps the add-on out of the public AMO listing while
still obtaining Mozilla's signature. A normal branded Firefox install should
use the signed XPI; the unsigned archive produced locally is an AMO submission
artifact, not a production install.

LibreWolf is Firefox-derived, but its own configuration controls whether
unsigned or restricted add-ons are accepted. The AMO-signed XPI is the safest
common distribution artifact for both browsers. The repository's acceptance
harness deliberately disables signature checks in a disposable VM; that is not
an end-user installation procedure.

## Build the AMO submission archive

Run from the repository root:

```bash
python3 extension/build.py
python3 scripts/package_firefox_extension.py
```

The script creates:

```text
dist/distraction-blocker-firefox-1.9.2.xpi
```

The XPI contains `manifest.json` at its root, preserves the stable Gecko ID,
uses deterministic ZIP metadata, and excludes Python caches and platform
metadata. It is unsigned until AMO processes it.

The Gecko manifest declares `browsingActivity` as required because the
extension must inspect requested URLs to enforce the user's configured policy
and reports bounded observations only to the locally installed native host.
It does not request page content, interaction, or optional data categories.

Do not modify an XPI after Mozilla signs it. In particular, do not unzip and
repack the signed file, because that invalidates the signature.

## AMO source-code archive

Because the Firefox adapter is generated from shared JavaScript modules,
select **Yes** when AMO asks whether source code is required. Build the
reviewer source archive with:

```bash
python3 scripts/package_firefox_source.py
```

The output is `dist/distraction-blocker-firefox-source.zip`. It contains the
shared source modules, Firefox adapter sources and assets, the build script,
the XPI packager, and `extension/README.md` with the operating-system,
Python-version, dependency, and exact reproduction instructions. Generated
`extension/firefox/core/` copies are intentionally omitted; reviewers
recreate them with `python3 extension/build.py` before packaging the XPI.

Upload this source ZIP in AMO's source-code field. Upload the XPI separately
as the add-on artifact.

## AMO submission notes

Use these notes in the AMO submission metadata:

### Version notes

> Version 1.9.2 fixes timed-allowance usage reporting by persisting the
> service lease ID with every queued usage interval. It also discards reports
> whose in-memory service lease was invalidated by a service restart. The
> extension requires the Distraction Blocker Ubuntu service and
> native-messaging host. No remote account or developer server is used.


### Notes to reviewer

> No website account is required. This is a desktop-only local policy adapter.
> Testing requires the Distraction Blocker Ubuntu service and native-messaging
> host to be installed first; see `FIREFOXADDONS.md`. The extension
> communicates only with the locally installed
> `org.distraction_blocker.extension` host. Configure a browser rule, load a
> matching URL, and verify that Firefox blocks the request and reports the
> bounded denial to the local service.

## AMO self-distribution

1. Sign in to the [AMO Developer Hub](https://addons.mozilla.org/developers/).
2. Submit the generated XPI as a new add-on.
3. Select the self-distribution or **On your own** distribution path rather
   than publishing a public AMO listing.
4. Complete Mozilla's validation, listing, privacy, and review information.
5. Download the Mozilla-signed XPI produced for the approved version.
6. Distribute that signed XPI from a controlled release location.

For updates, increment the version in both adapter manifests, rebuild the
shared core, submit the new XPI for AMO signing, and distribute the new signed
artifact. Keep the Gecko ID unchanged:

```text
{e4f1a2b3-9c8d-4e5f-a6b7-8c9d0e1f2a3b}
```

This release does not configure a self-hosted Firefox update manifest because
no public update URL is owned by the project yet. Until one exists, update
users by distributing each newly signed XPI deliberately. Never point
`update_url` at an unowned or temporary location.

## Install on Firefox or LibreWolf

Install the Ubuntu service and native host first:

```bash
sudo python3 scripts/install.py --confirm --owner-uid "$(id -u)"
```

Then install the signed XPI:

1. Open the browser's Add-ons or Extensions page.
2. Choose **Install Add-on From File** from the add-ons settings menu.
3. Select the signed `distraction-blocker-firefox-1.9.2.xpi`.
4. Confirm the installation and verify that the add-on ID is
   `{e4f1a2b3-9c8d-4e5f-a6b7-8c9d0e1f2a3b}`.

A hosted download may also be offered from a controlled HTTPS site. For a
browser install link, serve the signed artifact with the MIME type
`application/x-xpinstall`. Do not serve the unsigned build to production
users.

The root installer places the native host manifest in the Firefox and
LibreWolf system and per-user locations. It allows the stable Gecko ID above;
if that ID changes, update the manifest, native host allowlist, tests, and
release artifact together.

## Validation

The repository's Firefox acceptance harness uses an unsigned extension only
inside a marked disposable VM. Run it only according to the VM procedure in
`README.md`; it is not a substitute for AMO signing or a production browser
install.

Mozilla references:

- [Signing and distribution overview](https://extensionworkshop.com/documentation/publish/signing-and-distribution-overview/)
- [Distributing an add-on yourself](https://extensionworkshop.com/documentation/publish/self-distribution/)
- [Package your extension](https://extensionworkshop.com/documentation/publish/package-your-extension/)
- [Submitting an add-on](https://extensionworkshop.com/documentation/publish/submitting-an-add-on/)
