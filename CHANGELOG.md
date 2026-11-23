<!--
SPDX-FileCopyrightText: 2024 Foundation Devices Inc.

SPDX-License-Identifier: MIT
-->

## Unreleased

* Added `Tor.stopAllInProcess()`, which stops every Tor proxy in the process, including one whose isolate died without stopping it, cancels every start and bootstrap in flight, and waits for them to end.
* Added `TorProxyFailure.processWideStop`, set when `Tor.stopAllInProcess()` caused the failure. The generated `waitForProxyExit` now returns a `TorProxyLoss` instead of a message.
* `Tor.stop()` issues the native stop of the published proxy at once instead of queueing it behind a bootstrap or dormant call in flight. The client is still disposed after them.
* Stopping a proxy now also releases its native client, even if a Dart wrapper is never disposed. A native `bootstrap` of that client then fails with `ClientNotInitialized`, and `setDormant` does nothing. A bootstrap already running on it ends with the stop.
* The client is dropped on a release thread. A stop waits up to 5 seconds for that and otherwise fails with a timeout, while the drop carries on. A client whose tasks didn't stop in time is dropped once they end, so Arti's locks come back.
* A start cancelled after its bootstrap finished now fails natively with a cancelled-bootstrap error, instead of returning a proxy for Dart to tear down.
* A stop of a proxy that another stop is already stopping now waits for that stop to finish.
* The Android build no longer pins its own Android Gradle Plugin on a buildscript classpath; the app's is used, as it already was. The plugin's `android/` directory therefore can't be synced on its own, outside an app.

## 0.2.2

* Added compatibility with Gradle 9.1 and Android Gradle Plugin 9.0.1.
* Updated the Android build to compile against API 36 with Java 17 and a minimum SDK of 24.
* Pinned `flutter_rust_bridge` to 2.11.1 to match the generated bindings.

## 0.2.1

* Migrated native bindings to `flutter_rust_bridge`.
* Hardened Tor startup, liveness checks, cancellation, and deterministic shutdown.
* Added support for a caller-configurable Tor data directory.
* Fixed iOS initialization, plugin packaging, and `.onion` SOCKS connections.
* Reduced sensitive environment output from Apple builds.

## 0.0.9

* Bumped arti to version 1.4.3

## 0.0.8

* Bumped arti to version 1.2.7

## 0.0.7

* Relicensed to MIT

## 0.0.6

* Pinned 'time' to a specific version

## 0.0.5

* Added rust-toolchain file

## 0.0.4

* Bumped arti to version 1.2.4

## 0.0.3

* Added functions to stop and restart the proxy.

## 0.0.2

* Fixed the Windows build.

## 0.0.1

* Initial release.
