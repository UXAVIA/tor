// SPDX-FileCopyrightText: 2026 Foundation Devices Inc.
//
// SPDX-License-Identifier: MIT

import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:tor/src/rust/api/tor.dart' as rust;
import 'package:tor/tor.dart';

import 'support/tor_test_support.dart';

void main() {
  final native = setUpTorTests();
  final tor = Tor.instance;

  test('overlapping stops both report failed teardown', () async {
    native.startResult.complete(native.instance);
    await tor.start();
    native.stopError = const rust.TorError.proxyStopError('cleanup timed out');

    final first = tor.stop();
    final second = tor.stop();
    await Future.wait([
      expectLater(first, throwsA(isA<rust.TorError>())),
      expectLater(second, throwsA(isA<rust.TorError>())),
    ]);
    expect(native.stops, 1);
  });

  test('stop issues the native stop before it returns', () async {
    native.startResult.complete(native.instance);
    await tor.start();

    final stop = tor.stop();
    expect(native.stops, 1);
    await stop;
    expect(native.instance.client.isDisposed, isTrue);
  });

  test(
      'stop does not hold the native stop behind an active dormant call, '
      'but still disposes the client after it', () async {
    native.startResult.complete(native.instance);
    await tor.start();
    final dormant = tor.setClientDormant(true);
    await native.dormantEntered.future;

    final stop = tor.stop();
    await Future<void>.delayed(Duration.zero);
    final stopsWhileDormantPending = native.stops;
    final disposedWhileDormantPending = native.instance.client.isDisposed;
    native.dormantResult.complete();
    await Future.wait([dormant, stop]);

    expect(stopsWhileDormantPending, 1);
    expect(disposedWhileDormantPending, isFalse);
    expect(native.instance.client.isDisposed, isTrue);
    expect(native.stops, 1);
  });

  test('stop disposes the client only after the native stop resolves',
      () async {
    native.startResult.complete(native.instance);
    await tor.start();
    final gate = native.stopGate = Completer<void>();

    final stop = tor.stop();
    await Future<void>.delayed(Duration.zero);
    final stopsWhileGated = native.stops;
    final disposedWhileGated = native.instance.client.isDisposed;
    gate.complete();
    await stop;

    expect(stopsWhileGated, 1);
    expect(disposedWhileGated, isFalse,
        reason: 'the client was disposed before the native stop resolved');
    expect(native.instance.client.isDisposed, isTrue);
  });

  test('a native stop that fails early is reported once, by stop', () async {
    native.startResult.complete(native.instance);
    await tor.start();
    final dormant = tor.setClientDormant(true);
    await native.dormantEntered.future;
    native.stopError = const rust.TorError.proxyStopError('cleanup timed out');

    final stop = tor.stop();
    final stopFailed = expectLater(stop, throwsA(isA<rust.TorError>()));
    // The native stop has failed while the dispose is still queued.
    await Future<void>.delayed(Duration.zero);
    native.dormantResult.complete();

    await dormant;
    await stopFailed;
    expect(native.stops, 1);
    expect(native.instance.client.isDisposed, isTrue);
  });

  test('stopAllInProcess returns how many proxies the native sweep stopped',
      () async {
    native.sweepResult = 2;

    expect(await Tor.stopAllInProcess(), 2);
    expect(native.sweeps, 1);
  });

  test('a process-wide stop reaches a live owner as a proxy failure', () async {
    final failure = tor.failures.stream.first;
    native.startResult.complete(native.instance);
    await tor.start();
    native.sweepResult = 1;

    expect(await Tor.stopAllInProcess(), 1);

    final lost = await failure;
    expect(lost.message, 'Tor proxy was stopped by a process-wide stop');
    expect(lost.processWideStop, isTrue);
    expect(tor.port, -1);
    expect(tor.started, isFalse);
    // The owner's own stop still runs; natively it finds nothing left to do.
    expect(native.stops, 1);
    expect(native.instance.client.isDisposed, isTrue);
  });

  test('stop skips a queued dormant call from the previous generation',
      () async {
    native.startResult.complete(native.instance);
    await tor.start();
    native.dormantResult.complete();

    final dormant = tor.setClientDormant(true);
    final stop = tor.stop();
    await Future.wait([dormant, stop]);

    expect(native.dormantEntered.isCompleted, isFalse);
  });

  test('a second stop invalidates a replacement queued after the first stop',
      () async {
    native.startResult.complete(native.instance);
    await tor.start();
    final firstStop = tor.stop();
    native.startEntered = Completer();
    native.startResult = Completer()..complete(FakeTorInstance());
    final replacement = tor.start();
    final secondStop = tor.stop();

    await Future.wait([firstStop, replacement, secondStop]);

    expect(native.startEntered.isCompleted, isFalse);
    expect(tor.started, isFalse);
    expect(tor.port, -1);
    expect(native.stops, 1);
  });
}
