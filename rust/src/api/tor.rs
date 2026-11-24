// SPDX-FileCopyrightText: 2024 Foundation Devices Inc.
//
// SPDX-License-Identifier: MIT

use anyhow::Result;
use arti::proxy::{self, ListenProtocols};
use arti_client::config::CfgPath;
use arti_client::{DormantMode, TorClient, TorClientConfig};
use async_trait::async_trait;
use flutter_rust_bridge::frb;
use futures::channel::oneshot;
use futures::future::{self, Either, FutureObj};
use futures::stream::{FuturesUnordered, StreamExt};
use futures::task::{Spawn, SpawnError};
use futures::FutureExt;
use lazy_static::lazy_static;
use std::any::Any;
use std::cell::Cell;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use tokio::runtime::{Builder, Runtime as TokioRuntime};
use tokio::sync::watch;
use tokio::task::{AbortHandle, JoinHandle};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tor_config::Listen;
use tor_rtcompat::tokio::TokioNativeTlsRuntime;
use tor_rtcompat::{
    Blocking, CompoundRuntime, JoinSet, JoinSetProvider, NetStreamListener, NetStreamProvider,
    TcpListenOptions, ToplevelBlockOn,
};

lazy_static! {
    static ref RUNTIME: io::Result<TokioRuntime> = Builder::new_multi_thread().enable_all().build();
}

const PROXY_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const PROCESS_WIDE_STOP_MESSAGE: &str = "Tor proxy was stopped by a process-wide stop";
/// How long a sweep waits for the starts, re-bootstraps and stops it found running.
const SWEEP_WAIT: std::time::Duration = std::time::Duration::from_secs(15);
/// How long a stop waits for its client to be dropped.
const CLIENT_RELEASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const BOOTSTRAP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);
// The app sandbox already keeps other apps out of Tor's directories on phones,
// so Arti's ownership checks add nothing there and can stop Tor starting at all.
const SANDBOXED_STORAGE: bool = cfg!(any(target_os = "ios", target_os = "android"));

type TrackedTorRuntime = CompoundRuntime<
    TrackedSpawner,
    TokioNativeTlsRuntime,
    TokioNativeTlsRuntime,
    TokioNativeTlsRuntime,
    TokioNativeTlsRuntime,
    TokioNativeTlsRuntime,
    TokioNativeTlsRuntime,
>;

#[derive(Clone, Debug, Default)]
#[frb(ignore)]
struct TrackedTasks {
    tracker: TaskTracker,
    cancellation: CancellationToken,
}

impl TrackedTasks {
    fn stop_and_wait(&self) -> Result<(), TorError> {
        self.cancellation.cancel();
        self.tracker.close();
        let rt = RUNTIME
            .as_ref()
            .map_err(|error| TorError::RuntimeError(error.to_string()))?;
        if rt
            .block_on(async {
                tokio::time::timeout(PROXY_SHUTDOWN_TIMEOUT, self.tracker.wait()).await
            })
            .is_err()
        {
            Err(TorError::ProxyStopError(
                "Timed out stopping Tor client tasks".to_owned(),
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug)]
struct TrackedSpawner {
    runtime: TokioNativeTlsRuntime,
    tasks: TrackedTasks,
}

impl TrackedSpawner {
    fn new(runtime: TokioNativeTlsRuntime) -> Self {
        Self {
            runtime,
            tasks: TrackedTasks::default(),
        }
    }
}

impl Spawn for TrackedSpawner {
    fn spawn_obj(&self, future: FutureObj<'static, ()>) -> Result<(), SpawnError> {
        if self.tasks.tracker.is_closed() {
            return Err(SpawnError::shutdown());
        }

        let cancellation = self.tasks.cancellation.clone();
        let future = self.tasks.tracker.track_future(async move {
            tokio::select! {
                _ = cancellation.cancelled() => {}
                _ = future => {}
            }
        });
        self.runtime.spawn_obj(Box::new(future).into())
    }
}

impl Blocking for TrackedSpawner {
    type ThreadHandle<T: Send + 'static> = <TokioNativeTlsRuntime as Blocking>::ThreadHandle<T>;

    fn spawn_blocking<F, T>(&self, f: F) -> Self::ThreadHandle<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        self.runtime.spawn_blocking(f)
    }

    fn reenter_block_on<F>(&self, future: F) -> F::Output
    where
        F: Future,
        F::Output: Send + 'static,
    {
        self.runtime.reenter_block_on(future)
    }

    fn blocking_io<F, T>(&self, f: F) -> impl Future<Output = T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        self.runtime.blocking_io(f)
    }
}

impl ToplevelBlockOn for TrackedSpawner {
    fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.runtime.block_on(future)
    }
}

impl JoinSetProvider for TrackedSpawner {
    type JoinSet<T: Send + Sync + 'static> = TrackedJoinSet<T>;

    fn new_join_set<T>(&self) -> Self::JoinSet<T>
    where
        T: Send + Sync + 'static,
    {
        TrackedJoinSet {
            spawner: self.clone(),
            pending: FuturesUnordered::new(),
        }
    }
}

type JoinOutput<T> = std::result::Result<T, Box<dyn Any + Send>>;

/// The client's `JoinSet`. Its tasks go through the tracked spawner like
/// every other task the client spawns, so a stop cancels them and waits for
/// them. A task a stop cancelled has no output, and `join_next` skips it
/// rather than panicking, which a `RemoteHandle` would do. Dropping the set
/// ends its tasks, as with Tokio's `JoinSet`.
#[frb(ignore)]
struct TrackedJoinSet<T> {
    spawner: TrackedSpawner,
    pending: FuturesUnordered<oneshot::Receiver<JoinOutput<T>>>,
}

#[async_trait]
impl<T: Send + Sync + 'static> JoinSet<T> for TrackedJoinSet<T> {
    fn spawn<F>(&mut self, task: F) -> Result<(), SpawnError>
    where
        F: Future<Output = T> + Send + 'static,
    {
        let (mut sender, receiver) = oneshot::channel();
        self.spawner.spawn_obj(FutureObj::new(Box::new(async move {
            let task = AssertUnwindSafe(task).catch_unwind();
            let output = match future::select(sender.cancellation(), Box::pin(task)).await {
                Either::Left(_) => return,
                Either::Right((output, _)) => output,
            };
            let _ = sender.send(output);
        })))?;
        self.pending.push(receiver);
        Ok(())
    }

    async fn join_next(&mut self) -> Option<JoinOutput<T>> {
        while let Some(received) = self.pending.next().await {
            if let Ok(output) = received {
                return Some(output);
            }
        }
        None
    }
}

fn create_arti_runtime() -> io::Result<(TrackedTorRuntime, TrackedTasks)> {
    let runtime = TokioNativeTlsRuntime::create()?;
    let spawner = TrackedSpawner::new(runtime.clone());
    let tasks = spawner.tasks.clone();
    let runtime = CompoundRuntime::new(
        spawner,
        runtime.clone(),
        runtime.clone(),
        runtime.clone(),
        runtime.clone(),
        runtime.clone(),
        runtime,
    );
    Ok((runtime, tasks))
}

enum BootstrapWaitError<E> {
    Cancelled,
    TimedOut,
    Failed(E),
}

async fn wait_for_bootstrap<F, T, E>(
    future: F,
    cancellation: &CancellationToken,
    timeout: std::time::Duration,
) -> std::result::Result<T, BootstrapWaitError<E>>
where
    F: Future<Output = std::result::Result<T, E>>,
{
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(BootstrapWaitError::Cancelled),
        result = tokio::time::timeout(timeout, future) => match result {
            Err(_) => Err(BootstrapWaitError::TimedOut),
            Ok(Err(error)) => Err(BootstrapWaitError::Failed(error)),
            Ok(Ok(value)) => Ok(value),
        },
    }
}

/// Stops the tasks of a start that failed and releases what it built. With
/// `pending`, a cleanup that fails is reported to a sweep waiting for it.
fn finish_failed_start<T: Send + 'static>(
    pending: Option<&InFlight<'_>>,
    tasks: TrackedTasks,
    error: TorError,
    leftover: T,
) -> TorError {
    let stopped = tasks.stop_and_wait();
    let drain = Drain {
        tasks: stopped.is_err().then(|| tasks.tracker.clone()),
        ..Drain::default()
    };
    let released = release(
        leftover,
        drain,
        stopped.is_ok().then_some(CLIENT_RELEASE_TIMEOUT),
    );
    match stopped.and(released) {
        Ok(()) => error,
        Err(cleanup_error) => {
            if let Some(pending) = pending {
                pending.mark_unclean();
            }
            TorError::RuntimeError(format!(
                "{error}; failed to clean up the partially started Tor client: {cleanup_error}"
            ))
        }
    }
}

fn tor_client_config(
    state_dir: String,
    cache_dir: String,
    sandboxed_storage: bool,
) -> Result<TorClientConfig, TorError> {
    let mut cfg_builder = TorClientConfig::builder();
    cfg_builder
        .storage()
        .state_dir(CfgPath::new(state_dir))
        .cache_dir(CfgPath::new(cache_dir));
    if sandboxed_storage {
        cfg_builder
            .storage()
            .permissions()
            .dangerously_trust_everyone();
    }
    cfg_builder.address_filter().allow_onion_addrs(true);
    cfg_builder
        .preemptive_circuits()
        .disable_at_threshold(1)
        .min_exit_circs_for_port(1)
        .initial_predicted_ports()
        .clear();

    cfg_builder
        .build()
        .map_err(|e| TorError::ConfigError(e.to_string()))
}

// Arti's own message leaves out its causes, such as the path a check rejected.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let cause_message = cause.to_string();
        if !message.contains(&cause_message) {
            message.push_str(": ");
            message.push_str(&cause_message);
        }
        source = cause.source();
    }
    message
}

/// Custom error types for Tor operations
#[derive(Debug, thiserror::Error)]
pub enum TorError {
    #[error("Failed to bootstrap Tor: {0}")]
    BootstrapError(String),

    #[error("Failed to start proxy: {0}")]
    ProxyStartError(String),

    #[error("Failed to stop proxy: {0}")]
    ProxyStopError(String),

    #[error("Client not initialized")]
    ClientNotInitialized,

    #[error("Runtime error: {0}")]
    RuntimeError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

#[frb(opaque)]
pub struct TorBootstrapCancellationToken {
    token: CancellationToken,
}

impl TorBootstrapCancellationToken {
    #[frb(sync)]
    pub fn new() -> Self {
        Self {
            token: CancellationToken::new(),
        }
    }

    #[frb(sync)]
    pub fn cancel(&self) {
        self.token.cancel();
    }
}

type LiveClient = Arc<TorClient<TrackedTorRuntime>>;
/// A client and the runtime that drives it.
type OwnedClient = (LiveClient, TrackedTorRuntime);
type ClientSlot = Arc<ClientCell>;

/// Where a started client lives. Stopping its proxy empties it, so a Dart
/// wrapper, which reaches the client only through it, can't keep a stopped
/// client (and with it Arti's directory and state locks) alive, even when the
/// wrapper is never disposed: a start whose result reached a dead isolate, say.
struct ClientCell {
    state: Mutex<ClientCellState>,
    /// Notified when a bootstrap gives the client back.
    returned: Condvar,
    /// Cancelled when the client's proxy stops, which ends any bootstrap that
    /// has borrowed it.
    stopped: CancellationToken,
}

struct ClientCellState {
    client: Option<OwnedClient>,
    /// Bootstraps holding a clone of the client.
    borrowers: usize,
}

impl ClientCell {
    fn new(client: OwnedClient) -> ClientSlot {
        Arc::new(Self {
            state: Mutex::new(ClientCellState {
                client: Some(client),
                borrowers: 0,
            }),
            returned: Condvar::new(),
            stopped: CancellationToken::new(),
        })
    }

    /// Lends the client until the guard drops, unless its proxy is stopping.
    fn borrow(self: &Arc<Self>) -> Option<Borrowed> {
        let mut state = lock_unpoisoned(&self.state);
        if self.stopped.is_cancelled() {
            return None;
        }
        let client = state.client.clone()?;
        state.borrowers += 1;
        Some(Borrowed {
            cell: Arc::clone(self),
            client: Some(client),
        })
    }

    fn wait_for_borrowers(&self) {
        let state = lock_unpoisoned(&self.state);
        drop(
            self.returned
                .wait_while(state, |state| state.borrowers > 0)
                .unwrap_or_else(PoisonError::into_inner),
        );
    }
}

/// A client lent to a bootstrap. It drops its clone before giving the client
/// back, so the stop that released the client always drops the last one.
struct Borrowed {
    cell: ClientSlot,
    client: Option<OwnedClient>,
}

impl Drop for Borrowed {
    fn drop(&mut self) {
        drop(self.client.take());
        lock_unpoisoned(&self.cell.state).borrowers -= 1;
        self.cell.returned.notify_all();
    }
}

/// Opaque wrapper for TorClient - FRB handles this automatically
#[frb(opaque)]
pub struct TorClientWrapper {
    slot: ClientSlot,
}

impl Clone for TorClientWrapper {
    fn clone(&self) -> Self {
        TorClientWrapper {
            slot: Arc::clone(&self.slot),
        }
    }
}

/// Opaque wrapper for proxy handle
#[frb(opaque)]
pub struct TorProxyHandle {
    state: Arc<Mutex<TorProxyState>>,
}

struct TorProxyState {
    accept_loop_abort: Option<AbortHandle>,
    accept_loop_monitor: Option<JoinHandle<()>>,
    /// 0 while running, then the [`StopReason`] of the stop that took the handles.
    stop_reason: Arc<AtomicU8>,
    tasks: Option<TrackedTasks>,
    /// The client this proxy serves, released when it stops.
    client: Option<ClientSlot>,
    /// Set by the stop that took the handles, for any later stop to wait on.
    stopping: Option<Arc<StopDone>>,
}

/// Who stopped a proxy, as its monitor reports it.
#[derive(Clone, Copy)]
#[repr(u8)]
enum StopReason {
    /// The proxy's own handle: an expected stop, which reports no loss.
    Owner = 1,
    /// `stop_all_proxies`, which can't tell a live isolate's proxy from an
    /// orphan's, so a live owner hears of it as a loss and stops publishing
    /// the port.
    ProcessWide = 2,
}

/// The end of a proxy's stop: whether it stopped and released everything.
#[derive(Default)]
#[frb(ignore)]
struct StopDone {
    clean: Mutex<Option<bool>>,
    ended: Condvar,
}

impl StopDone {
    /// Waits for the stop to end. True when it stopped and released everything.
    fn wait(&self) -> bool {
        let clean = self
            .ended
            .wait_while(lock_unpoisoned(&self.clean), |clean| clean.is_none())
            .unwrap_or_else(PoisonError::into_inner);
        clean.unwrap_or(false)
    }
}

/// Ends a stop on drop, as unclean unless told otherwise, so a stop that
/// panics can't leave a later stop waiting for ever.
struct FinishStop {
    done: Arc<StopDone>,
    clean: bool,
}

impl Drop for FinishStop {
    fn drop(&mut self) {
        *lock_unpoisoned(&self.done.clean) = Some(self.clean);
        self.done.ended.notify_all();
    }
}

// Every critical section on these locks leaves its data whole (an `Option`
// taken or not, an entry pushed or not), so a panic elsewhere is no reason to
// refuse to stop anything afterwards.
fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What has to end before a released client, or runtime, may be dropped.
#[derive(Default)]
#[frb(ignore)]
struct Drain {
    /// Bootstraps that borrowed the client give it back.
    borrowers: Option<ClientSlot>,
    /// An accept loop that didn't stop in time.
    accept_loop: Option<JoinHandle<()>>,
    /// Client tasks that didn't stop in time.
    tasks: Option<TaskTracker>,
}

impl Drain {
    /// Waits, with no time limit, for everything that could still hold a
    /// reference. Runs on a release thread.
    fn wait(self) {
        let Drain {
            borrowers,
            accept_loop,
            tasks,
        } = self;
        if accept_loop.is_some() || tasks.is_some() {
            if let Ok(rt) = RUNTIME.as_ref() {
                rt.block_on(async {
                    if let Some(accept_loop) = accept_loop {
                        let _ = accept_loop.await;
                    }
                    if let Some(tasks) = tasks {
                        tasks.wait().await;
                    }
                });
            }
        }
        if let Some(cell) = borrowers {
            cell.wait_for_borrowers();
        }
    }
}

/// Drops `value` on its own thread once `drain` has finished. Dropping a
/// client's last reference drops its tokio runtime, which waits for that
/// runtime's blocking tasks with no time limit, and doing it inside a tokio
/// worker panics; neither may hold up a stop for good. With `wait`, waits that
/// long for the drop; without, returns at once and the drop happens whenever
/// the drain ends.
fn release<T: Send + 'static>(
    value: T,
    drain: Drain,
    wait: Option<std::time::Duration>,
) -> Result<(), TorError> {
    let (sender, released) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("tor-client-release".to_owned())
        .spawn(move || {
            drain.wait();
            drop(value);
            let _ = sender.send(());
        })
        .map_err(|error| {
            TorError::RuntimeError(format!("Couldn't start releasing the Tor client: {error}"))
        })?;
    let Some(wait) = wait else {
        return Ok(());
    };
    released.recv_timeout(wait).map_err(|error| {
        TorError::ProxyStopError(match error {
            std::sync::mpsc::RecvTimeoutError::Timeout => {
                "Timed out releasing the Tor client; Arti's locks may still be held".to_owned()
            }
            std::sync::mpsc::RecvTimeoutError::Disconnected => {
                "Releasing the Tor client failed; Arti's locks may still be held".to_owned()
            }
        })
    })
}

/// Every proxy `start_tor` has published in this process that nothing has
/// stopped yet, and every start, re-bootstrap and stop in flight, whichever
/// isolate began them.
///
/// Dart holds clients and proxies through per-isolate handles, so an isolate
/// can only stop what it started itself, and a proxy whose isolate has died
/// (an engine destroyed without any Dart callback) keeps listening with no
/// handle left anywhere. This record is how `stop_all_proxies` reaches it.
static REGISTRY: Registry = Registry::new();

struct Registry {
    state: Mutex<RegistryState>,
    /// Notified whenever an [`InFlight`] entry ends.
    ended: Condvar,
}

/// How many entries that ended unclean the registry remembers for sweeps.
const UNCLEAN_KEPT: usize = 64;

struct RegistryState {
    live: Vec<TorProxyHandle>,
    /// A sweep cancels these tokens, which only bootstraps watch, and waits
    /// for every entry it saw to end.
    in_flight: Vec<(u64, CancellationToken)>,
    /// In-flight entries that ended without releasing everything in time, so
    /// a sweep that waited for them can say so.
    unclean: Vec<u64>,
    next_id: u64,
}

impl Registry {
    const fn new() -> Self {
        Self {
            state: Mutex::new(RegistryState {
                live: Vec::new(),
                in_flight: Vec::new(),
                unclean: Vec::new(),
                next_id: 0,
            }),
            ended: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, RegistryState> {
        lock_unpoisoned(&self.state)
    }
}

/// A start, re-bootstrap or stop in progress. Deregisters on drop.
struct InFlight<'a> {
    registry: &'a Registry,
    id: u64,
    /// Cancelled by the caller's token or by a sweep.
    token: CancellationToken,
    unclean: Cell<bool>,
}

impl<'a> InFlight<'a> {
    /// A bootstrap, which a sweep cancels and then waits for.
    fn bootstrap(registry: &'a Registry, caller: &CancellationToken) -> Self {
        Self::begin(registry, caller.child_token())
    }

    /// A stop, which a sweep waits for.
    fn stop(registry: &'a Registry) -> Self {
        Self::begin(registry, CancellationToken::new())
    }

    fn begin(registry: &'a Registry, token: CancellationToken) -> Self {
        let mut state = registry.lock();
        let id = state.next_id;
        state.next_id += 1;
        state.in_flight.push((id, token.clone()));
        drop(state);
        Self {
            registry,
            id,
            token,
            unclean: Cell::new(false),
        }
    }

    /// Records a started proxy, unless this start has been cancelled, by its
    /// caller or by a sweep; the caller must then tear it down. Checked under
    /// the registry lock, so a sweep either finds the proxy or has cancelled
    /// its start, never neither.
    fn publish(&self, proxy: &TorProxyHandle) -> bool {
        let mut state = self.registry.lock();
        if self.token.is_cancelled() {
            return false;
        }
        state.live.push(proxy.clone());
        true
    }

    /// Reports, to a sweep waiting for this entry, that it ended without
    /// releasing everything in time.
    fn mark_unclean(&self) {
        self.unclean.set(true);
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        let mut state = self.registry.lock();
        state.in_flight.retain(|(id, _)| *id != self.id);
        if self.unclean.get() {
            if state.unclean.len() == UNCLEAN_KEPT {
                state.unclean.remove(0);
            }
            state.unclean.push(self.id);
        }
        drop(state);
        self.registry.ended.notify_all();
    }
}

/// How a published proxy was lost without its owner stopping it.
#[derive(Clone, Debug)]
pub struct TorProxyLoss {
    pub message: String,
    /// True when `stop_all_proxies` stopped it, false when it failed by itself.
    pub process_wide_stop: bool,
}

#[derive(Clone, Debug)]
struct TorProxyExit {
    /// `None` when the proxy's owner stopped it.
    loss: Option<TorProxyLoss>,
}

#[frb(opaque)]
pub struct TorProxyMonitor {
    exit: watch::Receiver<Option<TorProxyExit>>,
}

impl Clone for TorProxyMonitor {
    fn clone(&self) -> Self {
        Self {
            exit: self.exit.clone(),
        }
    }
}

impl Clone for TorProxyHandle {
    fn clone(&self) -> Self {
        TorProxyHandle {
            state: Arc::clone(&self.state),
        }
    }
}

/// Result of starting Tor - contains both client and proxy
pub struct TorInstance {
    pub client: TorClientWrapper,
    pub proxy: TorProxyHandle,
    pub proxy_monitor: TorProxyMonitor,
    pub socks_port: u16,
}

/// Initialize FRB
#[frb(init)]
pub fn init_app() {
    flutter_rust_bridge::setup_default_user_utils();
}

/// Start Tor client and proxy
///
/// This is a blocking operation that may take several seconds.
/// It bootstraps the Tor network connection and starts a SOCKS proxy.
pub fn start_tor(
    socks_port: u16,
    state_dir: String,
    cache_dir: String,
    cancellation_token: &TorBootstrapCancellationToken,
) -> Result<TorInstance, TorError> {
    let cfg = tor_client_config(state_dir, cache_dir, SANDBOXED_STORAGE)?;
    start_tor_with(
        &REGISTRY,
        socks_port,
        &cancellation_token.token,
        |runtime| async move {
            TorClient::with_runtime(runtime)
                .config(cfg)
                .create_bootstrapped()
                .await
        },
    )
}

/// `start_tor` with the bootstrap passed in, so tests can stand in for the network.
fn start_tor_with<F, Fut>(
    registry: &Registry,
    socks_port: u16,
    caller: &CancellationToken,
    bootstrap: F,
) -> Result<TorInstance, TorError>
where
    F: FnOnce(TrackedTorRuntime) -> Fut,
    Fut: Future<Output = arti_client::Result<LiveClient>>,
{
    // The first local, so it is dropped last: a sweep waits for this start to
    // end, and by then everything below has been released.
    let pending = InFlight::bootstrap(registry, caller);
    let (runtime, tasks) =
        create_arti_runtime().map_err(|e| TorError::RuntimeError(e.to_string()))?;

    let client = runtime.block_on(wait_for_bootstrap(
        bootstrap(runtime.clone()),
        &pending.token,
        BOOTSTRAP_TIMEOUT,
    ));
    let client = match client {
        Ok(client) => client,
        Err(BootstrapWaitError::Cancelled) => {
            return Err(finish_failed_start(
                Some(&pending),
                tasks,
                TorError::BootstrapError("Bootstrap was cancelled".to_owned()),
                runtime,
            ));
        }
        Err(BootstrapWaitError::TimedOut) => {
            return Err(finish_failed_start(
                Some(&pending),
                tasks,
                TorError::BootstrapError("Bootstrap timed out".to_owned()),
                runtime,
            ));
        }
        Err(BootstrapWaitError::Failed(error)) => {
            return Err(finish_failed_start(
                Some(&pending),
                tasks,
                TorError::BootstrapError(error_chain(&error)),
                runtime,
            ));
        }
    };

    publish_started(&pending, socks_port, client, runtime, tasks)
}

/// The rest of a start once its client has bootstrapped: opens the SOCKS
/// listener and publishes the proxy, unless the start was cancelled meanwhile.
fn publish_started(
    pending: &InFlight<'_>,
    socks_port: u16,
    client: LiveClient,
    runtime: TrackedTorRuntime,
    tasks: TrackedTasks,
) -> Result<TorInstance, TorError> {
    let (accept_loop, socks_port) = match start_proxy_internal(socks_port, Arc::clone(&client)) {
        Ok(proxy) => proxy,
        Err(error) => {
            return Err(finish_failed_start(
                Some(pending),
                tasks,
                error,
                (client, runtime),
            ))
        }
    };
    let slot = ClientCell::new((client, runtime));
    let (proxy, proxy_monitor) = monitor_proxy(accept_loop, Some(tasks), Some(Arc::clone(&slot)))?;
    if !pending.publish(&proxy) {
        // Cancelled after the bootstrap finished: whoever cancelled it has
        // already stopped publishing this start, so don't hand back a proxy.
        return Err(match stop_proxy_inner(&proxy, StopReason::Owner) {
            Ok(_) => TorError::BootstrapError("Bootstrap was cancelled".to_owned()),
            Err(error) => {
                pending.mark_unclean();
                error
            }
        });
    }

    Ok(TorInstance {
        client: TorClientWrapper { slot },
        proxy,
        proxy_monitor,
        socks_port,
    })
}

fn start_proxy_internal(
    port: u16,
    client: Arc<TorClient<TrackedTorRuntime>>,
) -> Result<(JoinHandle<Result<()>>, u16), TorError> {
    let rt = RUNTIME
        .as_ref()
        .map_err(|e| TorError::RuntimeError(e.to_string()))?;

    let runtime = client.runtime().clone();
    let (listeners, bound_port) = runtime
        .block_on(async {
            if port == 0 {
                let address = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
                let listener = runtime
                    .listen(&address, &TcpListenOptions::default())
                    .await
                    .map_err(|error| anyhow::anyhow!("Can't listen on {address}: {error}"))?;
                let bound_port = listener
                    .local_addr()
                    .map_err(|error| anyhow::anyhow!("Can't read SOCKS listener address: {error}"))?
                    .port();
                return Ok((vec![listener], bound_port));
            }

            let listen = Listen::new_localhost(port);
            let listen_options = TcpListenOptions::default();
            let mut listeners = Vec::new();

            for addrgroup in listen.ip_addrs()? {
                let mut bound_in_group = false;
                for addr in addrgroup {
                    match runtime.listen(&addr, &listen_options).await {
                        Ok(listener) => {
                            bound_in_group = true;
                            listeners.push(listener);
                        }
                        #[cfg(unix)]
                        Err(ref e) if e.raw_os_error() == Some(libc::EAFNOSUPPORT) => {}
                        Err(e) => return Err(anyhow::anyhow!("Can't listen on {addr}: {e}")),
                    }
                }

                if !bound_in_group {
                    return Err(anyhow::anyhow!(
                        "Couldn't open any SOCKS listener in address group"
                    ));
                }
            }

            if listeners.is_empty() {
                return Err(anyhow::anyhow!("Couldn't open SOCKS listeners"));
            }

            Ok((listeners, port))
        })
        .map_err(|e: anyhow::Error| TorError::ProxyStartError(e.to_string()))?;

    Ok((
        rt.spawn(proxy::run_proxy_with_listeners(
            client,
            listeners,
            ListenProtocols::SocksOnly,
            None,
        )),
        bound_port,
    ))
}

fn monitor_proxy(
    accept_loop: JoinHandle<Result<()>>,
    tasks: Option<TrackedTasks>,
    client: Option<ClientSlot>,
) -> Result<(TorProxyHandle, TorProxyMonitor), TorError> {
    let rt = match RUNTIME.as_ref() {
        Ok(rt) => rt,
        Err(error) => {
            accept_loop.abort();
            let error = TorError::RuntimeError(error.to_string());
            let leftover = client.and_then(|cell| lock_unpoisoned(&cell.state).client.take());
            return Err(match tasks {
                Some(tasks) => finish_failed_start(None, tasks, error, leftover),
                None => error,
            });
        }
    };
    let accept_loop_abort = accept_loop.abort_handle();
    let stop_reason = Arc::new(AtomicU8::new(0));
    let stop_reason_for_monitor = Arc::clone(&stop_reason);
    let (exit_sender, exit_receiver) = watch::channel(None);
    let accept_loop_monitor = rt.spawn(async move {
        let result = accept_loop.await;
        let reason = stop_reason_for_monitor.load(Ordering::Acquire);
        let process_wide_stop = reason == StopReason::ProcessWide as u8;
        let message = match result {
            _ if process_wide_stop => PROCESS_WIDE_STOP_MESSAGE.to_owned(),
            Ok(Ok(())) => "Tor proxy accept loop exited".to_owned(),
            Ok(Err(error)) => format!("Tor proxy accept loop failed: {error}"),
            Err(error) if error.is_cancelled() => "Tor proxy accept loop was cancelled".to_owned(),
            Err(error) => format!("Tor proxy accept loop panicked: {error}"),
        };

        let loss = (reason != StopReason::Owner as u8).then(|| {
            log::warn!("{message}");
            TorProxyLoss {
                message,
                process_wide_stop,
            }
        });
        let _ = exit_sender.send(Some(TorProxyExit { loss }));
    });

    Ok((
        TorProxyHandle {
            state: Arc::new(Mutex::new(TorProxyState {
                accept_loop_abort: Some(accept_loop_abort),
                accept_loop_monitor: Some(accept_loop_monitor),
                stop_reason,
                tasks,
                client,
                stopping: None,
            })),
        },
        TorProxyMonitor {
            exit: exit_receiver,
        },
    ))
}

/// Wait for the proxy's accept loop to end
///
/// Returns `None` when its owner stopped it, and how it was lost otherwise.
pub async fn wait_for_proxy_exit(
    mut monitor: TorProxyMonitor,
) -> Result<Option<TorProxyLoss>, TorError> {
    if monitor.exit.borrow().is_none() {
        monitor.exit.changed().await.map_err(|_| {
            TorError::RuntimeError("Tor proxy monitor stopped without an exit event".to_owned())
        })?;
    }

    let exit = monitor.exit.borrow().clone().ok_or_else(|| {
        TorError::RuntimeError("Tor proxy monitor stopped without an exit event".to_owned())
    })?;
    Ok(exit.loss)
}

/// Re-bootstrap the Tor client
///
/// Call this after network changes or to refresh the connection. Fails with
/// `ClientNotInitialized` once the client's proxy has stopped.
pub fn bootstrap(
    client: &TorClientWrapper,
    cancellation_token: &TorBootstrapCancellationToken,
) -> Result<(), TorError> {
    bootstrap_with(
        &REGISTRY,
        client,
        &cancellation_token.token,
        |client| async move { client.bootstrap().await },
    )
}

/// `bootstrap` with the bootstrap passed in, so tests can stand in for the network.
fn bootstrap_with<F, Fut, E>(
    registry: &Registry,
    wrapper: &TorClientWrapper,
    caller: &CancellationToken,
    bootstrap: F,
) -> Result<(), TorError>
where
    F: FnOnce(LiveClient) -> Fut,
    Fut: Future<Output = std::result::Result<(), E>>,
    E: std::fmt::Display,
{
    // The first local, so it is dropped last, after the client is given back:
    // a sweep waits for this bootstrap to end.
    let pending = InFlight::bootstrap(registry, caller);
    let borrowed = wrapper
        .slot
        .borrow()
        .ok_or(TorError::ClientNotInitialized)?;
    let (client, runtime) = borrowed
        .client
        .as_ref()
        .ok_or(TorError::ClientNotInitialized)?;
    // A stop of the client's proxy ends the bootstrap as well, so it can't keep
    // the client, and Arti's locks, past that stop.
    let stopped = borrowed.cell.stopped.clone();
    let bootstrap = bootstrap(Arc::clone(client));
    let until_stopped = async move {
        tokio::select! {
            biased;
            _ = stopped.cancelled() => Err(None),
            result = bootstrap => result.map_err(Some),
        }
    };
    match runtime.block_on(wait_for_bootstrap(
        until_stopped,
        &pending.token,
        BOOTSTRAP_TIMEOUT,
    )) {
        Ok(()) => Ok(()),
        Err(BootstrapWaitError::Cancelled) | Err(BootstrapWaitError::Failed(None)) => Err(
            TorError::BootstrapError("Bootstrap was cancelled".to_owned()),
        ),
        Err(BootstrapWaitError::TimedOut) => {
            Err(TorError::BootstrapError("Bootstrap timed out".to_owned()))
        }
        Err(BootstrapWaitError::Failed(Some(error))) => {
            Err(TorError::BootstrapError(error.to_string()))
        }
    }
}

/// Set the client dormant mode
///
/// * `soft_mode` - If true, uses Soft dormant mode (keeps some circuits warm)
///   If false, uses Normal mode (full operation)
///
/// Does nothing once the client's proxy has stopped.
pub fn set_dormant(client: &TorClientWrapper, soft_mode: bool) {
    let dormant_mode = if soft_mode {
        DormantMode::Soft
    } else {
        DormantMode::Normal
    };
    // Under the cell's lock, so a stop can't release the client meanwhile.
    if let Some((client, _)) = lock_unpoisoned(&client.slot.state).client.as_ref() {
        client.set_dormant(dormant_mode);
    }
}

/// Stop the Tor proxy
///
/// Stops the accept loop and the client runtime that owns accepted
/// connections, and releases the client. Stopping a proxy that is already
/// stopped, or being stopped, does nothing and returns once that stop has
/// finished, with an error if it failed.
///
/// Each step is bounded: 5 seconds for the accept loop, 5 for the client's
/// tasks and 5 for dropping the client, which waits for the client runtime's
/// blocking tasks. A client that takes longer is still dropped once it can,
/// but this returns an error saying Arti's locks may still be held.
pub fn stop_proxy(proxy: TorProxyHandle) -> Result<(), TorError> {
    stop_registered_proxy(&REGISTRY, &proxy)
}

/// Stop every Tor proxy in this process
///
/// Stops every proxy started in this process that hasn't been stopped yet,
/// whichever isolate started it, including one whose isolate no longer
/// exists, and cancels every bootstrap in flight. It then waits, for up to 15
/// seconds, for every start, re-bootstrap and stop that was already running
/// when it was called to end. "Already running" means the native call had
/// begun: a call still queued for a worker thread isn't covered.
///
/// Returns how many proxies it stopped. Once it has returned `Ok`, nothing
/// started before it still holds a SOCKS listener or a client, so Arti's
/// state and cache locks are free. An error means that may not hold: a proxy
/// failed to stop or to release its client in time, or something it waited
/// for was still running. Each proxy takes at most about 15 seconds to stop
/// (see `stop_proxy`), so a sweep returns within that per proxy plus the
/// 15-second wait.
///
/// It can't tell an orphan from a live isolate's proxy: a live owner's proxy
/// monitor reports the stop as a loss with `process_wide_stop` set.
pub fn stop_all_proxies() -> Result<u32, TorError> {
    stop_all_registered(&REGISTRY, SWEEP_WAIT)
}

fn stop_registered_proxy(registry: &Registry, proxy: &TorProxyHandle) -> Result<(), TorError> {
    // The first local, so it is dropped last: a sweep that begins while this
    // stop runs waits for it to end.
    let _in_flight = InFlight::stop(registry);
    // Stopped before its entry is removed, so a sweep that runs meanwhile
    // still finds the proxy and waits on its lock.
    let result = stop_proxy_inner(proxy, StopReason::Owner);
    registry
        .lock()
        .live
        .retain(|live| !Arc::ptr_eq(&live.state, &proxy.state));
    if result.is_err() {
        _in_flight.mark_unclean();
    }
    result.map(|_| ())
}

fn stop_all_registered(registry: &Registry, wait: std::time::Duration) -> Result<u32, TorError> {
    let (live, waiting_for) = {
        let mut state = registry.lock();
        for (_, token) in &state.in_flight {
            token.cancel();
        }
        let waiting_for: Vec<u64> = state.in_flight.iter().map(|(id, _)| *id).collect();
        (std::mem::take(&mut state.live), waiting_for)
    };

    let mut stopped = 0;
    let mut failures = Vec::new();
    for proxy in &live {
        match stop_proxy_inner(proxy, StopReason::ProcessWide) {
            Ok(true) => stopped += 1,
            Ok(false) => {}
            Err(error) => failures.push(stop_error_detail(&error)),
        }
    }
    drop(live);

    let waiting = |state: &mut RegistryState| {
        state
            .in_flight
            .iter()
            .any(|(id, _)| waiting_for.contains(id))
    };
    let (mut state, _) = registry
        .ended
        .wait_timeout_while(registry.lock(), wait, waiting)
        .unwrap_or_else(PoisonError::into_inner);
    let still_running = waiting(&mut state);
    let ended_unclean = state
        .unclean
        .iter()
        .filter(|id| waiting_for.contains(id))
        .count();
    state.unclean.retain(|id| !waiting_for.contains(id));
    drop(state);

    let mut problems = Vec::new();
    if !failures.is_empty() {
        let attempted = stopped as usize + failures.len();
        problems.push(format!(
            "stopped {stopped} of {attempted} Tor proxies cleanly: {}",
            failures.join("; ")
        ));
    }
    if ended_unclean > 0 {
        problems.push(format!(
            "{ended_unclean} Tor start(s) or stop(s) begun before this one couldn't \
             release their client in time, so Arti's locks may still be held"
        ));
    }
    if still_running {
        problems.push(format!(
            "a Tor start or stop begun before this one was still running after {} s, \
             so a SOCKS listener or Arti's locks may still be held",
            wait.as_secs()
        ));
    }
    if problems.is_empty() {
        Ok(stopped)
    } else {
        Err(TorError::ProxyStopError(problems.join("; ")))
    }
}

/// An error's text without the "Failed to stop proxy" prefix a combined stop
/// error adds again.
fn stop_error_detail(error: &TorError) -> String {
    match error {
        TorError::ProxyStopError(detail) => detail.clone(),
        other => other.to_string(),
    }
}

/// Stops the accept loop and the client tasks of `proxy` and releases its
/// client, unless another stop already has. Returns whether this call did the
/// stopping; a later stop returns only once the earlier one has ended.
fn stop_proxy_inner(proxy: &TorProxyHandle, reason: StopReason) -> Result<bool, TorError> {
    let mut state = lock_unpoisoned(&proxy.state);
    let accept_loop_abort = state.accept_loop_abort.take();
    let mut accept_loop_monitor = state.accept_loop_monitor.take();
    let tasks = state.tasks.take();
    let client = state.client.take();
    if accept_loop_abort.is_none()
        && accept_loop_monitor.is_none()
        && tasks.is_none()
        && client.is_none()
    {
        let earlier = state.stopping.clone();
        drop(state);
        return match earlier.is_none_or(|done| done.wait()) {
            true => Ok(false),
            false => Err(TorError::ProxyStopError(
                "Another stop of this Tor proxy failed; Arti's locks may still be held".to_owned(),
            )),
        };
    }
    // Before the abort, so the monitor reports why the accept loop ended.
    state.stop_reason.store(reason as u8, Ordering::Release);
    let mut finish = FinishStop {
        done: Arc::new(StopDone::default()),
        clean: false,
    };
    state.stopping = Some(Arc::clone(&finish.done));
    drop(state);

    // Ends a bootstrap that has borrowed the client, so it gives it back.
    if let Some(cell) = &client {
        cell.stopped.cancel();
    }
    if let Some(abort) = accept_loop_abort {
        abort.abort();
    }

    let accept_result = match (accept_loop_monitor.as_mut(), RUNTIME.as_ref()) {
        (Some(monitor), Ok(rt)) => rt.block_on(async {
            match tokio::time::timeout(PROXY_SHUTDOWN_TIMEOUT, monitor).await {
                Err(_) => Err(TorError::ProxyStopError(
                    "Timed out stopping Tor proxy accept loop".to_owned(),
                )),
                Ok(Err(error)) => Err(TorError::ProxyStopError(format!(
                    "Tor proxy monitor failed: {error}"
                ))),
                Ok(Ok(())) => Ok(()),
            }
        }),
        (Some(_), Err(error)) => Err(TorError::RuntimeError(error.to_string())),
        (None, _) => Ok(()),
    };
    if accept_result.is_ok() {
        accept_loop_monitor = None;
    }
    let task_result = tasks.as_ref().map_or(Ok(()), TrackedTasks::stop_and_wait);
    let still_running = task_result
        .is_err()
        .then(|| tasks.as_ref().map(|tasks| tasks.tracker.clone()))
        .flatten();
    let stopped = accept_result.and(task_result);

    // A client whose tasks stopped is dropped within the bound; one whose
    // tasks may still be running is dropped once they end, however long that
    // takes, and this stop has already failed.
    let owned = client
        .as_ref()
        .and_then(|cell| lock_unpoisoned(&cell.state).client.take());
    let released = match owned {
        None => Ok(()),
        Some(owned) => release(
            owned,
            Drain {
                borrowers: client,
                accept_loop: accept_loop_monitor,
                tasks: still_running,
            },
            stopped.is_ok().then_some(CLIENT_RELEASE_TIMEOUT),
        ),
    };
    let result = stopped.and(released);
    finish.clean = result.is_ok();
    result.map(|()| true)
}

/// Test function to verify library linking
pub fn hello() {
    println!("HELLO THERE");
}

// Platform-specific rlimit functions
#[cfg(not(target_os = "windows"))]
pub fn get_nofile_limit() -> Result<u64, TorError> {
    rlimit::getrlimit(rlimit::Resource::NOFILE)
        .map(|(soft, _hard)| soft)
        .map_err(|e| TorError::RuntimeError(e.to_string()))
}

#[cfg(not(target_os = "windows"))]
pub fn set_nofile_limit(limit: u64) -> Result<u64, TorError> {
    rlimit::increase_nofile_limit(limit).map_err(|e| TorError::RuntimeError(e.to_string()))
}

#[cfg(target_os = "windows")]
pub fn get_nofile_limit() -> Result<u64, TorError> {
    Ok(0) // Not applicable on Windows
}

#[cfg(target_os = "windows")]
pub fn set_nofile_limit(_limit: u64) -> Result<u64, TorError> {
    Ok(0) // Not applicable on Windows
}

#[cfg(test)]
mod tests {
    use super::*;
    use arti_client::config::TorClientConfigBuilder;
    use std::future::pending;
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::{Duration, Instant};
    use tor_rtcompat::NetStreamListener;

    #[test]
    fn proxy_selects_and_holds_its_ephemeral_port() {
        let _global = global_registry();
        let state_dir = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let config = TorClientConfigBuilder::from_directories(state_dir.path(), cache_dir.path())
            .build()
            .unwrap();
        let (runtime, tasks) = create_arti_runtime().unwrap();
        let client = TorClient::with_runtime(runtime.clone())
            .config(config)
            .create_unbootstrapped()
            .unwrap();

        let (proxy_task, port) = start_proxy_internal(0, Arc::clone(&client)).unwrap();

        assert_ne!(port, 0);
        assert!(
            TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_err(),
            "the published SOCKS port was not retained by the proxy"
        );

        let (proxy, _) = monitor_proxy(proxy_task, Some(tasks), None).unwrap();
        stop_proxy(proxy).unwrap();

        TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
    }

    #[test]
    fn proxy_start_fails_when_a_requested_port_is_already_owned() {
        let state_dir = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let config = TorClientConfigBuilder::from_directories(state_dir.path(), cache_dir.path())
            .build()
            .unwrap();
        let (runtime, _tasks) = create_arti_runtime().unwrap();
        let client = TorClient::with_runtime(runtime)
            .config(config)
            .create_unbootstrapped()
            .unwrap();
        let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = occupied.local_addr().unwrap().port();

        let result = start_proxy_internal(port, client);

        assert!(matches!(result, Err(TorError::ProxyStartError(_))));
    }

    #[test]
    fn stop_proxy_drops_an_idle_connection() {
        let _global = global_registry();
        let state_dir = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let config = TorClientConfigBuilder::from_directories(state_dir.path(), cache_dir.path())
            .build()
            .unwrap();
        let (runtime, tasks) = create_arti_runtime().unwrap();
        let client = TorClient::with_runtime(runtime.clone())
            .config(config)
            .create_unbootstrapped()
            .unwrap();
        let baseline_client_references = Arc::strong_count(&client);
        let listen_address: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (listener, address) = runtime.block_on(async {
            let listener = runtime
                .listen(&listen_address, &TcpListenOptions::default())
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            (listener, address)
        });
        let proxy_task = RUNTIME
            .as_ref()
            .unwrap()
            .spawn(proxy::run_proxy_with_listeners(
                Arc::clone(&client),
                vec![listener],
                ListenProtocols::SocksOnly,
                None,
            ));
        let _idle_connection = TcpStream::connect(address).unwrap();

        let deadline = Instant::now() + Duration::from_secs(1);
        while Arc::strong_count(&client) <= baseline_client_references + 1
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            Arc::strong_count(&client) > baseline_client_references + 1,
            "the idle connection was not accepted"
        );

        let (proxy, _) = monitor_proxy(proxy_task, Some(tasks), None).unwrap();
        stop_proxy(proxy).unwrap();

        assert_eq!(Arc::strong_count(&client), baseline_client_references);
    }

    #[test]
    fn stop_proxy_succeeds_when_the_accept_loop_already_failed() {
        let _global = global_registry();
        let accept_loop = RUNTIME
            .as_ref()
            .unwrap()
            .spawn(async { Err(anyhow::anyhow!("fatal accept error")) });

        let deadline = Instant::now() + Duration::from_secs(1);
        while !accept_loop.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(accept_loop.is_finished(), "the accept loop did not finish");

        // A proxy that already died is exactly when the caller has to be able
        // to restart, so a stale accept-loop error must not fail teardown.
        let (proxy, _) = monitor_proxy(accept_loop, None, None).unwrap();
        stop_proxy(proxy).unwrap();
    }

    #[test]
    fn bootstrap_wait_can_be_cancelled_or_timed_out() {
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let cancelled_result = RUNTIME.as_ref().unwrap().block_on(wait_for_bootstrap(
            pending::<std::result::Result<(), ()>>(),
            &cancelled,
            Duration::from_secs(1),
        ));
        assert!(matches!(
            cancelled_result,
            Err(BootstrapWaitError::Cancelled)
        ));

        let timed_out = RUNTIME.as_ref().unwrap().block_on(wait_for_bootstrap(
            pending::<std::result::Result<(), ()>>(),
            &CancellationToken::new(),
            Duration::from_millis(10),
        ));
        assert!(matches!(timed_out, Err(BootstrapWaitError::TimedOut)));
    }

    #[test]
    fn proxy_exit_reports_whether_stop_was_expected() {
        let _global = global_registry();
        let rt = RUNTIME.as_ref().unwrap();
        let failed_loop = rt.spawn(async { Err(anyhow::anyhow!("fatal accept error")) });
        let (failed_proxy, failed_monitor) = monitor_proxy(failed_loop, None, None).unwrap();
        let failed_exit = rt.block_on(wait_for_proxy_exit(failed_monitor)).unwrap();
        let loss = failed_exit.unwrap();
        assert!(loss.message.contains("fatal accept error"));
        assert!(!loss.process_wide_stop);
        stop_proxy(failed_proxy).unwrap();

        let running_loop = rt.spawn(pending::<Result<()>>());
        let (running_proxy, running_monitor) = monitor_proxy(running_loop, None, None).unwrap();
        stop_proxy(running_proxy).unwrap();
        let stopped_exit = rt.block_on(wait_for_proxy_exit(running_monitor)).unwrap();
        assert!(stopped_exit.is_none());
    }

    /// Tests that go through the process-wide `REGISTRY` run one at a time,
    /// since a sweep there stops whatever another test registered.
    static GLOBAL_REGISTRY_TESTS: Mutex<()> = Mutex::new(());

    fn global_registry() -> MutexGuard<'static, ()> {
        let guard = lock_unpoisoned(&GLOBAL_REGISTRY_TESTS);
        let state = REGISTRY.lock();
        assert!(state.live.is_empty() && state.in_flight.is_empty());
        drop(state);
        guard
    }

    fn running_proxy(tasks: Option<TrackedTasks>) -> (TorProxyHandle, TorProxyMonitor) {
        let accept_loop = RUNTIME.as_ref().unwrap().spawn(pending::<Result<()>>());
        monitor_proxy(accept_loop, tasks, None).unwrap()
    }

    fn exit_loss(monitor: TorProxyMonitor) -> Option<TorProxyLoss> {
        RUNTIME
            .as_ref()
            .unwrap()
            .block_on(wait_for_proxy_exit(monitor))
            .unwrap()
    }

    fn assert_swept(monitor: TorProxyMonitor) {
        let loss = exit_loss(monitor).expect("a process-wide stop reported no loss");
        assert!(loss.process_wide_stop);
        assert_eq!(loss.message, PROCESS_WIDE_STOP_MESSAGE);
    }

    fn register(registry: &Registry, proxy: &TorProxyHandle) {
        let start = InFlight::bootstrap(registry, &CancellationToken::new());
        assert!(start.publish(proxy));
    }

    fn is_live(registry: &Registry, proxy: &TorProxyHandle) -> bool {
        let state = registry.lock();
        state
            .live
            .iter()
            .any(|live| Arc::ptr_eq(&live.state, &proxy.state))
    }

    struct OfflineDirs {
        state: tempfile::TempDir,
        cache: tempfile::TempDir,
    }

    impl OfflineDirs {
        fn new() -> Self {
            Self {
                state: tempfile::tempdir().unwrap(),
                cache: tempfile::tempdir().unwrap(),
            }
        }

        /// A client that never touches the network.
        fn client(&self, runtime: TrackedTorRuntime) -> arti_client::Result<LiveClient> {
            let config =
                TorClientConfigBuilder::from_directories(self.state.path(), self.cache.path())
                    .build()
                    .unwrap();
            TorClient::with_runtime(runtime)
                .config(config)
                .create_unbootstrapped()
        }
    }

    type WeakClient = std::sync::Weak<TorClient<TrackedTorRuntime>>;

    fn client_of(wrapper: &TorClientWrapper) -> WeakClient {
        let state = lock_unpoisoned(&wrapper.slot.state);
        let (client, _) = state
            .client
            .as_ref()
            .expect("the client was already released");
        Arc::downgrade(client)
    }

    fn is_released(wrapper: &TorClientWrapper) -> bool {
        lock_unpoisoned(&wrapper.slot.state).client.is_none()
    }

    /// A proxy serving a real offline client, and a weak reference to it.
    fn proxy_with_client(
        dirs: &OfflineDirs,
        tasks: Option<TrackedTasks>,
        stuck_blocking_task: Option<Duration>,
    ) -> (TorProxyHandle, TorClientWrapper, WeakClient) {
        let (runtime, _) = create_arti_runtime().unwrap();
        let client = dirs.client(runtime.clone()).unwrap();
        if let Some(stuck) = stuck_blocking_task {
            // Its runtime's drop waits for this, however long it takes.
            drop(runtime.spawn_blocking(move || thread::sleep(stuck)));
        }
        let weak = Arc::downgrade(&client);
        let slot = ClientCell::new((client, runtime));
        let accept_loop = RUNTIME.as_ref().unwrap().spawn(pending::<Result<()>>());
        let (proxy, _) = monitor_proxy(accept_loop, tasks, Some(Arc::clone(&slot))).unwrap();
        (proxy, TorClientWrapper { slot }, weak)
    }

    fn eventually(what: &str, within: Duration, condition: impl Fn() -> bool) {
        let deadline = Instant::now() + within;
        while !condition() {
            assert!(Instant::now() < deadline, "gave up waiting until {what}");
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn wait_until(what: &str, condition: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !condition() {
            if Instant::now() > deadline {
                eprintln!("gave up waiting until {what}");
                return false;
            }
            thread::sleep(Duration::from_millis(1));
        }
        true
    }

    #[test]
    fn stop_all_stops_every_registered_proxy_once() {
        let registry = Registry::new();
        let (first, first_monitor) = running_proxy(None);
        let (second, second_monitor) = running_proxy(Some(TrackedTasks::default()));
        register(&registry, &first);
        register(&registry, &second);

        assert_eq!(stop_all_registered(&registry, SWEEP_WAIT).unwrap(), 2);

        assert!(registry.lock().live.is_empty());
        // An owner that is still alive hears of the stop as a loss.
        assert_swept(first_monitor);
        assert_swept(second_monitor);

        // Nothing is left to stop, and the owners' own stops are no-ops.
        assert_eq!(stop_all_registered(&registry, SWEEP_WAIT).unwrap(), 0);
        stop_registered_proxy(&registry, &first).unwrap();
        assert!(!stop_proxy_inner(&second, StopReason::Owner).unwrap());
    }

    #[test]
    fn an_owner_stop_removes_only_its_own_entry() {
        let registry = Registry::new();
        let (stopped, stopped_monitor) = running_proxy(None);
        let (kept, kept_monitor) = running_proxy(None);
        register(&registry, &stopped);
        register(&registry, &kept);

        stop_registered_proxy(&registry, &stopped).unwrap();

        assert!(
            exit_loss(stopped_monitor).is_none(),
            "an owner's stop is expected"
        );
        assert!(!is_live(&registry, &stopped));
        assert!(is_live(&registry, &kept));
        assert!(registry.lock().in_flight.is_empty());
        assert_eq!(stop_all_registered(&registry, SWEEP_WAIT).unwrap(), 1);
        assert_swept(kept_monitor);
    }

    #[test]
    fn stop_all_cancels_bootstraps_in_flight_but_not_later_ones() {
        let registry = Registry::new();
        let caller = CancellationToken::new();
        let registered = std::sync::Barrier::new(2);

        thread::scope(|scope| {
            let start = scope.spawn(|| {
                let before = InFlight::bootstrap(&registry, &caller);
                registered.wait();
                assert!(wait_until("the sweep cancels the start", || before
                    .token
                    .is_cancelled()));
                // A start that finishes bootstrapping after the sweep can't publish.
                let (late, late_monitor) = running_proxy(None);
                let published = before.publish(&late);
                assert!(stop_proxy_inner(&late, StopReason::Owner).unwrap());
                assert!(exit_loss(late_monitor).is_none());
                published
            });
            registered.wait();
            assert_eq!(stop_all_registered(&registry, SWEEP_WAIT).unwrap(), 0);
            assert!(!start.join().unwrap());
        });

        assert!(
            !caller.is_cancelled(),
            "the caller's own token was cancelled"
        );
        assert!(registry.lock().live.is_empty());
        let after = InFlight::bootstrap(&registry, &CancellationToken::new());
        assert!(!after.token.is_cancelled());
        let (proxy, _) = running_proxy(None);
        assert!(after.publish(&proxy));
        drop(after);
        assert!(registry.lock().in_flight.is_empty());
        assert_eq!(stop_all_registered(&registry, SWEEP_WAIT).unwrap(), 1);
    }

    #[test]
    fn a_start_its_caller_cancelled_does_not_publish() {
        let registry = Registry::new();
        let caller = CancellationToken::new();
        let start = InFlight::bootstrap(&registry, &caller);

        caller.cancel();

        assert!(start.token.is_cancelled());
        let (proxy, _) = running_proxy(None);
        assert!(!start.publish(&proxy));
        assert!(registry.lock().live.is_empty());
        stop_proxy_inner(&proxy, StopReason::Owner).unwrap();
    }

    #[test]
    fn a_sweep_waits_for_a_cancelled_start_to_finish_tearing_down() {
        let registry = Registry::new();
        let torn_down = std::sync::atomic::AtomicBool::new(false);
        let registered = std::sync::Barrier::new(2);

        thread::scope(|scope| {
            scope.spawn(|| {
                let pending = InFlight::bootstrap(&registry, &CancellationToken::new());
                registered.wait();
                wait_until("the sweep cancels the start", || {
                    pending.token.is_cancelled()
                });
                // Standing in for finish_failed_start, which can take seconds.
                thread::sleep(Duration::from_millis(300));
                torn_down.store(true, Ordering::SeqCst);
                drop(pending);
            });
            registered.wait();
            let began = Instant::now();
            stop_all_registered(&registry, SWEEP_WAIT).unwrap();
            assert!(torn_down.load(Ordering::SeqCst));
            // Woken when the start ends, not at the end of its wait.
            assert!(
                began.elapsed() < Duration::from_secs(5),
                "{:?}",
                began.elapsed()
            );
        });
    }

    #[test]
    fn a_sweep_reports_what_it_was_still_waiting_for() {
        let registry = Registry::new();
        let _stuck = InFlight::bootstrap(&registry, &CancellationToken::new());

        let error = stop_all_registered(&registry, Duration::from_millis(50)).unwrap_err();

        let message = error.to_string();
        assert!(message.contains("still running after"), "{message}");
    }

    #[test]
    fn a_second_stop_returns_only_after_the_first_has_finished() {
        let tasks = TrackedTasks::default();
        let task_ended = Arc::new(Mutex::new(None));
        let ended = Arc::clone(&task_ended);
        // A task that ignores cancellation, so the first stop takes a while.
        RUNTIME
            .as_ref()
            .unwrap()
            .spawn(tasks.tracker.track_future(async move {
                tokio::time::sleep(Duration::from_millis(300)).await;
                *lock_unpoisoned(&ended) = Some(Instant::now());
            }));
        let (proxy, _) = running_proxy(Some(tasks.clone()));
        let registry = Registry::new();
        register(&registry, &proxy);

        let second_returned = thread::scope(|scope| {
            let first = scope.spawn(|| stop_all_registered(&registry, SWEEP_WAIT).unwrap());
            while !tasks.cancellation.is_cancelled() {
                thread::sleep(Duration::from_millis(1));
            }
            // The first stop has taken the proxy and is waiting for its tasks.
            stop_registered_proxy(&registry, &proxy).unwrap();
            let second_returned = Instant::now();
            assert_eq!(first.join().unwrap(), 1);
            second_returned
        });

        let task_ended = lock_unpoisoned(&task_ended).expect("the task never ended");
        assert!(second_returned >= task_ended, "the second stop didn't wait");
    }

    #[test]
    fn a_sweep_waits_for_an_owner_stop_already_running() {
        let tasks = TrackedTasks::default();
        RUNTIME
            .as_ref()
            .unwrap()
            .spawn(tasks.tracker.track_future(async {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }));
        let (proxy, monitor) = running_proxy(Some(tasks.clone()));
        let registry = Registry::new();
        register(&registry, &proxy);

        thread::scope(|scope| {
            let owner = scope.spawn(|| stop_registered_proxy(&registry, &proxy));
            while !tasks.cancellation.is_cancelled() {
                thread::sleep(Duration::from_millis(1));
            }

            // The owner's stop got there first, so this sweep stops nothing,
            // but it must not return before that stop has finished.
            assert_eq!(stop_all_registered(&registry, SWEEP_WAIT).unwrap(), 0);
            assert!(tasks.tracker.is_empty(), "the owner's stop hadn't finished");
            assert!(registry.lock().in_flight.is_empty());
            owner.join().unwrap().unwrap();
        });
        assert!(exit_loss(monitor).is_none(), "the owner's stop is expected");
    }

    #[test]
    fn a_failed_stop_drops_its_client_once_its_tasks_end() {
        let dirs = OfflineDirs::new();
        let tasks = TrackedTasks::default();
        // Outlasts the stop's 5 s bound, so the stop fails with tasks running.
        RUNTIME
            .as_ref()
            .unwrap()
            .spawn(tasks.tracker.track_future(async {
                tokio::time::sleep(PROXY_SHUTDOWN_TIMEOUT + Duration::from_secs(1)).await;
            }));
        let (proxy, wrapper, client) = proxy_with_client(&dirs, Some(tasks.clone()), None);
        let registry = Registry::new();
        register(&registry, &proxy);

        let error = stop_all_registered(&registry, SWEEP_WAIT).unwrap_err();
        // Give a release thread that didn't wait for the tasks time to act.
        thread::sleep(Duration::from_millis(300));
        assert!(!tasks.tracker.is_empty(), "the stuck task ended too soon");

        assert_eq!(
            error.to_string(),
            "Failed to stop proxy: stopped 0 of 1 Tor proxies cleanly: \
             Timed out stopping Tor client tasks"
        );
        assert!(is_released(&wrapper));
        assert!(client.upgrade().is_some(), "dropped while its tasks ran");
        // A later stop learns that this one failed.
        let later = stop_registered_proxy(&registry, &proxy).unwrap_err();
        assert!(later
            .to_string()
            .contains("Another stop of this Tor proxy failed"));
        // Once the stuck task ends, the release thread drops the client.
        eventually("the client is dropped", Duration::from_secs(5), || {
            client.upgrade().is_none()
        });
    }

    #[test]
    fn a_failed_start_keeps_its_runtime_until_its_tasks_end() {
        /// Stands in for the runtime a failed start leaves behind.
        struct Leftover(Arc<std::sync::atomic::AtomicBool>);

        impl Drop for Leftover {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let tasks = TrackedTasks::default();
        RUNTIME
            .as_ref()
            .unwrap()
            .spawn(tasks.tracker.track_future(async {
                tokio::time::sleep(PROXY_SHUTDOWN_TIMEOUT + Duration::from_secs(1)).await;
            }));
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let error = finish_failed_start(
            None,
            tasks.clone(),
            TorError::BootstrapError("Bootstrap was cancelled".to_owned()),
            Leftover(Arc::clone(&dropped)),
        );
        // Give a release thread that didn't wait for the tasks time to act.
        thread::sleep(Duration::from_millis(300));
        assert!(!tasks.tracker.is_empty(), "the stuck task ended too soon");

        assert!(matches!(error, TorError::RuntimeError(_)), "{error}");
        assert!(
            !dropped.load(Ordering::SeqCst),
            "dropped while its tasks ran"
        );
        eventually("the leftover is dropped", Duration::from_secs(5), || {
            dropped.load(Ordering::SeqCst)
        });
    }

    #[test]
    fn a_client_drop_that_hangs_times_out_and_finishes_later() {
        let dirs = OfflineDirs::new();
        let stuck = CLIENT_RELEASE_TIMEOUT + Duration::from_millis(1500);
        let (proxy, _wrapper, client) = proxy_with_client(&dirs, None, Some(stuck));
        let registry = Registry::new();
        register(&registry, &proxy);

        let began = Instant::now();
        let error = stop_registered_proxy(&registry, &proxy).unwrap_err();
        let took = began.elapsed();

        assert_eq!(
            error.to_string(),
            "Failed to stop proxy: Timed out releasing the Tor client; \
             Arti's locks may still be held"
        );
        assert!(
            took < CLIENT_RELEASE_TIMEOUT + Duration::from_secs(1),
            "{took:?}"
        );
        assert!(!is_live(&registry, &proxy));
        eventually("the client is dropped", Duration::from_secs(5), || {
            client.upgrade().is_none()
        });
    }

    #[test]
    fn a_sweep_stays_bounded_when_a_client_drop_hangs() {
        let dirs = OfflineDirs::new();
        let stuck = CLIENT_RELEASE_TIMEOUT + Duration::from_secs(3);
        let (hung, _hung_wrapper, _) = proxy_with_client(&dirs, None, Some(stuck));
        let (fine, _fine_wrapper, fine_client) = proxy_with_client(&OfflineDirs::new(), None, None);
        let registry = Registry::new();
        register(&registry, &hung);
        register(&registry, &fine);

        let began = Instant::now();
        let error = stop_all_registered(&registry, SWEEP_WAIT).unwrap_err();
        let took = began.elapsed();

        assert!(
            took < CLIENT_RELEASE_TIMEOUT + Duration::from_secs(2),
            "{took:?}"
        );
        let message = error.to_string();
        assert!(message.contains("stopped 1 of 2"), "{message}");
        assert!(
            message.contains("Timed out releasing the Tor client"),
            "{message}"
        );
        assert!(fine_client.upgrade().is_none());
    }

    /// A bootstrap that never finishes and, once abandoned, takes a while to
    /// let go of its client.
    struct SlowToLetGo(#[allow(dead_code)] LiveClient);

    impl Future for SlowToLetGo {
        type Output = std::result::Result<(), arti_client::Error>;

        fn poll(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            std::task::Poll::Pending
        }
    }

    impl Drop for SlowToLetGo {
        fn drop(&mut self) {
            thread::sleep(Duration::from_millis(300));
        }
    }

    #[test]
    fn a_stop_ends_a_re_bootstrap_that_borrowed_its_client() {
        let dirs = OfflineDirs::new();
        let (proxy, wrapper, client) = proxy_with_client(&dirs, None, None);
        let registry = Registry::new();
        register(&registry, &proxy);
        let caller = CancellationToken::new();
        let (sender, receiver) = std::sync::mpsc::channel();

        thread::scope(|scope| {
            scope.spawn(|| {
                let result = bootstrap_with(&registry, &wrapper, &caller, SlowToLetGo);
                sender.send(result).unwrap();
            });
            assert!(wait_until("the re-bootstrap borrows the client", || {
                lock_unpoisoned(&wrapper.slot.state).borrowers == 1
            }));

            let began = Instant::now();
            let stopped = stop_registered_proxy(&registry, &proxy);
            let took = began.elapsed();
            let alive_after_stop = client.upgrade().is_some();
            let ended = receiver.recv_timeout(Duration::from_secs(5));
            caller.cancel(); // Only so a failing run doesn't hang.

            stopped.unwrap();
            assert!(took < Duration::from_secs(2), "{took:?}");
            assert!(
                !alive_after_stop,
                "the stop returned before the client was gone"
            );
            let result = ended.expect("the stop didn't end the re-bootstrap");
            assert!(matches!(result, Err(TorError::BootstrapError(_))));
        });

        // A re-bootstrap begun after the stop finds nothing to borrow.
        assert!(matches!(
            bootstrap_with(&registry, &wrapper, &caller, |_| {
                pending::<std::result::Result<(), arti_client::Error>>()
            }),
            Err(TorError::ClientNotInitialized)
        ));
    }

    #[test]
    fn a_sweep_reports_an_owner_stop_that_failed_to_release() {
        let registry = Registry::new();
        let stop = InFlight::stop(&registry);
        let registered = std::sync::Barrier::new(2);

        thread::scope(|scope| {
            scope.spawn(|| {
                registered.wait();
                wait_until("the sweep begins", || stop.token.is_cancelled());
                stop.mark_unclean();
                drop(stop);
            });
            registered.wait();
            let message = stop_all_registered(&registry, SWEEP_WAIT)
                .unwrap_err()
                .to_string();
            assert!(
                message.contains("couldn't release their client"),
                "{message}"
            );
        });
        assert!(registry.lock().unclean.is_empty());
    }

    // Through the process-wide registry and the FFI entry points.

    #[test]
    fn a_start_publishes_its_proxy_and_stop_proxy_releases_it() {
        let _global = global_registry();
        let dirs = OfflineDirs::new();
        let instance = start_tor_with(&REGISTRY, 0, &CancellationToken::new(), |runtime| {
            std::future::ready(dirs.client(runtime))
        })
        .unwrap();
        let client = client_of(&instance.client);
        assert!(
            is_live(&REGISTRY, &instance.proxy),
            "the start wasn't published"
        );
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, instance.socks_port)).is_err());
        assert!(REGISTRY.lock().in_flight.is_empty());

        stop_proxy(instance.proxy.clone()).unwrap();

        assert!(
            !is_live(&REGISTRY, &instance.proxy),
            "stop_proxy left it registered"
        );
        TcpListener::bind((Ipv4Addr::LOCALHOST, instance.socks_port)).unwrap();
        assert!(
            client.upgrade().is_none(),
            "the stopped client is still alive"
        );
        // What the Dart wrapper still holds is empty, so disposing it can't
        // drop a client, or its runtime, on the Dart thread.
        assert!(is_released(&instance.client));
        set_dormant(&instance.client, true);
        assert!(matches!(
            bootstrap(&instance.client, &TorBootstrapCancellationToken::new()),
            Err(TorError::ClientNotInitialized)
        ));
    }

    #[test]
    fn stop_all_frees_a_client_no_isolate_holds_any_more() {
        let _global = global_registry();
        let dirs = OfflineDirs::new();
        // Kept, like a result FRB couldn't deliver to a dead isolate: it holds
        // a client wrapper and the proxy for the life of the process.
        let leaked = start_tor_with(&REGISTRY, 0, &CancellationToken::new(), |runtime| {
            std::future::ready(dirs.client(runtime))
        })
        .unwrap();
        let client = client_of(&leaked.client);
        let wrapper = leaked.client.clone();

        assert_eq!(stop_all_proxies().unwrap(), 1);

        TcpListener::bind((Ipv4Addr::LOCALHOST, leaked.socks_port)).unwrap();
        assert!(
            client.upgrade().is_none(),
            "the orphaned client is still alive"
        );
        assert!(is_released(&wrapper));
        assert!(REGISTRY.lock().live.is_empty());
        assert_swept(leaked.proxy_monitor.clone());
    }

    #[test]
    fn a_start_cancelled_after_its_bootstrap_tears_down_instead_of_publishing() {
        let _global = global_registry();
        let dirs = OfflineDirs::new();
        let caller = CancellationToken::new();
        let client = Mutex::new(None);

        let result = start_tor_with(&REGISTRY, 0, &caller, |runtime| {
            let built = dirs.client(runtime);
            *lock_unpoisoned(&client) = built.as_ref().ok().map(Arc::downgrade);
            let caller = caller.clone();
            // The cancel lands after the bootstrap has finished.
            async move {
                caller.cancel();
                built
            }
        });

        assert!(matches!(result, Err(TorError::BootstrapError(_))));
        assert!(REGISTRY.lock().live.is_empty());
        assert!(REGISTRY.lock().in_flight.is_empty());
        let client = lock_unpoisoned(&client).take().unwrap();
        assert!(
            client.upgrade().is_none(),
            "the cancelled start kept its client"
        );
    }

    #[test]
    fn a_sweep_cancels_a_start_still_bootstrapping() {
        let _global = global_registry();
        let caller = CancellationToken::new();
        let (sender, receiver) = std::sync::mpsc::channel();

        thread::scope(|scope| {
            scope.spawn(|| {
                let result = start_tor_with(&REGISTRY, 0, &caller, |_| {
                    pending::<arti_client::Result<LiveClient>>()
                });
                sender.send(result.err()).unwrap();
            });
            wait_until("the start registers", || {
                !REGISTRY.lock().in_flight.is_empty()
            });

            let swept = stop_all_proxies();
            let ended = receiver.recv_timeout(Duration::from_secs(5));
            caller.cancel(); // Only so a failing run doesn't hang.

            assert_eq!(swept.unwrap(), 0);
            let error = ended.expect("the sweep didn't cancel the start");
            assert!(matches!(error, Some(TorError::BootstrapError(_))));
        });
    }

    #[test]
    fn a_sweep_cancels_a_re_bootstrap_in_flight() {
        let _global = global_registry();
        let dirs = OfflineDirs::new();
        let (runtime, _) = create_arti_runtime().unwrap();
        let client = dirs.client(runtime.clone()).unwrap();
        let wrapper = TorClientWrapper {
            slot: ClientCell::new((client, runtime)),
        };
        let caller = CancellationToken::new();
        let (sender, receiver) = std::sync::mpsc::channel();

        thread::scope(|scope| {
            scope.spawn(|| {
                let result = bootstrap_with(&REGISTRY, &wrapper, &caller, |_| {
                    pending::<std::result::Result<(), arti_client::Error>>()
                });
                sender.send(result).unwrap();
            });
            wait_until("the re-bootstrap registers", || {
                !REGISTRY.lock().in_flight.is_empty()
            });

            let swept = stop_all_proxies();
            let ended = receiver.recv_timeout(Duration::from_secs(5));
            caller.cancel(); // Only so a failing run doesn't hang.

            assert_eq!(swept.unwrap(), 0);
            let result = ended.expect("the sweep didn't cancel the re-bootstrap");
            assert!(matches!(result, Err(TorError::BootstrapError(_))));
        });
    }

    #[cfg(unix)]
    #[test]
    fn sandboxed_storage_accepts_a_state_dir_arti_would_reject() {
        use std::os::unix::fs::PermissionsExt;

        let state_dir = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        // World-writable, which fs-mistrust refuses for persistent state.
        std::fs::set_permissions(state_dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let path = |dir: &tempfile::TempDir| dir.path().to_str().unwrap().to_owned();
        let create = |sandboxed_storage| {
            let config =
                tor_client_config(path(&state_dir), path(&cache_dir), sandboxed_storage).unwrap();
            let (runtime, _tasks) = create_arti_runtime().unwrap();
            TorClient::with_runtime(runtime)
                .config(config)
                .create_unbootstrapped()
        };

        let rejection = error_chain(
            &create(false)
                .err()
                .expect("Arti accepted a world-writable state directory"),
        );
        let state_dir_name = state_dir.path().file_name().unwrap().to_str().unwrap();
        assert!(rejection.contains(state_dir_name), "{rejection}");
        create(true).unwrap();
    }

    /// Signals when the task holding it is dropped, finished or not.
    struct DropSignal(std::sync::mpsc::Sender<()>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }

    #[test]
    fn a_join_set_returns_what_its_tasks_return_and_their_panics() {
        let (runtime, _tasks) = create_arti_runtime().unwrap();
        let mut set = runtime.new_join_set::<u32>();
        set.spawn(async { 7 }).unwrap();
        set.spawn(async { panic!("a join set task panicked") })
            .unwrap();

        let outputs = runtime.block_on(async {
            let mut outputs = Vec::new();
            while let Some(output) = set.join_next().await {
                outputs.push(output.ok());
            }
            outputs
        });

        assert_eq!(outputs.len(), 2);
        assert!(outputs.contains(&Some(7)));
        assert!(outputs.contains(&None));
    }

    #[test]
    fn a_stop_cancels_join_set_tasks_and_waits_for_them() {
        let (runtime, tasks) = create_arti_runtime().unwrap();
        let mut set = runtime.new_join_set::<()>();
        let (sender, dropped) = std::sync::mpsc::channel();
        let signal = DropSignal(sender);
        set.spawn(async move {
            let _signal = signal;
            pending::<()>().await
        })
        .unwrap();

        tasks.stop_and_wait().unwrap();

        assert!(
            dropped.try_recv().is_ok(),
            "the stop returned before the join set's task ended"
        );
        assert!(runtime.block_on(set.join_next()).is_none());
        assert!(set.spawn(async {}).is_err());
    }

    #[test]
    fn dropping_a_join_set_ends_its_tasks() {
        let (runtime, _tasks) = create_arti_runtime().unwrap();
        let mut set = runtime.new_join_set::<()>();
        let (sender, dropped) = std::sync::mpsc::channel();
        let signal = DropSignal(sender);
        set.spawn(async move {
            let _signal = signal;
            pending::<()>().await
        })
        .unwrap();

        drop(set);

        dropped
            .recv_timeout(Duration::from_secs(5))
            .expect("the join set's task outlived the set");
    }
}
