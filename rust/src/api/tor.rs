// SPDX-FileCopyrightText: 2024 Foundation Devices Inc.
//
// SPDX-License-Identifier: MIT

use anyhow::Result;
use arti::proxy::{self, ListenProtocols};
use arti_client::config::CfgPath;
use arti_client::{DormantMode, TorClient, TorClientConfig};
use flutter_rust_bridge::frb;
use futures::future::FutureObj;
use futures::task::{Spawn, SpawnError};
use lazy_static::lazy_static;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use tokio::runtime::{Builder, Runtime as TokioRuntime};
use tokio::sync::watch;
use tokio::task::{AbortHandle, JoinHandle};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tor_config::Listen;
use tor_rtcompat::tokio::TokioNativeTlsRuntime;
use tor_rtcompat::{
    Blocking, CompoundRuntime, NetStreamListener, NetStreamProvider, TcpListenOptions,
    ToplevelBlockOn,
};

lazy_static! {
    static ref RUNTIME: io::Result<TokioRuntime> = Builder::new_multi_thread().enable_all().build();
}

const PROXY_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const PROCESS_WIDE_STOP_MESSAGE: &str = "Tor proxy was stopped by a process-wide stop";
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

fn finish_failed_start(tasks: TrackedTasks, error: TorError) -> TorError {
    match tasks.stop_and_wait() {
        Ok(()) => error,
        Err(cleanup_error) => TorError::RuntimeError(format!(
            "{error}; failed to stop partially started Tor tasks: {cleanup_error}"
        )),
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

/// Opaque wrapper for TorClient - FRB handles this automatically
#[frb(opaque)]
pub struct TorClientWrapper {
    client: Arc<TorClient<TrackedTorRuntime>>,
    runtime: TrackedTorRuntime,
}

impl Clone for TorClientWrapper {
    fn clone(&self) -> Self {
        TorClientWrapper {
            client: Arc::clone(&self.client),
            runtime: self.runtime.clone(),
        }
    }
}

/// Opaque wrapper for proxy handle
#[frb(opaque)]
pub struct TorProxyHandle {
    state: Arc<std::sync::Mutex<TorProxyState>>,
}

struct TorProxyState {
    accept_loop_abort: Option<AbortHandle>,
    accept_loop_monitor: Option<JoinHandle<()>>,
    /// 0 while running, then the [`StopReason`] of the stop that took the handles.
    stop_reason: Arc<AtomicU8>,
    tasks: Option<TrackedTasks>,
}

/// Who stopped a proxy, as its monitor reports it.
#[derive(Clone, Copy)]
#[repr(u8)]
enum StopReason {
    /// The proxy's own handle: an expected stop, which reports no failure.
    Owner = 1,
    /// `stop_all_proxies`, which can't tell a live isolate's proxy from an
    /// orphan's, so a live owner hears of it as a failure and stops publishing
    /// the port.
    ProcessWide = 2,
}

type LiveClient = Arc<TorClient<TrackedTorRuntime>>;

/// Every proxy `start_tor` has started in this process that nothing has stopped
/// yet, and every bootstrap in flight, whichever isolate started them.
///
/// Dart holds clients and proxies through per-isolate handles, so an isolate
/// can only stop what it started itself, and a proxy whose isolate has died
/// (an engine destroyed without any Dart callback) keeps listening with no
/// handle left anywhere. This record is how `stop_all_proxies` reaches it.
static REGISTRY: Mutex<ProxyRegistry<LiveClient>> = Mutex::new(ProxyRegistry::new());

/// Generic over the client so the bookkeeping can be tested without Arti.
struct ProxyRegistry<C> {
    live: Vec<LiveProxy<C>>,
    bootstraps: Vec<(u64, CancellationToken)>,
    next_bootstrap: u64,
}

struct LiveProxy<C> {
    proxy: TorProxyHandle,
    /// Holds the client until its proxy has stopped, so that when nothing else
    /// does (its isolate is gone) the last reference is dropped by the call
    /// that stopped it, on an FRB worker thread. Otherwise it would be dropped
    /// inside a tokio task, and dropping the runtime the client owns from an
    /// async context panics. Never read: only its drop matters.
    _client: C,
}

impl<C> ProxyRegistry<C> {
    const fn new() -> Self {
        Self {
            live: Vec::new(),
            bootstraps: Vec::new(),
            next_bootstrap: 0,
        }
    }

    fn remove(&mut self, proxy: &TorProxyHandle) -> Option<LiveProxy<C>> {
        let index = self
            .live
            .iter()
            .position(|live| Arc::ptr_eq(&live.proxy.state, &proxy.state))?;
        Some(self.live.swap_remove(index))
    }
}

fn lock_registry<C>(registry: &Mutex<ProxyRegistry<C>>) -> MutexGuard<'_, ProxyRegistry<C>> {
    // Each critical section is a single push, retain, remove or take, so a
    // panic can't leave the record half-updated, and refusing to stop anything
    // after one would be worse than carrying on.
    registry.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A bootstrap in flight, which `stop_all_proxies` cancels. Deregisters on drop.
struct PendingBootstrap<'a, C> {
    registry: &'a Mutex<ProxyRegistry<C>>,
    id: u64,
    /// Cancelled by the caller's token or by a process-wide stop.
    token: CancellationToken,
}

impl<'a, C> PendingBootstrap<'a, C> {
    fn begin(registry: &'a Mutex<ProxyRegistry<C>>, caller: &CancellationToken) -> Self {
        let token = caller.child_token();
        let mut state = lock_registry(registry);
        let id = state.next_bootstrap;
        state.next_bootstrap += 1;
        state.bootstraps.push((id, token.clone()));
        drop(state);
        Self {
            registry,
            id,
            token,
        }
    }
}

impl<C: Clone> PendingBootstrap<'_, C> {
    /// Records a started proxy, unless this start has been cancelled, by its
    /// caller or by a process-wide stop; the caller must then tear it down.
    /// Checked under the registry lock, so a process-wide stop either finds the
    /// proxy or has cancelled its start, never neither.
    fn publish(&self, proxy: &TorProxyHandle, client: &C) -> bool {
        let mut state = lock_registry(self.registry);
        if self.token.is_cancelled() {
            return false;
        }
        state.live.push(LiveProxy {
            proxy: proxy.clone(),
            _client: client.clone(),
        });
        true
    }
}

impl<C> Drop for PendingBootstrap<'_, C> {
    fn drop(&mut self) {
        lock_registry(self.registry)
            .bootstraps
            .retain(|(id, _)| *id != self.id);
    }
}

#[derive(Clone, Debug)]
struct TorProxyExit {
    expected: bool,
    message: String,
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
    let pending = PendingBootstrap::begin(&REGISTRY, &cancellation_token.token);
    let cfg = tor_client_config(state_dir, cache_dir, SANDBOXED_STORAGE)?;

    let (runtime, tasks) =
        create_arti_runtime().map_err(|e| TorError::RuntimeError(e.to_string()))?;

    let client = runtime.block_on(wait_for_bootstrap(
        async {
            TorClient::with_runtime(runtime.clone())
                .config(cfg)
                .create_bootstrapped()
                .await
        },
        &pending.token,
        BOOTSTRAP_TIMEOUT,
    ));
    let client = match client {
        Ok(client) => client,
        Err(BootstrapWaitError::Cancelled) => {
            return Err(finish_failed_start(
                tasks,
                TorError::BootstrapError("Bootstrap was cancelled".to_owned()),
            ));
        }
        Err(BootstrapWaitError::TimedOut) => {
            return Err(finish_failed_start(
                tasks,
                TorError::BootstrapError("Bootstrap timed out".to_owned()),
            ));
        }
        Err(BootstrapWaitError::Failed(error)) => {
            return Err(finish_failed_start(
                tasks,
                TorError::BootstrapError(error_chain(&error)),
            ));
        }
    };

    let (accept_loop, socks_port) = match start_proxy_internal(socks_port, Arc::clone(&client)) {
        Ok(proxy) => proxy,
        Err(error) => return Err(finish_failed_start(tasks, error)),
    };
    let (proxy, proxy_monitor) = monitor_proxy(accept_loop, Some(tasks))?;
    if !pending.publish(&proxy, &client) {
        // Cancelled after the bootstrap finished: whoever cancelled it has
        // already stopped publishing this start, so don't hand back a proxy.
        return Err(match stop_proxy_inner(&proxy, StopReason::Owner) {
            Ok(_) => TorError::BootstrapError("Bootstrap was cancelled".to_owned()),
            Err(error) => error,
        });
    }

    Ok(TorInstance {
        client: TorClientWrapper { client, runtime },
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
) -> Result<(TorProxyHandle, TorProxyMonitor), TorError> {
    let rt = match RUNTIME.as_ref() {
        Ok(rt) => rt,
        Err(error) => {
            accept_loop.abort();
            let error = TorError::RuntimeError(error.to_string());
            return Err(match tasks {
                Some(tasks) => finish_failed_start(tasks, error),
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
        let expected = reason == StopReason::Owner as u8;
        let message = match result {
            _ if reason == StopReason::ProcessWide as u8 => PROCESS_WIDE_STOP_MESSAGE.to_owned(),
            Ok(Ok(())) => "Tor proxy accept loop exited".to_owned(),
            Ok(Err(error)) => format!("Tor proxy accept loop failed: {error}"),
            Err(error) if error.is_cancelled() => "Tor proxy accept loop was cancelled".to_owned(),
            Err(error) => format!("Tor proxy accept loop panicked: {error}"),
        };

        if !expected {
            log::warn!("{message}");
        }
        let _ = exit_sender.send(Some(TorProxyExit { expected, message }));
    });

    Ok((
        TorProxyHandle {
            state: Arc::new(std::sync::Mutex::new(TorProxyState {
                accept_loop_abort: Some(accept_loop_abort),
                accept_loop_monitor: Some(accept_loop_monitor),
                stop_reason,
                tasks,
            })),
        },
        TorProxyMonitor {
            exit: exit_receiver,
        },
    ))
}

pub async fn wait_for_proxy_exit(mut monitor: TorProxyMonitor) -> Result<Option<String>, TorError> {
    if monitor.exit.borrow().is_none() {
        monitor.exit.changed().await.map_err(|_| {
            TorError::RuntimeError("Tor proxy monitor stopped without an exit event".to_owned())
        })?;
    }

    let exit = monitor.exit.borrow().clone().ok_or_else(|| {
        TorError::RuntimeError("Tor proxy monitor stopped without an exit event".to_owned())
    })?;
    Ok((!exit.expected).then_some(exit.message))
}

/// Re-bootstrap the Tor client
///
/// Call this after network changes or to refresh the connection.
pub fn bootstrap(
    client: &TorClientWrapper,
    cancellation_token: &TorBootstrapCancellationToken,
) -> Result<(), TorError> {
    let pending = PendingBootstrap::begin(&REGISTRY, &cancellation_token.token);
    match client.runtime.block_on(wait_for_bootstrap(
        client.client.as_ref().bootstrap(),
        &pending.token,
        BOOTSTRAP_TIMEOUT,
    )) {
        Ok(()) => Ok(()),
        Err(BootstrapWaitError::Cancelled) => Err(TorError::BootstrapError(
            "Bootstrap was cancelled".to_owned(),
        )),
        Err(BootstrapWaitError::TimedOut) => {
            Err(TorError::BootstrapError("Bootstrap timed out".to_owned()))
        }
        Err(BootstrapWaitError::Failed(error)) => Err(TorError::BootstrapError(error.to_string())),
    }
}

/// Set the client dormant mode
///
/// * `soft_mode` - If true, uses Soft dormant mode (keeps some circuits warm)
///   If false, uses Normal mode (full operation)
pub fn set_dormant(client: &TorClientWrapper, soft_mode: bool) {
    let dormant_mode = if soft_mode {
        DormantMode::Soft
    } else {
        DormantMode::Normal
    };
    client.client.as_ref().set_dormant(dormant_mode);
}

/// Stop the Tor proxy
///
/// Stops the accept loop and the client runtime that owns accepted connections.
/// Stopping a proxy that is already stopped, or being stopped, does nothing
/// and returns once that stop has finished.
pub fn stop_proxy(proxy: TorProxyHandle) -> Result<(), TorError> {
    stop_registered_proxy(&REGISTRY, &proxy)
}

/// Stop every Tor proxy in this process
///
/// Stops every proxy started in this process that hasn't been stopped yet,
/// whichever isolate started it, including one whose isolate no longer
/// exists, and cancels every bootstrap in flight, so nothing started before
/// this call is left running after it. Returns how many proxies it stopped.
///
/// It can't tell an orphan from a live isolate's proxy: a live owner's proxy
/// monitor reports the stop as a failure.
pub fn stop_all_proxies() -> Result<u32, TorError> {
    stop_all_registered(&REGISTRY)
}

fn stop_registered_proxy<C>(
    registry: &Mutex<ProxyRegistry<C>>,
    proxy: &TorProxyHandle,
) -> Result<(), TorError> {
    let entry = lock_registry(registry).remove(proxy);
    let result = stop_proxy_inner(proxy, StopReason::Owner).map(|_| ());
    drop(entry);
    result
}

fn stop_all_registered<C>(registry: &Mutex<ProxyRegistry<C>>) -> Result<u32, TorError> {
    let live = {
        let mut state = lock_registry(registry);
        for (_, token) in &state.bootstraps {
            token.cancel();
        }
        std::mem::take(&mut state.live)
    };

    let total = live.len();
    let mut stopped = 0;
    let mut errors = Vec::new();
    for entry in live {
        match stop_proxy_inner(&entry.proxy, StopReason::ProcessWide) {
            Ok(true) => stopped += 1,
            Ok(false) => {}
            Err(error) => errors.push(error.to_string()),
        }
        drop(entry);
    }

    if errors.is_empty() {
        Ok(stopped)
    } else {
        Err(TorError::ProxyStopError(format!(
            "stopped {stopped} of {total} Tor proxies cleanly: {}",
            errors.join("; ")
        )))
    }
}

/// Stops the accept loop and the client tasks of `proxy`, unless another stop
/// already has. Returns whether this call did the stopping.
fn stop_proxy_inner(proxy: &TorProxyHandle, reason: StopReason) -> Result<bool, TorError> {
    // Held for the whole stop, so a second stop of the same proxy (its owner's
    // racing a process-wide one) returns only once the first has finished.
    let mut state = proxy
        .state
        .lock()
        .map_err(|e| TorError::ProxyStopError(e.to_string()))?;
    let accept_loop_abort = state.accept_loop_abort.take();
    let accept_loop_monitor = state.accept_loop_monitor.take();
    let tasks = state.tasks.take();
    let stopping = accept_loop_abort.is_some() || accept_loop_monitor.is_some() || tasks.is_some();
    if !stopping {
        return Ok(false);
    }

    // Before the abort, so the monitor reports why the accept loop ended.
    state.stop_reason.store(reason as u8, Ordering::Release);
    if let Some(abort) = accept_loop_abort {
        abort.abort();
    }

    let accept_result = match (accept_loop_monitor, RUNTIME.as_ref()) {
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

    let task_result = tasks.map_or(Ok(()), |tasks| tasks.stop_and_wait());
    drop(state);

    accept_result.and(task_result).map(|()| true)
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

        let (proxy, _) = monitor_proxy(proxy_task, Some(tasks)).unwrap();
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

        let (proxy, _) = monitor_proxy(proxy_task, Some(tasks)).unwrap();
        stop_proxy(proxy).unwrap();

        assert_eq!(Arc::strong_count(&client), baseline_client_references);
    }

    #[test]
    fn stop_proxy_succeeds_when_the_accept_loop_already_failed() {
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
        let (proxy, _) = monitor_proxy(accept_loop, None).unwrap();
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
        let rt = RUNTIME.as_ref().unwrap();
        let failed_loop = rt.spawn(async { Err(anyhow::anyhow!("fatal accept error")) });
        let (failed_proxy, failed_monitor) = monitor_proxy(failed_loop, None).unwrap();
        let failed_exit = rt.block_on(wait_for_proxy_exit(failed_monitor)).unwrap();
        assert!(failed_exit.unwrap().contains("fatal accept error"));
        stop_proxy(failed_proxy).unwrap();

        let running_loop = rt.spawn(pending::<Result<()>>());
        let (running_proxy, running_monitor) = monitor_proxy(running_loop, None).unwrap();
        stop_proxy(running_proxy).unwrap();
        let stopped_exit = rt.block_on(wait_for_proxy_exit(running_monitor)).unwrap();
        assert!(stopped_exit.is_none());
    }

    fn running_proxy(tasks: Option<TrackedTasks>) -> (TorProxyHandle, TorProxyMonitor) {
        let accept_loop = RUNTIME.as_ref().unwrap().spawn(pending::<Result<()>>());
        monitor_proxy(accept_loop, tasks).unwrap()
    }

    fn exit_message(monitor: TorProxyMonitor) -> Option<String> {
        RUNTIME
            .as_ref()
            .unwrap()
            .block_on(wait_for_proxy_exit(monitor))
            .unwrap()
    }

    fn register<C: Clone>(registry: &Mutex<ProxyRegistry<C>>, proxy: &TorProxyHandle, client: &C) {
        let start = PendingBootstrap::begin(registry, &CancellationToken::new());
        assert!(start.publish(proxy, client));
    }

    #[test]
    fn stop_all_stops_every_registered_proxy_once() {
        let registry = Mutex::new(ProxyRegistry::new());
        let client = Arc::new(());
        let (first, first_monitor) = running_proxy(None);
        let (second, second_monitor) = running_proxy(Some(TrackedTasks::default()));
        register(&registry, &first, &client);
        register(&registry, &second, &client);
        assert_eq!(Arc::strong_count(&client), 3);

        assert_eq!(stop_all_registered(&registry).unwrap(), 2);

        assert!(lock_registry(&registry).live.is_empty());
        assert_eq!(Arc::strong_count(&client), 1, "a client outlived its proxy");
        // An owner that is still alive hears of the stop as a failure.
        for monitor in [first_monitor, second_monitor] {
            assert_eq!(
                exit_message(monitor).as_deref(),
                Some(PROCESS_WIDE_STOP_MESSAGE)
            );
        }

        // Nothing is left to stop, and the owners' own stops are no-ops.
        assert_eq!(stop_all_registered(&registry).unwrap(), 0);
        stop_registered_proxy(&registry, &first).unwrap();
        assert!(!stop_proxy_inner(&second, StopReason::Owner).unwrap());
    }

    #[test]
    fn an_owner_stop_removes_only_its_own_entry() {
        let registry = Mutex::new(ProxyRegistry::new());
        let (stopped, stopped_monitor) = running_proxy(None);
        let (kept, kept_monitor) = running_proxy(None);
        register(&registry, &stopped, &());
        register(&registry, &kept, &());

        stop_registered_proxy(&registry, &stopped).unwrap();

        assert_eq!(
            exit_message(stopped_monitor),
            None,
            "an owner's stop is expected"
        );
        {
            let state = lock_registry(&registry);
            assert_eq!(state.live.len(), 1);
            assert!(Arc::ptr_eq(&state.live[0].proxy.state, &kept.state));
        }
        assert_eq!(stop_all_registered(&registry).unwrap(), 1);
        assert_eq!(
            exit_message(kept_monitor).as_deref(),
            Some(PROCESS_WIDE_STOP_MESSAGE)
        );
    }

    #[test]
    fn stop_all_cancels_bootstraps_in_flight_but_not_later_ones() {
        let registry = Mutex::new(ProxyRegistry::new());
        let caller = CancellationToken::new();
        let before = PendingBootstrap::begin(&registry, &caller);

        assert_eq!(stop_all_registered(&registry).unwrap(), 0);

        assert!(before.token.is_cancelled());
        assert!(
            !caller.is_cancelled(),
            "the caller's own token was cancelled"
        );
        // A start that finishes bootstrapping after the sweep can't publish.
        let (late, late_monitor) = running_proxy(None);
        assert!(!before.publish(&late, &()));
        assert!(lock_registry(&registry).live.is_empty());
        assert!(stop_proxy_inner(&late, StopReason::Owner).unwrap());
        assert_eq!(exit_message(late_monitor), None);

        let after = PendingBootstrap::begin(&registry, &CancellationToken::new());
        assert!(!after.token.is_cancelled());
        let (proxy, _) = running_proxy(None);
        assert!(after.publish(&proxy, &()));

        drop(before);
        drop(after);
        assert!(lock_registry(&registry).bootstraps.is_empty());
        assert_eq!(stop_all_registered(&registry).unwrap(), 1);
    }

    #[test]
    fn a_start_its_caller_cancelled_does_not_publish() {
        let registry = Mutex::new(ProxyRegistry::new());
        let caller = CancellationToken::new();
        let start = PendingBootstrap::begin(&registry, &caller);

        caller.cancel();

        assert!(start.token.is_cancelled());
        let (proxy, _) = running_proxy(None);
        assert!(!start.publish(&proxy, &()));
        assert!(lock_registry(&registry).live.is_empty());
        stop_proxy_inner(&proxy, StopReason::Owner).unwrap();
    }

    #[test]
    fn stop_all_frees_a_client_no_isolate_holds_any_more() {
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
        let (accept_loop, port) = start_proxy_internal(0, Arc::clone(&client)).unwrap();
        let (proxy, _monitor) = monitor_proxy(accept_loop, Some(tasks)).unwrap();
        let registry = Mutex::new(ProxyRegistry::new());
        register(&registry, &proxy, &client);

        // The isolate that started it has gone, and with it every handle.
        let orphan = Arc::downgrade(&client);
        drop((client, runtime, proxy));
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_err());

        assert_eq!(stop_all_registered(&registry).unwrap(), 1);

        TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
        assert!(
            orphan.upgrade().is_none(),
            "the orphaned client is still alive"
        );
    }

    #[test]
    fn a_second_stop_returns_only_after_the_first_has_finished() {
        let tasks = TrackedTasks::default();
        // A task that ignores cancellation, so the first stop takes a while.
        RUNTIME
            .as_ref()
            .unwrap()
            .spawn(tasks.tracker.track_future(async {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }));
        let (proxy, _) = running_proxy(Some(tasks.clone()));
        let registry = Mutex::new(ProxyRegistry::new());
        register(&registry, &proxy, &());

        let (first_finished, second_returned) = thread::scope(|scope| {
            let first = scope.spawn(|| {
                let stopped = stop_all_registered(&registry).unwrap();
                (stopped, Instant::now())
            });
            while !tasks.cancellation.is_cancelled() {
                thread::sleep(Duration::from_millis(1));
            }
            // The first stop now holds the proxy and is waiting for its tasks.
            stop_registered_proxy(&registry, &proxy).unwrap();
            let second_returned = Instant::now();
            let (stopped, first_finished) = first.join().unwrap();
            assert_eq!(stopped, 1);
            (first_finished, second_returned)
        });

        assert!(second_returned >= first_finished);
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
}
