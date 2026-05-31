//! Background-task supervision (`supervisor`) — Req 50.7, 50.12.
//!
//! A lightweight [`Supervisor`] owns every long-lived background task
//! (segment prefetchers, the warmup refresher, integration list-sync workers,
//! the SSE broadcaster, the Acestream/Telegram session managers, the Redis
//! connection manager, and the leaked-resource reaper) and restarts it on
//! crash **with backoff**, guarded against crash-loops (design: Resilience →
//! Pattern 5 "Self-Healing & Supervision"; Components → Background-task
//! supervision).
//!
//! ## What the monitor loop guarantees
//!
//! Each supervised task runs inside a monitor loop on its own `tokio` task.
//! The task's run-future is polled inside
//! [`AssertUnwindSafe`](std::panic::AssertUnwindSafe) +
//! [`catch_unwind`](futures::future::FutureExt::catch_unwind), so a **panic**
//! in one task is caught by the loop and **never tears down the process**
//! (Req 50.8 is the per-request analogue; this is its background-task
//! counterpart — Req 50.7). When the run-future resolves (panic, an `Err`
//! crash, or even an `Ok(())` early exit) the loop treats it as an unexpected
//! exit of a long-lived task and **restarts it with backoff**, recording a
//! [`RestartEvent`] each time (Req 50.7). A task that **runs forever** never
//! resolves, so the loop never restarts it — only an actual exit triggers a
//! restart.
//!
//! ## Crash-loop guard (Req 50.7, 50.12)
//!
//! Unbounded restarts of a permanently-broken task would spin the CPU, so the
//! [`CrashLoopGuard`] caps restarts to `max_restarts` within a sliding
//! `window`: the number of restarts performed inside any window of that length
//! never exceeds `max_restarts`. Once the cap is hit the task is parked in the
//! [`Failed`](TaskStatus::Failed) state, surfaced via metrics / `/health`, and
//! the rest of the system keeps serving (Req 50.13, graceful partial startup).
//!
//! ## Graceful shutdown (Req 49.4)
//!
//! A [`ShutdownToken`] threads into every task. When the owning
//! [`ShutdownSignal`] fires, the monitor loop stops restarting and lets the
//! task drain — a clean exit during shutdown parks the task as
//! [`Stopped`](TaskStatus::Stopped), **not** `Failed`.
//!
//! ## Clock choice (testability)
//!
//! The monitor loop's backoff sleeps use [`tokio::time::sleep`] and its
//! crash-loop window is measured against a [`tokio::time::Instant`], so under a
//! paused test runtime (`#[tokio::test(start_paused = true)]`) the whole loop
//! runs on a deterministic fake clock with no real sleeping. The pure
//! [`CrashLoopGuard`] and [`RestartPolicy::backoff`] take explicit timestamps /
//! indices and are unit/property-testable with no runtime at all.

use std::any::Any;
use std::collections::VecDeque;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::future::FutureExt;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::errors::AppError;

/// The leaked-resource reaper (task 7.2): periodically reclaims abandoned SSE
/// subscriptions, idle prefetchers, stale Acestream sessions, zombie FFmpeg
/// children, and orphaned upstream connections on a configurable interval. It
/// is one of the long-lived tasks owned by the [`Supervisor`] (design:
/// Resilience → Pattern 5; Req 50.12, 41.5, 7.5, 10.6, 6.12).
pub mod reaper;

/// The uniform shape of a supervised task's run-future: a boxed, `Send` future
/// that resolves to `Ok(())` on a clean completion or `Err` on a crash. Both
/// outcomes — and a panic — are treated by the monitor loop as an unexpected
/// exit of a long-lived task and trigger a restart (Req 50.7).
pub type TaskFuture = Pin<Box<dyn Future<Output = Result<(), AppError>> + Send>>;

// ---------------------------------------------------------------------------
// RestartPolicy + backoff schedule
// ---------------------------------------------------------------------------

/// Restart-with-backoff policy plus crash-loop guard parameters (design:
/// Pattern 5).
///
/// The first four fields define the **backoff schedule** applied between
/// restarts; the last two define the **crash-loop guard** that caps restarts
/// within a sliding window (Req 50.7, 50.12).
#[derive(Clone, Debug)]
pub struct RestartPolicy {
    /// The first backoff term, used for the first restart (e.g. `200ms`).
    pub base_backoff: Duration,
    /// Cap applied to the exponential backoff term (e.g. `30s`); no restart
    /// delay ever exceeds this.
    pub max_backoff: Duration,
    /// Exponential factor applied per consecutive restart (e.g. `2.0`).
    pub multiplier: f64,
    /// Maximum restarts permitted within `window` before the task is parked
    /// `Failed` (crash-loop guard).
    pub max_restarts: u32,
    /// Sliding crash-loop detection window (e.g. `60s`).
    pub window: Duration,
}

impl Default for RestartPolicy {
    /// The design's example policy: `200ms` base, `30s` cap, ×2, 5 restarts
    /// per `60s` window.
    fn default() -> Self {
        Self {
            base_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(30),
            multiplier: 2.0,
            max_restarts: 5,
            window: Duration::from_secs(60),
        }
    }
}

impl RestartPolicy {
    /// The backoff delay before the restart at zero-based `restart_index`
    /// within the current window:
    /// `min(max_backoff, base_backoff · multiplierʳᵉˢᵗᵃʳᵗ⁻ⁱⁿᵈᵉˣ)`.
    ///
    /// Computed in `f64` seconds so a large index saturates to `max_backoff`
    /// instead of overflowing [`Duration::mul_f64`]; the result is therefore
    /// **always `<= max_backoff`** (Property 52 / Req 50.7).
    pub fn backoff(&self, restart_index: u32) -> Duration {
        let base_secs = self.base_backoff.as_secs_f64();
        let max_secs = self.max_backoff.as_secs_f64();
        let factor = self.multiplier.powi(restart_index as i32);
        let exp_secs = base_secs * factor;
        let capped_secs = exp_secs.min(max_secs);
        let capped_secs = if capped_secs.is_finite() {
            capped_secs.max(0.0)
        } else {
            max_secs
        };
        Duration::from_secs_f64(capped_secs)
    }
}

// ---------------------------------------------------------------------------
// Crash-loop guard (pure, deterministic)
// ---------------------------------------------------------------------------

/// The monitor loop's decision after a task exits (panic / crash / early exit).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RestartDecision {
    /// Restart after waiting `backoff`; `in_window_index` is the zero-based
    /// position of this restart within the current crash-loop window.
    Restart {
        /// How long to wait before re-running the task.
        backoff: Duration,
        /// Zero-based index of this restart within the sliding window.
        in_window_index: u32,
    },
    /// The crash-loop cap is reached — park the task in `Failed` rather than
    /// restart it again (Req 50.7, 50.12).
    Park,
}

/// A pure, deterministic sliding-window crash-loop guard (design: Pattern 5 —
/// "tracks (restart_count, window_start) per task").
///
/// It records the millisecond timestamp of each restart it authorizes and
/// prunes timestamps older than [`RestartPolicy::window`]; a restart is
/// authorized only while fewer than [`RestartPolicy::max_restarts`] restarts
/// fall inside the trailing window. This guarantees the number of restarts in
/// **any** window of length `window` never exceeds `max_restarts` (Property 55
/// / Req 50.12). Because it takes an explicit `now_ms`, it is fully
/// deterministic and testable without a runtime.
pub struct CrashLoopGuard {
    policy: RestartPolicy,
    /// Millisecond timestamps of authorized restarts still inside the window.
    window: VecDeque<u64>,
}

impl CrashLoopGuard {
    /// A fresh guard for `policy` with an empty restart history.
    pub fn new(policy: RestartPolicy) -> Self {
        Self {
            policy,
            window: VecDeque::new(),
        }
    }

    /// Drop restart timestamps that have rolled out of the trailing window
    /// ending at `now_ms` (kept iff `now_ms − ts < window`).
    fn prune(&mut self, now_ms: u64) {
        let window_ms = self.policy.window.as_millis() as u64;
        while let Some(&front) = self.window.front() {
            if now_ms.saturating_sub(front) >= window_ms {
                self.window.pop_front();
            } else {
                break;
            }
        }
    }

    /// Decide whether to restart a task that just exited at `now_ms`.
    ///
    /// Authorizes a restart (recording `now_ms`) while fewer than
    /// `max_restarts` restarts remain inside the trailing window; otherwise
    /// returns [`Park`](RestartDecision::Park). As the window rolls forward and
    /// old restarts are pruned, restarts become available again (Property 55).
    pub fn on_exit(&mut self, now_ms: u64) -> RestartDecision {
        self.prune(now_ms);
        let in_window_index = self.window.len() as u32;
        if in_window_index < self.policy.max_restarts {
            let backoff = self.policy.backoff(in_window_index);
            self.window.push_back(now_ms);
            RestartDecision::Restart {
                backoff,
                in_window_index,
            }
        } else {
            RestartDecision::Park
        }
    }

    /// The number of restarts currently counted inside the window (for
    /// metrics / tests).
    pub fn restarts_in_window(&self) -> usize {
        self.window.len()
    }
}

// ---------------------------------------------------------------------------
// Task status, exit reason, and restart events
// ---------------------------------------------------------------------------

/// The supervised task's lifecycle status (surfaced via `/health` component
/// status — Req 50.13).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskStatus {
    /// Running (or backing off between restarts) under the supervisor.
    Running,
    /// Drained cleanly in response to graceful shutdown (not a failure).
    Stopped,
    /// Parked after the crash-loop guard tripped (Req 50.7, 50.12).
    Failed,
}

/// Why a supervised task's run-future resolved.
#[derive(Clone, Debug)]
pub enum ExitReason {
    /// The future returned `Ok(())` — a clean but unexpected early exit of a
    /// long-lived task.
    Completed,
    /// The future returned `Err(_)` — a crash carrying the error's message.
    Crashed(String),
    /// The future panicked — the panic payload was caught at the boundary.
    Panicked(String),
}

/// A structured record of one restart, kept for inspection and emitted to the
/// structured log (Req 50.7 — "record the restart in the structured log").
#[derive(Clone, Debug)]
pub struct RestartEvent {
    /// The supervised task's name.
    pub task: &'static str,
    /// Monotonic (1-based) count of restarts performed for this task.
    pub restart_count: u32,
    /// The backoff delay applied before this restart (always `<= max_backoff`).
    pub backoff: Duration,
    /// Why the previous run exited.
    pub reason: ExitReason,
    /// Monitor-clock millisecond timestamp of the exit that triggered the
    /// restart.
    pub at_millis: u64,
}

// ---------------------------------------------------------------------------
// Shutdown signalling
// ---------------------------------------------------------------------------

/// The owner side of a graceful-shutdown signal. Dropping it does **not**
/// signal shutdown (see [`ShutdownToken::cancelled`]); only [`shutdown`] does.
///
/// [`shutdown`]: ShutdownSignal::shutdown
#[derive(Clone)]
pub struct ShutdownSignal {
    tx: watch::Sender<bool>,
}

impl ShutdownSignal {
    /// A fresh signal in the not-shutdown state.
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(false);
        Self { tx }
    }

    /// A fresh [`ShutdownToken`] observing this signal.
    pub fn token(&self) -> ShutdownToken {
        ShutdownToken {
            rx: self.tx.subscribe(),
        }
    }

    /// Trigger graceful shutdown: every observing token's
    /// [`cancelled`](ShutdownToken::cancelled) resolves and
    /// [`is_shutdown`](ShutdownToken::is_shutdown) becomes `true`.
    pub fn shutdown(&self) {
        let _ = self.tx.send(true);
    }
}

impl Default for ShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

/// The task side of a graceful-shutdown signal, handed to every supervised
/// task so it can drain promptly (Req 49.4). Cheap to [`Clone`].
#[derive(Clone)]
pub struct ShutdownToken {
    rx: watch::Receiver<bool>,
}

impl ShutdownToken {
    /// Whether shutdown has been requested (non-blocking).
    pub fn is_shutdown(&self) -> bool {
        *self.rx.borrow()
    }

    /// Resolve once shutdown is requested.
    ///
    /// If the owning [`ShutdownSignal`] is dropped **without** signalling, this
    /// deliberately never resolves — a dropped owner is not a shutdown — so a
    /// task selecting on it is not spuriously cancelled.
    pub async fn cancelled(&self) {
        let mut rx = self.rx.clone();
        loop {
            if *rx.borrow_and_update() {
                return;
            }
            if rx.changed().await.is_err() {
                // Sender dropped: no further changes are possible and this is
                // not a shutdown — wait forever rather than report cancelled.
                std::future::pending::<()>().await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Task handle + shared inspectable state
// ---------------------------------------------------------------------------

/// Mutable state shared between the monitor loop and the [`TaskHandle`].
struct InnerState {
    status: TaskStatus,
    restart_count: u32,
    events: Vec<RestartEvent>,
}

/// A handle to a supervised task: inspect its status / restart history and
/// await or abort its monitor loop.
pub struct TaskHandle {
    name: &'static str,
    shared: Arc<Mutex<InnerState>>,
    join: JoinHandle<()>,
}

impl TaskHandle {
    /// The supervised task's name.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The task's current [`TaskStatus`].
    pub fn status(&self) -> TaskStatus {
        self.shared
            .lock()
            .expect("supervisor state poisoned")
            .status
    }

    /// The number of restarts performed so far.
    pub fn restart_count(&self) -> u32 {
        self.shared
            .lock()
            .expect("supervisor state poisoned")
            .restart_count
    }

    /// A snapshot of the recorded [`RestartEvent`]s.
    pub fn events(&self) -> Vec<RestartEvent> {
        self.shared
            .lock()
            .expect("supervisor state poisoned")
            .events
            .clone()
    }

    /// Abort the monitor loop (forceful; used as a backstop in tests/shutdown).
    pub fn abort(&self) {
        self.join.abort();
    }

    /// Await the monitor loop's termination (it ends on graceful shutdown or
    /// when the crash-loop guard parks the task).
    pub async fn wait(&mut self) {
        let _ = (&mut self.join).await;
    }
}

// ---------------------------------------------------------------------------
// The monitor loop
// ---------------------------------------------------------------------------

/// Best-effort human-readable message from a caught panic payload (mirrors the
/// HTTP panic-boundary's extractor).
fn panic_message(panic: &(dyn Any + Send)) -> String {
    if let Some(s) = panic.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = panic.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic payload".to_string()
    }
}

/// Spawn a monitor loop that supervises the future produced by `make` (design:
/// Pattern 5 monitor loop). The single place the restart-with-backoff +
/// crash-loop-guard logic is applied; both [`spawn_supervised`] and
/// [`Supervisor::spawn_all`] funnel through here.
fn spawn_monitor<Mk>(
    name: &'static str,
    policy: RestartPolicy,
    shutdown: ShutdownToken,
    make: Mk,
) -> TaskHandle
where
    Mk: Fn(ShutdownToken) -> TaskFuture + Send + 'static,
{
    let shared = Arc::new(Mutex::new(InnerState {
        status: TaskStatus::Running,
        restart_count: 0,
        events: Vec::new(),
    }));
    let task_state = shared.clone();

    let join = tokio::spawn(async move {
        let mut guard = CrashLoopGuard::new(policy);
        let base = Instant::now();

        loop {
            // Do not (re)start once shutdown has been requested.
            if shutdown.is_shutdown() {
                set_status(&task_state, TaskStatus::Stopped);
                break;
            }

            // Run one iteration of the task, catching any panic so it is
            // isolated to this loop and never tears down the process.
            let run = make(shutdown.clone());
            let outcome = AssertUnwindSafe(run).catch_unwind().await;

            // A clean exit *because* shutdown was requested is graceful drain,
            // not a crash — stop without restarting (Req 49.4).
            if shutdown.is_shutdown() {
                set_status(&task_state, TaskStatus::Stopped);
                break;
            }

            let reason = match outcome {
                Ok(Ok(())) => ExitReason::Completed,
                Ok(Err(err)) => ExitReason::Crashed(err.to_string()),
                Err(panic) => ExitReason::Panicked(panic_message(&*panic)),
            };
            let now_ms = base.elapsed().as_millis() as u64;

            match guard.on_exit(now_ms) {
                RestartDecision::Restart { backoff, .. } => {
                    let restart_count = {
                        let mut state = task_state.lock().expect("supervisor state poisoned");
                        state.restart_count += 1;
                        state.status = TaskStatus::Running;
                        let count = state.restart_count;
                        state.events.push(RestartEvent {
                            task: name,
                            restart_count: count,
                            backoff,
                            reason: reason.clone(),
                            at_millis: now_ms,
                        });
                        count
                    };
                    tracing::warn!(
                        task = name,
                        restart = restart_count,
                        backoff_ms = backoff.as_millis() as u64,
                        reason = ?reason,
                        "supervised background task exited unexpectedly; restarting with backoff",
                    );

                    // Wait out the backoff, but cut it short if shutdown fires.
                    tokio::select! {
                        _ = tokio::time::sleep(backoff) => {}
                        _ = shutdown.cancelled() => {
                            set_status(&task_state, TaskStatus::Stopped);
                            break;
                        }
                    }
                }
                RestartDecision::Park => {
                    set_status(&task_state, TaskStatus::Failed);
                    tracing::error!(
                        task = name,
                        max_restarts = guard.restarts_in_window(),
                        "supervised background task exceeded its crash-loop budget; parked in Failed state",
                    );
                    break;
                }
            }
        }
    });

    TaskHandle { name, shared, join }
}

/// Set the shared status under the lock (no `await` held).
fn set_status(state: &Arc<Mutex<InnerState>>, status: TaskStatus) {
    state.lock().expect("supervisor state poisoned").status = status;
}

/// Supervise a long-lived background task produced by `factory`, restarting it
/// with backoff on panic or unexpected exit and recording each restart (design:
/// Components → Background-task supervision; Req 50.7).
///
/// `factory` is called once per run, producing a fresh future each time. The
/// returned [`TaskHandle`] exposes the task's status and restart history; the
/// caller-supplied `shutdown` token stops further restarts when its owning
/// [`ShutdownSignal`] fires.
///
/// > Reconciliation note: the design's Components sketch typed the backoff as a
/// > `RetryPolicy`, but the crash-loop guard parameters (`max_restarts`,
/// > `window`) live on [`RestartPolicy`] (Pattern 5), so this is the policy
/// > type used here.
pub fn spawn_supervised<F, Fut>(
    name: &'static str,
    policy: RestartPolicy,
    shutdown: ShutdownToken,
    factory: F,
) -> TaskHandle
where
    F: Fn() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    spawn_monitor(name, policy, shutdown, move |_token| {
        let fut = factory();
        Box::pin(async move {
            fut.await;
            Ok::<(), AppError>(())
        })
    })
}

// ---------------------------------------------------------------------------
// SupervisedTask trait + Supervisor
// ---------------------------------------------------------------------------

/// A long-lived background task owned by the [`Supervisor`] (design: Pattern 5).
///
/// `Send + Sync` is required so the task can be shared (`Arc`) into its monitor
/// loop and re-run after each restart; `run` produces a **fresh** future for
/// every run.
pub trait SupervisedTask: Send + Sync + 'static {
    /// A stable name for logs, metrics, and `/health` component status.
    fn name(&self) -> &'static str;

    /// One run of the task. Resolving (with `Ok` or `Err`) — or panicking — is
    /// treated as an unexpected exit and triggers a supervised restart; a task
    /// that should keep running must not resolve until `shutdown` fires.
    fn run(&self, shutdown: ShutdownToken) -> TaskFuture;
}

/// Owns a set of [`SupervisedTask`]s and a shared graceful-shutdown signal,
/// spawning a monitor loop per task (design: Pattern 5).
pub struct Supervisor {
    policy: RestartPolicy,
    tasks: Vec<Arc<dyn SupervisedTask>>,
    signal: ShutdownSignal,
}

impl Supervisor {
    /// A supervisor governed by `policy` with no tasks yet.
    pub fn new(policy: RestartPolicy) -> Self {
        Self {
            policy,
            tasks: Vec::new(),
            signal: ShutdownSignal::new(),
        }
    }

    /// Register a task to be supervised when [`spawn_all`](Self::spawn_all) is
    /// called.
    pub fn add_task(&mut self, task: Arc<dyn SupervisedTask>) -> &mut Self {
        self.tasks.push(task);
        self
    }

    /// A [`ShutdownToken`] observing this supervisor's shutdown signal.
    pub fn token(&self) -> ShutdownToken {
        self.signal.token()
    }

    /// Signal graceful shutdown of every supervised task.
    pub fn shutdown(&self) {
        self.signal.shutdown();
    }

    /// Spawn a monitor loop for each registered task, returning a handle per
    /// task. All loops share this supervisor's shutdown signal.
    pub fn spawn_all(&self) -> Vec<TaskHandle> {
        self.tasks
            .iter()
            .map(|task| {
                let task = task.clone();
                let name = task.name();
                spawn_monitor(
                    name,
                    self.policy.clone(),
                    self.signal.token(),
                    move |token| task.run(token),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    // ===================================================================
    // Pure backoff schedule (no runtime)
    // ===================================================================

    fn schedule_policy() -> RestartPolicy {
        RestartPolicy {
            base_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
            multiplier: 2.0,
            max_restarts: 16,
            window: Duration::from_secs(60),
        }
    }

    /// Backoff grows as `base · multiplierⁿ` before the cap, then saturates at
    /// `max_backoff` and never exceeds it (Property 52 bound / Req 50.7).
    #[test]
    fn backoff_follows_capped_exponential_and_never_exceeds_max() {
        let policy = schedule_policy();
        assert_eq!(policy.backoff(0), Duration::from_millis(100));
        assert_eq!(policy.backoff(1), Duration::from_millis(200));
        assert_eq!(policy.backoff(2), Duration::from_millis(400));
        assert_eq!(policy.backoff(3), Duration::from_millis(800));
        // 100ms·2⁶ = 6.4s > 5s ⇒ capped.
        assert_eq!(policy.backoff(6), Duration::from_secs(5));
        // A huge index saturates rather than overflowing.
        assert_eq!(policy.backoff(1000), Duration::from_secs(5));
        for index in 0..128u32 {
            assert!(
                policy.backoff(index) <= policy.max_backoff,
                "backoff({index}) exceeded max_backoff",
            );
        }
    }

    // ===================================================================
    // Pure crash-loop guard (no runtime, explicit timestamps)
    // ===================================================================

    fn guard_policy(max_restarts: u32, window: Duration) -> RestartPolicy {
        RestartPolicy {
            base_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
            multiplier: 2.0,
            max_restarts,
            window,
        }
    }

    /// Up to `max_restarts` rapid exits are restarted; the next one is parked
    /// (Req 50.7, 50.12).
    #[test]
    fn guard_allows_up_to_max_restarts_then_parks() {
        let mut guard = CrashLoopGuard::new(guard_policy(3, Duration::from_secs(10)));
        assert!(matches!(guard.on_exit(0), RestartDecision::Restart { .. }));
        assert!(matches!(guard.on_exit(1), RestartDecision::Restart { .. }));
        assert!(matches!(guard.on_exit(2), RestartDecision::Restart { .. }));
        assert_eq!(guard.on_exit(3), RestartDecision::Park);
        // Still parked while the window has not yet rolled forward.
        assert_eq!(guard.on_exit(4), RestartDecision::Park);
    }

    /// The in-window index drives the backoff schedule: successive rapid
    /// restarts back off by `base · 2ⁿ`.
    #[test]
    fn guard_restart_backoff_follows_in_window_index() {
        let policy = RestartPolicy {
            base_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
            multiplier: 2.0,
            max_restarts: 5,
            window: Duration::from_secs(60),
        };
        let mut guard = CrashLoopGuard::new(policy);
        assert_eq!(
            guard.on_exit(0),
            RestartDecision::Restart {
                backoff: Duration::from_millis(100),
                in_window_index: 0
            }
        );
        assert_eq!(
            guard.on_exit(1),
            RestartDecision::Restart {
                backoff: Duration::from_millis(200),
                in_window_index: 1
            }
        );
        assert_eq!(
            guard.on_exit(2),
            RestartDecision::Restart {
                backoff: Duration::from_millis(400),
                in_window_index: 2
            }
        );
    }

    /// Once the window rolls forward (old restarts age out), restarts resume —
    /// the guard self-heals rather than being permanently latched (Property 55:
    /// "not restarted again until the window has rolled forward").
    #[test]
    fn guard_recovers_after_window_rolls_forward() {
        let mut guard = CrashLoopGuard::new(guard_policy(3, Duration::from_millis(1000)));
        guard.on_exit(0);
        guard.on_exit(10);
        guard.on_exit(20);
        assert_eq!(
            guard.on_exit(30),
            RestartDecision::Park,
            "cap hit within window"
        );

        // At t=1100 the restarts at 0/10/20 are all >= 1000ms old ⇒ pruned, so
        // a restart is authorized again.
        assert!(
            matches!(guard.on_exit(1100), RestartDecision::Restart { .. }),
            "window rolled forward ⇒ restarts resume",
        );
    }

    /// For any stream of exits, the number of authorized restarts inside every
    /// trailing window of length `window` never exceeds `max_restarts`
    /// (Property 55 invariant / Req 50.12).
    #[test]
    fn guard_never_exceeds_max_restarts_in_any_window() {
        let max_restarts = 2u32;
        let window_ms = 100u64;
        let mut guard =
            CrashLoopGuard::new(guard_policy(max_restarts, Duration::from_millis(window_ms)));

        let mut restarts: Vec<u64> = Vec::new();
        let mut t = 0u64;
        while t < 2000 {
            if let RestartDecision::Restart { .. } = guard.on_exit(t) {
                restarts.push(t);
            }
            t += 7;
        }
        assert!(!restarts.is_empty(), "some restarts should be authorized");

        // Every trailing window (e - window, e] ending at an authorized restart
        // contains at most `max_restarts` restarts.
        for &end in &restarts {
            let lo = end.saturating_sub(window_ms);
            let count = restarts.iter().filter(|&&x| x > lo && x <= end).count();
            assert!(
                count as u32 <= max_restarts,
                "window ending at {end} held {count} restarts (> {max_restarts})",
            );
        }
    }

    // ===================================================================
    // Live monitor loop (paused "fake clock" runtime)
    // ===================================================================

    fn fast_policy(max_restarts: u32) -> RestartPolicy {
        RestartPolicy {
            base_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(100),
            multiplier: 2.0,
            max_restarts,
            window: Duration::from_secs(600),
        }
    }

    /// Let spawned tasks make progress under the paused runtime.
    async fn settle() {
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
    }

    /// A panicking task is caught, restarted with backoff after each panic, and
    /// finally parked `Failed` once the crash-loop cap is hit — the process is
    /// never torn down (Req 50.7, 50.8, 50.12).
    #[tokio::test(start_paused = true)]
    async fn restarts_after_panic_then_parks_failed_at_crash_loop_cap() {
        let runs = Arc::new(AtomicU32::new(0));
        let signal = ShutdownSignal::new();
        let r = runs.clone();

        let mut handle = spawn_supervised("panicker", fast_policy(3), signal.token(), move || {
            let r = r.clone();
            async move {
                r.fetch_add(1, Ordering::SeqCst);
                panic!("boom");
            }
        });

        handle.wait().await;

        // 1 initial run + 3 restarts = 4 runs, then parked.
        assert_eq!(
            runs.load(Ordering::SeqCst),
            4,
            "initial run + max_restarts runs"
        );
        assert_eq!(handle.restart_count(), 3);
        assert_eq!(handle.status(), TaskStatus::Failed);

        let events = handle.events();
        assert_eq!(events.len(), 3, "one restart event recorded per restart");
        for event in &events {
            assert!(
                event.backoff <= Duration::from_millis(100),
                "backoff within max"
            );
            assert!(matches!(event.reason, ExitReason::Panicked(_)));
        }

        // Keep the signal alive for the whole test.
        drop(signal);
    }

    /// An early `Ok(())` exit of a long-lived task is also an unexpected exit
    /// and is restarted with backoff (Req 50.7).
    #[tokio::test(start_paused = true)]
    async fn restarts_after_early_exit_and_records_events() {
        let runs = Arc::new(AtomicU32::new(0));
        let signal = ShutdownSignal::new();
        let r = runs.clone();

        let mut handle =
            spawn_supervised("early-exit", fast_policy(2), signal.token(), move || {
                let r = r.clone();
                async move {
                    r.fetch_add(1, Ordering::SeqCst);
                    // returns () immediately => early exit
                }
            });

        handle.wait().await;

        assert_eq!(runs.load(Ordering::SeqCst), 3, "initial run + 2 restarts");
        assert_eq!(handle.restart_count(), 2);
        assert_eq!(handle.status(), TaskStatus::Failed);
        let events = handle.events();
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0].reason, ExitReason::Completed));
        drop(signal);
    }

    /// Restart backoff follows the configured schedule and is always capped at
    /// `max_backoff` (Property 52 bound / Req 50.7).
    #[tokio::test(start_paused = true)]
    async fn restart_backoff_schedule_is_bounded_by_max_backoff() {
        let policy = RestartPolicy {
            base_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(25),
            multiplier: 2.0,
            max_restarts: 5,
            window: Duration::from_secs(600),
        };
        let signal = ShutdownSignal::new();

        let mut handle = spawn_supervised("schedule", policy, signal.token(), || async {
            // immediate early exit
        });

        handle.wait().await;

        let backoffs: Vec<Duration> = handle.events().iter().map(|e| e.backoff).collect();
        // indices 0..4 ⇒ 10, 20, 40→25(cap), 25, 25
        assert_eq!(
            backoffs,
            vec![
                Duration::from_millis(10),
                Duration::from_millis(20),
                Duration::from_millis(25),
                Duration::from_millis(25),
                Duration::from_millis(25),
            ],
        );
        drop(signal);
    }

    /// A task that runs forever is never restarted — only an actual exit
    /// triggers a restart (Property 52: "never restarts a still-running task").
    #[tokio::test(start_paused = true)]
    async fn never_restarts_a_still_running_task() {
        let started = Arc::new(AtomicU32::new(0));
        let signal = ShutdownSignal::new();
        let s = started.clone();

        let handle = spawn_supervised("forever", fast_policy(5), signal.token(), move || {
            let s = s.clone();
            async move {
                s.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<()>().await; // never completes
            }
        });

        settle().await;
        // Advance the fake clock far beyond any backoff window.
        tokio::time::advance(Duration::from_secs(3600)).await;
        settle().await;

        assert_eq!(
            started.load(Ordering::SeqCst),
            1,
            "task entered exactly once"
        );
        assert_eq!(
            handle.restart_count(),
            0,
            "a running task is never restarted"
        );
        assert_eq!(handle.status(), TaskStatus::Running);

        handle.abort();
        drop(signal);
    }

    // ===================================================================
    // Trait-based Supervisor
    // ===================================================================

    struct PanicTask {
        runs: Arc<AtomicU32>,
    }

    impl SupervisedTask for PanicTask {
        fn name(&self) -> &'static str {
            "panic-task"
        }
        fn run(&self, _shutdown: ShutdownToken) -> TaskFuture {
            let runs = self.runs.clone();
            Box::pin(async move {
                runs.fetch_add(1, Ordering::SeqCst);
                panic!("trait task boom");
            })
        }
    }

    struct LoopTask {
        runs: Arc<AtomicU32>,
    }

    impl SupervisedTask for LoopTask {
        fn name(&self) -> &'static str {
            "loop-task"
        }
        fn run(&self, shutdown: ShutdownToken) -> TaskFuture {
            let runs = self.runs.clone();
            Box::pin(async move {
                runs.fetch_add(1, Ordering::SeqCst);
                // Well-behaved long-lived task: only returns on shutdown.
                shutdown.cancelled().await;
                Ok(())
            })
        }
    }

    /// `Supervisor::spawn_all` supervises each task: a panicking task is
    /// restarted up to the crash-loop cap then parked `Failed`.
    #[tokio::test(start_paused = true)]
    async fn supervisor_restarts_panicking_task_until_capped() {
        let runs = Arc::new(AtomicU32::new(0));
        let mut supervisor = Supervisor::new(fast_policy(2));
        supervisor.add_task(Arc::new(PanicTask { runs: runs.clone() }));

        let mut handles = supervisor.spawn_all();
        assert_eq!(handles.len(), 1);
        handles[0].wait().await;

        assert_eq!(runs.load(Ordering::SeqCst), 3, "initial run + 2 restarts");
        assert_eq!(handles[0].restart_count(), 2);
        assert_eq!(handles[0].status(), TaskStatus::Failed);
    }

    /// Graceful shutdown drains a well-behaved task without restarting it, and
    /// parks it `Stopped` (not `Failed`) (Req 49.4).
    #[tokio::test(start_paused = true)]
    async fn graceful_shutdown_drains_without_restart() {
        let runs = Arc::new(AtomicU32::new(0));
        let mut supervisor = Supervisor::new(fast_policy(5));
        supervisor.add_task(Arc::new(LoopTask { runs: runs.clone() }));

        let mut handles = supervisor.spawn_all();
        settle().await;
        assert_eq!(
            runs.load(Ordering::SeqCst),
            1,
            "task started once and is running"
        );

        supervisor.shutdown();
        handles[0].wait().await;

        assert_eq!(
            runs.load(Ordering::SeqCst),
            1,
            "no restart on graceful shutdown"
        );
        assert_eq!(handles[0].restart_count(), 0);
        assert_eq!(handles[0].status(), TaskStatus::Stopped);
    }
}
