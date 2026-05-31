//! Leaked-resource reaper (`supervisor::reaper`) — Req 50.12, 41.5, 7.5, 10.6,
//! 6.12.
//!
//! A long-lived, supervised background task that periodically sweeps the
//! system's resource registries and **reclaims leaked, idle, or stale
//! resources** so a slow client, a crashed peer, or a forgotten subscription
//! can never accumulate into an unbounded leak (design: Resilience → Pattern 5
//! "Self-Healing & Supervision" → recovery table). The reaper is one of the
//! tasks owned by the [`Supervisor`](super) (task 7.1): a panic in a sweep is
//! caught and the task restarted with backoff, and on graceful shutdown it
//! stops sweeping and drains.
//!
//! ## What gets reaped (recovery table)
//!
//! | Resource kind | Staleness criterion | Req |
//! |---|---|---|
//! | Abandoned **SSE subscriptions** | client disconnected / no longer reachable | 41.5 |
//! | Idle **playlist prefetchers** | no request within the inactivity timeout | 7.5 |
//! | Stale **Acestream sessions** | no remaining clients | 10.6 |
//! | Zombie **FFmpeg** children | process exited with no live client | 6.12 |
//! | Orphaned **upstream connections** | owning request/stream is gone | 50.12 |
//!
//! Client-disconnect already kills the FFmpeg child and drops the upstream
//! body inline (Req 6.12); the reaper is the **backstop** that catches anything
//! the inline path missed (design: recovery table "as a backstop against
//! leaks").
//!
//! ## Decoupled design (the [`Reapable`] seam)
//!
//! This module is intentionally **self-contained**: it knows nothing about the
//! concrete SSE broadcaster, prefetcher cache, Acestream session manager,
//! FFmpeg supervisor, or upstream-connection table. Each of those registries
//! implements the [`Reapable`] trait and is registered with the [`Reaper`];
//! the reaper just drives them on a configurable interval. This lets those
//! modules land later (and be developed in parallel) without the reaper taking
//! a dependency on any of them.
//!
//! For the common case, [`ReapTable`] is a ready-made generic registry: a keyed
//! table whose entries are reclaimed when a caller-supplied staleness predicate
//! holds, with an optional eviction hook for cleanup (kill the process, abort
//! the sender, …). The five resource kinds above all map onto it by choosing
//! the right predicate (idle-timeout, no-client, dead-pid, orphaned-owner).

use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The supervised-task name the [`Reaper`] registers under (Req 50.7, 50.12).
pub const REAPER_TASK_NAME: &str = "leaked-resource-reaper";

/// A resource registry the [`Reaper`] can sweep to reclaim leaked/idle/stale
/// entries (design: Resilience → Pattern 5).
///
/// This is the single seam between the reaper and the concrete resource
/// registries (SSE subscriptions, prefetchers, Acestream sessions, FFmpeg
/// children, upstream connections). An implementor owns its own staleness
/// criterion and any cleanup it must perform when reclaiming an entry; the
/// reaper only decides *when* to sweep, never *what* is stale.
///
/// Implementors must be `Send + Sync` so the reaper can hold them as
/// `Arc<dyn Reapable>` and sweep them from its supervised task.
pub trait Reapable: Send + Sync {
    /// A stable, human-readable identifier for this resource kind (e.g.
    /// `"sse-subscription"`, `"prefetcher"`). Used in the structured reap
    /// log/metric so operators can see the self-healing happen (Req 50.14).
    fn kind(&self) -> &'static str;

    /// Reclaim every currently-stale resource, returning the number reclaimed.
    ///
    /// Called once per sweep. Must not block for long (it runs inside the
    /// reaper's interval loop); registries that need async teardown should
    /// hand the reclaimed handle to a drop/abort path rather than awaiting it
    /// here.
    fn reap(&self) -> usize;
}

/// The number of resources of one [`kind`](Reapable::kind) reclaimed in a
/// single sweep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReapCount {
    /// The resource kind (the [`Reapable::kind`] of the swept registry).
    pub kind: &'static str,
    /// How many resources of that kind were reclaimed this sweep.
    pub reclaimed: usize,
}

/// The outcome of one [`Reaper::sweep_once`]: a per-registry reclaim count.
///
/// Returned so a sweep is observable (logs/metrics, Req 50.14) and so the unit
/// tests can assert exactly what each sweep reclaimed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReapReport {
    /// One [`ReapCount`] per registered [`Reapable`], in registration order.
    pub reclaimed: Vec<ReapCount>,
}

impl ReapReport {
    /// Total resources reclaimed across every registry in this sweep.
    pub fn total(&self) -> usize {
        self.reclaimed.iter().map(|c| c.reclaimed).sum()
    }

    /// How many resources of `kind` were reclaimed this sweep (summed across
    /// any registries sharing that kind label).
    pub fn for_kind(&self, kind: &str) -> usize {
        self.reclaimed
            .iter()
            .filter(|c| c.kind == kind)
            .map(|c| c.reclaimed)
            .sum()
    }

    /// Whether nothing was reclaimed this sweep (the steady state).
    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }
}

/// The leaked-resource reaper: drives every registered [`Reapable`] on a
/// **configurable interval** (design: Resilience → Pattern 5; Req 50.12).
///
/// The reaper holds its targets as `Arc<dyn Reapable>` so the same registry can
/// be shared with the module that owns it (e.g. the SSE broadcaster keeps its
/// table and also registers a clone here). One sweep ([`sweep_once`]) walks
/// every target once; [`run`] performs a sweep every `interval` until a
/// shutdown signal resolves.
///
/// [`sweep_once`]: Reaper::sweep_once
/// [`run`]: Reaper::run
pub struct Reaper {
    interval: Duration,
    targets: Vec<Arc<dyn Reapable>>,
}

impl Reaper {
    /// A reaper that sweeps every `interval`, with no targets yet (register
    /// them with [`register`](Self::register)).
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            targets: Vec::new(),
        }
    }

    /// A reaper that sweeps every `interval` over a pre-built target list.
    pub fn with_targets(interval: Duration, targets: Vec<Arc<dyn Reapable>>) -> Self {
        Self { interval, targets }
    }

    /// Register a resource registry to be swept on every interval. Chainable.
    pub fn register(&mut self, target: Arc<dyn Reapable>) -> &mut Self {
        self.targets.push(target);
        self
    }

    /// The configured sweep interval (Req 50.12 — "within a configurable
    /// interval").
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// How many resource registries are registered.
    pub fn target_count(&self) -> usize {
        self.targets.len()
    }

    /// Sweep every registered registry exactly once, returning the per-kind
    /// reclaim counts (design: Pattern 5).
    ///
    /// This is the pure, synchronous unit of work the [`run`](Self::run) loop
    /// invokes per tick; exposing it directly keeps the sweep deterministically
    /// testable without driving the interval timer.
    pub fn sweep_once(&self) -> ReapReport {
        let reclaimed = self
            .targets
            .iter()
            .map(|target| ReapCount {
                kind: target.kind(),
                reclaimed: target.reap(),
            })
            .collect();
        ReapReport { reclaimed }
    }

    /// Run the reaper: sweep every registry every `interval` until `shutdown`
    /// resolves (Req 50.12; graceful drain on shutdown, Req 49.4).
    ///
    /// The first sweep happens after one full interval (the immediate tick that
    /// [`tokio::time::interval`] yields at `t = 0` is consumed first), so a
    /// freshly-started reaper does not sweep empty registries on boot. Each
    /// sweep that reclaims anything emits a structured `reaper` log so the
    /// self-healing is observable (Req 50.14).
    ///
    /// A zero interval is clamped up to 1ms (a zero period would panic
    /// [`tokio::time::interval`]); supply a sane interval from config.
    pub async fn run<S>(&self, shutdown: S)
    where
        S: Future<Output = ()>,
    {
        let period = if self.interval.is_zero() {
            Duration::from_millis(1)
        } else {
            self.interval
        };

        let mut ticker = tokio::time::interval(period);
        // Skip catch-up bursts after a slow/blocked sweep: space ticks by the
        // full interval rather than firing back-to-back (Req 50.12 cadence).
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Consume the immediate `t = 0` tick so the first real sweep is one
        // interval out.
        ticker.tick().await;

        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                // Prefer shutdown so a pending stop is honored promptly rather
                // than racing an also-ready tick.
                biased;
                _ = &mut shutdown => break,
                _ = ticker.tick() => {
                    let report = self.sweep_once();
                    if !report.is_empty() {
                        tracing::info!(
                            target: "reaper",
                            total = report.total(),
                            "reclaimed leaked or idle resources",
                        );
                    }
                }
            }
        }
    }
}

/// A staleness predicate over a registry value: returns `true` when the entry
/// should be reclaimed.
type StalePredicate<V> = Arc<dyn Fn(&V) -> bool + Send + Sync>;

/// An eviction hook run for each reclaimed entry, for cleanup (kill the FFmpeg
/// child, abort the SSE sender, close the upstream connection, …).
type EvictionHook<K, V> = Arc<dyn Fn(&K, &V) + Send + Sync>;

/// A generic, keyed registry of resources that the [`Reaper`] can sweep
/// (design: Pattern 5 — the reusable backing for the recovery-table rows).
///
/// Entries are reclaimed when the caller-supplied staleness predicate holds.
/// Choosing the predicate adapts this one type to every resource kind:
///
/// * **Idle prefetcher / abandoned SSE subscription** (Req 7.5, 41.5):
///   `|e| now() - e.last_activity > idle_timeout`.
/// * **Stale Acestream session** (Req 10.6): `|e| e.client_count == 0`.
/// * **Zombie FFmpeg child** (Req 6.12): `|e| e.process_exited`.
/// * **Orphaned upstream connection** (Req 50.12): `|e| !e.owner_alive`.
///
/// An optional eviction hook performs cleanup as each entry is removed. The
/// table is internally synchronized (`Mutex<HashMap<..>>`) so it can be shared
/// (`Arc`) between the owning module and the reaper.
pub struct ReapTable<K, V> {
    kind: &'static str,
    entries: Mutex<HashMap<K, V>>,
    is_stale: StalePredicate<V>,
    on_reap: Option<EvictionHook<K, V>>,
}

impl<K, V> ReapTable<K, V>
where
    K: Eq + Hash + Clone + Send + 'static,
    V: Send + 'static,
{
    /// A table of `kind` whose entries are reclaimed when `is_stale` holds.
    pub fn new<F>(kind: &'static str, is_stale: F) -> Self
    where
        F: Fn(&V) -> bool + Send + Sync + 'static,
    {
        Self {
            kind,
            entries: Mutex::new(HashMap::new()),
            is_stale: Arc::new(is_stale),
            on_reap: None,
        }
    }

    /// A table of `kind` whose entries are reclaimed when `is_stale` holds,
    /// running `on_reap(&key, &value)` for each reclaimed entry (cleanup hook).
    pub fn with_on_reap<F, G>(kind: &'static str, is_stale: F, on_reap: G) -> Self
    where
        F: Fn(&V) -> bool + Send + Sync + 'static,
        G: Fn(&K, &V) + Send + Sync + 'static,
    {
        Self {
            kind,
            entries: Mutex::new(HashMap::new()),
            is_stale: Arc::new(is_stale),
            on_reap: Some(Arc::new(on_reap)),
        }
    }

    /// Insert or replace an entry, returning the previous value if any.
    pub fn insert(&self, key: K, value: V) -> Option<V> {
        self.entries.lock().unwrap().insert(key, value)
    }

    /// Remove an entry explicitly (e.g. the owning module reclaimed it inline).
    pub fn remove(&self, key: &K) -> Option<V> {
        self.entries.lock().unwrap().remove(key)
    }

    /// Whether an entry for `key` is currently present.
    pub fn contains(&self, key: &K) -> bool {
        self.entries.lock().unwrap().contains_key(key)
    }

    /// The current number of live entries.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    /// Whether the table currently holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.lock().unwrap().is_empty()
    }

    /// Mutate an entry in place if present (e.g. record fresh activity to keep
    /// it from being reaped, or decrement a client count). Returns `true` if
    /// the entry existed.
    pub fn update<F>(&self, key: &K, f: F) -> bool
    where
        F: FnOnce(&mut V),
    {
        match self.entries.lock().unwrap().get_mut(key) {
            Some(value) => {
                f(value);
                true
            }
            None => false,
        }
    }
}

impl<K, V> Reapable for ReapTable<K, V>
where
    K: Eq + Hash + Clone + Send + 'static,
    V: Send + 'static,
{
    fn kind(&self) -> &'static str {
        self.kind
    }

    fn reap(&self) -> usize {
        let mut entries = self.entries.lock().unwrap();

        // Collect the stale keys first (can't remove while iterating).
        let stale_keys: Vec<K> = entries
            .iter()
            .filter(|(_, value)| (self.is_stale)(value))
            .map(|(key, _)| key.clone())
            .collect();

        for key in &stale_keys {
            if let Some(value) = entries.remove(key) {
                if let Some(hook) = &self.on_reap {
                    hook(key, &value);
                }
            }
        }
        stale_keys.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    // -- Test doubles -------------------------------------------------------

    /// A `Reapable` double that records how many times it was swept and
    /// reclaims a fixed number of resources each sweep — used to verify the
    /// reaper's interval-driven sweeping without any real resource.
    ///
    /// It optionally pings an unbounded channel on every sweep so a paused-time
    /// test can await *actual* sweep completion (deterministic) rather than
    /// guessing scheduler timing with bare `yield_now`s.
    struct CountingReapable {
        kind: &'static str,
        sweeps: AtomicUsize,
        reclaimed_total: AtomicUsize,
        reclaim_per_sweep: usize,
        on_sweep: Mutex<Option<tokio::sync::mpsc::UnboundedSender<()>>>,
    }

    impl CountingReapable {
        fn new(kind: &'static str, reclaim_per_sweep: usize) -> Self {
            Self {
                kind,
                sweeps: AtomicUsize::new(0),
                reclaimed_total: AtomicUsize::new(0),
                reclaim_per_sweep,
                on_sweep: Mutex::new(None),
            }
        }

        /// Build the double together with a receiver pinged once per sweep, so
        /// a test can `recv().await` to observe each sweep deterministically.
        fn with_signal(
            kind: &'static str,
            reclaim_per_sweep: usize,
        ) -> (Self, tokio::sync::mpsc::UnboundedReceiver<()>) {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            let double = Self {
                kind,
                sweeps: AtomicUsize::new(0),
                reclaimed_total: AtomicUsize::new(0),
                reclaim_per_sweep,
                on_sweep: Mutex::new(Some(tx)),
            };
            (double, rx)
        }

        fn sweeps(&self) -> usize {
            self.sweeps.load(Ordering::SeqCst)
        }

        fn reclaimed_total(&self) -> usize {
            self.reclaimed_total.load(Ordering::SeqCst)
        }
    }

    impl Reapable for CountingReapable {
        fn kind(&self) -> &'static str {
            self.kind
        }

        fn reap(&self) -> usize {
            self.sweeps.fetch_add(1, Ordering::SeqCst);
            self.reclaimed_total
                .fetch_add(self.reclaim_per_sweep, Ordering::SeqCst);
            if let Some(tx) = self.on_sweep.lock().unwrap().as_ref() {
                // Non-blocking send; ignore a closed receiver (test finished).
                let _ = tx.send(());
            }
            self.reclaim_per_sweep
        }
    }

    /// A test clock the idle-based staleness predicates read, advanced
    /// manually so idle-timeout reaping is deterministic (no real sleeping).
    #[derive(Clone, Default)]
    struct TestClock(Arc<AtomicU64>);

    impl TestClock {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
        fn advance(&self, by: Duration) {
            self.0.fetch_add(by.as_millis() as u64, Ordering::SeqCst);
        }
    }

    // Domain-ish entry shapes mirroring the five recovery-table resource kinds.

    /// An SSE subscription entry: reaped when the client is no longer connected
    /// (Req 41.5).
    struct SseSub {
        connected: bool,
    }

    /// A playlist prefetcher entry: reaped when idle past the inactivity
    /// timeout (Req 7.5).
    struct Prefetcher {
        last_activity_ms: u64,
    }

    /// An Acestream session entry: reaped when no clients remain (Req 10.6).
    struct AceSession {
        client_count: usize,
    }

    /// An FFmpeg child entry: reaped when the process has exited (Req 6.12).
    struct FfmpegChild {
        exited: bool,
    }

    /// An upstream connection entry: reaped when its owning request is gone
    /// (Req 50.12).
    struct UpstreamConn {
        owner_alive: bool,
    }

    // -- sweep_once: sweeps every registered kind ---------------------------

    /// One sweep reclaims the stale entries of *every* registered resource
    /// kind (abandoned SSE subs, idle prefetchers, stale Acestream sessions,
    /// zombie FFmpeg, orphaned upstream connections) and leaves the live ones
    /// (Req 50.12, 41.5, 7.5, 10.6, 6.12).
    #[test]
    fn sweep_reclaims_stale_entries_of_every_resource_kind() {
        let clock = TestClock::default();
        let idle_ms = 30_000; // 30s inactivity timeout

        // SSE subscriptions: one abandoned, one connected.
        let sse = Arc::new(ReapTable::new("sse-subscription", |s: &SseSub| {
            !s.connected
        }));
        sse.insert("live", SseSub { connected: true });
        sse.insert("abandoned", SseSub { connected: false });

        // Prefetchers: one idle past the timeout, one fresh.
        let prefetchers = Arc::new({
            let clock = clock.clone();
            ReapTable::new("prefetcher", move |p: &Prefetcher| {
                clock.now_ms().saturating_sub(p.last_activity_ms) > idle_ms
            })
        });
        prefetchers.insert(
            "idle",
            Prefetcher {
                last_activity_ms: 0,
            },
        );
        prefetchers.insert(
            "fresh",
            Prefetcher {
                last_activity_ms: 0,
            },
        );

        // Acestream sessions: one with no clients, one still watched.
        let acestream = Arc::new(ReapTable::new("acestream-session", |a: &AceSession| {
            a.client_count == 0
        }));
        acestream.insert("orphan", AceSession { client_count: 0 });
        acestream.insert("watched", AceSession { client_count: 2 });

        // FFmpeg children: one exited (zombie), one running.
        let ffmpeg = Arc::new(ReapTable::new("ffmpeg", |f: &FfmpegChild| f.exited));
        ffmpeg.insert("zombie", FfmpegChild { exited: true });
        ffmpeg.insert("running", FfmpegChild { exited: false });

        // Upstream connections: one orphaned, one with a live owner.
        let conns = Arc::new(ReapTable::new("upstream-connection", |c: &UpstreamConn| {
            !c.owner_alive
        }));
        conns.insert("orphan", UpstreamConn { owner_alive: false });
        conns.insert("owned", UpstreamConn { owner_alive: true });

        // Advance the clock so the "idle" prefetcher crosses the timeout while
        // "fresh" stays fresh (touch it at the new now).
        clock.advance(Duration::from_secs(31));
        prefetchers.update(&"fresh", |p| p.last_activity_ms = clock.now_ms());

        let reaper = Reaper::with_targets(
            Duration::from_secs(60),
            vec![
                sse.clone(),
                prefetchers.clone(),
                acestream.clone(),
                ffmpeg.clone(),
                conns.clone(),
            ],
        );

        let report = reaper.sweep_once();

        // Each kind reclaimed exactly its one stale entry.
        assert_eq!(report.for_kind("sse-subscription"), 1);
        assert_eq!(report.for_kind("prefetcher"), 1);
        assert_eq!(report.for_kind("acestream-session"), 1);
        assert_eq!(report.for_kind("ffmpeg"), 1);
        assert_eq!(report.for_kind("upstream-connection"), 1);
        assert_eq!(report.total(), 5);

        // The live entries survived; the stale ones are gone.
        assert!(sse.contains(&"live") && !sse.contains(&"abandoned"));
        assert!(prefetchers.contains(&"fresh") && !prefetchers.contains(&"idle"));
        assert!(acestream.contains(&"watched") && !acestream.contains(&"orphan"));
        assert!(ffmpeg.contains(&"running") && !ffmpeg.contains(&"zombie"));
        assert!(conns.contains(&"owned") && !conns.contains(&"orphan"));
    }

    /// A second sweep with nothing newly stale is a no-op (steady state): the
    /// reaper does not churn live resources.
    #[test]
    fn sweep_is_idempotent_once_stale_entries_are_gone() {
        let sse = Arc::new(ReapTable::new("sse-subscription", |s: &SseSub| {
            !s.connected
        }));
        sse.insert("live", SseSub { connected: true });
        sse.insert("abandoned", SseSub { connected: false });

        let reaper = Reaper::with_targets(Duration::from_secs(10), vec![sse.clone()]);

        assert_eq!(
            reaper.sweep_once().total(),
            1,
            "first sweep reclaims abandoned"
        );
        assert_eq!(reaper.sweep_once().total(), 0, "second sweep is a no-op");
        assert_eq!(sse.len(), 1, "the live subscription is untouched");
    }

    // -- Idle-timeout reaping (prefetcher / SSE) ----------------------------

    /// A prefetcher idle past the inactivity timeout is reaped; one whose
    /// activity was refreshed survives — and it becomes reapable only once the
    /// clock advances past its own timeout (Req 7.5).
    #[test]
    fn idle_prefetcher_reaped_only_after_inactivity_timeout() {
        let clock = TestClock::default();
        let idle = Duration::from_secs(30);

        let table = Arc::new({
            let clock = clock.clone();
            ReapTable::new("prefetcher", move |p: &Prefetcher| {
                clock.now_ms().saturating_sub(p.last_activity_ms) > idle.as_millis() as u64
            })
        });
        table.insert(
            "p",
            Prefetcher {
                last_activity_ms: clock.now_ms(),
            },
        );

        let reaper = Reaper::with_targets(Duration::from_secs(5), vec![table.clone()]);

        // Within the timeout → not reaped.
        clock.advance(Duration::from_secs(29));
        assert_eq!(reaper.sweep_once().total(), 0);
        assert!(table.contains(&"p"));

        // A fresh request resets the activity clock → still not reaped even
        // after more time, as long as it stays under the timeout.
        table.update(&"p", |p| p.last_activity_ms = clock.now_ms());
        clock.advance(Duration::from_secs(29));
        assert_eq!(reaper.sweep_once().total(), 0);
        assert!(table.contains(&"p"));

        // Cross the timeout with no activity → reaped.
        clock.advance(Duration::from_secs(2));
        assert_eq!(reaper.sweep_once().total(), 1);
        assert!(!table.contains(&"p"));
    }

    // -- Eviction hook (cleanup) --------------------------------------------

    /// The eviction hook runs once per reclaimed entry — this is where a real
    /// registry kills the FFmpeg child / aborts the SSE sender (Req 6.12,
    /// 41.5). Live entries never trigger it.
    #[test]
    fn eviction_hook_runs_for_each_reclaimed_entry() {
        let killed = Arc::new(Mutex::new(Vec::<u32>::new()));

        let table = Arc::new({
            let killed = killed.clone();
            ReapTable::with_on_reap(
                "ffmpeg",
                |f: &FfmpegChild| f.exited,
                move |pid: &u32, _child: &FfmpegChild| killed.lock().unwrap().push(*pid),
            )
        });
        table.insert(101, FfmpegChild { exited: true });
        table.insert(102, FfmpegChild { exited: false });
        table.insert(103, FfmpegChild { exited: true });

        let reaper = Reaper::with_targets(Duration::from_secs(5), vec![table.clone()]);
        assert_eq!(reaper.sweep_once().for_kind("ffmpeg"), 2);

        let mut killed = killed.lock().unwrap().clone();
        killed.sort_unstable();
        assert_eq!(
            killed,
            vec![101, 103],
            "only the exited children are reaped"
        );
        assert!(table.contains(&102), "the running child survives");
    }

    // -- Report shape -------------------------------------------------------

    /// The report carries one entry per registered registry, in registration
    /// order, and the aggregation helpers (`total`/`for_kind`/`is_empty`) agree.
    #[test]
    fn report_aggregations_are_consistent() {
        let a = Arc::new(CountingReapable::new("a", 2));
        let b = Arc::new(CountingReapable::new("b", 0));
        let c = Arc::new(CountingReapable::new("c", 3));
        let reaper = Reaper::with_targets(Duration::from_secs(1), vec![a, b, c]);

        let report = reaper.sweep_once();
        assert_eq!(
            report.reclaimed,
            vec![
                ReapCount {
                    kind: "a",
                    reclaimed: 2
                },
                ReapCount {
                    kind: "b",
                    reclaimed: 0
                },
                ReapCount {
                    kind: "c",
                    reclaimed: 3
                },
            ],
        );
        assert_eq!(report.total(), 5);
        assert_eq!(report.for_kind("a"), 2);
        assert_eq!(report.for_kind("c"), 3);
        assert!(!report.is_empty());

        let empty = ReapReport::default();
        assert!(empty.is_empty());
        assert_eq!(empty.total(), 0);
    }

    /// An empty reaper (no registries) sweeps to an empty report.
    #[test]
    fn empty_reaper_sweeps_to_empty_report() {
        let reaper = Reaper::new(Duration::from_secs(1));
        assert_eq!(reaper.target_count(), 0);
        let report = reaper.sweep_once();
        assert!(report.is_empty());
        assert_eq!(report.total(), 0);
    }

    /// `register` accumulates targets and `interval` echoes the configured
    /// cadence (Req 50.12 — configurable interval).
    #[test]
    fn register_accumulates_targets_and_interval_is_configurable() {
        let mut reaper = Reaper::new(Duration::from_secs(45));
        assert_eq!(reaper.interval(), Duration::from_secs(45));
        reaper.register(Arc::new(CountingReapable::new("x", 1)));
        reaper.register(Arc::new(CountingReapable::new("y", 1)));
        assert_eq!(reaper.target_count(), 2);
        assert_eq!(reaper.sweep_once().total(), 2);
    }

    // -- run loop: sweeps on the configurable interval ----------------------

    /// The `run` loop sweeps every registry once per `interval` tick, and the
    /// first sweep lands one interval after start (not at `t = 0`). Driven on a
    /// paused runtime so the cadence is deterministic (Req 50.12).
    #[tokio::test(start_paused = true)]
    async fn run_sweeps_on_each_configured_interval() {
        let (double, mut swept) = CountingReapable::with_signal("conn", 1);
        let counter = Arc::new(double);
        let interval = Duration::from_secs(10);
        let reaper = Reaper::with_targets(interval, vec![counter.clone()]);

        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            reaper
                .run(async move {
                    let _ = stop_rx.await;
                })
                .await;
        });

        // Before the first interval elapses, no sweep has happened (the
        // immediate t=0 tick is consumed).
        tokio::task::yield_now().await;
        assert_eq!(counter.sweeps(), 0, "no sweep before the first interval");

        // Each elapsed interval triggers exactly one sweep. Awaiting the
        // per-sweep signal makes the assertion deterministic (no timing races).
        for expected in 1..=3 {
            tokio::time::advance(interval).await;
            swept.recv().await.expect("a sweep happens each interval");
            assert_eq!(counter.sweeps(), expected, "one sweep per interval tick");
        }
        assert_eq!(
            counter.reclaimed_total(),
            3,
            "reclaimed one resource per sweep"
        );

        // Shutdown stops the loop and lets the task drain.
        let _ = stop_tx.send(());
        handle.await.expect("reaper task joins on shutdown");

        // No further sweeps after shutdown even as time advances.
        let after_shutdown = counter.sweeps();
        tokio::time::advance(interval * 3).await;
        tokio::task::yield_now().await;
        assert_eq!(counter.sweeps(), after_shutdown, "no sweeps after shutdown");
    }

    /// A shorter interval yields more sweeps over the same elapsed time —
    /// demonstrating the interval is genuinely configurable (Req 50.12).
    #[tokio::test(start_paused = true)]
    async fn shorter_interval_sweeps_more_often() {
        let (double, mut swept) = CountingReapable::with_signal("conn", 0);
        let counter = Arc::new(double);
        let reaper = Reaper::with_targets(Duration::from_secs(2), vec![counter.clone()]);

        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            reaper
                .run(async move {
                    let _ = stop_rx.await;
                })
                .await;
        });

        // Over 10s with a 2s interval we expect exactly 5 sweeps; await each
        // sweep's signal so the count is deterministic on the paused clock.
        for _ in 0..5 {
            tokio::time::advance(Duration::from_secs(2)).await;
            swept
                .recv()
                .await
                .expect("a sweep happens each 2s interval");
        }
        assert_eq!(counter.sweeps(), 5);

        let _ = stop_tx.send(());
        handle.await.expect("task joins");
    }

    /// The reaper is supervised under a stable task name (Req 50.7, 50.12).
    #[test]
    fn reaper_task_name_is_stable() {
        assert_eq!(REAPER_TASK_NAME, "leaked-resource-reaper");
    }
}
