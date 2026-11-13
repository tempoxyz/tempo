//! Test-only transparent TCP gates. No protocol replies are synthesized and buffered bytes
//! survive a hold. The workload must observe the matching live lease, not merely eventual healing.

use antithesis_sdk::random::get_random;
use eyre::WrapErr as _;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fs::{self, File, OpenOptions},
    future::Future,
    io::{self, Read as _, Write as _},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::AsyncWriteExt as _,
    net::{
        TcpListener, TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::watch,
    task::JoinSet,
    time::{Instant, timeout},
};

#[cfg(test)]
pub(super) use tests::initial_statuses;

const MAX_HOLD: Duration = Duration::from_secs(180);
const ACK_WAIT: Duration = Duration::from_secs(5);
const TICK: Duration = Duration::from_millis(25);
const STATUS_FRESH_MS: u64 = 1_000;
const MAX_JSON: u64 = 2_048;
const MAX_CONNECTIONS: usize = 128;
const BUFFER_BYTES: usize = 8_192;
const CONNECTION_LIFETIME: Duration = Duration::from_secs(3_600);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST: &str = "network.json";

/// Exclusive network episode guard. The caller also holds the ledger's episode lock.
/// Drop requests cancellation; expiry is the backstop when the workload is killed.
pub(super) struct Fault {
    dir: PathBuf,
    request: Request,
    armed: bool,
    _lock: File,
}

impl Fault {
    /// Pauses selected sequencers' L1/P2P traffic (bits 0..2), awaiting all three proxies.
    /// P2P masks apply at both source and destination, including existing connections.
    pub(super) async fn apply(
        dir: &Path,
        l1_mask: u8,
        p2p_mask: u8,
        hold: Duration,
    ) -> eyre::Result<Self> {
        eyre::ensure!(
            hold >= Duration::from_millis(1) && hold <= MAX_HOLD,
            "network hold must be in [1ms, 180s]"
        );
        validate_masks(l1_mask, p2p_mask)?;
        let lock = lock(dir)?;
        let statuses = read_statuses(dir)?;
        eyre::ensure!(
            statuses.iter().all(|status| status.phase != Phase::Active),
            "network fault already active"
        );
        let now = epoch_ms()?;
        let request = Request {
            id: [get_random(), get_random()],
            serial: next_serial(dir)?,
            boots: statuses.map(|status| status.boot),
            issued_ms: now,
            deadline_ms: now
                .checked_add(u64::try_from(hold.as_millis())?)
                .ok_or_else(|| eyre::eyre!("network deadline overflow"))?,
            l1_mask,
            p2p_mask,
            cancelled: false,
        };
        let fault = Self {
            dir: dir.to_owned(),
            request,
            armed: true,
            _lock: lock,
        };
        atomic_json(dir, REQUEST, &fault.request)?;
        fault.wait_active().await?;
        Ok(fault)
    }

    /// Changes gates under a new ID without extending the original deadline; awaits all acks.
    pub(super) async fn reconfigure(&mut self, l1_mask: u8, p2p_mask: u8) -> eyre::Result<()> {
        self.ensure_active().await?;
        validate_masks(l1_mask, p2p_mask)?;
        let mut request = self.request.clone();
        request.serial = next_serial(&self.dir)?;
        request.id = [get_random(), get_random()];
        request.l1_mask = l1_mask;
        request.p2p_mask = p2p_mask;
        atomic_json(&self.dir, REQUEST, &request)?;
        self.request = request;
        self.wait_active().await
    }

    async fn wait_active(&self) -> eyre::Result<()> {
        timeout(ACK_WAIT, async {
            loop {
                let statuses = read_statuses(&self.dir)?;
                if statuses
                    .iter()
                    .all(|status| status.id == Some(self.request.id))
                {
                    return self.ensure_active().await;
                }
                tokio::time::sleep(TICK).await;
            }
        })
        .await
        .wrap_err("network proxies did not acknowledge lease")?
    }

    /// Fails if any proxy expired, restarted, lost the lease, or stopped reporting fresh acks.
    pub(super) async fn ensure_active(&self) -> eyre::Result<()> {
        eyre::ensure!(
            self.armed && epoch_ms()? < self.request.deadline_ms,
            "network fault lease expired or released"
        );
        let current: Request = read_json(&self.dir.join(REQUEST))?;
        eyre::ensure!(current == self.request, "network fault request replaced");
        for (index, status) in read_statuses(&self.dir)?.iter().enumerate() {
            eyre::ensure!(
                status.phase == Phase::Active
                    && status.id == Some(self.request.id)
                    && status.boot == self.request.boots[index]
                    && status.deadline_ms == Some(self.request.deadline_ms)
                    && status.l1_mask == self.request.l1_mask
                    && status.p2p_mask == self.request.p2p_mask,
                "network proxy {index} lost active lease: {status:?}"
            );
        }
        Ok(())
    }

    /// Monitors the matching active acknowledgements throughout work, including its completion.
    /// The lease deadline bounds this wait even if work never returns.
    pub(super) async fn while_active<T>(
        &self,
        work: impl Future<Output = eyre::Result<T>>,
    ) -> eyre::Result<T> {
        self.ensure_active().await?;
        tokio::pin!(work);
        let result = loop {
            tokio::select! {
                result = &mut work => break result,
                () = tokio::time::sleep(TICK) => self.ensure_active().await?,
            }
        };
        self.ensure_active().await?;
        result
    }

    /// Cancels this lease and waits for all proxies to acknowledge that traffic is unblocked.
    pub(super) async fn heal(&mut self) -> eyre::Result<()> {
        self.cancel()?;
        wait_healed(&self.dir, Some(self.request.id)).await?;
        self.armed = false;
        Ok(())
    }

    fn cancel(&self) -> eyre::Result<()> {
        let current: Request = read_json(&self.dir.join(REQUEST))?;
        eyre::ensure!(
            current.id == self.request.id,
            "refusing to cancel another network lease"
        );
        let mut request = self.request.clone();
        request.cancelled = true;
        atomic_json(&self.dir, REQUEST, &request)
    }
}

impl Drop for Fault {
    fn drop(&mut self) {
        if self.armed
            && let Err(error) = self.cancel()
        {
            eprintln!("network lease cancellation failed; watchdog remains armed: {error:#}");
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Request {
    id: [u64; 2],
    serial: u64,
    boots: [[u64; 2]; 3],
    issued_ms: u64,
    deadline_ms: u64,
    l1_mask: u8,
    p2p_mask: u8,
    cancelled: bool,
}

impl Request {
    fn validate(&self, now: u64, index: usize, boot: [u64; 2]) -> eyre::Result<()> {
        validate_masks(self.l1_mask, self.p2p_mask)?;
        eyre::ensure!(
            self.boots[index] == boot,
            "network lease belongs to a previous proxy boot"
        );
        eyre::ensure!(
            self.issued_ms <= now
                && now < self.deadline_ms
                && self
                    .deadline_ms
                    .checked_sub(self.issued_ms)
                    .is_some_and(|ms| ms > 0 && ms <= 180_000),
            "invalid or expired network lease deadline"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Idle,
    Active,
    Cancelled,
    Expired,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Status {
    boot: [u64; 2],
    id: Option<[u64; 2]>,
    phase: Phase,
    deadline_ms: Option<u64>,
    l1_mask: u8,
    p2p_mask: u8,
    updated_ms: u64,
    connections: usize,
}

#[derive(Clone, Copy, Debug, Default)]
struct Gates {
    l1_mask: u8,
    p2p_mask: u8,
}

#[derive(Clone, Copy, Debug)]
enum Route {
    L1 { target: u8 },
    P2p { target: u8, source: u8 },
}

impl Route {
    fn blocked(self, gates: Gates) -> bool {
        match self {
            Self::L1 { target } => gates.l1_mask & (1 << target) != 0,
            Self::P2p { target, source } => gates.p2p_mask & ((1 << target) | (1 << source)) != 0,
        }
    }
}

struct Controller {
    index: usize,
    status: Status,
    last_request: Option<Request>,
    expires: Option<Instant>,
    high_water: u64,
}

impl Controller {
    fn new(index: usize, boot: [u64; 2]) -> Self {
        Self {
            index,
            status: Status {
                boot,
                id: None,
                phase: Phase::Idle,
                deadline_ms: None,
                l1_mask: 0,
                p2p_mask: 0,
                updated_ms: 0,
                connections: 0,
            },
            last_request: None,
            expires: None,
            high_water: 0,
        }
    }

    fn update(&mut self, request: Option<Request>, now: u64) -> Gates {
        self.status.updated_ms = now;
        match request {
            None => {
                self.status.phase = Phase::Idle;
                self.expires = None;
            }
            Some(request) => {
                self.status.id = Some(request.id);
                if request.cancelled {
                    self.high_water = self.high_water.max(request.serial);
                    self.status.phase = Phase::Cancelled;
                    self.expires = None;
                } else if self
                    .last_request
                    .as_ref()
                    .is_none_or(|last| last.id != request.id)
                {
                    self.status.deadline_ms = Some(request.deadline_ms);
                    if request.serial > self.high_water
                        && request.validate(now, self.index, self.status.boot).is_ok()
                    {
                        self.high_water = request.serial;
                        self.status.phase = Phase::Active;
                        self.expires =
                            Some(Instant::now() + Duration::from_millis(request.deadline_ms - now));
                        self.status.l1_mask = request.l1_mask;
                        self.status.p2p_mask = request.p2p_mask;
                    } else {
                        self.status.phase = Phase::Rejected;
                        self.expires = None;
                    }
                } else if self.last_request.as_ref() != Some(&request) {
                    // A lease's ID commits its entire shape, including cancellation.
                    self.status.phase = Phase::Rejected;
                    self.expires = None;
                }
                self.last_request = Some(request);
            }
        }
        if self.status.phase == Phase::Active
            && (self
                .expires
                .is_none_or(|deadline| Instant::now() >= deadline)
                || self
                    .status
                    .deadline_ms
                    .is_none_or(|deadline| now >= deadline))
        {
            self.status.phase = Phase::Expired;
            self.expires = None;
        }
        if self.status.phase == Phase::Active {
            Gates {
                l1_mask: self.status.l1_mask,
                p2p_mask: self.status.p2p_mask,
            }
        } else {
            self.status.l1_mask = 0;
            self.status.p2p_mask = 0;
            Gates::default()
        }
    }
}

/// Runs one sidecar before Context initialization (no zone.json required).
/// Index 0..2 binds :8546 to L1 and :9200 to the corresponding sequencer.
pub(super) async fn run(index: usize, dir: &Path) -> eyre::Result<()> {
    eyre::ensure!(index < 3, "proxy index must be 0, 1 or 2");
    fs::create_dir_all(dir).wrap_err("creating network control directory")?;
    let l1 = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 8546))
        .await
        .wrap_err("binding L1 proxy")?;
    let p2p = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 9200))
        .await
        .wrap_err("binding P2P proxy")?;
    let mut controller = Controller::new(index, [get_random(), get_random()]);
    let (gates, _) = watch::channel(Gates::default());
    let mut tasks = JoinSet::new();
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _ = tick.tick() => {
                let request = match read_json::<Request>(&dir.join(REQUEST)) {
                    Ok(request) => Some(request),
                    Err(error) if error.downcast_ref::<io::Error>().is_some_and(|e| e.kind() == io::ErrorKind::NotFound) => None,
                    Err(error) => {
                        // A corrupt control file is a harness failure, not a successful test.
                        gates.send_replace(Gates::default());
                        return Err(error).wrap_err("invalid network fault control file");
                    }
                };
                gates.send_replace(controller.update(request, epoch_ms()?));
                controller.status.connections = tasks.len();
                // send_replace waits for all current gate readers, so this acknowledges the
                // gate on already-open sockets too, not just newly accepted connections.
                // Bytes already queued in the OS may still arrive: the campaign separately
                // observes actual node anchors, never infers node state from this ack.
                atomic_json(dir, &format!("proxy-{index}.json"), &controller.status)?;
            }
            accepted = l1.accept(), if tasks.len() < MAX_CONNECTIONS => {
                let (stream, _) = accepted.wrap_err("accepting L1 proxy connection")?;
                spawn_connection(&mut tasks, stream, SocketAddr::from(([10,20,0,10],8546)),
                    Route::L1 { target: u8::try_from(index)? }, gates.subscribe());
            }
            accepted = p2p.accept(), if tasks.len() < MAX_CONNECTIONS => {
                let (stream, peer) = accepted.wrap_err("accepting P2P proxy connection")?;
                // Unknown sources must not bypass a partition; close without a protocol reply.
                if let Some(source) = source_index(peer.ip()) {
                    spawn_connection(&mut tasks, stream, SocketAddr::from(([10,20,0,11 + u8::try_from(index)?],9200)),
                        Route::P2p { target: u8::try_from(index)?, source }, gates.subscribe());
                }
            }
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(result) = result { result.wrap_err("network proxy task panicked")?; }
            }
        }
    }
}

fn source_index(ip: IpAddr) -> Option<u8> {
    match ip {
        IpAddr::V4(ip) => match ip.octets() {
            [10, 20, 0, last @ 11..=13] => Some(last - 11),
            [10, 20, 0, 20] => Some(3),
            _ => None,
        },
        _ => None,
    }
}

fn spawn_connection(
    tasks: &mut JoinSet<()>,
    stream: TcpStream,
    upstream: SocketAddr,
    route: Route,
    gates: watch::Receiver<Gates>,
) {
    if tasks.len() >= MAX_CONNECTIONS {
        eprintln!("proxy connection limit reached");
        return;
    }
    tasks.spawn(async move {
        match timeout(CONNECTION_LIFETIME, async {
            let upstream = timeout(CONNECT_TIMEOUT, TcpStream::connect(upstream)).await??;
            let (client_read, client_write) = stream.into_split();
            let (upstream_read, upstream_write) = upstream.into_split();
            tokio::try_join!(
                pump(client_read, upstream_write, route, gates.clone()),
                pump(upstream_read, client_write, route, gates)
            )?;
            Ok::<_, io::Error>(())
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => eprintln!("proxy connection ended: {error}"),
            Err(_) => eprintln!("proxy connection lifetime exceeded"),
        }
    });
}

async fn pump(
    read: OwnedReadHalf,
    mut write: OwnedWriteHalf,
    route: Route,
    mut gates: watch::Receiver<Gates>,
) -> io::Result<()> {
    let mut buffer = [0_u8; BUFFER_BYTES];
    let mut start = 0;
    let mut end = 0;
    loop {
        if route.blocked(*gates.borrow_and_update()) {
            gates.changed().await.map_err(io::Error::other)?;
            continue;
        }
        if start == end {
            tokio::select! {
                changed = gates.changed() => { changed.map_err(io::Error::other)?; continue; }
                ready = read.readable() => ready?,
            }
            let count = {
                let policy = gates.borrow_and_update();
                if route.blocked(*policy) {
                    continue;
                }
                read.try_read(&mut buffer)
            };
            match count {
                Ok(0) => {
                    write.shutdown().await?;
                    return Ok(());
                }
                Ok(count) => {
                    start = 0;
                    end = count;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error),
            }
        } else {
            tokio::select! {
                changed = gates.changed() => { changed.map_err(io::Error::other)?; continue; }
                ready = write.writable() => ready?,
            }
            let count = {
                let policy = gates.borrow_and_update();
                if route.blocked(*policy) {
                    continue;
                }
                write.try_write(&buffer[start..end])
            };
            match count {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(count) => start += count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error),
            }
        }
    }
}

/// Releases abandoned network gates before terminal checks; never releases a live owner's lock.
pub(super) async fn release_network_faults(dir: &Path) -> eyre::Result<()> {
    let _lock = lock(dir)?;
    match fs::remove_file(dir.join(REQUEST)) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).wrap_err("removing network lease"),
    }
    wait_healed(dir, None).await
}

async fn wait_healed(dir: &Path, id: Option<[u64; 2]>) -> eyre::Result<()> {
    timeout(ACK_WAIT, async {
        loop {
            let statuses = read_statuses(dir)?;
            if statuses.iter().all(|s| {
                s.phase != Phase::Active
                    && s.l1_mask == 0
                    && s.p2p_mask == 0
                    && id.is_none_or(|id| s.id == Some(id))
            }) {
                return Ok(());
            }
            tokio::time::sleep(TICK).await;
        }
    })
    .await
    .wrap_err("network proxies did not acknowledge healing")?
}

fn lock(dir: &Path) -> eyre::Result<File> {
    fs::create_dir_all(dir).wrap_err("creating fault-control directory")?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join("network.lock"))?;
    file.try_lock()
        .wrap_err("another network fault owns the control lock")?;
    Ok(file)
}

fn next_serial(dir: &Path) -> eyre::Result<u64> {
    let previous = match read_json::<u64>(&dir.join("network-serial.json")) {
        Ok(value) => value,
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) =>
        {
            0
        }
        Err(error) => return Err(error),
    };
    let serial = previous
        .checked_add(1)
        .ok_or_else(|| eyre::eyre!("network lease serial overflow"))?;
    atomic_json(dir, "network-serial.json", &serial)?;
    Ok(serial)
}

fn validate_masks(l1_mask: u8, p2p_mask: u8) -> eyre::Result<()> {
    eyre::ensure!(
        l1_mask <= 7 && p2p_mask <= 7 && (l1_mask | p2p_mask) != 0,
        "network masks must select at least one of nodes 0..2"
    );
    Ok(())
}

fn epoch_ms() -> eyre::Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn read_statuses(dir: &Path) -> eyre::Result<[Status; 3]> {
    let statuses = [
        read_json::<Status>(&dir.join("proxy-0.json"))?,
        read_json::<Status>(&dir.join("proxy-1.json"))?,
        read_json::<Status>(&dir.join("proxy-2.json"))?,
    ];
    let now = epoch_ms()?;
    for status in &statuses {
        eyre::ensure!(
            now.checked_sub(status.updated_ms)
                .is_some_and(|age| age <= STATUS_FRESH_MS)
                && status.connections <= MAX_CONNECTIONS,
            "network proxy status stale or invalid"
        );
    }
    Ok(statuses)
}

fn read_json<T: DeserializeOwned>(path: &Path) -> eyre::Result<T> {
    let file = File::open(path).wrap_err("reading network control JSON")?;
    let mut bytes = Vec::new();
    file.take(MAX_JSON + 1).read_to_end(&mut bytes)?;
    eyre::ensure!(
        u64::try_from(bytes.len())? <= MAX_JSON,
        "network control JSON exceeds size limit"
    );
    serde_json::from_slice(&bytes).wrap_err("invalid network control JSON")
}

fn atomic_json(dir: &Path, name: &str, value: &impl Serialize) -> eyre::Result<()> {
    let bytes = serde_json::to_vec(value)?;
    eyre::ensure!(
        u64::try_from(bytes.len())? <= MAX_JSON,
        "network control JSON exceeds size limit"
    );
    let temporary = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let mut file = File::create(&temporary).wrap_err("creating atomic network control file")?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(temporary, dir.join(name)).wrap_err("publishing atomic network control file")?;
    File::open(dir)?
        .sync_all()
        .wrap_err("syncing network control directory")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt as _;

    fn request(now: u64) -> Request {
        Request {
            id: [u64::MAX, 7],
            serial: 1,
            boots: [[10, 20]; 3],
            issued_ms: now,
            deadline_ms: now + 1_000,
            l1_mask: 1,
            p2p_mask: 2,
            cancelled: false,
        }
    }

    #[test]
    fn strict_json_and_masks_and_bounds() {
        let dir = tempfile::tempdir().unwrap();
        let value = request(1_000);
        atomic_json(dir.path(), REQUEST, &value).unwrap();
        assert_eq!(
            read_json::<Request>(&dir.path().join(REQUEST)).unwrap(),
            value
        );
        let mut extra = serde_json::to_value(&value).unwrap();
        extra["unexpected"] = true.into();
        assert!(
            serde_json::from_value::<Request>(extra)
                .unwrap_err()
                .to_string()
                .contains("unknown field")
        );
        for (l1, p2p) in [(8, 0), (0, 8), (0, 0), (255, 255)] {
            assert_eq!(
                validate_masks(l1, p2p).unwrap_err().to_string(),
                "network masks must select at least one of nodes 0..2"
            );
        }
        for l1 in 0..=7 {
            for p2p in 0..=7 {
                if l1 | p2p != 0 {
                    validate_masks(l1, p2p).unwrap();
                }
            }
        }
        fs::write(
            dir.path().join(REQUEST),
            vec![b' '; usize::try_from(MAX_JSON + 1).unwrap()],
        )
        .unwrap();
        assert_eq!(
            read_json::<Request>(&dir.path().join(REQUEST))
                .unwrap_err()
                .to_string(),
            "network control JSON exceeds size limit"
        );
        assert_eq!(next_serial(dir.path()).unwrap(), 1);
        assert_eq!(next_serial(dir.path()).unwrap(), 2);
        let held = lock(dir.path()).unwrap();
        assert_eq!(
            lock(dir.path()).unwrap_err().to_string(),
            "another network fault owns the control lock"
        );
        drop(held);
        assert!(lock(dir.path()).is_ok());
    }

    #[test]
    fn source_and_target_gates_are_independent_of_l1() {
        let gates = Gates {
            l1_mask: 1,
            p2p_mask: 2,
        };
        for source in 0..4 {
            for target in 0..3 {
                assert_eq!(
                    Route::P2p { source, target }.blocked(gates),
                    source == 1 || target == 1
                );
                assert_eq!(Route::L1 { target }.blocked(gates), target == 0);
            }
        }
        for node in 0..3 {
            assert_eq!(
                source_index(IpAddr::from([10, 20, 0, 11 + node])),
                Some(node)
            );
        }
        assert_eq!(source_index(IpAddr::from([10, 20, 0, 20])), Some(3));
        for ip in [[10, 20, 0, 41], [10, 20, 0, 30], [127, 0, 0, 1]] {
            assert_eq!(source_index(IpAddr::from(ip)), None);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_cancel_replay_and_restart_cannot_rearm() {
        let now = 1_000;
        let value = request(now);
        let mut controller = Controller::new(0, [10, 20]);
        assert_eq!(controller.update(Some(value.clone()), now).l1_mask, 1);
        assert_eq!(controller.status.phase, Phase::Active);
        tokio::time::advance(Duration::from_secs(2)).await;
        // Even a frozen/backwards wall clock cannot extend the monotonic watchdog.
        assert_eq!(controller.update(Some(value.clone()), now).l1_mask, 0);
        assert_eq!(controller.status.phase, Phase::Expired);
        assert_eq!(controller.update(Some(value.clone()), now).l1_mask, 0);
        let mut restarted = Controller::new(0, [11, 21]);
        assert_eq!(restarted.update(Some(value.clone()), now).l1_mask, 0);
        assert_eq!(restarted.status.phase, Phase::Rejected);

        let mut controller = Controller::new(0, [10, 20]);
        controller.update(Some(value.clone()), now);
        let mut cancelled = value.clone();
        cancelled.cancelled = true;
        assert_eq!(controller.update(Some(cancelled), now).p2p_mask, 0);
        assert_eq!(controller.status.phase, Phase::Cancelled);
        assert_eq!(controller.update(Some(value.clone()), now).p2p_mask, 0);
        assert_eq!(controller.status.phase, Phase::Rejected);
        let mut next = value.clone();
        next.id[1] += 1;
        next.serial += 1;
        assert_eq!(controller.update(Some(next), now).p2p_mask, 2);
        assert_eq!(controller.update(Some(value.clone()), now).p2p_mask, 0);
        assert_eq!(controller.status.phase, Phase::Rejected);
        controller.update(None, now);
        assert_eq!(controller.update(Some(value), now).p2p_mask, 0);
    }

    #[tokio::test]
    async fn invalid_deadlines_and_changed_lease_are_rejected() {
        let now = 1_000;
        for (issued, deadline) in [
            (now + 1, now + 2),
            (now, now),
            (now, now + 180_001),
            (now - 1, now),
        ] {
            let mut value = request(now);
            value.issued_ms = issued;
            value.deadline_ms = deadline;
            assert_eq!(
                value.validate(now, 0, [10, 20]).unwrap_err().to_string(),
                "invalid or expired network lease deadline"
            );
        }
        let mut controller = Controller::new(0, [10, 20]);
        let mut value = request(now);
        controller.update(Some(value.clone()), now);
        value.l1_mask = 4;
        assert_eq!(controller.update(Some(value), now).l1_mask, 0);
        assert_eq!(controller.status.phase, Phase::Rejected);
    }

    async fn echo_fixture(route: Route) -> (TcpStream, watch::Sender<Gates>, JoinSet<()>) {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = echo.local_addr().unwrap();
        let listen = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listen.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, _) = listen.accept().await.unwrap();
        let (gates, receiver) = watch::channel(Gates::default());
        let mut tasks = JoinSet::new();
        spawn_connection(&mut tasks, stream, upstream, route, receiver);
        tasks.spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let mut buffer = [0; BUFFER_BYTES];
            loop {
                let count = stream.read(&mut buffer).await.unwrap();
                if count == 0 {
                    break;
                }
                stream.write_all(&buffer[..count]).await.unwrap();
            }
        });
        (client, gates, tasks)
    }

    #[tokio::test]
    async fn existing_tcp_streams_pause_and_resume_without_losing_bytes() {
        timeout(Duration::from_secs(5), async {
            for (route, blocked) in [
                (
                    Route::L1 { target: 0 },
                    Gates {
                        l1_mask: 1,
                        p2p_mask: 0,
                    },
                ),
                (
                    Route::P2p {
                        target: 0,
                        source: 1,
                    },
                    Gates {
                        l1_mask: 0,
                        p2p_mask: 2,
                    },
                ),
                (
                    Route::P2p {
                        target: 1,
                        source: 0,
                    },
                    Gates {
                        l1_mask: 0,
                        p2p_mask: 2,
                    },
                ),
                (
                    Route::P2p {
                        target: 1,
                        source: 3,
                    },
                    Gates {
                        l1_mask: 0,
                        p2p_mask: 2,
                    },
                ),
            ] {
                let (mut client, gates, mut tasks) = echo_fixture(route).await;
                client.write_all(b"before").await.unwrap();
                let mut first = [0; 6];
                client.read_exact(&mut first).await.unwrap();
                assert_eq!(&first, b"before");
                gates.send_replace(blocked);
                let payload = vec![0xab; BUFFER_BYTES * 4 + 11];
                client.write_all(&payload).await.unwrap();
                let mut byte = [0; 1];
                assert!(
                    timeout(Duration::from_millis(40), client.read(&mut byte))
                        .await
                        .is_err(),
                    "held stream forwarded payload"
                );
                gates.send_replace(Gates::default());
                let mut received = vec![0; payload.len()];
                client.read_exact(&mut received).await.unwrap();
                assert_eq!(received, payload);
                tasks.shutdown().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn downstream_also_pauses_and_connection_capacity_is_bounded() {
        timeout(Duration::from_secs(5), async {
            let listen = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut client = TcpStream::connect(listen.local_addr().unwrap())
                .await
                .unwrap();
            let (stream, _) = listen.accept().await.unwrap();
            let (gates, receiver) = watch::channel(Gates::default());
            let mut tasks = JoinSet::new();
            spawn_connection(
                &mut tasks,
                stream,
                upstream.local_addr().unwrap(),
                Route::L1 { target: 0 },
                receiver,
            );
            let (mut server, _) = upstream.accept().await.unwrap();
            gates.send_replace(Gates {
                l1_mask: 1,
                p2p_mask: 0,
            });
            server.write_all(b"server").await.unwrap();
            let mut received = [0; 6];
            assert!(
                timeout(Duration::from_millis(40), client.read_exact(&mut received))
                    .await
                    .is_err()
            );
            gates.send_replace(Gates::default());
            client.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, b"server");
            tasks.shutdown().await;
            for _ in 0..MAX_CONNECTIONS {
                tasks.spawn(std::future::pending::<()>());
            }
            let extra = TcpStream::connect(listen.local_addr().unwrap())
                .await
                .unwrap();
            let (stream, _) = listen.accept().await.unwrap();
            spawn_connection(
                &mut tasks,
                stream,
                upstream.local_addr().unwrap(),
                Route::L1 { target: 0 },
                gates.subscribe(),
            );
            assert_eq!(tasks.len(), MAX_CONNECTIONS);
            drop(extra);
            tasks.shutdown().await;
        })
        .await
        .unwrap();
    }

    async fn controllers(dir: PathBuf) {
        let mut controllers = [
            Controller::new(0, [10, 20]),
            Controller::new(1, [10, 20]),
            Controller::new(2, [10, 20]),
        ];
        loop {
            let request = match read_json::<Request>(&dir.join(REQUEST)) {
                Ok(value) => Some(value),
                Err(error)
                    if error
                        .downcast_ref::<io::Error>()
                        .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) =>
                {
                    None
                }
                Err(error) => panic!("fixture invalid request: {error:#}"),
            };
            for (index, controller) in controllers.iter_mut().enumerate() {
                controller.update(request.clone(), epoch_ms().unwrap());
                atomic_json(&dir, &format!("proxy-{index}.json"), &controller.status).unwrap();
            }
            tokio::time::sleep(TICK).await;
        }
    }

    /// Publishes fresh idle acknowledgements for fixtures that only release network gates.
    pub(crate) fn initial_statuses(dir: &Path) {
        for index in 0..3 {
            let mut controller = Controller::new(index, [10, 20]);
            controller.update(None, epoch_ms().unwrap());
            atomic_json(dir, &format!("proxy-{index}.json"), &controller.status).unwrap();
        }
    }

    #[tokio::test]
    async fn apply_reconfigure_heal_drop_and_terminal_release() {
        timeout(Duration::from_secs(5), async {
            let dir = tempfile::tempdir().unwrap();
            initial_statuses(dir.path());
            let task = tokio::spawn(controllers(dir.path().to_owned()));
            let mut fault = Fault::apply(dir.path(), 0, 2, Duration::from_secs(10))
                .await
                .unwrap();
            fault.ensure_active().await.unwrap();
            let original_deadline = fault.request.deadline_ms;
            let original_id = fault.request.id;
            fault.reconfigure(1, 2).await.unwrap();
            assert_ne!(fault.request.id, original_id);
            assert_eq!(fault.request.deadline_ms, original_deadline);
            assert_eq!(fault.while_active(async { Ok(42) }).await.unwrap(), 42);
            fault.heal().await.unwrap();
            assert_eq!(
                fault.ensure_active().await.unwrap_err().to_string(),
                "network fault lease expired or released"
            );
            drop(fault);
            let fault = Fault::apply(dir.path(), 1, 0, Duration::from_secs(10))
                .await
                .unwrap();
            let id = fault.request.id;
            drop(fault);
            assert!(
                read_json::<Request>(&dir.path().join(REQUEST))
                    .unwrap()
                    .cancelled
            );
            wait_healed(dir.path(), Some(id)).await.unwrap();
            release_network_faults(dir.path()).await.unwrap();
            assert!(!dir.path().join(REQUEST).exists());
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cancelled_pending_apply_publishes_release_and_bad_arguments_do_not_write() {
        let dir = tempfile::tempdir().unwrap();
        initial_statuses(dir.path());
        assert_eq!(
            run(3, dir.path()).await.unwrap_err().to_string(),
            "proxy index must be 0, 1 or 2"
        );
        for hold in [
            Duration::ZERO,
            Duration::from_nanos(1),
            MAX_HOLD + Duration::from_millis(1),
        ] {
            match Fault::apply(dir.path(), 1, 0, hold).await {
                Ok(_) => panic!("invalid hold accepted"),
                Err(error) => assert_eq!(error.to_string(), "network hold must be in [1ms, 180s]"),
            }
        }
        assert!(!dir.path().join(REQUEST).exists());
        assert!(
            timeout(
                Duration::from_millis(50),
                Fault::apply(dir.path(), 1, 0, Duration::from_secs(5))
            )
            .await
            .is_err()
        );
        let request = read_json::<Request>(&dir.path().join(REQUEST)).unwrap();
        assert!(request.cancelled);
        assert!(
            lock(dir.path()).is_ok(),
            "cancelled apply leaked its exclusive lock"
        );
        for bad in [
            b"{} {}".as_slice(),
            b"{\"id\":[1],\"extra\":true}".as_slice(),
        ] {
            fs::write(dir.path().join(REQUEST), bad).unwrap();
            assert_eq!(
                read_json::<Request>(&dir.path().join(REQUEST))
                    .unwrap_err()
                    .to_string(),
                "invalid network control JSON"
            );
        }
    }

    #[tokio::test]
    async fn lost_ack_watchdog_and_replacement_are_not_success() {
        timeout(Duration::from_secs(5), async {
            let dir = tempfile::tempdir().unwrap();
            initial_statuses(dir.path());
            let task = tokio::spawn(controllers(dir.path().to_owned()));
            let mut fault = Fault::apply(dir.path(), 1, 2, Duration::from_millis(100))
                .await
                .unwrap();
            assert_eq!(
                fault
                    .while_active(std::future::pending::<eyre::Result<()>>())
                    .await
                    .unwrap_err()
                    .to_string(),
                "network fault lease expired or released"
            );
            fault.heal().await.unwrap();
            drop(fault);
            let fault = Fault::apply(dir.path(), 1, 0, Duration::from_secs(2))
                .await
                .unwrap();
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            let mut statuses = read_statuses(dir.path()).unwrap();
            statuses[1].boot = [99, 99];
            atomic_json(dir.path(), "proxy-1.json", &statuses[1]).unwrap();
            assert!(
                fault
                    .ensure_active()
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("proxy 1 lost active lease")
            );
            statuses[1].boot = [10, 20];
            statuses[1].updated_ms = 0;
            atomic_json(dir.path(), "proxy-1.json", &statuses[1]).unwrap();
            assert_eq!(
                fault.ensure_active().await.unwrap_err().to_string(),
                "network proxy status stale or invalid"
            );
            let mut replaced = fault.request.clone();
            replaced.id = [111, 222];
            atomic_json(dir.path(), REQUEST, &replaced).unwrap();
            assert_eq!(
                fault.ensure_active().await.unwrap_err().to_string(),
                "network fault request replaced"
            );
            drop(fault);
            assert_eq!(
                read_json::<Request>(&dir.path().join(REQUEST)).unwrap(),
                replaced
            );
        })
        .await
        .unwrap();
    }
}
