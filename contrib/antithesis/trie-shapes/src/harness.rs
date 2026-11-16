//! The reth-state-root workload's test-template harness. A long-running server owns the database,
//! the engine and the model; the short commands Antithesis runs from the test template talk to it
//! over a Unix socket, one JSON request and one JSON response per line. Blocks are built only when
//! a command asks, so Antithesis decides how writes, blocks, proofs, checks and faults interleave.
//!
//! A command that finds the server down (killed, restarting or recovering) exits successfully: a
//! restart is a fault Antithesis injected, not a failure of the command.

use crate::{Collider, Write};
use alloy_primitives::{Address, B256, U256};
use antithesis_sdk::{
    assert_sometimes, assert_unreachable, lifecycle::setup_complete, random::AntithesisRng,
};
use eyre::{bail, Result, WrapErr};
use rand_09::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs,
    io::{self, BufRead, BufReader, ErrorKind, Write as _},
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

/// Environment variable that overrides the socket path, for local runs.
const SOCKET_ENV: &str = "ANTITHESIS_TRIE_SOCKET";
/// The server and the commands run in the same container.
const DEFAULT_SOCKET: &str = "/run/antithesis-trie.sock";
/// How long first and finally commands wait for the server to answer.
const STARTUP_WAIT: Duration = Duration::from_secs(600);
/// Longest a request may take. A block or flush waits on persistence for at most the server's
/// own timeout, so a request past this is a hung server.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(900);

/// A command's request to the server.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// The round, its frontiers and a sample of the tip state. Answered with [Response::Summary].
    StateSummary,
    /// Queues writes for the next blocks of a round and merges the collider the writes were
    /// drawn from. Rejected once that round is over.
    SubmitWrites {
        /// The round of the summary the writes were drawn from.
        round: u64,
        /// Writes in the order they apply.
        writes: Vec<Write>,
        /// The summary's collider after drawing the writes.
        collider: Collider,
    },
    /// Builds one block from queued writes, padded with the server's own random writes.
    BuildBlock,
    /// Proofs of targets at a block of a round, as eth_getMultiProof serves them. Rejected when
    /// the round is over or the target has no proofs.
    GetProof {
        /// The round of the summary the block came from.
        round: u64,
        /// The block number.
        block: u64,
        /// One account proof per target, in order.
        targets: Vec<ProofTarget>,
    },
    /// Checks the state root the overlay serves at the tip against the model's.
    CheckRoot,
    /// Persists both frontiers up to the head; the server checks the persisted state.
    Flush,
}

/// The server's answer to one request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    /// The answer to [Request::StateSummary].
    Summary(Summary),
    /// Writes were queued; pending counts every write waiting for a block.
    Queued { pending: usize },
    /// A block was built and its root matches the model's.
    Block { round: u64, number: u64, root: B256 },
    /// The serialized account proofs, one per target.
    Proofs { proofs: Value },
    /// The root at the tip matches the model's.
    Root { number: u64, root: B256 },
    /// Both frontiers reached the head and the persisted state matches the model.
    Flushed { round: u64, head: u64 },
    /// The request no longer applies, such as one for a round that is over.
    Rejected { reason: String },
}

/// What a command needs to draw its next request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    /// The round's random ID; a new round starts on a fresh database.
    pub round: u64,
    /// The newest block.
    pub head: u64,
    /// The newest block whose block data is persisted.
    pub db_tip: u64,
    /// The newest block whose state and trie are persisted.
    pub state_tip: u64,
    /// Blocks the server proves, with the model's state root at each; never empty.
    pub roots: Vec<BlockRoot>,
    /// A sample of the tip state's accounts.
    pub accounts: Vec<AccountSample>,
    /// The server's recorded trie-shapes groups.
    pub collider: Collider,
}

/// A block and the model's state root after it.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockRoot {
    pub number: u64,
    pub root: B256,
}

/// An account and some of the slots it has written, deleted ones included.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountSample {
    pub address: Address,
    pub slots: Vec<U256>,
}

/// An account and the storage slots to prove with it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofTarget {
    pub address: Address,
    pub slots: Vec<B256>,
}

/// A command's connection to the server.
#[derive(Debug)]
pub struct Client {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl Client {
    /// Connects to the server, or returns None while it is down.
    pub fn connect() -> Result<Option<Self>> {
        let stream = match UnixStream::connect(socket_path()) {
            Ok(stream) => stream,
            Err(error)
                if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) =>
            {
                return Ok(None)
            }
            Err(error) => return Err(error).wrap_err("connect to the trie server"),
        };
        stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
        Ok(Some(Self { writer: stream.try_clone()?, reader: BufReader::new(stream) }))
    }

    /// Waits up to STARTUP_WAIT for the server to answer a state summary.
    pub fn wait() -> Result<(Self, Summary)> {
        let deadline = Instant::now() + STARTUP_WAIT;
        while Instant::now() < deadline {
            if let Some(mut client) = Self::connect()? &&
                let Some(summary) = client.summary()?
            {
                return Ok((client, summary));
            }
            thread::sleep(Duration::from_secs(1));
        }
        bail!("the trie server did not answer within {STARTUP_WAIT:?}")
    }

    /// Sends one request. None when the server went away before answering.
    pub fn call(&mut self, request: &Request) -> Result<Option<Response>> {
        let mut text = serde_json::to_vec(request)?;
        text.push(b'\n');
        match self.writer.write_all(&text) {
            Ok(()) => {}
            Err(error) if gone(&error) => return Ok(None),
            Err(error) => return Err(error).wrap_err("send a request"),
        }
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => Ok(None),
            Ok(_) => Ok(Some(serde_json::from_str(&line).wrap_err("decode a response")?)),
            Err(error) if gone(&error) => Ok(None),
            Err(error) => Err(error).wrap_err("receive a response"),
        }
    }

    /// The server's state summary. None when the server went away.
    pub fn summary(&mut self) -> Result<Option<Summary>> {
        match self.call(&Request::StateSummary)? {
            None => Ok(None),
            Some(Response::Summary(summary)) => Ok(Some(summary)),
            Some(other) => bail!("unexpected answer to state_summary: {other:?}"),
        }
    }
}

/// Serves requests until the process exits, after emitting setup_complete with details. A request
/// the handler fails is a broken invariant or an engine error: the server reports it and exits.
pub fn serve<F>(details: &Value, handler: F) -> Result<()>
where
    F: Fn(Request) -> Result<Response> + Send + Sync + 'static,
{
    let path = socket_path();
    // A killed server leaves its socket file behind.
    match fs::remove_file(&path) {
        Err(error) if error.kind() != ErrorKind::NotFound => {
            return Err(error).wrap_err("remove the old socket")
        }
        _ => {}
    }
    let listener =
        UnixListener::bind(&path).wrap_err_with(|| format!("bind {}", path.display()))?;
    setup_complete(details);
    let handler = Arc::new(handler);
    for stream in listener.incoming() {
        let stream = stream?;
        let handler = Arc::clone(&handler);
        thread::spawn(move || {
            if let Err(error) = connection(stream, &*handler) {
                assert_unreachable!(
                    "Trie server handles every request",
                    &json!({"error": format!("{error:#}")})
                );
                eprintln!("{error:?}");
                std::process::exit(1);
            }
        });
    }
    Ok(())
}

/// first_genesis: waits for the server, then builds the first block.
pub fn first_genesis() -> Result<()> {
    let (mut client, _) = Client::wait()?;
    build(&mut client, 1)
}

/// parallel_driver_writes: draws one trie-shapes step against the tip state and queues it.
pub fn parallel_driver_writes() -> Result<()> {
    let Some(mut client) = Client::connect()? else { return unavailable() };
    let Some(summary) = client.summary()? else { return unavailable() };
    let mut rng = AntithesisRng;
    let mut collider = summary.collider;
    let owner = (!summary.accounts.is_empty())
        .then(|| summary.accounts[rng.random_range(0..summary.accounts.len())].address);
    let budget = rng.random_range(2..=16);
    let writes = collider.step(&mut rng, owner, budget);
    let submitted = writes.len();
    assert_sometimes!(
        writes.iter().any(|write| matches!(write, Write::Storage { .. })),
        "A driver submits storage writes"
    );
    match client.call(&Request::SubmitWrites { round: summary.round, writes, collider })? {
        None => unavailable(),
        Some(Response::Queued { pending }) => {
            assert_sometimes!(pending > submitted, "Driver writes queue up across submissions");
            Ok(())
        }
        Some(Response::Rejected { reason }) => rejected(&reason),
        Some(other) => bail!("unexpected answer to submit_writes: {other:?}"),
    }
}

/// parallel_driver_blocks: builds one to four blocks.
pub fn parallel_driver_blocks() -> Result<()> {
    let Some(mut client) = Client::connect()? else { return unavailable() };
    build(&mut client, AntithesisRng.random_range(1..=4))
}

/// Flushes both frontiers to the head, which makes the server check the persisted state. Returns
/// the client for further checks, or None when the server is down or went away.
pub fn persisted() -> Result<Option<Client>> {
    let Some(mut client) = Client::connect()? else {
        unavailable()?;
        return Ok(None);
    };
    match client.call(&Request::Flush)? {
        None => {
            unavailable()?;
            Ok(None)
        }
        Some(Response::Flushed { round, head }) => {
            println!("{}", json!({"flushed": {"round": round, "head": head}}));
            Ok(Some(client))
        }
        Some(other) => bail!("unexpected answer to flush: {other:?}"),
    }
}

/// finally_recovered: runs check, which returns false when the server went away or the state moved
/// on before it finished, until it completes. Faults have stopped, so the server must let it
/// complete within STARTUP_WAIT.
pub fn finally(mut check: impl FnMut() -> Result<bool>) -> Result<()> {
    let deadline = Instant::now() + STARTUP_WAIT;
    while Instant::now() < deadline {
        if check()? {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(1));
    }
    bail!("the final check did not complete within {STARTUP_WAIT:?}")
}

/// Logs a request the server rejected; the state moved on, so the command has nothing to do.
pub fn rejected(reason: &str) -> Result<()> {
    println!("{}", json!({"rejected": reason}));
    Ok(())
}

/// Logs that the server is down; the command ends successfully.
pub fn unavailable() -> Result<()> {
    println!("{}", json!({"server": "unavailable"}));
    Ok(())
}

fn build(client: &mut Client, blocks: usize) -> Result<()> {
    for _ in 0..blocks {
        match client.call(&Request::BuildBlock)? {
            None => return unavailable(),
            Some(Response::Block { round, number, root }) => {
                println!("{}", json!({"block": {"round": round, "number": number, "root": root}}));
            }
            Some(other) => bail!("unexpected answer to build_block: {other:?}"),
        }
    }
    Ok(())
}

/// Answers a connection's requests until it closes.
fn connection(stream: UnixStream, handler: &impl Fn(Request) -> Result<Response>) -> Result<()> {
    let mut writer = stream.try_clone()?;
    for line in BufReader::new(stream).lines() {
        // A killed command drops its connection mid-request.
        let Ok(line) = line else { return Ok(()) };
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(request) => handler(request)?,
            Err(error) => Response::Rejected { reason: format!("invalid request: {error}") },
        };
        let mut text = serde_json::to_vec(&response)?;
        text.push(b'\n');
        if writer.write_all(&text).is_err() {
            return Ok(());
        }
    }
    Ok(())
}

fn gone(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::BrokenPipe | ErrorKind::ConnectionReset | ErrorKind::UnexpectedEof
    )
}

fn socket_path() -> PathBuf {
    std::env::var_os(SOCKET_ENV).map_or_else(|| PathBuf::from(DEFAULT_SOCKET), PathBuf::from)
}
