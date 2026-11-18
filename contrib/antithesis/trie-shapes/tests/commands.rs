//! Socket-level coverage of command rejection handling, including the final recovery retry.

use antithesis_trie_shapes::{
    harness::{BlockRoot, Request, Response, Summary},
    Collider,
};
use serde_json::json;
use std::{
    fs,
    io::{BufRead, BufReader, ErrorKind, Write},
    os::unix::net::{UnixListener, UnixStream},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

const TIMEOUT: Duration = Duration::from_secs(10);
static NEXT_SOCKET: AtomicU64 = AtomicU64::new(0);

fn run(command: &str, replies: &[(&str, Response)]) -> Output {
    let path = std::env::temp_dir().join(format!(
        "trie-commands-{}-{}.sock",
        std::process::id(),
        NEXT_SOCKET.fetch_add(1, Ordering::Relaxed)
    ));
    let listener = UnixListener::bind(&path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_reth-state-root-commands"))
        .arg(command)
        .env("ANTITHESIS_TRIE_SOCKET", &path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + TIMEOUT;
    let mut connection: Option<BufReader<UnixStream>> = None;
    for (method, response) in replies {
        let request = loop {
            assert!(Instant::now() < deadline, "command did not request {method}");
            if let Some(reader) = &mut connection {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() != 0 {
                    break serde_json::from_str::<serde_json::Value>(&line).unwrap();
                }
                connection = None;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
                    stream.set_write_timeout(Some(TIMEOUT)).unwrap();
                    connection = Some(BufReader::new(stream));
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => thread::yield_now(),
                Err(error) => panic!("accept command: {error}"),
            }
        };
        assert_eq!(request["method"], *method);
        // Decode too: the test replies to the same strict protocol as the server.
        serde_json::from_value::<Request>(request).unwrap();
        writeln!(
            connection.as_mut().unwrap().get_mut(),
            "{}",
            serde_json::to_string(response).unwrap()
        )
        .unwrap();
    }
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            panic!("command did not finish");
        }
        thread::yield_now();
    }
    fs::remove_file(path).unwrap();
    child.wait_with_output().unwrap()
}

fn rejected() -> Response {
    Response::Rejected { reason: "no active round".into() }
}

fn summary() -> Response {
    Response::Summary(Summary {
        round: 1,
        head: 0,
        db_tip: 0,
        state_tip: 0,
        roots: vec![BlockRoot { number: 0, root: Default::default() }],
        accounts: Vec::new(),
        collider: Collider::default(),
    })
}

fn unavailable(output: Output) {
    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "{\"server\":\"unavailable\"}\n");
    assert_eq!(String::from_utf8(output.stderr).unwrap(), "");
}

fn unexpected(output: Output, method: &str) {
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().lines().next().unwrap(),
        format!("Error: unexpected answer to {method}: Queued {{ pending: 0 }}")
    );
}

#[test]
fn writes_stop_when_summary_is_rejected() {
    unavailable(run("parallel_driver_writes", &[("state_summary", rejected())]));
}

#[test]
fn proofs_stop_when_summary_is_rejected() {
    unavailable(run("parallel_driver_proofs", &[("state_summary", rejected())]));
}

#[test]
fn blocks_stop_when_build_is_rejected() {
    unavailable(run("parallel_driver_blocks", &[("build_block", rejected())]));
}

#[test]
fn genesis_retries_a_rejected_summary_and_stops_when_build_is_rejected() {
    unavailable(run(
        "first_genesis",
        &[("state_summary", rejected()), ("state_summary", summary()), ("build_block", rejected())],
    ));
}

#[test]
fn persisted_stops_when_flush_is_rejected() {
    unavailable(run("eventually_persisted", &[("flush", rejected())]));
}

#[test]
fn root_check_stops_when_rejected() {
    unavailable(run("anytime_root", &[("check_root", rejected())]));
}

#[test]
fn recovery_retries_a_rejected_flush_but_reports_unexpected_responses() {
    let output = run(
        "finally_recovered",
        &[("flush", rejected()), ("flush", Response::Queued { pending: 0 })],
    );
    assert_eq!(output.stdout, b"{\"server\":\"unavailable\"}\n");
    unexpected(output, "flush");
}

#[test]
fn writes_preserve_normal_rejection() {
    let output = run(
        "parallel_driver_writes",
        &[
            ("state_summary", summary()),
            ("submit_writes", Response::Rejected { reason: "too many queued writes".into() }),
        ],
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        json!({"rejected": "too many queued writes"})
    );
}

#[test]
fn proofs_preserve_normal_rejection() {
    let output = run(
        "parallel_driver_proofs",
        &[
            ("state_summary", summary()),
            ("get_proof", Response::Rejected { reason: "round 1 is over".into() }),
        ],
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        json!({"rejected": "round 1 is over"})
    );
}

#[test]
fn summary_reports_unexpected_responses() {
    let output =
        run("parallel_driver_writes", &[("state_summary", Response::Queued { pending: 0 })]);
    unexpected(output, "state_summary");
}

#[test]
fn build_reports_unexpected_responses() {
    let output = run("parallel_driver_blocks", &[("build_block", Response::Queued { pending: 0 })]);
    unexpected(output, "build_block");
}

#[test]
fn root_check_reports_unexpected_responses() {
    let output = run("anytime_root", &[("check_root", Response::Queued { pending: 0 })]);
    unexpected(output, "check_root");
}
