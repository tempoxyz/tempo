//! Integration tests for the genesis ceremony.

use std::{net::SocketAddr, path::PathBuf};
use tempo_ceremony::{
    ceremony::{self, CeremonyArgs},
    config::{CeremonyConfig, Participant},
    constants::output,
    keygen::{self, KeygenArgs},
};

/// Get an available port by binding to port 0.
fn get_available_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

#[test]
fn ceremony_with_3_participants() {
    // 1. Generate N keys using keygen::run() with actual file output
    let keygen_dirs: Vec<_> = (0..3)
        .map(|_| {
            let dir = tempfile::tempdir().unwrap();
            keygen::run(KeygenArgs {
                output_dir: dir.path().to_path_buf(),
                force: false,
            })
            .unwrap();
            dir
        })
        .collect();

    // 2. Read back the generated public keys and sort by key bytes (deterministic ordering)
    let mut keygen_with_keys: Vec<_> = keygen_dirs
        .into_iter()
        .map(|dir| {
            let public_key =
                std::fs::read_to_string(dir.path().join("identity-public.hex")).unwrap();
            (dir, public_key)
        })
        .collect();
    keygen_with_keys.sort_by(|(_, a), (_, b)| a.cmp(b));

    // 3. Allocate N ports
    let ports: Vec<u16> = (0..3).map(|_| get_available_port()).collect();

    // 4. Build participant list
    let participants: Vec<Participant> = keygen_with_keys
        .iter()
        .zip(&ports)
        .enumerate()
        .map(|(i, ((_, public_hex), port))| Participant {
            name: format!("node-{i}"),
            public_key: public_hex.clone(),
            address: SocketAddr::from(([127, 0, 0, 1], *port)),
        })
        .collect();

    // 5. Build per-node configs and write to temp files, then spawn threads
    let handles: Vec<_> = keygen_with_keys
        .into_iter()
        .zip(ports)
        .enumerate()
        .map(|(i, ((keygen_dir, _public_key), port))| {
            let participants = participants.clone();
            std::thread::spawn(move || {
                // Create temp dir for ceremony output
                let ceremony_dir = tempfile::tempdir().unwrap();
                let config_path = ceremony_dir.path().join("config.toml");
                let output_dir = ceremony_dir.path().join("output");

                // Build config
                let config = CeremonyConfig::new(
                    "test-ceremony".into(),
                    SocketAddr::from(([127, 0, 0, 1], port)),
                    participants,
                );

                // Write config file
                std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();

                // Run the full ceremony using signing key from keygen output
                let result = ceremony::run(CeremonyArgs {
                    config: config_path,
                    signing_key: keygen_dir.path().join("identity-private.hex"),
                    output_dir: output_dir.clone(),
                    log_level: "warn".into(),
                });

                // Return output dir path and tempdirs (to keep them alive)
                result
                    .map(|()| (output_dir, keygen_dir, ceremony_dir))
                    .map_err(|e| format!("ceremony {i} failed: {e}"))
            })
        })
        .collect();

    // 6. Await all threads and collect results
    let outputs: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("thread panicked").unwrap())
        .collect();

    // 7. Verify outputs match across all participants
    verify_outputs_match(
        &outputs
            .iter()
            .map(|(p, _, _)| p.clone())
            .collect::<Vec<_>>(),
    );
}

/// Verify that ceremony outputs match across all participants.
fn verify_outputs_match(output_dirs: &[PathBuf]) {
    assert!(
        output_dirs.len() >= 2,
        "need at least 2 participants to compare"
    );

    // Shared files should be identical across all participants
    for filename in output::SHARED_FILES {
        let first_content = std::fs::read_to_string(output_dirs[0].join(filename))
            .unwrap_or_else(|e| panic!("failed to read {filename} from first output: {e}"));

        for (i, dir) in output_dirs.iter().enumerate().skip(1) {
            let content = std::fs::read_to_string(dir.join(filename))
                .unwrap_or_else(|e| panic!("failed to read {filename} from output {i}: {e}"));

            assert_eq!(
                first_content, content,
                "{filename} mismatch between participant 0 and {i}"
            );
        }
    }

    // share-private.hex should exist but be unique per participant
    for (i, dir) in output_dirs.iter().enumerate() {
        let share_path = dir.join(output::SHARE);
        assert!(
            share_path.exists(),
            "share-private.hex missing for participant {i}"
        );
    }

    // Verify shares are different (each participant gets a unique share)
    let shares: Vec<_> = output_dirs
        .iter()
        .map(|dir| std::fs::read_to_string(dir.join(output::SHARE)).unwrap())
        .collect();

    for i in 0..shares.len() {
        for j in (i + 1)..shares.len() {
            assert_ne!(
                shares[i], shares[j],
                "shares should be unique but participant {i} and {j} have the same share"
            );
        }
    }
}
