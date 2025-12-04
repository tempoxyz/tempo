//! Terminal display for ceremony status.

use commonware_codec::Encode;
use commonware_cryptography::ed25519::PublicKey;
use commonware_utils::set::OrderedAssociated;
use crossterm::{
    cursor::MoveTo,
    execute,
    style::{Color, ResetColor, SetForegroundColor},
    terminal::{Clear, ClearType},
};
use std::{
    collections::HashSet,
    io::{Write as _, stdout},
    net::SocketAddr,
    path::Path,
};

use crate::protocol::CeremonyStatus;

/// Display info for a participant.
pub struct ParticipantInfo {
    /// Human-readable name from config.
    pub name: String,
    /// Network address for P2P connection.
    pub address: SocketAddr,
}

/// Type alias for participants list used in display.
pub type Participants = OrderedAssociated<PublicKey, ParticipantInfo>;

const GREEN: Color = Color::Green;
const RED: Color = Color::Red;
const YELLOW: Color = Color::Yellow;
const CYAN: Color = Color::Cyan;

fn clear_and_header(phase: &str) {
    let _ = execute!(stdout(), Clear(ClearType::All), MoveTo(0, 0));

    println!("+-----------------------------------------------------------------+");
    println!("|           TEMPO CEREMONY                                        |");
    println!("|           {phase:<53}|");
    println!("+-----------------------------------------------------------------+");
    println!();
}

fn format_short_key(pubkey: &PublicKey) -> String {
    let hex = const_hex::encode(pubkey.encode().as_ref());
    format!("0x{}...{}", &hex[..4], &hex[hex.len() - 4..])
}

fn print_missing_list(participants: &Participants, keys: &[PublicKey], color: Color) {
    let _ = execute!(stdout(), SetForegroundColor(color));
    for pubkey in keys {
        let name = participants
            .iter_pairs()
            .find(|(pk, _)| *pk == pubkey)
            .map(|(_, info)| info.name.as_str())
            .unwrap_or("Unknown");
        println!("    - {} ({})", name, format_short_key(pubkey));
    }
    let _ = execute!(stdout(), ResetColor);
}

/// Display connection status during Phase 1.
pub fn connection_status(
    participants: &Participants,
    connected_peers: &HashSet<PublicKey>,
    my_public_key: &PublicKey,
) {
    clear_and_header("Waiting for Connections");

    let total = participants.len();
    let conn_count = connected_peers.len() + 1;

    println!("  Participants: {conn_count}/{total} connected");
    println!();

    for (pubkey, info) in participants.iter_pairs() {
        let short_key = format_short_key(pubkey);
        let is_self = pubkey == my_public_key;
        let is_connected = is_self || connected_peers.contains(pubkey);

        if is_connected {
            let _ = execute!(stdout(), SetForegroundColor(GREEN));
            let suffix = if is_self { " (you)" } else { "" };
            println!(
                "  [+] {:<12} ({short_key})  {}{suffix}",
                info.name, info.address
            );
        } else {
            let _ = execute!(stdout(), SetForegroundColor(RED));
            println!(
                "  [-] {:<12} ({short_key})  {}  WAITING",
                info.name, info.address
            );
        }
        let _ = execute!(stdout(), ResetColor);
    }

    if conn_count < total {
        println!();
        let _ = execute!(stdout(), SetForegroundColor(YELLOW));
        println!(
            "  Waiting for {} more participant(s)...",
            total - conn_count
        );
        let _ = execute!(stdout(), ResetColor);
    }

    let _ = stdout().flush();
}

/// Display share/ack status during Phase 2.
pub fn share_status(participants: &Participants, status: &CeremonyStatus) {
    clear_and_header("Distributing Shares");

    let total = participants.len();
    let received = total - status.missing_acks.len();
    println!("  Acks received: {received}/{total}");
    println!();

    if status.missing_acks.is_empty() {
        let _ = execute!(stdout(), SetForegroundColor(GREEN));
        println!("  + All acks received!");
        let _ = execute!(stdout(), ResetColor);
    } else {
        println!("  Missing acks from:");
        print_missing_list(participants, &status.missing_acks, RED);
    }

    let _ = stdout().flush();
}

/// Display dealing collection status during Phase 4.
pub fn dealing_status(participants: &Participants, status: &CeremonyStatus) {
    clear_and_header("Collecting Dealings");

    let total = participants.len();
    let dealings_received = total - status.missing_dealings.len();
    let acks_received = total - 1 - status.missing_dealing_acks.len();
    println!("  Dealings received: {dealings_received}/{total}");
    println!("  Confirmations of ours: {}/{}", acks_received, total - 1);
    println!();

    if !status.missing_dealings.is_empty() {
        println!("  Missing dealings from:");
        print_missing_list(participants, &status.missing_dealings, RED);
    }

    if !status.missing_dealing_acks.is_empty() && status.missing_dealings.is_empty() {
        println!("  Waiting for confirmation from:");
        print_missing_list(participants, &status.missing_dealing_acks, YELLOW);
    }

    let _ = stdout().flush();
}

/// Display Phase 3 broadcasting.
pub fn phase3_broadcasting() {
    clear_and_header("Broadcasting Dealing");

    let _ = execute!(stdout(), SetForegroundColor(GREEN));
    println!("  + All shares distributed");
    println!("  + All acks received");
    println!("  + Dealing constructed (no reveals)");
    let _ = execute!(stdout(), ResetColor);

    println!();
    let _ = execute!(stdout(), SetForegroundColor(CYAN));
    println!("  ~ Broadcasting dealing to all participants...");
    let _ = execute!(stdout(), ResetColor);

    let _ = stdout().flush();
}

/// Display verification status during Phase 6.
pub fn verification_status(participants: &Participants, status: &CeremonyStatus) {
    clear_and_header("Verifying Outcomes");

    let total = participants.len();
    let outcomes_received = total - status.missing_outcomes.len();
    let acks_received = total - 1 - status.missing_outcome_acks.len();
    println!("  Outcomes received: {outcomes_received}/{total}");
    println!("  Confirmations of ours: {acks_received}/{}", total - 1);
    println!();

    if !status.missing_outcomes.is_empty() {
        println!("  Waiting for outcomes from:");
        print_missing_list(participants, &status.missing_outcomes, RED);
    }

    if !status.missing_outcome_acks.is_empty() && status.missing_outcomes.is_empty() {
        println!("  Waiting for confirmation from:");
        print_missing_list(participants, &status.missing_outcome_acks, YELLOW);
    }

    let _ = stdout().flush();
}

/// Display verification success.
pub fn verification_success() {
    clear_and_header("Verification Complete");

    let _ = execute!(stdout(), SetForegroundColor(GREEN));
    println!("  + All outcomes received");
    println!("  + All outcomes match - group key verified!");
    let _ = execute!(stdout(), ResetColor);

    println!();
    let _ = execute!(stdout(), SetForegroundColor(CYAN));
    println!("  ~ Writing output files...");
    let _ = execute!(stdout(), ResetColor);

    let _ = stdout().flush();
    std::thread::sleep(std::time::Duration::from_secs(1));
}

/// Display success screen.
pub fn success(output_dir: &Path) {
    clear_and_header("Complete!");

    let _ = execute!(stdout(), SetForegroundColor(GREEN));
    println!("  +---------------------------------------------------------+");
    println!("  |                                                         |");
    println!("  |              CEREMONY SUCCESSFUL!                       |");
    println!("  |                                                         |");
    println!("  +---------------------------------------------------------+");
    let _ = execute!(stdout(), ResetColor);

    println!();
    println!("  + All participants completed successfully");
    println!("  + All outcomes verified to match");
    println!("  + Group key computed");
    println!("  + Your private share computed");
    println!();
    println!("  Output files written to: {}", output_dir.display());
    println!();

    let _ = execute!(stdout(), SetForegroundColor(YELLOW));
    println!(
        "  ! IMPORTANT: Keep identity-private.hex and share-private.hex SECURE and BACKED UP!"
    );
    println!("  ! You will need both to run your validator node.");
    let _ = execute!(stdout(), ResetColor);

    println!();
    let _ = stdout().flush();
}

/// Display finalizing message.
pub fn finalizing() {
    clear_and_header("Finalizing");

    let _ = execute!(stdout(), SetForegroundColor(CYAN));
    println!("  ~ Computing group key and your private share...");
    let _ = execute!(stdout(), ResetColor);

    let _ = stdout().flush();
}

/// Display all connected message (during ceremony).
pub fn all_connected(total: usize) {
    clear_and_header("All Connected");

    let _ = execute!(stdout(), SetForegroundColor(GREEN));
    println!("  + All {total} participants connected!");
    println!();
    println!("  Proceeding to share distribution...");
    let _ = execute!(stdout(), ResetColor);

    let _ = stdout().flush();

    std::thread::sleep(std::time::Duration::from_secs(2));
}

/// Display connectivity test success.
pub fn connectivity_success(total: usize) {
    clear_and_header("Connectivity Test Passed");

    let _ = execute!(stdout(), SetForegroundColor(GREEN));
    println!("  +---------------------------------------------------------+");
    println!("  |                                                         |");
    println!("  |          CONNECTIVITY TEST SUCCESSFUL!                  |");
    println!("  |                                                         |");
    println!("  +---------------------------------------------------------+");
    let _ = execute!(stdout(), ResetColor);

    println!();
    println!("  + All {total} participants can connect to each other");
    println!();
    println!("  You are ready to run the ceremony.");
    println!("  Use: tempo-ceremony ceremony --config ... --signing-key ...");
    println!();

    let _ = stdout().flush();
}
