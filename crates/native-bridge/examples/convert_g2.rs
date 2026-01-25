//! Convert compressed G2 to EIP-2537 format.
//!
//! Usage: cargo run -p tempo-native-bridge --example convert_g2 -- <hex-g2-compressed>

use tempo_native_bridge::eip2537::g2_to_eip2537;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: convert_g2 <hex-g2-compressed-96-bytes>");
        eprintln!("Example: convert_g2 0x98c6e82f...");
        std::process::exit(1);
    }

    let hex_input = args[1].trim_start_matches("0x");
    let compressed = hex::decode(hex_input).expect("invalid hex");

    if compressed.len() != 96 {
        eprintln!(
            "Error: G2 compressed must be 96 bytes, got {}",
            compressed.len()
        );
        std::process::exit(1);
    }

    let compressed: [u8; 96] = compressed.try_into().unwrap();
    let eip2537 = g2_to_eip2537(&compressed).expect("failed to convert G2");

    println!("0x{}", hex::encode(eip2537));
}
