//! Encode and decode Tempo bech32m addresses.
//!
//! Run with: `cargo run --example tempo_address -p tempo-alloy`

use alloy::primitives::address;
use tempo_alloy::address::TempoAddress;

fn main() {
    // Encode a mainnet address (no zone)
    let addr = TempoAddress::new(address!("742d35CC6634c0532925a3B844bc9e7595F2Bd28"));
    println!("Mainnet: {addr}");

    // Encode a zone address
    let zone_addr =
        TempoAddress::with_zone(address!("742d35CC6634c0532925a3B844bc9e7595F2Bd28"), 1);
    println!("Zone 1:  {zone_addr}");

    // Parse from string
    let parsed: TempoAddress = "tempo1qp6z6dwvvc6vq5efyk3ms39une6etu4a9qtj2kk0"
        .parse()
        .expect("valid tempo address");
    println!(
        "Parsed:  {} (zone: {:?})",
        parsed.address(),
        parsed.zone_id()
    );

    // Validate
    assert!(TempoAddress::validate(
        "tempo1qp6z6dwvvc6vq5efyk3ms39une6etu4a9qtj2kk0"
    ));
    assert!(!TempoAddress::validate("not_valid"));

    // Convert from/to alloy Address
    let converted: TempoAddress = address!("742d35CC6634c0532925a3B844bc9e7595F2Bd28").into();
    let raw: alloy::primitives::Address = converted.into();
    println!("Raw:     {raw}");
}
