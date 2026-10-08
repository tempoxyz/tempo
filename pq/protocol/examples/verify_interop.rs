//! Check a public TypeScript fixture against the Rust token and device-key implementation.

use serde::Deserialize;
use std::io::{self, Read};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    device_key: Vec<u8>,
    digest: [u8; 32],
    signature: Vec<u8>,
    witness: tempo_pq_oidc::Witness,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let fixture: Fixture = serde_json::from_str(&input)?;
    let statement = tempo_pq_oidc::evaluate(&fixture.witness)?;
    tempo_pq_oidc::verify_signature(&fixture.device_key, &fixture.signature, &fixture.digest)?;
    if tempo_pq_oidc::access_key_id(&fixture.device_key)? != statement.access_key_id {
        return Err("device key differs from the statement".into());
    }
    println!("{}", serde_json::to_string(&statement)?);
    Ok(())
}
