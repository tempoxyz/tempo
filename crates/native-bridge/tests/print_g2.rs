use tempo_native_bridge::eip2537::g2_to_eip2537;

#[test]
fn print_g2_conversion() {
    // Network identity from devnet-bridge genesis (seed 0, 4 validators)
    let hex_input = "98c6e82fdf8990fa8b78df3788c45d4a36d83dd6c4e619b7b746abe12891427dd93ccd2d00596b8a87a5b084578fd2cf0a1f3a02672f4b370b2601e6425f873eafeb10a62adaa093b503a8630b89994c5f1401e62001896d2bd4f858be2cb941";
    let compressed = hex::decode(hex_input).unwrap();
    let compressed: [u8; 96] = compressed.try_into().unwrap();
    let eip2537 = g2_to_eip2537(&compressed).unwrap();

    println!("\n\nG2_EIP2537=0x{}\n", hex::encode(eip2537));
}
