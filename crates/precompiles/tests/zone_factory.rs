#[test]
fn exports_zone_portal_storage_slots() {
    let _ = tempo_precompiles::zone_factory::zone_portal_slots::ADMIN;
    let _ = tempo_precompiles::zone_factory::zone_portal_slots::TOKEN_CONFIGS;
}
