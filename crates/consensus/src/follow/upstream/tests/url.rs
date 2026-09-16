use super::super::parse_upstream_url;

#[test]
fn parse_upstream_url_preserves_explicit_url() {
    assert_eq!(
        parse_upstream_url("wss://upstream.example:8546")
            .unwrap()
            .to_string(),
        "wss://upstream.example:8546/"
    );
}

#[test]
fn parse_upstream_url_prefixes_localhost_and_socketaddr() {
    assert_eq!(
        parse_upstream_url("localhost:8546").unwrap().to_string(),
        "ws://localhost:8546/"
    );
    assert_eq!(
        parse_upstream_url("127.0.0.1:8546").unwrap().to_string(),
        "ws://127.0.0.1:8546/"
    );
}

#[test]
fn parse_upstream_url_rejects_non_ws_schemes() {
    assert!(parse_upstream_url("http://upstream.example:8546").is_err());
}

#[test]
fn parse_upstream_url_rejects_non_url_values() {
    assert!(parse_upstream_url("not a url").is_err());
    assert!(parse_upstream_url("localhost").is_err());
}
