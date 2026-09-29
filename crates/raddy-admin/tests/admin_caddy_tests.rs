use raddy_admin::{check_host, origin_allowed, unsynced_config_access};
use serde_json::json;

#[test]
fn test_admin_handler_check_host_case_insensitive() {
    let cases = vec![
        (
            "allow-list uppercase, request Host lowercase",
            "http://Example.com:2019",
            "example.com:2019",
            false,
        ),
        (
            "allow-list lowercase, request Host uppercase",
            "http://example.com:2019",
            "EXAMPLE.com:2019",
            false,
        ),
        (
            "default localhost entry, request Host uppercase",
            "http://localhost:2019",
            "LOCALHOST:2019",
            false,
        ),
        (
            "different host is still rejected",
            "http://example.com:2019",
            "evil.example.org:2019",
            true,
        ),
    ];

    for (name, allowed, host, want_err) in cases {
        let res = check_host(host, &[allowed]);
        if want_err {
            assert!(res.is_err(), "{}: expected error for host {}", name, host);
        } else {
            assert!(res.is_ok(), "{}: expected ok for host {}, got {:?}", name, host, res.err());
        }
    }
}

#[test]
fn test_admin_handler_origin_allowed_case_insensitive_host() {
    let cases = vec![
        (
            "allow-list uppercase, origin lowercase",
            "http://Example.com:8080",
            "http://example.com:8080",
            true,
        ),
        (
            "allow-list lowercase, origin uppercase",
            "http://example.com:8080",
            "http://EXAMPLE.com:8080",
            true,
        ),
        (
            "different origin is rejected",
            "http://example.com:8080",
            "http://evil.com:8080",
            false,
        ),
    ];

    for (name, allowed, origin, want_ok) in cases {
        let ok = origin_allowed(origin, &[allowed]);
        assert_eq!(ok, want_ok, "{}: origin {} allowed should be {}", name, origin, want_ok);
    }
}

#[test]
fn test_unsynced_config_access() {
    let mut config = json!({});

    let cases = vec![
        (
            "POST",
            "/",
            r#"{"foo": "bar", "list": ["a", "b", "c"]}"#,
            json!({"foo": "bar", "list": ["a", "b", "c"]}),
            false,
        ),
        (
            "POST",
            "/foo",
            r#""jet""#,
            json!({"foo": "jet", "list": ["a", "b", "c"]}),
            false,
        ),
        (
            "POST",
            "/bar",
            r#"{"aa": "bb", "qq": "zz"}"#,
            json!({"foo": "jet", "bar": {"aa": "bb", "qq": "zz"}, "list": ["a", "b", "c"]}),
            false,
        ),
        (
            "DELETE",
            "/bar/qq",
            "",
            json!({"foo": "jet", "bar": {"aa": "bb"}, "list": ["a", "b", "c"]}),
            false,
        ),
        (
            "DELETE",
            "/bar/qq",
            "",
            json!({"foo": "jet", "bar": {"aa": "bb"}, "list": ["a", "b", "c"]}),
            true, // should err because already deleted
        ),
        (
            "POST",
            "/list",
            r#""e""#,
            json!({"foo": "jet", "bar": {"aa": "bb"}, "list": ["a", "b", "c", "e"]}),
            false,
        ),
        (
            "PUT",
            "/list/3",
            r#""d""#,
            json!({"foo": "jet", "bar": {"aa": "bb"}, "list": ["a", "b", "c", "d", "e"]}),
            false,
        ),
        (
            "DELETE",
            "/list/3",
            "",
            json!({"foo": "jet", "bar": {"aa": "bb"}, "list": ["a", "b", "c", "e"]}),
            false,
        ),
        (
            "PATCH",
            "/list/3",
            r#""d""#,
            json!({"foo": "jet", "bar": {"aa": "bb"}, "list": ["a", "b", "c", "d"]}),
            false,
        ),
        (
            "POST",
            "/list/...",
            r#"["e", "f", "g"]"#,
            json!({"foo": "jet", "bar": {"aa": "bb"}, "list": ["a", "b", "c", "d", "e", "f", "g"]}),
            false,
        ),
    ];

    for (i, (method, path, payload, expect, should_err)) in cases.into_iter().enumerate() {
        let res = unsynced_config_access(&mut config, method, path, payload.as_bytes());
        if should_err {
            assert!(res.is_err(), "Test {}: Expected error for {} {}", i, method, path);
        } else {
            assert!(res.is_ok(), "Test {}: Unexpected error for {} {}: {:?}", i, method, path, res.err());
            assert_eq!(config, expect, "Test {}: config mismatch after {} {}", i, method, path);
        }
    }
}
