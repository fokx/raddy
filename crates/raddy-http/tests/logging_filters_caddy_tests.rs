use std::collections::HashMap;
use regex::Regex;
use raddy_http::logging::{
    apply_filter, mask_ip_string, sha256_short_hex, FilterAction,
};
use serde_json::json;

#[test]
fn test_ip_mask_single_value() {
    assert_eq!(
        mask_ip_string("255.255.255.255", 16, 32),
        "255.255.0.0"
    );
    assert_eq!(
        mask_ip_string("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 16, 32),
        "ffff:ffff::"
    );
    assert_eq!(mask_ip_string("not-an-ip", 16, 32), "not-an-ip");
}

#[test]
fn test_ip_mask_comma_value() {
    assert_eq!(
        mask_ip_string("255.255.255.255, 244.244.244.244", 16, 32),
        "255.255.0.0, 244.244.0.0"
    );
    assert_eq!(
        mask_ip_string(
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff, ff00:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            16,
            32
        ),
        "ffff:ffff::, ff00:ffff::"
    );
    assert_eq!(
        mask_ip_string("not-an-ip, 255.255.255.255", 16, 32),
        "not-an-ip, 255.255.0.0"
    );
}

#[test]
fn test_ip_mask_multi_value() {
    let mut val = json!({
        "client_ip": ["255.255.255.255", "244.244.244.244"]
    });
    apply_filter(
        &mut val,
        &["client_ip".into()],
        &FilterAction::IpMask { ipv4: 16, ipv6: 32 },
    );
    assert_eq!(val["client_ip"][0], "255.255.0.0");
    assert_eq!(val["client_ip"][1], "244.244.0.0");

    let mut val = json!({
        "client_ip": ["ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ff00:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
    });
    apply_filter(
        &mut val,
        &["client_ip".into()],
        &FilterAction::IpMask { ipv4: 16, ipv6: 32 },
    );
    assert_eq!(val["client_ip"][0], "ffff:ffff::");
    assert_eq!(val["client_ip"][1], "ff00:ffff::");
}

#[test]
fn test_query_filter_single_value() {
    let mut replace = HashMap::new();
    replace.insert("foo".into(), "REDACTED".into());
    replace.insert("notexist".into(), "REDACTED".into());

    let action = FilterAction::Query {
        delete: vec!["bar".into(), "notexist".into()],
        replace,
        hash: vec!["hash".into()],
    };

    let mut val = json!({
        "uri": "/path?foo=a&foo=b&bar=c&bar=d&baz=e&hash=hashed"
    });
    apply_filter(&mut val, &["uri".into()], &action);

    assert_eq!(
        val["uri"],
        "/path?baz=e&foo=REDACTED&foo=REDACTED&hash=1a06df82"
    );
}

#[test]
fn test_query_filter_multi_value() {
    let mut replace = HashMap::new();
    replace.insert("foo".into(), "REDACTED".into());
    replace.insert("notexist".into(), "REDACTED".into());

    let action = FilterAction::Query {
        delete: vec!["bar".into(), "notexist".into()],
        replace,
        hash: vec!["hash".into()],
    };

    let mut val = json!({
        "uris": [
            "/path1?foo=a&foo=b&bar=c&bar=d&baz=e&hash=alpha",
            "/path2?foo=c&foo=d&bar=e&bar=f&baz=g&hash=beta"
        ]
    });
    apply_filter(&mut val, &["uris".into()], &action);

    assert_eq!(
        val["uris"][0],
        "/path1?baz=e&foo=REDACTED&foo=REDACTED&hash=8ed3f6ad"
    );
    assert_eq!(
        val["uris"][1],
        "/path2?baz=g&foo=REDACTED&foo=REDACTED&hash=f44e64e7"
    );
}

#[test]
fn test_cookie_filter() {
    let mut replace = HashMap::new();
    replace.insert("foo".into(), "REDACTED".into());

    let action = FilterAction::Cookie {
        delete: vec!["bar".into()],
        replace,
        hash: vec!["hash".into()],
    };

    let mut val = json!({
        "cookie": "foo=a; foo=b; bar=c; bar=d; baz=e; hash=hashed"
    });
    apply_filter(&mut val, &["cookie".into()], &action);

    assert_eq!(
        val["cookie"],
        "foo=REDACTED; foo=REDACTED; baz=e; hash=1a06df82"
    );
}

#[test]
fn test_set_cookie_filter() {
    let mut replace = HashMap::new();
    replace.insert("foo".into(), "REDACTED".into());

    let action = FilterAction::SetCookie {
        delete: vec!["bar".into()],
        replace,
        hash: vec!["hash".into()],
    };

    let mut val = json!({
        "set_cookie": [
            "foo=\"a\"; Path=/; Priority=High",
            "bar=c; Path=/; Secure",
            "hash=hashed; Path=/; HttpOnly",
            "baz=e; Path=/; SameSite=Strict"
        ]
    });
    apply_filter(&mut val, &["set_cookie".into()], &action);

    assert_eq!(val["set_cookie"].as_array().unwrap().len(), 3);
    assert_eq!(val["set_cookie"][0], "foo=\"REDACTED\"; Path=/; Priority=High");
    assert_eq!(val["set_cookie"][1], "hash=1a06df82; Path=/; HttpOnly");
    assert_eq!(val["set_cookie"][2], "baz=e; Path=/; SameSite=Strict");
}

#[test]
fn test_set_cookie_filter_invalid_header_passes_through() {
    let action = FilterAction::SetCookie {
        delete: vec![],
        replace: HashMap::new(),
        hash: vec!["session".into()],
    };

    let mut val = json!({
        "set_cookie": ["not-a-cookie"]
    });
    apply_filter(&mut val, &["set_cookie".into()], &action);

    assert_eq!(val["set_cookie"][0], "not-a-cookie");
}

#[test]
fn test_set_cookie_filter_hash_without_attributes() {
    let action = FilterAction::SetCookie {
        delete: vec![],
        replace: HashMap::new(),
        hash: vec!["session".into()],
    };

    let mut val = json!({
        "set_cookie": ["session=secret"]
    });
    apply_filter(&mut val, &["set_cookie".into()], &action);

    assert_eq!(val["set_cookie"][0], "session=2bb80d53");
}

#[test]
fn test_set_cookie_filter_cookie_name_matching_is_case_sensitive() {
    let action = FilterAction::SetCookie {
        delete: vec![],
        replace: HashMap::new(),
        hash: vec!["session".into()],
    };

    let mut val = json!({
        "set_cookie": ["Session=secret; Path=/"]
    });
    apply_filter(&mut val, &["set_cookie".into()], &action);

    assert_eq!(val["set_cookie"][0], "Session=secret; Path=/");
}

#[test]
fn test_set_cookie_filter_first_match_wins() {
    let action = FilterAction::SetCookie {
        delete: vec!["session".into()],
        replace: HashMap::new(),
        hash: vec!["session".into()],
    };

    let mut val = json!({
        "set_cookie": ["session=secret; Path=/"]
    });
    apply_filter(&mut val, &["set_cookie".into()], &action);

    assert_eq!(val["set_cookie"].as_array().unwrap().len(), 0);
}

#[test]
fn test_set_cookie_filter_hash_empty_value() {
    let action = FilterAction::SetCookie {
        delete: vec![],
        replace: HashMap::new(),
        hash: vec!["session".into()],
    };

    let mut val = json!({
        "set_cookie": ["session=; Max-Age=0; Path=/; HttpOnly"]
    });
    apply_filter(&mut val, &["set_cookie".into()], &action);

    assert_eq!(
        val["set_cookie"][0],
        "session=e3b0c442; Max-Age=0; Path=/; HttpOnly"
    );
}

#[test]
fn test_regexp_filter_single_value() {
    let re = Regex::new("secret").unwrap();
    let action = FilterAction::Regexp(re, "REDACTED".into());

    let mut val = json!({
        "field": "foo-secret-bar"
    });
    apply_filter(&mut val, &["field".into()], &action);

    assert_eq!(val["field"], "foo-REDACTED-bar");
}

#[test]
fn test_regexp_filter_multi_value() {
    let re = Regex::new("secret").unwrap();
    let action = FilterAction::Regexp(re, "REDACTED".into());

    let mut val = json!({
        "field": ["foo-secret-bar", "bar-secret-foo"]
    });
    apply_filter(&mut val, &["field".into()], &action);

    assert_eq!(val["field"][0], "foo-REDACTED-bar");
    assert_eq!(val["field"][1], "bar-REDACTED-foo");
}

#[test]
fn test_hash_filter_single_value() {
    let mut val = json!({
        "field": "foo"
    });
    apply_filter(&mut val, &["field".into()], &FilterAction::Hash);

    assert_eq!(val["field"], "2c26b46b");
    assert_eq!(sha256_short_hex("foo"), "2c26b46b");
}

#[test]
fn test_hash_filter_multi_value() {
    let mut val = json!({
        "field": ["foo", "bar"]
    });
    apply_filter(&mut val, &["field".into()], &FilterAction::Hash);

    assert_eq!(val["field"][0], "2c26b46b");
    assert_eq!(val["field"][1], "fcde2b2e");
}
