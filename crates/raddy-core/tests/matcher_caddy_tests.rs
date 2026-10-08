use http::{HeaderMap, Method, Uri};
use raddy_core::{
    Context, HeaderMatcher, HeaderRegexpMatcher, HostMatcher, Matcher, MethodMatcher, PathMatcher,
    PathRegexpMatcher, QueryMatcher, RemoteIpMatcher,
};
use std::collections::HashMap;
use std::net::SocketAddr;

fn make_ctx(
    host: &str,
    method: &str,
    uri: &str,
    headers: HeaderMap,
    remote_addr: Option<SocketAddr>,
) -> Context {
    let mut ctx = Context::new(
        method.parse::<Method>().unwrap(),
        uri.parse::<Uri>().unwrap(),
        headers,
        bytes::Bytes::new(),
    );
    ctx.remote_addr = remote_addr;
    if !host.is_empty() {
        ctx.headers.insert("host", host.parse().unwrap());
    }
    ctx
}

#[test]
fn test_host_matcher() {
    unsafe {
        std::env::set_var("GO_BENCHMARK_DOMAIN", "localhost");
    }

    let cases = vec![
        (vec![], "example.com", false),
        (vec!["example.com"], "example.com", true),
        (vec!["EXAMPLE.COM"], "example.com", true),
        (vec!["example.com"], "EXAMPLE.COM", true),
        (vec!["example.com"], "foo.example.com", false),
        (vec!["foo.example.com"], "foo.example.com", true),
        (vec!["foo.example.com"], "bar.example.com", false),
        (vec!["*.example.com"], "example.com", false),
        (vec!["*.example.com"], "SUB.EXAMPLE.COM", true),
        (vec!["*.example.com"], "foo.example.com", true),
        (vec!["*.example.com"], "foo.bar.example.com", false),
        (vec!["*.example.com", "example.net"], "example.net", true),
        (
            vec!["example.net", "*.example.com"],
            "foo.example.com",
            true,
        ),
        (
            vec!["*.example.net", "*.*.example.com"],
            "foo.bar.example.com",
            true,
        ),
        (
            vec!["*.example.net", "sub.*.example.com"],
            "sub.foo.example.com",
            true,
        ),
        (
            vec!["*.example.net", "sub.*.example.com"],
            "sub.foo.example.net",
            false,
        ),
        (vec!["www.*.*"], "www.example.com", true),
        (vec!["example.com"], "example.com:5555", true),
        (vec!["{env.GO_BENCHMARK_DOMAIN}"], "localhost", true),
        (vec!["{env.GO_NONEXISTENT}"], "localhost", false),
    ];

    for (i, (patterns, input_host, expect)) in cases.into_iter().enumerate() {
        let patterns_str: Vec<String> = patterns.into_iter().map(String::from).collect();
        let matcher = HostMatcher::new(patterns_str);
        let ctx = make_ctx(input_host, "GET", "/", HeaderMap::new(), None);
        let actual = matcher.matches(&ctx);
        assert_eq!(
            actual, expect,
            "Test {} failed: host '{}' with matcher {:?}, expected {}",
            i, input_host, matcher.hosts, expect
        );
    }
}

#[test]
fn test_path_matcher() {
    let cases = vec![
        (vec![], "/", false),
        (vec!["/"], "/", true),
        (vec!["/foo/bar"], "/", false),
        (vec!["/foo/bar"], "/foo/bar", true),
        (vec!["/foo/bar/"], "/foo/bar", false),
        (vec!["/foo/bar/"], "/foo/bar/", true),
        (vec!["/foo/bar/", "/other"], "/other/", false),
        (vec!["/foo/bar/", "/other"], "/other", true),
        (vec!["*.ext"], "/foo/bar.ext", true),
        (vec!["*.php"], "/index.PHP", true),
        (vec!["/foo/*/baz"], "/foo/bar/baz", true),
        (vec!["/foo/*/baz"], "/foo/bar/bam", false),
        (vec!["*substring*"], "/foo/substring/bar.txt", true),
        (vec!["/foo*"], "/foo/bar", true),
        (vec!["*"], "/any/path/goes", true),
    ];

    for (i, (patterns, input_path, expect)) in cases.into_iter().enumerate() {
        let patterns_str: Vec<String> = patterns.into_iter().map(String::from).collect();
        let matcher = PathMatcher::new(patterns_str);
        let ctx = make_ctx("localhost", "GET", input_path, HeaderMap::new(), None);
        let actual = matcher.matches(&ctx);
        assert_eq!(
            actual, expect,
            "Test {} failed: path '{}' with matcher {:?}, expected {}",
            i, input_path, matcher.patterns, expect
        );
    }
}

#[test]
fn test_method_matcher() {
    let cases = vec![
        (vec!["GET"], "GET", true),
        (vec!["GET"], "get", true),
        (vec!["GET"], "POST", false),
        (vec!["GET", "POST"], "POST", true),
        (vec!["PUT", "DELETE"], "GET", false),
    ];

    for (i, (methods, input_method, expect)) in cases.into_iter().enumerate() {
        let methods_str: Vec<String> = methods.into_iter().map(String::from).collect();
        let matcher = MethodMatcher::new(methods_str);
        let ctx = make_ctx("localhost", input_method, "/", HeaderMap::new(), None);
        let actual = matcher.matches(&ctx);
        assert_eq!(
            actual, expect,
            "Test {} failed: method '{}' with matcher {:?}, expected {}",
            i, input_method, matcher.methods, expect
        );
    }
}

#[test]
fn test_header_matcher() {
    let mut headers = HeaderMap::new();
    headers.insert("x-custom-header", "custom-value".parse().unwrap());
    headers.insert("accept", "text/html,application/xhtml+xml".parse().unwrap());

    let ctx = make_ctx("localhost", "GET", "/", headers, None);

    let mut map1 = HashMap::new();
    map1.insert(
        "x-custom-header".to_string(),
        vec!["custom-value".to_string()],
    );
    assert!(HeaderMatcher::new(map1).matches(&ctx));

    let mut map2 = HashMap::new();
    map2.insert(
        "x-custom-header".to_string(),
        vec!["other-value".to_string()],
    );
    assert!(!HeaderMatcher::new(map2).matches(&ctx));

    // Wildcard match
    let mut map3 = HashMap::new();
    map3.insert("x-custom-header".to_string(), vec!["*".to_string()]);
    assert!(HeaderMatcher::new(map3).matches(&ctx));

    // Missing header
    let mut map4 = HashMap::new();
    map4.insert("authorization".to_string(), vec!["*".to_string()]);
    assert!(!HeaderMatcher::new(map4).matches(&ctx));
}

#[test]
fn test_header_regexp_matcher() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "user-agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".parse().unwrap(),
    );

    let ctx = make_ctx("localhost", "GET", "/", headers, None);

    let mut patterns = HashMap::new();
    patterns.insert("user-agent".to_string(), r"Mozilla/\d\.\d".to_string());
    let matcher = HeaderRegexpMatcher::new(patterns).unwrap();
    assert!(matcher.matches(&ctx));

    let mut patterns2 = HashMap::new();
    patterns2.insert("user-agent".to_string(), r"^curl/".to_string());
    let matcher2 = HeaderRegexpMatcher::new(patterns2).unwrap();
    assert!(!matcher2.matches(&ctx));
}

#[test]
fn test_path_regexp_matcher() {
    let matcher = PathRegexpMatcher::new(r"^/api/v\d+/(items|users)/?$").unwrap();

    let ctx1 = make_ctx("localhost", "GET", "/api/v1/items", HeaderMap::new(), None);
    assert!(matcher.matches(&ctx1));

    let ctx2 = make_ctx("localhost", "GET", "/api/v2/users/", HeaderMap::new(), None);
    assert!(matcher.matches(&ctx2));

    let ctx3 = make_ctx(
        "localhost",
        "GET",
        "/api/v1/unknown",
        HeaderMap::new(),
        None,
    );
    assert!(!matcher.matches(&ctx3));
}

#[test]
fn test_query_matcher() {
    let mut params = HashMap::new();
    params.insert(
        "format".to_string(),
        vec!["json".to_string(), "yaml".to_string()],
    );
    params.insert("version".to_string(), vec!["*".to_string()]);
    let matcher = QueryMatcher::new(params);

    let ctx1 = make_ctx(
        "localhost",
        "GET",
        "/data?format=json&version=2",
        HeaderMap::new(),
        None,
    );
    assert!(matcher.matches(&ctx1));

    let ctx2 = make_ctx(
        "localhost",
        "GET",
        "/data?format=xml&version=2",
        HeaderMap::new(),
        None,
    );
    assert!(!matcher.matches(&ctx2));

    let ctx3 = make_ctx(
        "localhost",
        "GET",
        "/data?format=yaml",
        HeaderMap::new(),
        None,
    );
    assert!(!matcher.matches(&ctx3));
}

#[test]
fn test_remote_ip_matcher() {
    let matcher = RemoteIpMatcher::parse(&[
        "127.0.0.1".to_string(),
        "192.168.1.0/24".to_string(),
        "10.0.0.5".to_string(),
        "::1".to_string(),
    ]);

    let ctx1 = make_ctx(
        "localhost",
        "GET",
        "/",
        HeaderMap::new(),
        Some("127.0.0.1:12345".parse().unwrap()),
    );
    assert!(matcher.matches(&ctx1));

    let ctx2 = make_ctx(
        "localhost",
        "GET",
        "/",
        HeaderMap::new(),
        Some("192.168.1.55:12345".parse().unwrap()),
    );
    assert!(matcher.matches(&ctx2));

    let ctx3 = make_ctx(
        "localhost",
        "GET",
        "/",
        HeaderMap::new(),
        Some("192.168.2.1:12345".parse().unwrap()),
    );
    assert!(!matcher.matches(&ctx3));

    let ctx4 = make_ctx(
        "localhost",
        "GET",
        "/",
        HeaderMap::new(),
        Some("[::1]:12345".parse().unwrap()),
    );
    assert!(matcher.matches(&ctx4));
}

#[test]
fn test_expression_matcher() {
    use raddy_core::ExpressionMatcher;

    let mut ctx = make_ctx("localhost", "GET", "/test", HeaderMap::new(), None);
    ctx.set_var("http.error.status_code", "404");
    ctx.set_var("err.status_code", "404");

    let m1 = ExpressionMatcher::new("{http.error.status_code} == 404".to_string());
    assert!(m1.matches(&ctx));

    let m2 = ExpressionMatcher::new("{http.error.status_code} == 500".to_string());
    assert!(!m2.matches(&ctx));

    let m3 = ExpressionMatcher::new("{http.error.status_code} in [404, 500]".to_string());
    assert!(m3.matches(&ctx));

    let m4 = ExpressionMatcher::new(
        "{http.error.status_code} >= 400 && {http.error.status_code} < 500".to_string(),
    );
    assert!(m4.matches(&ctx));

    let m5 = ExpressionMatcher::new("http.error.status_code == 404".to_string());
    assert!(m5.matches(&ctx));
}
