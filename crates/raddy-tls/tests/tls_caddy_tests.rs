use raddy_tls::{RemoteIpMatcher, ServerNameMatcher, ServerNameREMatcher};

#[test]
fn test_server_name_matcher() {
    let cases = vec![
        (vec!["example.com"], "example.com", true),
        (vec!["example.com"], "foo.com", false),
        (vec!["example.com"], "", false),
        (vec![], "", false),
        (vec!["foo", "example.com"], "example.com", true),
        (vec!["foo", "example.com"], "sub.example.com", false),
        (vec!["foo", "example.com"], "foo.com", false),
        (vec!["*.example.com"], "example.com", false),
        (vec!["*.example.com"], "sub.example.com", true),
        (
            vec!["*.example.com", "*.sub.example.com"],
            "sub2.sub.example.com",
            true,
        ),
    ];

    for (i, (names, input, expect)) in cases.into_iter().enumerate() {
        let names_str: Vec<String> = names.into_iter().map(String::from).collect();
        let matcher = ServerNameMatcher::new(names_str);
        let actual = matcher.matches(input);
        assert_eq!(
            actual, expect,
            "Test {} failed: input '{}' with names {:?}, expected {}",
            i, input, matcher.names, expect
        );
    }
}

#[test]
fn test_server_name_re_matcher() {
    let cases = vec![
        (r"^example\.(com|net)$", "example.com", true),
        (r"^example\.(com|net)$", "foo.com", false),
        (r"^example\.(com|net)$", "", false),
        ("", "", true),
        (r"^example\.(com|net)$", "foo.example.com", false),
    ];

    for (i, (pattern, input, expect)) in cases.into_iter().enumerate() {
        let matcher = ServerNameREMatcher::new(pattern).unwrap();
        let actual = matcher.matches(input);
        assert_eq!(
            actual, expect,
            "Test {} failed: input '{}' with pattern '{}', expected {}",
            i, input, pattern, expect
        );
    }
}

#[test]
fn test_remote_ip_matcher() {
    let cases = vec![
        (vec!["127.0.0.1"], vec![], "127.0.0.1:12345", true),
        (vec!["127.0.0.1"], vec![], "127.0.0.2:12345", false),
        (vec!["127.0.0.1/16"], vec![], "127.0.1.23:12345", true),
        (
            vec!["127.0.0.1", "192.168.1.105"],
            vec![],
            "192.168.1.105:12345",
            true,
        ),
        (vec![], vec!["127.0.0.1"], "127.0.0.1:12345", false),
        (vec![], vec!["127.0.0.2"], "127.0.0.1:12345", true),
        (
            vec!["127.0.0.1"],
            vec!["127.0.0.2"],
            "127.0.0.1:12345",
            true,
        ),
        (
            vec!["127.0.0.2"],
            vec!["127.0.0.2"],
            "127.0.0.2:12345",
            false,
        ),
        (
            vec!["127.0.0.2"],
            vec!["127.0.0.2"],
            "127.0.0.3:12345",
            false,
        ),
    ];

    for (i, (ranges, not_ranges, input, expect)) in cases.into_iter().enumerate() {
        let r_str: Vec<String> = ranges.into_iter().map(String::from).collect();
        let nr_str: Vec<String> = not_ranges.into_iter().map(String::from).collect();
        let matcher = RemoteIpMatcher::new(&r_str, &nr_str);
        let actual = matcher.matches(input);
        assert_eq!(
            actual, expect,
            "Test {} failed: input '{}' with ranges {:?} notRanges {:?}, expected {}",
            i, input, matcher.ranges, matcher.not_ranges, expect
        );
    }
}
