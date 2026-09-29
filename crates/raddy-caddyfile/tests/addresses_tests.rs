use raddy_caddyfile::{parse_address, Address};

#[test]
fn test_parse_address() {
    let cases = vec![
        ("", "", "", "", "", false),
        ("localhost", "", "localhost", "", "", false),
        ("localhost:1234", "", "localhost", "1234", "", false),
        ("localhost:", "", "localhost", "", "", false),
        ("0.0.0.0", "", "0.0.0.0", "", "", false),
        ("127.0.0.1:1234", "", "127.0.0.1", "1234", "", false),
        (":1234", "", "", "1234", "", false),
        ("[::1]", "", "::1", "", "", false),
        ("[::1]:1234", "", "::1", "1234", "", false),
        (":", "", "", "", "", false),
        (":http", "", "", "", "", true),
        (":https", "", "", "", "", true),
        ("localhost:http", "", "", "", "", true),
        ("localhost:https", "", "", "", "", true),
        ("http://localhost:https", "", "", "", "", true),
        ("http://localhost:http", "", "", "", "", true),
        ("host:https/path", "", "", "", "", true),
        ("http://localhost:443", "http", "localhost", "443", "", false),
        ("https://localhost:80", "https", "localhost", "80", "", false),
        ("http://localhost", "http", "localhost", "", "", false),
        ("https://localhost", "https", "localhost", "", "", false),
        ("http://{env.APP_DOMAIN}", "http", "{env.APP_DOMAIN}", "", "", false),
        ("{env.APP_DOMAIN}:80", "", "{env.APP_DOMAIN}", "80", "", false),
        ("{env.APP_DOMAIN}/path", "", "{env.APP_DOMAIN}", "", "/path", false),
        ("example.com/{env.APP_PATH}", "", "example.com", "", "/{env.APP_PATH}", false),
        ("http://127.0.0.1", "http", "127.0.0.1", "", "", false),
        ("https://127.0.0.1", "https", "127.0.0.1", "", "", false),
        ("http://[::1]", "http", "::1", "", "", false),
        ("http://localhost:1234", "http", "localhost", "1234", "", false),
        ("https://127.0.0.1:1234", "https", "127.0.0.1", "1234", "", false),
        ("http://[::1]:1234", "http", "::1", "1234", "", false),
        ("::1", "", "::1", "", "", false),
        ("localhost::", "", "localhost::", "", "", false),
        ("#$%@", "", "#$%@", "", "", false),
        ("host/path", "", "host", "", "/path", false),
        ("http://host/", "http", "host", "", "/", false),
        ("//asdf", "", "", "", "//asdf", false),
        (":1234/asdf", "", "", "1234", "/asdf", false),
        ("http://host/path", "http", "host", "", "/path", false),
        ("https://host:443/path/foo", "https", "host", "443", "/path/foo", false),
        ("host:80/path", "", "host", "80", "/path", false),
        ("/path", "", "", "", "/path", false),
    ];

    for (i, (input, scheme, host, port, path, should_err)) in cases.into_iter().enumerate() {
        let res = parse_address(input);
        if should_err {
            assert!(res.is_err(), "Test {} ({}): Expected error, got ok", i, input);
        } else {
            assert!(res.is_ok(), "Test {} ({}): Expected ok, got error: {:?}", i, input, res.err());
            let actual = res.unwrap();
            assert_eq!(actual.original, input, "Test {} ({}): original mismatch", i, input);
            assert_eq!(actual.scheme, scheme, "Test {} ({}): scheme mismatch", i, input);
            assert_eq!(actual.host, host, "Test {} ({}): host mismatch", i, input);
            assert_eq!(actual.port, port, "Test {} ({}): port mismatch", i, input);
            assert_eq!(actual.path, path, "Test {} ({}): path mismatch", i, input);
        }
    }
}

#[test]
fn test_address_string() {
    let cases = vec![
        (
            Address {
                original: String::new(),
                scheme: "http".into(),
                host: "host".into(),
                port: "1234".into(),
                path: "/path".into(),
            },
            "http://host:1234/path",
        ),
        (
            Address {
                original: String::new(),
                scheme: "".into(),
                host: "host".into(),
                port: "".into(),
                path: "".into(),
            },
            "http://host",
        ),
        (
            Address {
                original: String::new(),
                scheme: "".into(),
                host: "host".into(),
                port: "80".into(),
                path: "".into(),
            },
            "http://host",
        ),
        (
            Address {
                original: String::new(),
                scheme: "".into(),
                host: "host".into(),
                port: "443".into(),
                path: "".into(),
            },
            "https://host",
        ),
        (
            Address {
                original: String::new(),
                scheme: "https".into(),
                host: "host".into(),
                port: "443".into(),
                path: "".into(),
            },
            "https://host",
        ),
        (
            Address {
                original: String::new(),
                scheme: "https".into(),
                host: "host".into(),
                port: "".into(),
                path: "".into(),
            },
            "https://host",
        ),
        (
            Address {
                original: String::new(),
                scheme: "".into(),
                host: "host".into(),
                port: "80".into(),
                path: "/path".into(),
            },
            "http://host/path",
        ),
        (
            Address {
                original: String::new(),
                scheme: "http".into(),
                host: "".into(),
                port: "1234".into(),
                path: "".into(),
            },
            "http://:1234",
        ),
        (
            Address {
                original: String::new(),
                scheme: "".into(),
                host: "".into(),
                port: "".into(),
                path: "".into(),
            },
            "",
        ),
    ];

    for (i, (addr, expected)) in cases.into_iter().enumerate() {
        let actual = addr.to_string_repr();
        assert_eq!(actual, expected, "Test {}: expected '{}', got '{}'", i, expected, actual);
    }
}

#[test]
fn test_key_normalization() {
    let cases = vec![
        ("example.com", Address { host: "example.com".into(), ..Default::default() }),
        (
            "http://host:1234/path",
            Address {
                scheme: "http".into(),
                host: "host".into(),
                port: "1234".into(),
                path: "/path".into(),
                ..Default::default()
            },
        ),
        (
            "HTTP://A/ABCDEF",
            Address {
                scheme: "http".into(),
                host: "a".into(),
                path: "/ABCDEF".into(),
                ..Default::default()
            },
        ),
        (
            "A/ABCDEF",
            Address {
                host: "a".into(),
                path: "/ABCDEF".into(),
                ..Default::default()
            },
        ),
        (
            "A:2015/Path",
            Address {
                host: "a".into(),
                port: "2015".into(),
                path: "/Path".into(),
                ..Default::default()
            },
        ),
        (
            "sub.{env.MY_DOMAIN}",
            Address {
                host: "sub.{env.MY_DOMAIN}".into(),
                ..Default::default()
            },
        ),
        (
            "sub.ExAmPle",
            Address {
                host: "sub.example".into(),
                ..Default::default()
            },
        ),
        (
            "sub.\\{env.MY_DOMAIN\\}",
            Address {
                host: "sub.\\{env.my_domain\\}".into(),
                ..Default::default()
            },
        ),
        (
            "sub.{env.MY_DOMAIN}.com",
            Address {
                host: "sub.{env.MY_DOMAIN}.com".into(),
                ..Default::default()
            },
        ),
        (
            ":80",
            Address {
                port: "80".into(),
                ..Default::default()
            },
        ),
        (
            ":443",
            Address {
                port: "443".into(),
                ..Default::default()
            },
        ),
        (
            ":1234",
            Address {
                port: "1234".into(),
                ..Default::default()
            },
        ),
        ("", Address::default()),
        (":", Address::default()),
        ("[::]", Address { host: "::".into(), ..Default::default() }),
        ("127.0.0.1", Address { host: "127.0.0.1".into(), ..Default::default() }),
        (
            "[2001:db8:85a3:8d3:1319:8a2e:370:7348]:1234",
            Address {
                host: "2001:db8:85a3:8d3:1319:8a2e:370:7348".into(),
                port: "1234".into(),
                ..Default::default()
            },
        ),
        (
            "[::ffff:cff4:e77d]:1234",
            Address {
                host: "::ffff:cff4:e77d".into(),
                port: "1234".into(),
                ..Default::default()
            },
        ),
        (
            "::ffff:cff4:e77d",
            Address {
                host: "::ffff:cff4:e77d".into(),
                ..Default::default()
            },
        ),
    ];

    for (i, (input, expected)) in cases.into_iter().enumerate() {
        let addr = parse_address(input).unwrap_or_else(|e| panic!("Test {}: Failed to parse '{}': {:?}", i, input, e));
        let actual = addr.normalize();
        assert_eq!(actual.scheme, expected.scheme, "Test {} ({}): scheme mismatch", i, input);
        assert_eq!(actual.host, expected.host, "Test {} ({}): host mismatch", i, input);
        assert_eq!(actual.port, expected.port, "Test {} ({}): port mismatch", i, input);
        assert_eq!(actual.path, expected.path, "Test {} ({}): path mismatch", i, input);
    }
}
