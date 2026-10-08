use raddy_core::{
    NetworkAddress, join_network_address, parse_network_address,
    parse_network_address_with_defaults, split_network_address,
};

#[test]
fn test_split_network_address() {
    let cases = vec![
        ("", "", "", "", false),
        ("foo", "", "foo", "", false),
        (":", "", "", "", false),
        ("::", "", "::", "", false),
        ("[::]", "", "::", "", false),
        (":1234", "", "", "1234", false),
        ("foo:1234", "", "foo", "1234", false),
        ("foo:1234-5678", "", "foo", "1234-5678", false),
        ("udp/foo:1234", "udp", "foo", "1234", false),
        ("tcp6/foo:1234-5678", "tcp6", "foo", "1234-5678", false),
        ("udp/", "udp", "", "", false),
        ("unix//foo/bar", "unix", "/foo/bar", "", false),
        ("unixgram//foo/bar", "unixgram", "/foo/bar", "", false),
        ("unixpacket//foo/bar", "unixpacket", "/foo/bar", "", false),
    ];

    for (i, (input, exp_net, exp_host, exp_port, should_err)) in cases.into_iter().enumerate() {
        let res = split_network_address(input);
        if should_err {
            assert!(res.is_err(), "Test {}: Expected error for '{}'", i, input);
        } else {
            assert!(
                res.is_ok(),
                "Test {}: Unexpected error for '{}': {:?}",
                i,
                input,
                res.err()
            );
            let (act_net, act_host, act_port) = res.unwrap();
            assert_eq!(
                act_net, exp_net,
                "Test {}: network mismatch for '{}'",
                i, input
            );
            assert_eq!(
                act_host, exp_host,
                "Test {}: host mismatch for '{}'",
                i, input
            );
            assert_eq!(
                act_port, exp_port,
                "Test {}: port mismatch for '{}'",
                i, input
            );
        }
    }
}

#[test]
fn test_join_network_address() {
    let cases = vec![
        ("", "", "", ""),
        ("tcp", "", "", "tcp/"),
        ("", "foo", "", "foo"),
        ("", "", "1234", ":1234"),
        ("", "", "1234-5678", ":1234-5678"),
        ("", "foo", "1234", "foo:1234"),
        ("udp", "foo", "1234", "udp/foo:1234"),
        ("udp", "", "1234", "udp/:1234"),
        ("unix", "/foo/bar", "", "unix//foo/bar"),
        ("unix", "/foo/bar", "0", "unix//foo/bar"),
        ("unix", "/foo/bar", "1234", "unix//foo/bar"),
        ("", "::1", "1234", "[::1]:1234"),
    ];

    for (i, (netw, host, port, expect)) in cases.into_iter().enumerate() {
        let actual = join_network_address(netw, host, port);
        assert_eq!(
            actual, expect,
            "Test {}: expected '{}', got '{}'",
            i, expect, actual
        );
    }
}

#[test]
fn test_parse_network_address() {
    let cases = vec![
        ("", "tcp", 0, NetworkAddress::default(), false),
        (
            ":",
            "udp",
            0,
            NetworkAddress {
                network: "udp".into(),
                ..Default::default()
            },
            false,
        ),
        (
            "[::]",
            "udp",
            53,
            NetworkAddress {
                network: "udp".into(),
                host: "::".into(),
                start_port: 53,
                end_port: 53,
            },
            false,
        ),
        (
            ":1234",
            "udp",
            0,
            NetworkAddress {
                network: "udp".into(),
                host: "".into(),
                start_port: 1234,
                end_port: 1234,
            },
            false,
        ),
        (
            "udp/:1234",
            "udp",
            0,
            NetworkAddress {
                network: "udp".into(),
                host: "".into(),
                start_port: 1234,
                end_port: 1234,
            },
            false,
        ),
        (
            "tcp6/:1234",
            "tcp",
            0,
            NetworkAddress {
                network: "tcp6".into(),
                host: "".into(),
                start_port: 1234,
                end_port: 1234,
            },
            false,
        ),
        (
            "tcp4/localhost:1234",
            "tcp",
            0,
            NetworkAddress {
                network: "tcp4".into(),
                host: "localhost".into(),
                start_port: 1234,
                end_port: 1234,
            },
            false,
        ),
        (
            "unix//foo/bar",
            "tcp",
            0,
            NetworkAddress {
                network: "unix".into(),
                host: "/foo/bar".into(),
                start_port: 0,
                end_port: 0,
            },
            false,
        ),
        (
            "localhost:1234-1234",
            "tcp",
            0,
            NetworkAddress {
                network: "tcp".into(),
                host: "localhost".into(),
                start_port: 1234,
                end_port: 1234,
            },
            false,
        ),
        ("localhost:2-1", "tcp", 0, NetworkAddress::default(), true),
        (
            "localhost:0",
            "tcp",
            0,
            NetworkAddress {
                network: "tcp".into(),
                host: "localhost".into(),
                start_port: 0,
                end_port: 0,
            },
            false,
        ),
        (
            "localhost:1-999999999999",
            "tcp",
            0,
            NetworkAddress::default(),
            true,
        ),
    ];

    for (i, (input, def_net, def_port, exp_addr, should_err)) in cases.into_iter().enumerate() {
        let res = parse_network_address_with_defaults(input, def_net, def_port);
        if should_err {
            assert!(res.is_err(), "Test {}: Expected error for '{}'", i, input);
        } else {
            assert!(
                res.is_ok(),
                "Test {}: Unexpected error for '{}': {:?}",
                i,
                input,
                res.err()
            );
            let actual = res.unwrap();
            assert_eq!(
                actual, exp_addr,
                "Test {}: addr mismatch for '{}'",
                i, input
            );
        }
    }
}

#[test]
fn test_port_span_boundary() {
    // 0-65535 spans 65536 ports and is rejected
    let res = parse_network_address("tcp/:0-65535");
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert!(err.contains("port range exceeds"));

    // 1-65535 spans 65535 ports and is accepted
    let res2 = parse_network_address("tcp/:1-65535");
    assert!(res2.is_ok(), "1-65535 should be accepted: {:?}", res2.err());
    let addr = res2.unwrap();
    assert_eq!(addr.start_port, 1);
    assert_eq!(addr.end_port, 65535);
}
