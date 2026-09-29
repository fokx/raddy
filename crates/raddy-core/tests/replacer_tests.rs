use raddy_core::Replacer;

#[test]
fn test_replacer_replace_all() {
    let rep = Replacer::new_empty();

    let cases = vec![
        ("{", "{", ""),
        (r#"\{"#, "{", ""),
        ("foo{", "foo{", ""),
        (r#"foo\{"#, "foo{", ""),
        ("foo{bar", "foo{bar", ""),
        (r#"foo\{bar"#, "foo{bar", ""),
        ("foo{bar}", "foo", ""),
        (r#"foo\{bar\}"#, "foo{bar}", ""),
        ("}", "}", ""),
        (r#"\}"#, "}", ""),
        ("{}", "", ""),
        (r#"\{\}"#, "{}", ""),
        (r#"{"json": "object"}"#, "", ""),
        (r#"\{"json": "object"}"#, r#"{"json": "object"}"#, ""),
        (r#"\{"json": "object"\}"#, r#"{"json": "object"}"#, ""),
        (r#"\{"json": "object{bar}"\}"#, r#"{"json": "object"}"#, ""),
        (r#"\{"json": \{"nested": "object"\}\}"#, r#"{"json": {"nested": "object"}}"#, ""),
        (r#"\{"json": \{"nested": "{bar}"\}\}"#, r#"{"json": {"nested": ""}}"#, ""),
        (r#"pre \{"json": \{"nested": "{bar}"\}\}"#, r#"pre {"json": {"nested": ""}}"#, ""),
        (r#"\{"json": \{"nested": "{bar}"\}\} post"#, r#"{"json": {"nested": ""}} post"#, ""),
        (r#"pre \{"json": \{"nested": "{bar}"\}\} post"#, r#"pre {"json": {"nested": ""}} post"#, ""),
        ("{{", "{{", ""),
        ("{{}", "", ""),
        (r#"{"json": "object"\}"#, "", ""),
        ("{unknown}", "-", "-"),
        (r#"back\slashes"#, r#"back\slashes"#, ""),
        (r#"double back\\slashes"#, r#"double back\\slashes"#, ""),
        (r#"placeholder {with \{ brace} in name"#, "placeholder  in name", ""),
        (r#"placeholder {with \} brace} in name"#, "placeholder  in name", ""),
        (r#"placeholder {with \} \} braces} in name"#, "placeholder  in name", ""),
        (
            r#"\{'group':'default','max_age':3600,'endpoints':[\{'url':'https://some.domain.local/a/d/g'\}],'include_subdomains':true\}"#,
            r#"{'group':'default','max_age':3600,'endpoints':[{'url':'https://some.domain.local/a/d/g'}],'include_subdomains':true}"#,
            "",
        ),
        (r#"{}{}{}{\\\\}\\\"#, r#"{\\\}\\\"#, ""),
        (r#"\\}"#, r#"\}"#, ""),
    ];

    for (i, (input, expect, empty)) in cases.into_iter().enumerate() {
        let actual = rep.replace_all(input, empty);
        assert_eq!(actual, expect, "Test {}: '{}' expected '{}', got '{}'", i, input, expect, actual);
    }
}

#[test]
fn test_replacer_set_get_delete() {
    let rep = Replacer::new_empty();

    rep.set("test1", "val1");
    rep.set("asdf", "123");
    rep.set("numbers", "123.456");
    rep.set("äöü", "öö_äü");
    rep.set("with space", "space value");
    rep.set("1", "test-123");
    rep.set("mySuper_IP", "1.2.3.4");
    rep.set("testEmpty", "");

    assert_eq!(rep.get("test1"), Some("val1".to_string()));
    assert_eq!(rep.get("asdf"), Some("123".to_string()));
    assert_eq!(rep.get("numbers"), Some("123.456".to_string()));
    assert_eq!(rep.get("äöü"), Some("öö_äü".to_string()));
    assert_eq!(rep.get("with space"), Some("space value".to_string()));
    assert_eq!(rep.get("1"), Some("test-123".to_string()));
    assert_eq!(rep.get("mySuper_IP"), Some("1.2.3.4".to_string()));
    assert_eq!(rep.get("testEmpty"), Some("".to_string()));

    rep.delete("asdf");
    assert_eq!(rep.get("asdf"), None);
}

#[test]
fn test_replacer_replace_known() {
    let mut rep = Replacer::new_empty();

    rep.map(|key| match key {
        "test1" => Some("val1".to_string()),
        "asdf" => Some("123".to_string()),
        "äöü" => Some("öö_äü".to_string()),
        "with space" => Some("space value".to_string()),
        _ => None,
    });

    rep.map(|key| match key {
        "1" => Some("test-123".to_string()),
        "mySuper_IP" => Some("1.2.3.4".to_string()),
        "testEmpty" => Some("".to_string()),
        _ => None,
    });

    let cases = vec![
        (
            "{test1}{asdf}{äöü}{1}{with space}{mySuper_IP}",
            "val1123öö_äütest-123space value1.2.3.4",
        ),
        (
            "{test1} {asdf} {äöü} {1} {with space} {mySuper_IP} ",
            "val1 123 öö_äü test-123 space value 1.2.3.4 ",
        ),
        (
            "{test1} {testEmpty} {asdf} {1} ",
            "val1 EMPTY 123 test-123 ",
        ),
        (
            "{te{test1}{as{{df{1}",
            "{teval1{as{{dftest-123",
        ),
        (
            "{test1} {nope} {1} ",
            "val1 {nope} test-123 ",
        ),
    ];

    for (i, (input, expected)) in cases.into_iter().enumerate() {
        let actual = rep.replace_known(input, "EMPTY");
        assert_eq!(actual, expected, "Test {}: input '{}' expected '{}', got '{}'", i, input, expected, actual);
    }
}

#[test]
fn test_replacer_new_global() {
    unsafe {
        std::env::set_var("CADDY_REPLACER_TEST", "envtest");
    }

    let repl = Replacer::new();

    assert_eq!(repl.get("system.slash"), Some(std::path::MAIN_SEPARATOR.to_string()));
    assert_eq!(repl.get("system.os"), Some(std::env::consts::OS.to_string()));
    assert_eq!(repl.get("system.arch"), Some(std::env::consts::ARCH.to_string()));
    assert!(repl.get("system.wd").is_some());
    assert!(repl.get("system.hostname").is_some());
    assert_eq!(repl.get("env.CADDY_REPLACER_TEST"), Some("envtest".to_string()));
}

#[test]
fn test_replacer_without_file() {
    let repl = Replacer::new().without_file();
    assert_eq!(repl.get("file.caddytest/integration/testdata/foo.txt"), None);
    assert_eq!(repl.get("system.os"), Some(std::env::consts::OS.to_string()));
}
