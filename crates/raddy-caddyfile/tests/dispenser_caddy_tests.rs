use raddy_caddyfile::caddyfile::new_test_dispenser;

#[test]
fn test_dispenser_val_next() {
    let input = "host:port\n\t\t\t  dir1 arg1\n\t\t\t  dir2 arg2 arg3\n\t\t\t  dir3";
    let mut d = new_test_dispenser(input);

    assert_eq!(
        d.val(),
        "",
        "Val(): Should return empty string when no token loaded"
    );

    let assert_next = |d: &mut raddy_caddyfile::caddyfile::Dispenser,
                           should_load: bool,
                           expected_cursor: isize,
                           expected_val: &str| {
        let loaded = d.next();
        assert_eq!(
            loaded, should_load,
            "Next(): Expected {} but got {} instead (val '{}')",
            should_load,
            loaded,
            d.val()
        );
        assert_eq!(
            d.cursor(),
            expected_cursor,
            "Expected cursor to be {}, but was {}",
            expected_cursor,
            d.cursor()
        );
        assert_eq!(
            d.nesting(),
            0,
            "Nesting should be 0, was {} instead",
            d.nesting()
        );
        assert_eq!(
            d.val(),
            expected_val,
            "Val(): Expected '{}' but got '{}'",
            expected_val,
            d.val()
        );
    };

    assert_next(&mut d, true, 0, "host:port");
    assert_next(&mut d, true, 1, "dir1");
    assert_next(&mut d, true, 2, "arg1");
    assert_next(&mut d, true, 3, "dir2");
    assert_next(&mut d, true, 4, "arg2");
    assert_next(&mut d, true, 5, "arg3");
    assert_next(&mut d, true, 6, "dir3");
    assert_next(&mut d, false, 6, "dir3");
}

#[test]
fn test_dispenser_next_arg() {
    let input = "dir1 arg1\n\t\t\t  dir2 arg2 arg3\n\t\t\t  dir3";
    let mut d = new_test_dispenser(input);

    let assert_next = |d: &mut raddy_caddyfile::caddyfile::Dispenser,
                       should_load: bool,
                       expected_val: &str,
                       expected_cursor: isize| {
        assert_eq!(
            d.next(),
            should_load,
            "Next(): Should load token but got false instead (val: '{}')",
            d.val()
        );
        assert_eq!(
            d.cursor(),
            expected_cursor,
            "Next(): Expected cursor to be at {}, but it was {}",
            expected_cursor,
            d.cursor()
        );
        assert_eq!(
            d.val(),
            expected_val,
            "Val(): Expected '{}' but got '{}'",
            expected_val,
            d.val()
        );
    };

    let assert_next_arg = |d: &mut raddy_caddyfile::caddyfile::Dispenser,
                           expected_val: &str,
                           load_another: bool,
                           expected_cursor: isize| {
        assert!(
            d.next_arg(),
            "NextArg(): Should load next argument but got false instead"
        );
        assert_eq!(
            d.cursor(),
            expected_cursor,
            "NextArg(): Expected cursor to be at {}, but it was {}",
            expected_cursor,
            d.cursor()
        );
        assert_eq!(
            d.val(),
            expected_val,
            "Val(): Expected '{}' but got '{}'",
            expected_val,
            d.val()
        );
        if !load_another {
            assert!(
                !d.next_arg(),
                "NextArg(): Should NOT load another argument, but got true instead (val: '{}')",
                d.val()
            );
            assert_eq!(
                d.cursor(),
                expected_cursor,
                "NextArg(): Expected cursor to remain at {}, but it was {}",
                expected_cursor,
                d.cursor()
            );
        }
    };

    assert_next(&mut d, true, "dir1", 0);
    assert_next_arg(&mut d, "arg1", false, 1);
    assert_next(&mut d, true, "dir2", 2);
    assert_next_arg(&mut d, "arg2", true, 3);
    assert_next_arg(&mut d, "arg3", false, 4);
    assert_next(&mut d, true, "dir3", 5);
    assert_next(&mut d, false, "dir3", 5);
}

#[test]
fn test_dispenser_next_line() {
    let input = "host:port\n\t\t\t  dir1 arg1\n\t\t\t  dir2 arg2 arg3";
    let mut d = new_test_dispenser(input);

    let assert_next_line = |d: &mut raddy_caddyfile::caddyfile::Dispenser,
                            should_load: bool,
                            expected_val: &str,
                            expected_cursor: isize| {
        assert_eq!(
            d.next_line(),
            should_load,
            "NextLine(): Should load token but got false instead (val: '{}')",
            d.val()
        );
        assert_eq!(
            d.cursor(),
            expected_cursor,
            "NextLine(): Expected cursor to be {}, instead was {}",
            expected_cursor,
            d.cursor()
        );
        assert_eq!(
            d.val(),
            expected_val,
            "Val(): Expected '{}' but got '{}'",
            expected_val,
            d.val()
        );
    };

    assert_next_line(&mut d, true, "host:port", 0);
    assert_next_line(&mut d, true, "dir1", 1);
    assert_next_line(&mut d, false, "dir1", 1);
    d.next(); // arg1
    assert_next_line(&mut d, true, "dir2", 3);
    assert_next_line(&mut d, false, "dir2", 3);
    d.next(); // arg2
    assert_next_line(&mut d, false, "arg2", 4);
    d.next(); // arg3
    assert_next_line(&mut d, false, "arg3", 5);
}

#[test]
fn test_dispenser_next_block() {
    let input = "foobar1 {\n\t\t\t  \tsub1 arg1\n\t\t\t  \tsub2\n\t\t\t  }\n\t\t\t  foobar2 {\n\t\t\t  }";
    let mut d = new_test_dispenser(input);

    let assert_next_block = |d: &mut raddy_caddyfile::caddyfile::Dispenser,
                             should_load: bool,
                             expected_cursor: isize,
                             expected_nesting: isize| {
        let loaded = d.next_block(0);
        assert_eq!(
            loaded, should_load,
            "NextBlock(): Should return {} but got {}",
            should_load, loaded
        );
        assert_eq!(
            d.cursor(),
            expected_cursor,
            "NextBlock(): Expected cursor to be {}, was {}",
            expected_cursor,
            d.cursor()
        );
        assert_eq!(
            d.nesting(),
            expected_nesting,
            "NextBlock(): Nesting should be {}, not {}",
            expected_nesting,
            d.nesting()
        );
    };

    assert_next_block(&mut d, false, -1, 0);
    d.next(); // foobar1
    assert_next_block(&mut d, true, 2, 1);
    assert_next_block(&mut d, true, 3, 1);
    assert_next_block(&mut d, true, 4, 1);
    assert_next_block(&mut d, false, 5, 0);
    d.next(); // foobar2
    assert_next_block(&mut d, false, 8, 0); // empty block is as if it didn't exist
}

#[test]
fn test_dispenser_quoted_braces_are_arguments() {
    let mut d = new_test_dispenser(
        "dir1 \"{\" \"}\" foo\n\t\t\t  dir2 \"}\" {\n\t\t\t\tsub1 \"{\"\n\t\t\t  }",
    );

    d.next(); // dir1
    assert!(
        !d.next_block(0),
        "NextBlock(): quoted '{{' must not open a block (val: '{}')",
        d.val()
    );
    assert_eq!(
        d.remaining_args(),
        vec!["{", "}", "foo"],
        "RemainingArgs(): quoted braces should be visible as arguments"
    );

    d.next(); // dir2
    assert_eq!(
        d.remaining_args(),
        vec!["}"],
        "RemainingArgs(): quoted '}}' should be an argument"
    );
    assert!(
        d.next_block(0) && d.val() == "sub1",
        "NextBlock(): unquoted '{{' should still open a block (val: '{}')",
        d.val()
    );
    assert_eq!(
        d.remaining_args(),
        vec!["{"],
        "RemainingArgs(): quoted '{{' inside block should be an argument"
    );
    assert!(
        !d.next_block(0) || d.nesting() == 0,
        "NextBlock(): block should have closed (nesting {})",
        d.nesting()
    );
}

#[test]
fn test_dispenser_args() {
    let mut s1 = String::new();
    let mut s2 = String::new();
    let mut s3 = String::new();
    let input = "dir1 arg1 arg2 arg3\n\t\t\t  dir2 arg4 arg5\n\t\t\t  dir3 arg6 arg7\n\t\t\t  dir4";
    let mut d = new_test_dispenser(input);

    d.next(); // dir1

    // As many strings as arguments
    assert!(
        d.args(&mut [&mut s1, &mut s2, &mut s3]),
        "Args(): Expected true, got false"
    );
    assert_eq!(s1, "arg1");
    assert_eq!(s2, "arg2");
    assert_eq!(s3, "arg3");

    d.next(); // dir2

    // More strings than arguments
    assert!(
        !d.args(&mut [&mut s1, &mut s2, &mut s3]),
        "Args(): Expected false, got true"
    );
    assert_eq!(s1, "arg4");
    assert_eq!(s2, "arg5");
    assert_eq!(s3, "arg3"); // s3 unchanged

    assert_eq!(d.cursor(), 6, "Cursor should be 6, but is {}", d.cursor());

    d.next(); // dir3

    // More arguments than strings
    assert!(d.args(&mut [&mut s1]), "Args(): Expected true, got false");
    assert_eq!(s1, "arg6");

    d.next(); // dir4

    // No arguments or strings
    assert!(d.args(&mut []), "Args(): Expected true, got false");

    // No arguments but at least one string
    assert!(!d.args(&mut [&mut s1]), "Args(): Expected false, got true");
}

#[test]
fn test_dispenser_remaining_args() {
    let input = "dir1 arg1 arg2 arg3\n\t\t\t  dir2 arg4 arg5\n\t\t\t  dir3 arg6 { arg7\n\t\t\t  dir4";
    let mut d = new_test_dispenser(input);

    d.next(); // dir1
    assert_eq!(d.remaining_args(), vec!["arg1", "arg2", "arg3"]);

    d.next(); // dir2
    assert_eq!(d.remaining_args(), vec!["arg4", "arg5"]);

    d.next(); // dir3
    assert_eq!(d.remaining_args(), vec!["arg6"]);

    d.next(); // {
    d.next(); // arg7
    d.next(); // dir4
    assert_eq!(d.remaining_args(), Vec::<String>::new());
}

#[test]
fn test_dispenser_remaining_args_as_tokens() {
    let input = "dir1 arg1 arg2 arg3\n\t\t\t  dir2 arg4 arg5\n\t\t\t  dir3 arg6 { arg7\n\t\t\t  dir4";
    let mut d = new_test_dispenser(input);

    d.next(); // dir1
    let texts: Vec<String> = d
        .remaining_args_as_tokens()
        .into_iter()
        .map(|t| t.text)
        .collect();
    assert_eq!(texts, vec!["arg1", "arg2", "arg3"]);

    d.next(); // dir2
    let texts: Vec<String> = d
        .remaining_args_as_tokens()
        .into_iter()
        .map(|t| t.text)
        .collect();
    assert_eq!(texts, vec!["arg4", "arg5"]);

    d.next(); // dir3
    let texts: Vec<String> = d
        .remaining_args_as_tokens()
        .into_iter()
        .map(|t| t.text)
        .collect();
    assert_eq!(texts, vec!["arg6"]);

    d.next(); // {
    d.next(); // arg7
    d.next(); // dir4
    let texts: Vec<String> = d
        .remaining_args_as_tokens()
        .into_iter()
        .map(|t| t.text)
        .collect();
    assert_eq!(texts, Vec::<String>::new());
}

#[test]
fn test_dispenser_arg_err_err() {
    let input = "dir1 {\n\t\t\t  }\n\t\t\t  dir2 arg1 arg2";
    let mut d = new_test_dispenser(input);

    d.cursor = 1; // {
    let err = d.arg_err();
    assert!(
        err.to_string().contains('{'),
        "ArgErr(): Expected error message with {{ in it, got '{}'",
        err
    );

    d.cursor = 5; // arg2
    let err = d.arg_err();
    assert!(
        err.to_string().contains("arg2"),
        "ArgErr(): Expected error message with 'arg2' in it, got '{}'",
        err
    );

    let err = d.err("foobar");
    assert!(
        err.to_string().contains("Testfile:3"),
        "Expected error message with filename:line in it; got '{}'",
        err
    );
    assert!(
        err.to_string().contains("foobar"),
        "Expected error message with custom message in it ('foobar'); got '{}'",
        err
    );

    #[derive(Debug)]
    struct BarFull;
    impl std::fmt::Display for BarFull {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "bar is full")
        }
    }
    impl std::error::Error for BarFull {}

    let booking_error = d.wrap_err(Box::new(BarFull));
    use std::error::Error;
    assert!(
        booking_error.source().is_some(),
        "Errf(): should be able to unwrap the error chain"
    );
}
