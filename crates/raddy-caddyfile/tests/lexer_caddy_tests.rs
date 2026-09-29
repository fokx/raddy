use raddy_caddyfile::caddyfile::{tokenize, Token};

struct TestCase {
    input: Vec<u8>,
    expected: Vec<Token>,
    expect_err: bool,
    error_message: &'static str,
}

#[test]
fn test_caddy_lexer() {
    let test_cases = vec![
        TestCase {
            input: b"host:123".to_vec(),
            expected: vec![Token {
                line: 1,
                text: "host:123".into(),
                ..Default::default()
            }],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"host:123\n\n\t\t\t\t\tdirective".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "host:123".into(),
                    ..Default::default()
                },
                Token {
                    line: 3,
                    text: "directive".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"host:123 {\n\t\t\t\t\t\tdirective\n\t\t\t\t\t}".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "host:123".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "{".into(),
                    ..Default::default()
                },
                Token {
                    line: 2,
                    text: "directive".into(),
                    ..Default::default()
                },
                Token {
                    line: 3,
                    text: "}".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"host:123 { directive }".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "host:123".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "{".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "directive".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "}".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"host:123 {\n\t\t\t\t\t\t#comment\n\t\t\t\t\t\tdirective\n\t\t\t\t\t\t# comment\n\t\t\t\t\t\tfoobar # another comment\n\t\t\t\t\t}".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "host:123".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "{".into(),
                    ..Default::default()
                },
                Token {
                    line: 3,
                    text: "directive".into(),
                    ..Default::default()
                },
                Token {
                    line: 5,
                    text: "foobar".into(),
                    ..Default::default()
                },
                Token {
                    line: 6,
                    text: "}".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"host:123 {\n\t\t\t\t\t\t# hash inside string is not a comment\n\t\t\t\t\t\tredir / /some/#/path\n\t\t\t\t\t}".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "host:123".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "{".into(),
                    ..Default::default()
                },
                Token {
                    line: 3,
                    text: "redir".into(),
                    ..Default::default()
                },
                Token {
                    line: 3,
                    text: "/".into(),
                    ..Default::default()
                },
                Token {
                    line: 3,
                    text: "/some/#/path".into(),
                    ..Default::default()
                },
                Token {
                    line: 4,
                    text: "}".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"# comment at beginning of file\n# comment at beginning of line\nhost:123".to_vec(),
            expected: vec![Token {
                line: 3,
                text: "host:123".into(),
                ..Default::default()
            }],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"a \"quoted value\" b\n\t\t\t\t\tfoobar".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "a".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "quoted value".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "b".into(),
                    ..Default::default()
                },
                Token {
                    line: 2,
                    text: "foobar".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"A \"quoted \\\"value\\\" inside\" B".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "A".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "quoted \"value\" inside".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "B".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"An escaped \"newline\\\ninside\" quotes".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "An".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "escaped".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "newline\\\ninside".into(),
                    ..Default::default()
                },
                Token {
                    line: 2,
                    text: "quotes".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"An escaped newline\\\noutside quotes".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "An".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "escaped".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "newline".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "outside".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "quotes".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"line1\\\nescaped\nline2\nline3".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "line1".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "escaped".into(),
                    ..Default::default()
                },
                Token {
                    line: 3,
                    text: "line2".into(),
                    ..Default::default()
                },
                Token {
                    line: 4,
                    text: "line3".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"line1\\\nescaped1\\\nescaped2\nline4\nline5".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "line1".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "escaped1".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "escaped2".into(),
                    ..Default::default()
                },
                Token {
                    line: 4,
                    text: "line4".into(),
                    ..Default::default()
                },
                Token {
                    line: 5,
                    text: "line5".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"\"unescapable\\ in quotes\"".to_vec(),
            expected: vec![Token {
                line: 1,
                text: "unescapable\\ in quotes".into(),
                ..Default::default()
            }],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"\"don't\\escape\"".to_vec(),
            expected: vec![Token {
                line: 1,
                text: "don't\\escape".into(),
                ..Default::default()
            }],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"\"don't\\\\escape\"".to_vec(),
            expected: vec![Token {
                line: 1,
                text: "don't\\\\escape".into(),
                ..Default::default()
            }],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"un\\escapable".to_vec(),
            expected: vec![Token {
                line: 1,
                text: "un\\escapable".into(),
                ..Default::default()
            }],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"A \"quoted value with line\n\t\t\t\t\tbreak inside\" {\n\t\t\t\t\t\tfoobar\n\t\t\t\t\t}".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "A".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "quoted value with line\n\t\t\t\t\tbreak inside".into(),
                    ..Default::default()
                },
                Token {
                    line: 2,
                    text: "{".into(),
                    ..Default::default()
                },
                Token {
                    line: 3,
                    text: "foobar".into(),
                    ..Default::default()
                },
                Token {
                    line: 4,
                    text: "}".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"\"C:\\php\\php-cgi.exe\"".to_vec(),
            expected: vec![Token {
                line: 1,
                text: "C:\\php\\php-cgi.exe".into(),
                ..Default::default()
            }],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"empty \"\" string".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "empty".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "string".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"skip those\r\nCR characters".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "skip".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "those".into(),
                    ..Default::default()
                },
                Token {
                    line: 2,
                    text: "CR".into(),
                    ..Default::default()
                },
                Token {
                    line: 2,
                    text: "characters".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"\xEF\xBB\xBF:8080".to_vec(),
            expected: vec![Token {
                line: 1,
                text: ":8080".into(),
                ..Default::default()
            }],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"simple `backtick quoted` string".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "simple".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "backtick quoted".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "string".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"multiline `backtick\nquoted\n` string".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "multiline".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "backtick\nquoted\n".into(),
                    ..Default::default()
                },
                Token {
                    line: 3,
                    text: "string".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"nested `\"quotes inside\" backticks` string".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "nested".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "\"quotes inside\" backticks".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "string".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"reverse-nested \"`backticks` inside\" quotes".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "reverse-nested".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "`backticks` inside".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "quotes".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"heredoc <<EOF\ncontent\nEOF same-line-arg\n\t".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "heredoc".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "content".into(),
                    ..Default::default()
                },
                Token {
                    line: 3,
                    text: "same-line-arg".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"heredoc <<VERY-LONG-MARKER\ncontent\nVERY-LONG-MARKER same-line-arg\n\t".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "heredoc".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "content".into(),
                    ..Default::default()
                },
                Token {
                    line: 3,
                    text: "same-line-arg".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"heredoc <<EOF\nextra-newline\n\nEOF same-line-arg\n\t".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "heredoc".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "extra-newline\n".into(),
                    ..Default::default()
                },
                Token {
                    line: 4,
                    text: "same-line-arg".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"heredoc <<EOF\nEOF\n\tHERE same-line-arg\n\t".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "heredoc".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "".into(),
                    ..Default::default()
                },
                Token {
                    line: 3,
                    text: "HERE".into(),
                    ..Default::default()
                },
                Token {
                    line: 3,
                    text: "same-line-arg".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"heredoc <<EOF\n\t\tEOF same-line-arg\n\t".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "heredoc".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "".into(),
                    ..Default::default()
                },
                Token {
                    line: 2,
                    text: "same-line-arg".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"heredoc <<EOF\n\tcontent\n\tEOF same-line-arg\n\t".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "heredoc".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "content".into(),
                    ..Default::default()
                },
                Token {
                    line: 3,
                    text: "same-line-arg".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"prev-line\n\theredoc <<EOF\n\t\tmulti\n\t\tline\n\t\tcontent\n\tEOF same-line-arg\n\tnext-line\n\t".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "prev-line".into(),
                    ..Default::default()
                },
                Token {
                    line: 2,
                    text: "heredoc".into(),
                    ..Default::default()
                },
                Token {
                    line: 2,
                    text: "\tmulti\n\tline\n\tcontent".into(),
                    ..Default::default()
                },
                Token {
                    line: 6,
                    text: "same-line-arg".into(),
                    ..Default::default()
                },
                Token {
                    line: 7,
                    text: "next-line".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"escaped-heredoc \\<< >>".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "escaped-heredoc".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "<<".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: ">>".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"not-a-heredoc <EOF\n\tcontent\n\t".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "not-a-heredoc".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "<EOF".into(),
                    ..Default::default()
                },
                Token {
                    line: 2,
                    text: "content".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"not-a-heredoc <<<EOF content".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "not-a-heredoc".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "<<<EOF".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "content".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"not-a-heredoc \"<<\" \">>\"".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "not-a-heredoc".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "<<".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: ">>".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"not-a-heredoc << >>".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "not-a-heredoc".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "<<".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: ">>".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"not-a-heredoc <<HERE SAME LINE\n\tcontent\n\tHERE same-line-arg\n\t".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "not-a-heredoc".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "<<HERE".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "SAME".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "LINE".into(),
                    ..Default::default()
                },
                Token {
                    line: 2,
                    text: "content".into(),
                    ..Default::default()
                },
                Token {
                    line: 3,
                    text: "HERE".into(),
                    ..Default::default()
                },
                Token {
                    line: 3,
                    text: "same-line-arg".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: "heredoc <<s\n\t\t\u{FFFD}\n\t\ts\n\t".as_bytes().to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "heredoc".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "\u{FFFD}".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: "\u{000A}heredoc \u{003C}\u{003C}\u{0073}\u{0073}\u{000A}\u{00BF}\u{0057}\u{0001}\u{0000}\u{00FF}\u{00FF}\u{00FF}\u{00FF}\u{00FF}\u{00FF}\u{00FF}\u{003D}\u{001F}\u{000A}\u{0073}\u{0073}\u{000A}\u{00BF}\u{0057}\u{0001}\u{0000}\u{00FF}\u{00FF}\u{00FF}\u{00FF}\u{00FF}\u{00FF}\u{00FF}\u{003D}\u{001F}\u{000A}\u{00BF}\u{00BF}\u{0057}\u{0001}\u{0000}\u{00FF}\u{00FF}\u{00FF}\u{00FF}\u{00FF}\u{00FF}\u{00FF}\u{003D}\u{001F}".as_bytes().to_vec(),
            expected: vec![
                Token {
                    line: 2,
                    text: "heredoc".into(),
                    ..Default::default()
                },
                Token {
                    line: 2,
                    text: "\u{00BF}\u{0057}\u{0001}\u{0000}\u{00FF}\u{00FF}\u{00FF}\u{00FF}\u{00FF}\u{00FF}\u{00FF}\u{003D}\u{001F}".into(),
                    ..Default::default()
                },
                Token {
                    line: 5,
                    text: "\u{00BF}\u{0057}\u{0001}\u{0000}\u{00FF}\u{00FF}\u{00FF}\u{00FF}\u{00FF}\u{00FF}\u{00FF}\u{003D}\u{001F}".into(),
                    ..Default::default()
                },
                Token {
                    line: 6,
                    text: "\u{00BF}\u{00BF}\u{0057}\u{0001}\u{0000}\u{00FF}\u{00FF}\u{00FF}\u{00FF}\u{00FF}\u{00FF}\u{00FF}\u{003D}\u{001F}".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"not-a-heredoc <<\n".to_vec(),
            expected: vec![],
            expect_err: true,
            error_message: "missing opening heredoc marker on line #1; must contain only alphanumeric characters, dashes and underscores; got empty string",
        },
        TestCase {
            input: b"heredoc <<<EOF\n\tcontent\n\tEOF same-line-arg\n\t".to_vec(),
            expected: vec![],
            expect_err: true,
            error_message: "too many '<' for heredoc on line #1; only use two, for example <<END",
        },
        TestCase {
            input: b"heredoc <<EOF\n\tcontent\n\t".to_vec(),
            expected: vec![],
            expect_err: true,
            error_message: "incomplete heredoc <<EOF on line #3, expected ending marker EOF",
        },
        TestCase {
            input: b"heredoc <<EOF\n\tcontent\n\t\tEOF\n\t".to_vec(),
            expected: vec![],
            expect_err: true,
            error_message: "mismatched leading whitespace in heredoc <<EOF on line #2 [\tcontent], expected whitespace [\t\t] to match the closing marker",
        },
        TestCase {
            input: b"heredoc <<EOF\n        content\n\t\tEOF\n\t".to_vec(),
            expected: vec![],
            expect_err: true,
            error_message: "mismatched leading whitespace in heredoc <<EOF on line #2 [        content], expected whitespace [\t\t] to match the closing marker",
        },
        TestCase {
            input: b"heredoc <<EOF\nThe next line is a blank line\n\nThe previous line is a blank line\nEOF".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "heredoc".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "The next line is a blank line\n\nThe previous line is a blank line".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"heredoc <<EOF\n\tOne tab indented heredoc with blank next line\n\n\tOne tab indented heredoc with blank previous line\n\tEOF".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "heredoc".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "One tab indented heredoc with blank next line\n\nOne tab indented heredoc with blank previous line".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"heredoc <<EOF\nThe next line is a blank line with one tab\n\t\nThe previous line is a blank line with one tab\nEOF".to_vec(),
            expected: vec![
                Token {
                    line: 1,
                    text: "heredoc".into(),
                    ..Default::default()
                },
                Token {
                    line: 1,
                    text: "The next line is a blank line with one tab\n\t\nThe previous line is a blank line with one tab".into(),
                    ..Default::default()
                },
            ],
            expect_err: false,
            error_message: "",
        },
        TestCase {
            input: b"heredoc <<EOF\n\t\tThe next line is a blank line with one tab less than the correct indentation\n\t\n\t\tThe previous line is a blank line with one tab less than the correct indentation\n\t\tEOF".to_vec(),
            expected: vec![],
            expect_err: true,
            error_message: "mismatched leading whitespace in heredoc <<EOF on line #3 [\t], expected whitespace [\t\t] to match the closing marker",
        },
    ];

    for (i, tc) in test_cases.iter().enumerate() {
        let actual = tokenize(&tc.input, "");
        if tc.expect_err {
            assert!(
                actual.is_err(),
                "Test case {}: expected error, got {:?}",
                i,
                actual
            );
            let err = actual.unwrap_err();
            assert_eq!(
                err, tc.error_message,
                "Test case {}: expected error '{}', got '{}'",
                i, tc.error_message, err
            );
            continue;
        }

        let actual = actual.unwrap_or_else(|e| panic!("Test case {}: unexpected error: {}", i, e));
        assert_eq!(
            tc.expected.len(),
            actual.len(),
            "Test case {}: expected {} tokens but got {}",
            i,
            tc.expected.len(),
            actual.len()
        );

        for (j, (exp, act)) in tc.expected.iter().zip(actual.iter()).enumerate() {
            assert_eq!(
                exp.line, act.line,
                "Test case {} token {} ('{}'): expected line {} but was line {}",
                i, j, exp.text, exp.line, act.line
            );
            assert_eq!(
                exp.text, act.text,
                "Test case {} token {}: expected text '{:?}' but was '{:?}'",
                i, j, exp.text, act.text
            );
        }
    }
}
