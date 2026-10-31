//! Environment variable substitution for Caddyfile.
//! Supports:
//! - `{$VAR}` and `{$VAR:default}`
//! - `{env.VAR}` and `{env.VAR:default}`
//! - Escaping: `\{\$VAR\}` and `\{env.VAR\}`

/// Replaces environment variable placeholders (`{$VAR}`, `{$VAR:default}`, `{env.VAR}`, `{env.VAR:default}`)
/// with values provided by a custom lookup function.
pub fn replace_env_vars_with_lookup<F>(input: &str, lookup: F) -> String
where
    F: Fn(&str) -> Option<String>,
{
    let mut out = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        // Handle backslash escaping
        if chars[i] == '\\' {
            let mut backslash_count = 0;
            while i + backslash_count < len && chars[i + backslash_count] == '\\' {
                backslash_count += 1;
            }

            if i + backslash_count < len && chars[i + backslash_count] == '{' {
                if backslash_count % 2 == 1 {
                    // Odd backslashes: the '{' is escaped!
                    // Output (backslash_count - 1) / 2 backslashes
                    for _ in 0..(backslash_count - 1) / 2 {
                        out.push('\\');
                    }
                    out.push('{');
                    i += backslash_count + 1;
                    continue;
                } else {
                    // Even backslashes: emit backslash_count / 2 backslashes
                    for _ in 0..(backslash_count / 2) {
                        out.push('\\');
                    }
                    i += backslash_count;
                    // continue to process '{' at index i
                }
            } else if i + backslash_count < len && chars[i + backslash_count] == '}' {
                if backslash_count % 2 == 1 {
                    // Odd backslashes: the '}' is escaped!
                    for _ in 0..(backslash_count - 1) / 2 {
                        out.push('\\');
                    }
                    out.push('}');
                    i += backslash_count + 1;
                    continue;
                } else {
                    for _ in 0..(backslash_count / 2) {
                        out.push('\\');
                    }
                    i += backslash_count;
                }
            } else {
                for _ in 0..backslash_count {
                    out.push('\\');
                }
                i += backslash_count;
                continue;
            }
        }

        if chars[i] == '{' {
            // Check if this opens an env placeholder: starts with '$' or 'env.'
            if let Some(close_rel) = chars[i + 1..].iter().position(|&c| c == '}') {
                let close_idx = i + 1 + close_rel;
                let inner: String = chars[i + 1..close_idx].iter().collect();

                let (is_env, var_spec) = if let Some(stripped) = inner.strip_prefix('$') {
                    (true, stripped)
                } else if let Some(stripped) = inner.strip_prefix("env.") {
                    (true, stripped)
                } else {
                    (false, "")
                };

                if is_env {
                    let (var_name, default_val) = if let Some((v, d)) = var_spec.split_once(':') {
                        (v, Some(d))
                    } else {
                        (var_spec, None)
                    };

                    let val = lookup(var_name);
                    match (val, default_val) {
                        (Some(v), Some(d)) => {
                            if v.is_empty() {
                                out.push_str(d);
                            } else {
                                out.push_str(&v);
                            }
                        }
                        (Some(v), None) => {
                            out.push_str(&v);
                        }
                        (None, Some(d)) => {
                            out.push_str(d);
                        }
                        (None, None) => {
                            // Variable not set and no default
                        }
                    }
                    i = close_idx + 1;
                    continue;
                }
            }
        }

        // Check for escaped closing brace '\}'
        if chars[i] == '\\' && i + 1 < len && chars[i + 1] == '}' {
            out.push('}');
            i += 2;
            continue;
        }

        out.push(chars[i]);
        i += 1;
    }

    out
}

/// Replaces environment variable placeholders (`{$VAR}`, `{$VAR:default}`, `{env.VAR}`, `{env.VAR:default}`)
/// with their runtime process environment values via `std::env::var`.
pub fn replace_env_vars(input: &str) -> String {
    replace_env_vars_with_lookup(input, |name| std::env::var(name).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn mock_lookup(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |name: &str| map.get(name).cloned()
    }

    #[test]
    fn test_replace_env_dollar_syntax() {
        let lookup = mock_lookup(&[("TEST_UPSTREAM_HOST", "upstream_service:8080")]);
        let res = replace_env_vars_with_lookup("reverse_proxy {$TEST_UPSTREAM_HOST}", lookup);
        assert_eq!(res, "reverse_proxy upstream_service:8080");
    }

    #[test]
    fn test_replace_env_dot_syntax() {
        let lookup = mock_lookup(&[("UPSTREAM_HOST", "upstream_app:80")]);
        let res = replace_env_vars_with_lookup("reverse_proxy {env.UPSTREAM_HOST}", lookup);
        assert_eq!(res, "reverse_proxy upstream_app:80");
    }

    #[test]
    fn test_replace_env_with_default_fallback() {
        let lookup = mock_lookup(&[]);
        let res1 = replace_env_vars_with_lookup("reverse_proxy {$NON_EXISTENT_VAR_123:fallback_app:8080}", &lookup);
        assert_eq!(res1, "reverse_proxy fallback_app:8080");

        let res2 = replace_env_vars_with_lookup("reverse_proxy {env.NON_EXISTENT_VAR_123:fallback_app:9000}", &lookup);
        assert_eq!(res2, "reverse_proxy fallback_app:9000");
    }

    #[test]
    fn test_replace_env_with_default_when_var_set() {
        let lookup = mock_lookup(&[("EXISTING_VAR_123", "real_backend:3000")]);
        let res = replace_env_vars_with_lookup("reverse_proxy {$EXISTING_VAR_123:fallback_app:8080}", lookup);
        assert_eq!(res, "reverse_proxy real_backend:3000");
    }

    #[test]
    fn test_multiple_env_in_single_line() {
        let lookup = mock_lookup(&[("HOST_PART", "api.example.com"), ("PORT_PART", "8443")]);
        let res = replace_env_vars_with_lookup("reverse_proxy {env.HOST_PART}:{env.PORT_PART}", lookup);
        assert_eq!(res, "reverse_proxy api.example.com:8443");
    }

    #[test]
    fn test_preserve_non_env_placeholders() {
        let input = "reverse_proxy {host} {path} {http.request.header.X-Forwarded-For} {remote_host}";
        let res = replace_env_vars(input);
        assert_eq!(res, input);
    }

    #[test]
    fn test_escaping_env_vars() {
        let input = "reverse_proxy \\{$TEST_VAR\\} and \\{env.TEST_VAR\\}";
        let res = replace_env_vars(input);
        assert_eq!(res, "reverse_proxy {$TEST_VAR} and {env.TEST_VAR}");
    }
}
