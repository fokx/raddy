use std::collections::HashMap;

/// Trait for resolving variable placeholders.
pub trait PlaceholderProvider {
    fn get_placeholder(&self, key: &str) -> Option<String>;
}

/// A simple map-based placeholder provider.
#[derive(Debug, Default, Clone)]
pub struct MapPlaceholderProvider {
    values: HashMap<String, String>,
}

impl MapPlaceholderProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: impl Into<String>, val: impl Into<String>) {
        self.values.insert(key.into(), val.into());
    }
}

impl PlaceholderProvider for MapPlaceholderProvider {
    fn get_placeholder(&self, key: &str) -> Option<String> {
        self.values.get(key).cloned()
    }
}

/// Evaluates a string containing `{placeholders}` using one or more providers.
/// Supports standard forms like:
/// - `{host}`
/// - `{path}`
/// - `{method}`
/// - `{env.VAR_NAME}`
/// - `{header.Header-Name}`
/// - `{query.param_name}`
/// - `{vars.var_name}`
pub fn eval_placeholders(input: &str, provider: &dyn PlaceholderProvider) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '{' {
            let mut key = String::new();
            let mut closed = false;

            while let Some(&next_ch) = chars.peek() {
                chars.next();
                if next_ch == '}' {
                    closed = true;
                    break;
                }
                key.push(next_ch);
            }

            if closed && !key.is_empty() {
                if let Some(val) = resolve_key(&key, provider) {
                    result.push_str(&val);
                } else {
                    // If not resolved, leave it or check env
                    result.push('{');
                    result.push_str(&key);
                    result.push('}');
                }
            } else {
                result.push('{');
                result.push_str(&key);
            }
        } else {
            result.push(ch);
        }
    }

    result
}

fn resolve_key(key: &str, provider: &dyn PlaceholderProvider) -> Option<String> {
    // 1. Direct provider check
    if let Some(val) = provider.get_placeholder(key) {
        return Some(val);
    }

    // 2. Check environment variable: {env.NAME}
    if let Some(stripped) = key.strip_prefix("env.") {
        return std::env::var(stripped).ok();
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eval_placeholders() {
        let mut map = MapPlaceholderProvider::new();
        map.insert("host", "example.com");
        map.insert("path", "/index.html");

        let out = eval_placeholders("http://{host}{path}?user=1", &map);
        assert_eq!(out, "http://example.com/index.html?user=1");
    }

    #[test]
    fn test_env_placeholder() {
        unsafe {
            std::env::set_var("RADDY_TEST_VAR", "super_secret");
        }
        let map = MapPlaceholderProvider::new();
        let out = eval_placeholders("val: {env.RADDY_TEST_VAR}", &map);
        assert_eq!(out, "val: super_secret");
    }
}
