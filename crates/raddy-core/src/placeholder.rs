use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, RwLock};

/// Trait for resolving variable placeholders.
pub trait PlaceholderProvider: Send + Sync {
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

pub type ProviderFn = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// Caddy-compatible Replacer supporting escaping, static maps, file reading,
/// system variables, and provider function chains.
#[derive(Clone)]
pub struct Replacer {
    static_map: Arc<RwLock<HashMap<String, String>>>,
    providers: Vec<ProviderFn>,
    file_enabled: bool,
}

impl Default for Replacer {
    fn default() -> Self {
        Self::new()
    }
}

impl Replacer {
    /// Creates a new Replacer with default system, env, and file providers.
    pub fn new() -> Self {
        let static_map = Arc::new(RwLock::new(HashMap::new()));
        let mut r = Self {
            static_map: static_map.clone(),
            providers: Vec::new(),
            file_enabled: true,
        };

        // 1. Global system and env provider
        r.providers.push(Arc::new(|key: &str| {
            if let Some(stripped) = key.strip_prefix("env.") {
                return std::env::var(stripped).ok();
            }

            match key {
                "system.hostname" => {
                    let host = std::fs::read_to_string("/etc/hostname")
                        .map(|s| s.trim().to_string())
                        .or_else(|_| std::env::var("HOSTNAME"))
                        .unwrap_or_default();
                    Some(host)
                }
                "system.slash" => Some(std::path::MAIN_SEPARATOR.to_string()),
                "system.os" => Some(std::env::consts::OS.to_string()),
                "system.arch" => Some(std::env::consts::ARCH.to_string()),
                "system.wd" => std::env::current_dir()
                    .ok()
                    .map(|p| p.to_string_lossy().to_string()),
                _ => None,
            }
        }));

        // 2. Static map provider
        let sm = static_map.clone();
        r.providers.push(Arc::new(move |key: &str| {
            sm.read().ok().and_then(|m| m.get(key).cloned())
        }));

        r
    }

    /// Creates an empty Replacer with only the static map provider.
    pub fn new_empty() -> Self {
        let static_map = Arc::new(RwLock::new(HashMap::new()));
        let mut r = Self {
            static_map: static_map.clone(),
            providers: Vec::new(),
            file_enabled: false,
        };

        let sm = static_map.clone();
        r.providers.push(Arc::new(move |key: &str| {
            sm.read().ok().and_then(|m| m.get(key).cloned())
        }));

        r
    }

    /// Returns a copy of the replacer without file reading capabilities.
    pub fn without_file(&self) -> Self {
        let mut copy = self.clone();
        copy.file_enabled = false;
        copy
    }

    /// Registers a custom provider function.
    pub fn map<F>(&mut self, f: F)
    where
        F: Fn(&str) -> Option<String> + Send + Sync + 'static,
    {
        self.providers.push(Arc::new(f));
    }

    /// Sets a static variable.
    pub fn set(&self, key: impl Into<String>, val: impl Into<String>) {
        if let Ok(mut map) = self.static_map.write() {
            map.insert(key.into(), val.into());
        }
    }

    /// Deletes a static variable.
    pub fn delete(&self, key: &str) {
        if let Ok(mut map) = self.static_map.write() {
            map.remove(key);
        }
    }

    /// Gets the value for a variable.
    pub fn get(&self, key: &str) -> Option<String> {
        // File provider check if enabled
        if self.file_enabled {
            if let Some(path_str) = key.strip_prefix("file.") {
                if let Ok(file) = File::open(Path::new(path_str)) {
                    let mut buf = Vec::new();
                    // Read up to 1MB
                    let mut handle = file.take(1024 * 1024);
                    if handle.read_to_end(&mut buf).is_ok() {
                        let mut text = String::from_utf8_lossy(&buf).to_string();
                        while text.ends_with('\n') || text.ends_with('\r') {
                            text.pop();
                        }
                        return Some(text);
                    }
                }
            }
        }

        // Search providers (checked in order)
        for provider in &self.providers {
            if let Some(val) = provider(key) {
                return Some(val);
            }
        }

        None
    }

    /// Replaces all placeholders. Unrecognized placeholders are replaced with `empty_val`.
    pub fn replace_all(&self, input: &str, empty_val: &str) -> String {
        self.replace_internal(input, empty_val, true)
    }

    /// Replaces only recognized placeholders. Unrecognized placeholders remain untouched.
    pub fn replace_known(&self, input: &str, empty_val: &str) -> String {
        self.replace_internal(input, empty_val, false)
    }

    fn replace_internal(
        &self,
        input: &str,
        empty_val: &str,
        treat_unknown_as_empty: bool,
    ) -> String {
        let bytes = input.as_bytes();
        let len = bytes.len();
        if !bytes.contains(&b'{') && !bytes.contains(&b'}') {
            return input.to_string();
        }

        let mut out = Vec::with_capacity(len);
        let mut last_write_cursor = 0;
        let mut unclosed_count = 0;
        let mut i = 0;

        'scan: while i < len {
            // Check for escaped braces
            if i > 0 && bytes[i - 1] == b'\\' && (bytes[i] == b'}' || bytes[i] == b'{') {
                out.extend_from_slice(&bytes[last_write_cursor..i - 1]);
                last_write_cursor = i;
                i += 1;
                continue;
            }

            if bytes[i] != b'{' {
                i += 1;
                continue;
            }

            if unclosed_count > 100 {
                break;
            }

            // Find the end of the placeholder
            let mut end = None;
            for j in i..len {
                if bytes[j] == b'}' {
                    end = Some(j);
                    break;
                }
            }

            let mut end_idx = match end {
                Some(idx) => idx,
                None => {
                    unclosed_count += 1;
                    i += 1;
                    continue;
                }
            };

            // If necessary look for the first closing brace that is not escaped
            while end_idx > 0 && end_idx < len - 1 && bytes[end_idx - 1] == b'\\' {
                let mut next_end = None;
                for j in (end_idx + 1)..len {
                    if bytes[j] == b'}' {
                        next_end = Some(j);
                        break;
                    }
                }
                match next_end {
                    Some(n_end) => {
                        end_idx = n_end;
                    }
                    None => {
                        unclosed_count += 1;
                        i += 1;
                        continue 'scan;
                    }
                }
            }

            // Write substring from lastWriteCursor to i
            out.extend_from_slice(&bytes[last_write_cursor..i]);

            let key_bytes = &bytes[i + 1..end_idx];
            let key = String::from_utf8_lossy(key_bytes).to_string();

            let opt_val = self.get(&key);
            match opt_val {
                Some(val) => {
                    if val.is_empty() {
                        out.extend_from_slice(empty_val.as_bytes());
                    } else {
                        out.extend_from_slice(val.as_bytes());
                    }
                    i = end_idx;
                    last_write_cursor = i + 1;
                }
                None => {
                    if treat_unknown_as_empty {
                        out.extend_from_slice(empty_val.as_bytes());
                        i = end_idx;
                        last_write_cursor = i + 1;
                    } else {
                        last_write_cursor = i;
                    }
                }
            }

            i += 1;
        }

        out.extend_from_slice(&bytes[last_write_cursor..]);
        String::from_utf8_lossy(&out).to_string()
    }
}

impl PlaceholderProvider for Replacer {
    fn get_placeholder(&self, key: &str) -> Option<String> {
        self.get(key)
    }
}

/// Evaluates a string containing `{placeholders}` using a `PlaceholderProvider`.
pub fn eval_placeholders(input: &str, provider: &dyn PlaceholderProvider) -> String {
    let replacer = Replacer::new_empty();
    let mut map = HashMap::new();
    // Parse placeholders from input and extract from provider
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '{' {
            if let Some(end) = chars[i + 1..].iter().position(|&c| c == '}') {
                let key: String = chars[i + 1..i + 1 + end].iter().collect();
                if let Some(val) = provider.get_placeholder(&key).or_else(|| {
                    if let Some(stripped) = key.strip_prefix("env.") {
                        std::env::var(stripped).ok()
                    } else {
                        None
                    }
                }) {
                    map.insert(key, val);
                }
                i += end + 1;
            }
        }
        i += 1;
    }

    for (k, v) in map {
        replacer.set(k, v);
    }

    replacer.replace_known(input, "")
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
            std::env::set_var("RADDY_TEST_VAR", "caddy_rocks");
        }
        let map = MapPlaceholderProvider::new();
        let out = eval_placeholders("val: {env.RADDY_TEST_VAR}", &map);
        assert_eq!(out, "val: caddy_rocks");
    }
}
