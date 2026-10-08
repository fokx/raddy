use serde_json::Value;

/// Normalizes a path like "/config/apps/http/servers" or "apps/http" into segments.
pub fn parse_path_segments(path: &str) -> Vec<&str> {
    path.trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect()
}

/// Retrieves a reference to a JSON value at the specified path.
pub fn get_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let segments = parse_path_segments(path);
    if segments.is_empty() {
        return Some(root);
    }

    let mut current = root;
    for seg in segments {
        match current {
            Value::Object(map) => {
                current = map.get(seg)?;
            }
            Value::Array(arr) => {
                let idx: usize = seg.parse().ok()?;
                current = arr.get(idx)?;
            }
            _ => return None,
        }
    }

    Some(current)
}

/// Sets or replaces a value in the JSON tree at the given path.
pub fn set_path(root: &mut Value, path: &str, new_val: Value) -> Result<(), String> {
    let segments = parse_path_segments(path);
    if segments.is_empty() {
        *root = new_val;
        return Ok(());
    }

    let mut current = root;
    let len = segments.len();

    for (i, seg) in segments.iter().enumerate() {
        if i == len - 1 {
            // Leaf node: insert/replace
            match current {
                Value::Object(map) => {
                    map.insert(seg.to_string(), new_val);
                    return Ok(());
                }
                Value::Array(arr) => {
                    let idx: usize = seg
                        .parse()
                        .map_err(|_| format!("Cannot index array with non-integer '{}'", seg))?;
                    if idx < arr.len() {
                        arr[idx] = new_val;
                        return Ok(());
                    } else if idx == arr.len() {
                        arr.push(new_val);
                        return Ok(());
                    } else {
                        return Err(format!("Index {} out of bounds (len: {})", idx, arr.len()));
                    }
                }
                _ => {
                    return Err(format!(
                        "Cannot set field on non-container node at '{}'",
                        seg
                    ));
                }
            }
        } else {
            // Intermediate node: descend or create Object
            match current {
                Value::Object(map) => {
                    current = map
                        .entry(seg.to_string())
                        .or_insert_with(|| Value::Object(serde_json::Map::new()));
                }
                Value::Array(arr) => {
                    let idx: usize = seg
                        .parse()
                        .map_err(|_| format!("Cannot index array with non-integer '{}'", seg))?;
                    if idx < arr.len() {
                        current = &mut arr[idx];
                    } else {
                        return Err(format!("Index {} out of bounds for intermediate path", idx));
                    }
                }
                _ => return Err(format!("Cannot traverse non-container node at '{}'", seg)),
            }
        }
    }

    Ok(())
}

/// Merges a JSON object into the existing value at the specified path.
pub fn patch_path(root: &mut Value, path: &str, patch_val: Value) -> Result<(), String> {
    let target = match parse_path_segments(path).as_slice() {
        [] => root,
        _ => {
            // Find existing target node
            let mut current = root;
            let segments = parse_path_segments(path);
            for seg in segments {
                match current {
                    Value::Object(map) => {
                        current = map
                            .get_mut(seg)
                            .ok_or_else(|| format!("Path '{}' not found", path))?;
                    }
                    Value::Array(arr) => {
                        let idx: usize = seg
                            .parse()
                            .map_err(|_| format!("Invalid array index '{}'", seg))?;
                        current = arr
                            .get_mut(idx)
                            .ok_or_else(|| format!("Index {} not found", idx))?;
                    }
                    _ => return Err(format!("Cannot patch non-container node at '{}'", seg)),
                }
            }
            current
        }
    };

    match (target, patch_val) {
        (Value::Object(orig_map), Value::Object(new_map)) => {
            for (k, v) in new_map {
                orig_map.insert(k, v);
            }
            Ok(())
        }
        _ => Err("PATCH target and payload must both be JSON objects".into()),
    }
}

/// Deletes a value at the specified path.
pub fn delete_path(root: &mut Value, path: &str) -> Result<(), String> {
    let segments = parse_path_segments(path);
    if segments.is_empty() {
        return Err("Cannot delete root configuration".into());
    }

    let mut current = root;
    let len = segments.len();

    for (i, seg) in segments.iter().enumerate() {
        if i == len - 1 {
            match current {
                Value::Object(map) => {
                    if map.remove(*seg).is_some() {
                        return Ok(());
                    } else {
                        return Err(format!("Field '{}' not found", seg));
                    }
                }
                Value::Array(arr) => {
                    let idx: usize = seg
                        .parse()
                        .map_err(|_| format!("Invalid array index '{}'", seg))?;
                    if idx < arr.len() {
                        arr.remove(idx);
                        return Ok(());
                    } else {
                        return Err(format!("Index {} out of bounds", idx));
                    }
                }
                _ => return Err(format!("Cannot delete from non-container at '{}'", seg)),
            }
        } else {
            match current {
                Value::Object(map) => {
                    current = map
                        .get_mut(*seg)
                        .ok_or_else(|| format!("Path segment '{}' not found", seg))?;
                }
                Value::Array(arr) => {
                    let idx: usize = seg
                        .parse()
                        .map_err(|_| format!("Invalid index '{}'", seg))?;
                    current = arr
                        .get_mut(idx)
                        .ok_or_else(|| format!("Index {} not found", idx))?;
                }
                _ => return Err(format!("Cannot descend into non-container at '{}'", seg)),
            }
        }
    }

    Ok(())
}

/// Helper to extract host:port from URL or host string.
fn extract_host_port(s: &str) -> String {
    let s = s.trim();
    if let Some(idx) = s.find("://") {
        let rest = &s[idx + 3..];
        let host_port = rest.split('/').next().unwrap_or(rest);
        host_port.to_lowercase()
    } else {
        let host_port = s.split('/').next().unwrap_or(s);
        host_port.to_lowercase()
    }
}

/// Checks if client Host header matches one of the allowed origins (case-insensitive).
pub fn check_host(host_header: &str, allowed_origins: &[&str]) -> Result<(), String> {
    let host_norm = extract_host_port(host_header);
    for &allowed in allowed_origins {
        let allowed_norm = extract_host_port(allowed);
        if host_norm == allowed_norm {
            return Ok(());
        }
    }
    Err(format!("Host '{}' not allowed", host_header))
}

/// Checks if origin URL is allowed (host comparison case-insensitive per RFC 3986 §3.2.2).
pub fn origin_allowed(origin: &str, allowed_origins: &[&str]) -> bool {
    let origin_norm = extract_host_port(origin);
    for &allowed in allowed_origins {
        let allowed_norm = extract_host_port(allowed);
        if origin_norm == allowed_norm {
            return true;
        }
    }
    false
}

/// Implements Caddy's unsyncedConfigAccess REST operations directly on a raw JSON Value.
pub fn unsynced_config_access(
    root: &mut Value,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<Option<Value>, String> {
    let payload: Option<Value> = if !body.is_empty() {
        let val: Value =
            serde_json::from_slice(body).map_err(|e| format!("decoding request body: {}", e))?;
        Some(val)
    } else {
        None
    };

    let clean_path = path.trim_matches('/');
    if clean_path.is_empty() {
        if method == "POST" {
            if let Some(val) = payload {
                *root = val;
                return Ok(None);
            }
        }
        return Err("no traversable path".into());
    }

    let mut parts: Vec<&str> = clean_path.split('/').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return Err("path missing".into());
    }

    let ellipses = parts.last() == Some(&"...");
    if ellipses {
        parts.pop();
    }

    let mut current = root;
    let num_parts = parts.len();

    for (i, &part) in parts.iter().enumerate() {
        let is_last = i == num_parts - 1;
        let is_second_to_last = num_parts >= 2 && i == num_parts - 2;

        match current {
            Value::Object(map) => {
                if !map.contains_key(part) {
                    if method == "POST" && is_last {
                        map.insert(part.to_string(), payload.clone().unwrap_or(Value::Null));
                        return Ok(None);
                    } else if method == "PUT" && is_last {
                        map.insert(part.to_string(), payload.clone().unwrap_or(Value::Null));
                        return Ok(None);
                    } else if method == "DELETE" && is_last {
                        return Err(format!("key does not exist: {}", part));
                    } else if method == "PATCH" && is_last {
                        return Err(format!("key does not exist: {}", part));
                    } else {
                        return Err(format!("path segment '{}' not found", part));
                    }
                }

                if is_second_to_last && map.get(part).map(|v| v.is_array()).unwrap_or(false) {
                    let arr = map.get_mut(part).unwrap().as_array_mut().unwrap();
                    let idx_str = parts[i + 1];
                    let idx: usize = idx_str
                        .parse()
                        .map_err(|_| format!("invalid array index '{}'", idx_str))?;

                    match method {
                        "GET" => {
                            if idx >= arr.len() {
                                return Err("array index out of bounds".into());
                            }
                            return Ok(Some(arr[idx].clone()));
                        }
                        "POST" => {
                            if ellipses {
                                let val_arr = payload
                                    .and_then(|v| v.as_array().cloned())
                                    .ok_or("final element is not an array")?;
                                arr.extend(val_arr);
                            } else {
                                arr.push(payload.unwrap_or(Value::Null));
                            }
                            return Ok(None);
                        }
                        "PUT" => {
                            if idx > arr.len() {
                                return Err("array index out of bounds".into());
                            }
                            arr.insert(idx, payload.unwrap_or(Value::Null));
                            return Ok(None);
                        }
                        "PATCH" => {
                            if idx >= arr.len() {
                                return Err("array index out of bounds".into());
                            }
                            arr[idx] = payload.unwrap_or(Value::Null);
                            return Ok(None);
                        }
                        "DELETE" => {
                            if idx >= arr.len() {
                                return Err("array index out of bounds".into());
                            }
                            arr.remove(idx);
                            return Ok(None);
                        }
                        _ => return Err(format!("unrecognized method {}", method)),
                    }
                }

                if is_last {
                    match method {
                        "GET" => return Ok(Some(map.get(part).cloned().unwrap_or(Value::Null))),
                        "POST" => {
                            let entry = map.get_mut(part).unwrap();
                            if let Value::Array(arr) = entry {
                                if ellipses {
                                    let val_arr = payload
                                        .and_then(|v| v.as_array().cloned())
                                        .ok_or("final element is not an array")?;
                                    arr.extend(val_arr);
                                } else {
                                    arr.push(payload.unwrap_or(Value::Null));
                                }
                            } else {
                                *entry = payload.unwrap_or(Value::Null);
                            }
                            return Ok(None);
                        }
                        "PUT" => {
                            return Err(format!("key already exists: {}", part));
                        }
                        "PATCH" => {
                            *map.get_mut(part).unwrap() = payload.unwrap_or(Value::Null);
                            return Ok(None);
                        }
                        "DELETE" => {
                            map.remove(part);
                            return Ok(None);
                        }
                        _ => return Err(format!("unrecognized method {}", method)),
                    }
                }

                current = map.get_mut(part).unwrap();
            }
            Value::Array(arr) => {
                let idx: usize = part
                    .parse()
                    .map_err(|_| format!("invalid array index '{}'", part))?;
                if is_last {
                    match method {
                        "GET" => {
                            if idx >= arr.len() {
                                return Err("array index out of bounds".into());
                            }
                            return Ok(Some(arr[idx].clone()));
                        }
                        "PUT" => {
                            if idx > arr.len() {
                                return Err("array index out of bounds".into());
                            }
                            arr.insert(idx, payload.unwrap_or(Value::Null));
                            return Ok(None);
                        }
                        "PATCH" => {
                            if idx >= arr.len() {
                                return Err("array index out of bounds".into());
                            }
                            arr[idx] = payload.unwrap_or(Value::Null);
                            return Ok(None);
                        }
                        "DELETE" => {
                            if idx >= arr.len() {
                                return Err("array index out of bounds".into());
                            }
                            arr.remove(idx);
                            return Ok(None);
                        }
                        _ => return Err(format!("unrecognized method {}", method)),
                    }
                }
                if idx >= arr.len() {
                    return Err("array index out of bounds".into());
                }
                current = &mut arr[idx];
            }
            _ => return Err(format!("cannot descend into non-container at '{}'", part)),
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_path_segments() {
        assert_eq!(
            parse_path_segments("/apps/http/servers/"),
            vec!["apps", "http", "servers"]
        );
        assert_eq!(
            parse_path_segments("logging/logs/default"),
            vec!["logging", "logs", "default"]
        );
        assert_eq!(parse_path_segments("///"), Vec::<&str>::new());
    }

    #[test]
    fn test_get_and_set_path() {
        let mut config = json!({
            "apps": {
                "http": {
                    "servers": {
                        "srv0": {
                            "listen": [":80", ":443"]
                        }
                    }
                }
            }
        });

        // Get existing
        let res = get_path(&config, "/apps/http/servers/srv0/listen/0");
        assert_eq!(res, Some(&json!(":80")));

        // Get non-existing
        assert_eq!(get_path(&config, "/apps/http/non_existent"), None);

        // Set value
        set_path(
            &mut config,
            "/apps/http/servers/srv0/listen/0",
            json!(":8080"),
        )
        .unwrap();
        assert_eq!(
            get_path(&config, "/apps/http/servers/srv0/listen/0"),
            Some(&json!(":8080"))
        );

        // Set nested new path
        set_path(
            &mut config,
            "/apps/tls/automation/policies/0",
            json!({"tag": "local"}),
        )
        .unwrap();
        assert_eq!(
            get_path(&config, "/apps/tls/automation/policies/0/tag"),
            Some(&json!("local"))
        );
    }

    #[test]
    fn test_patch_and_delete_path() {
        let mut config = json!({
            "logging": {
                "logs": {
                    "default": {
                        "level": "INFO",
                        "writer": "stdout"
                    }
                }
            }
        });

        // Patch default log
        patch_path(
            &mut config,
            "/logging/logs/default",
            json!({"level": "DEBUG", "new_opt": true}),
        )
        .unwrap();
        assert_eq!(
            get_path(&config, "/logging/logs/default/level"),
            Some(&json!("DEBUG"))
        );
        assert_eq!(
            get_path(&config, "/logging/logs/default/writer"),
            Some(&json!("stdout"))
        );
        assert_eq!(
            get_path(&config, "/logging/logs/default/new_opt"),
            Some(&json!(true))
        );

        // Delete field
        delete_path(&mut config, "/logging/logs/default/writer").unwrap();
        assert_eq!(get_path(&config, "/logging/logs/default/writer"), None);

        // Delete parent container
        delete_path(&mut config, "/logging").unwrap();
        assert_eq!(get_path(&config, "/logging"), None);
    }
}
