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
                _ => return Err(format!("Cannot set field on non-container node at '{}'", seg)),
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
                        current = map.get_mut(seg).ok_or_else(|| format!("Path '{}' not found", path))?;
                    }
                    Value::Array(arr) => {
                        let idx: usize = seg.parse().map_err(|_| format!("Invalid array index '{}'", seg))?;
                        current = arr.get_mut(idx).ok_or_else(|| format!("Index {} not found", idx))?;
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
                    let idx: usize = seg.parse().map_err(|_| format!("Invalid array index '{}'", seg))?;
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
                    current = map.get_mut(*seg).ok_or_else(|| format!("Path segment '{}' not found", seg))?;
                }
                Value::Array(arr) => {
                    let idx: usize = seg.parse().map_err(|_| format!("Invalid index '{}'", seg))?;
                    current = arr.get_mut(idx).ok_or_else(|| format!("Index {} not found", idx))?;
                }
                _ => return Err(format!("Cannot descend into non-container at '{}'", seg)),
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_path_segments() {
        assert_eq!(parse_path_segments("/apps/http/servers/"), vec!["apps", "http", "servers"]);
        assert_eq!(parse_path_segments("logging/logs/default"), vec!["logging", "logs", "default"]);
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
        set_path(&mut config, "/apps/http/servers/srv0/listen/0", json!(":8080")).unwrap();
        assert_eq!(get_path(&config, "/apps/http/servers/srv0/listen/0"), Some(&json!(":8080")));

        // Set nested new path
        set_path(&mut config, "/apps/tls/automation/policies/0", json!({"tag": "local"})).unwrap();
        assert_eq!(get_path(&config, "/apps/tls/automation/policies/0/tag"), Some(&json!("local")));
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
        patch_path(&mut config, "/logging/logs/default", json!({"level": "DEBUG", "new_opt": true})).unwrap();
        assert_eq!(get_path(&config, "/logging/logs/default/level"), Some(&json!("DEBUG")));
        assert_eq!(get_path(&config, "/logging/logs/default/writer"), Some(&json!("stdout")));
        assert_eq!(get_path(&config, "/logging/logs/default/new_opt"), Some(&json!(true)));

        // Delete field
        delete_path(&mut config, "/logging/logs/default/writer").unwrap();
        assert_eq!(get_path(&config, "/logging/logs/default/writer"), None);

        // Delete parent container
        delete_path(&mut config, "/logging").unwrap();
        assert_eq!(get_path(&config, "/logging"), None);
    }
}
