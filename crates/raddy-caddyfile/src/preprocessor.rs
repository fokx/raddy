use crate::ast::*;
use crate::env::replace_env_vars;
use crate::error::{ParseError, ParseResult};
use crate::lexer::Lexer;
use crate::parser::Parser;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

pub struct Preprocessor {
    snippets: HashMap<String, SnippetNode>,
    base_dir: PathBuf,
    import_stack: HashSet<String>,
}

impl Preprocessor {
    pub fn new(snippets: HashMap<String, SnippetNode>, base_dir: impl AsRef<Path>) -> Self {
        Self {
            snippets,
            base_dir: base_dir.as_ref().to_path_buf(),
            import_stack: HashSet::new(),
        }
    }

    /// Recursively expands all `import` directives across all site blocks and named routes.
    pub fn expand_caddyfile(&mut self, mut caddyfile: Caddyfile) -> ParseResult<Caddyfile> {
        // Collect snippets from the caddyfile into self.snippets
        for (k, v) in &caddyfile.snippets {
            self.snippets.insert(k.clone(), v.clone());
        }

        // Expand top-level imports
        let mut top_level_imports = std::mem::take(&mut caddyfile.imports);
        let mut top_level_import_stack = HashSet::new();
        while !top_level_imports.is_empty() {
            let next_imports = std::mem::take(&mut top_level_imports);
            for import_dir in next_imports {
                let target = import_dir
                    .args
                    .first()
                    .ok_or_else(|| ParseError::Import("Missing argument to import".into()))?;

                let is_glob = target.contains('*') || target.contains('?');
                if is_glob {
                    let matched_files = resolve_glob_files(&self.base_dir, target)?;
                    if matched_files.is_empty() {
                        tracing::warn!("No files matching import glob pattern: {}", target);
                        continue;
                    }
                    for file_path in matched_files {
                        let path_key = file_path.to_string_lossy().to_string();
                        if top_level_import_stack.contains(&path_key) {
                            return Err(ParseError::Import(format!(
                                "Circular import detected: '{}'",
                                path_key
                            )));
                        }
                        top_level_import_stack.insert(path_key);

                        let content = std::fs::read_to_string(&file_path).map_err(|e| {
                            ParseError::Import(format!(
                                "Failed to read imported file '{}': {}",
                                file_path.display(),
                                e
                            ))
                        })?;
                        let content = replace_env_vars(&content);

                        let tokens = Lexer::new(&content).tokenize()?;
                        let mut parser = Parser::new(tokens);
                        let imported_cf = parser.parse()?;

                        if caddyfile.global_options.is_none() && imported_cf.global_options.is_some() {
                            caddyfile.global_options = imported_cf.global_options;
                        }

                        for (k, v) in imported_cf.snippets {
                            self.snippets.insert(k.clone(), v.clone());
                            caddyfile.snippets.insert(k, v);
                        }

                        for site in imported_cf.site_blocks {
                            caddyfile.site_blocks.push(site);
                        }

                        for (k, v) in imported_cf.named_routes {
                            caddyfile.named_routes.insert(k, v);
                        }

                        for mut imp in imported_cf.imports {
                            if let Some(arg) = imp.args.first_mut() {
                                if !self.snippets.contains_key(arg) && Path::new(arg).is_relative() {
                                    if let Some(parent) = file_path.parent() {
                                        let resolved = parent.join(&*arg);
                                        *arg = resolved.to_string_lossy().to_string();
                                    }
                                }
                            }
                            top_level_imports.push(imp);
                        }
                    }
                    continue;
                }

                let file_path = if Path::new(target).is_absolute() {
                    PathBuf::from(target)
                } else {
                    self.base_dir.join(target)
                };

                if file_path.exists() && file_path.is_file() {
                    let path_key = file_path.to_string_lossy().to_string();
                    if top_level_import_stack.contains(&path_key) {
                        return Err(ParseError::Import(format!(
                            "Circular import detected: '{}'",
                            path_key
                        )));
                    }
                    top_level_import_stack.insert(path_key);

                    let content = std::fs::read_to_string(&file_path).map_err(|e| {
                        ParseError::Import(format!(
                            "Failed to read imported file '{}': {}",
                            file_path.display(),
                            e
                        ))
                    })?;
                    let content = replace_env_vars(&content);

                    let tokens = Lexer::new(&content).tokenize()?;
                    let mut parser = Parser::new(tokens);
                    let imported_cf = parser.parse()?;

                    if caddyfile.global_options.is_none() && imported_cf.global_options.is_some() {
                        caddyfile.global_options = imported_cf.global_options;
                    }

                    // Merge snippets
                    for (k, v) in imported_cf.snippets {
                        self.snippets.insert(k.clone(), v.clone());
                        caddyfile.snippets.insert(k, v);
                    }

                    // Merge site blocks
                    for site in imported_cf.site_blocks {
                        caddyfile.site_blocks.push(site);
                    }

                    // Merge named routes
                    for (k, v) in imported_cf.named_routes {
                        caddyfile.named_routes.insert(k, v);
                    }

                    // Top-level imports inside imported file
                    for mut imp in imported_cf.imports {
                        if let Some(arg) = imp.args.first_mut() {
                            if !self.snippets.contains_key(arg) && Path::new(arg).is_relative() {
                                if let Some(parent) = file_path.parent() {
                                    let resolved = parent.join(&*arg);
                                    *arg = resolved.to_string_lossy().to_string();
                                }
                            }
                        }
                        top_level_imports.push(imp);
                    }
                } else if let Some(snippet) = self.snippets.get(target).cloned() {
                    let args = if import_dir.args.len() > 1 {
                        &import_dir.args[1..]
                    } else {
                        &[]
                    };
                    let substituted = substitute_snippet_args(
                        &snippet.directives,
                        args,
                        import_dir.block.as_deref(),
                    );
                    for d in substituted {
                        if let Some(block) = d.block {
                            caddyfile.site_blocks.push(SiteBlockNode {
                                addresses: vec![d.name],
                                directives: block,
                                span: d.span,
                            });
                        }
                    }
                } else {
                    return Err(ParseError::Import(format!(
                        "Snippet or file not found for top-level import: '{}'",
                        target
                    )));
                }
            }
        }

        // Expand site blocks
        for site in &mut caddyfile.site_blocks {
            site.directives = self.expand_directive_list(&site.directives)?;
        }

        // Expand named routes
        for (_name, route) in &mut caddyfile.named_routes {
            route.directives = self.expand_directive_list(&route.directives)?;
        }

        Ok(caddyfile)
    }

    pub fn expand_directive_list(
        &mut self,
        directives: &[DirectiveNode],
    ) -> ParseResult<Vec<DirectiveNode>> {
        let mut expanded = Vec::new();

        for dir in directives {
            if dir.name == "import" {
                let target = dir
                    .args
                    .first()
                    .ok_or_else(|| ParseError::Import("Missing argument to import".into()))?;
                let args = if dir.args.len() > 1 {
                    &dir.args[1..]
                } else {
                    &[]
                };
                let block = dir.block.as_deref();

                let imported_dirs = self.resolve_import(target, args, block)?;
                expanded.extend(imported_dirs);
            } else {
                let mut dir_clone = dir.clone();
                if let Some(ref sub_dirs) = dir.block {
                    dir_clone.block = Some(self.expand_directive_list(sub_dirs)?);
                }
                expanded.push(dir_clone);
            }
        }

        Ok(expanded)
    }

    fn resolve_import(
        &mut self,
        target: &str,
        args: &[String],
        block: Option<&[DirectiveNode]>,
    ) -> ParseResult<Vec<DirectiveNode>> {
        if let Some(snippet) = self.snippets.get(target).cloned() {
            let snippet_key = format!("snippet:{}", target);
            if self.import_stack.contains(&snippet_key) {
                return Err(ParseError::Import(format!(
                    "Circular import detected: '{}'",
                    target
                )));
            }
            self.import_stack.insert(snippet_key.clone());
            let substituted = substitute_snippet_args(&snippet.directives, args, block);
            let res = self.expand_directive_list(&substituted);
            self.import_stack.remove(&snippet_key);
            return res;
        }

        let is_glob = target.contains('*') || target.contains('?');
        if is_glob {
            let matched_files = resolve_glob_files(&self.base_dir, target)?;
            if matched_files.is_empty() {
                tracing::warn!("No files matching import glob pattern: {}", target);
                return Ok(Vec::new());
            }
            let mut all_dirs = Vec::new();
            for file_path in matched_files {
                let path_key = file_path.to_string_lossy().to_string();
                if self.import_stack.contains(&path_key) {
                    return Err(ParseError::Import(format!(
                        "Circular import detected: '{}'",
                        path_key
                    )));
                }
                self.import_stack.insert(path_key.clone());

                let content = std::fs::read_to_string(&file_path).map_err(|e| {
                    ParseError::Import(format!(
                        "Failed to read imported file '{}': {}",
                        file_path.display(),
                        e
                    ))
                })?;
                let content = replace_env_vars(&content);

                let tokens = Lexer::new(&content).tokenize()?;
                let mut parser = Parser::new(tokens);
                let (snippets, dirs) = parser.parse_imported_directives()?;

                for (k, v) in snippets {
                    self.snippets.insert(k, v);
                }

                let old_base_dir = self.base_dir.clone();
                if let Some(parent) = file_path.parent() {
                    self.base_dir = parent.to_path_buf();
                }
                let substituted = substitute_snippet_args(&dirs, args, block);
                let expanded_res = self.expand_directive_list(&substituted);
                self.base_dir = old_base_dir;
                self.import_stack.remove(&path_key);

                all_dirs.extend(expanded_res?);
            }
            return Ok(all_dirs);
        }

        let file_path = if Path::new(target).is_absolute() {
            PathBuf::from(target)
        } else {
            self.base_dir.join(target)
        };
        if file_path.exists() && file_path.is_file() {
            let path_key = file_path.to_string_lossy().to_string();
            if self.import_stack.contains(&path_key) {
                return Err(ParseError::Import(format!(
                    "Circular import detected: '{}'",
                    path_key
                )));
            }
            self.import_stack.insert(path_key.clone());

            let content = std::fs::read_to_string(&file_path).map_err(|e| {
                ParseError::Import(format!(
                    "Failed to read imported file '{}': {}",
                    file_path.display(),
                    e
                ))
            })?;
            let content = replace_env_vars(&content);

            let tokens = Lexer::new(&content).tokenize()?;
            let mut parser = Parser::new(tokens);
            let (snippets, dirs) = parser.parse_imported_directives()?;

            // Collect snippets defined in the imported file
            for (k, v) in snippets {
                self.snippets.insert(k, v);
            }

            let old_base_dir = self.base_dir.clone();
            if let Some(parent) = file_path.parent() {
                self.base_dir = parent.to_path_buf();
            }
            let substituted = substitute_snippet_args(&dirs, args, block);
            let expanded_res = self.expand_directive_list(&substituted);
            self.base_dir = old_base_dir;
            self.import_stack.remove(&path_key);

            expanded_res
        } else {
            Err(ParseError::Import(format!(
                "Snippet or file not found for import: '{}'",
                target
            )))
        }
    }
}

fn resolve_glob_files(base_dir: &Path, target: &str) -> ParseResult<Vec<PathBuf>> {
    let full_path = if Path::new(target).is_absolute() {
        PathBuf::from(target)
    } else {
        base_dir.join(target)
    };

    let pattern_str = full_path.to_string_lossy();
    let paths = glob::glob(&pattern_str).map_err(|e| {
        ParseError::Import(format!("Invalid import glob pattern '{}': {}", target, e))
    })?;

    let mut matches = Vec::new();
    for entry in paths {
        match entry {
            Ok(p) => {
                if let Some(file_name) = p.file_name().and_then(|n| n.to_str()) {
                    if !file_name.starts_with('.') && p.is_file() {
                        matches.push(p);
                    }
                }
            }
            Err(e) => {
                return Err(ParseError::Import(format!(
                    "Failed to match import glob: {}",
                    e
                )));
            }
        }
    }
    matches.sort();
    Ok(matches)
}

fn substitute_snippet_args(
    directives: &[DirectiveNode],
    args: &[String],
    block: Option<&[DirectiveNode]>,
) -> Vec<DirectiveNode> {
    let mut out = Vec::new();

    for dir in directives {
        if dir.name == "{block}" {
            if let Some(block_dirs) = block {
                out.extend(block_dirs.iter().cloned());
            }
            continue;
        }

        let mut new_dir = dir.clone();
        new_dir.name = replace_args(&dir.name, args);
        new_dir.args = dir.args.iter().map(|arg| replace_args(arg, args)).collect();
        if let Some(ref matcher) = dir.matcher {
            new_dir.matcher = Some(replace_args(matcher, args));
        }
        if let Some(ref sub_block) = dir.block {
            new_dir.block = Some(substitute_snippet_args(sub_block, args, block));
        }
        out.push(new_dir);
    }

    out
}

fn replace_args(input: &str, args: &[String]) -> String {
    let mut out = input.to_string();
    for (i, arg) in args.iter().enumerate() {
        let placeholder = format!("{{args.{}}}", i);
        out = out.replace(&placeholder, arg);
        let placeholder_bracket = format!("{{args[{}]}}", i);
        out = out.replace(&placeholder_bracket, arg);
    }
    let all_args = args.join(" ");
    out = out.replace("{args...}", &all_args);
    out = out.replace("{block}", "");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snippet_expansion() {
        let mut snippets = HashMap::new();
        snippets.insert(
            "responder".into(),
            SnippetNode {
                name: "responder".into(),
                directives: vec![DirectiveNode {
                    name: "respond".into(),
                    matcher: None,
                    args: vec!["{args.0}".into(), "{args.1}".into()],
                    block: None,
                    span: Default::default(),
                }],
                span: Default::default(),
            },
        );

        let mut prep = Preprocessor::new(snippets, ".");
        let dirs = vec![DirectiveNode {
            name: "import".into(),
            matcher: None,
            args: vec!["responder".into(), "hello world".into(), "200".into()],
            block: None,
            span: Default::default(),
        }];

        let expanded = prep.expand_directive_list(&dirs).unwrap();
        assert_eq!(expanded.len(), 1);
        assert_eq!(expanded[0].name, "respond");
        assert_eq!(expanded[0].args, vec!["hello world", "200"]);
    }
}
