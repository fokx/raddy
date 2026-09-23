use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use crate::ast::*;
use crate::error::{ParseError, ParseResult};
use crate::lexer::Lexer;
use crate::parser::Parser;

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

    pub fn expand_directive_list(&mut self, directives: &[DirectiveNode]) -> ParseResult<Vec<DirectiveNode>> {
        let mut expanded = Vec::new();

        for dir in directives {
            if dir.name == "import" {
                let target = dir.args.first().ok_or_else(|| ParseError::Import("Missing argument to import".into()))?;
                let args = if dir.args.len() > 1 {
                    &dir.args[1..]
                } else {
                    &[]
                };

                let imported_dirs = self.resolve_import(target, args)?;
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

    fn resolve_import(&mut self, target: &str, args: &[String]) -> ParseResult<Vec<DirectiveNode>> {
        if self.import_stack.contains(target) {
            return Err(ParseError::Import(format!(
                "Circular import detected: '{}'",
                target
            )));
        }

        self.import_stack.insert(target.to_string());

        let result = if let Some(snippet) = self.snippets.get(target).cloned() {
            // Snippet import: substitute {args.0}, {args.1}, etc.
            let substituted = substitute_snippet_args(&snippet.directives, args);
            self.expand_directive_list(&substituted)
        } else {
            // File import
            let file_path = self.base_dir.join(target);
            if file_path.exists() && file_path.is_file() {
                let content = std::fs::read_to_string(&file_path)
                    .map_err(|e| ParseError::Import(format!("Failed to read imported file '{}': {}", file_path.display(), e)))?;

                let tokens = Lexer::new(&content).tokenize()?;
                let mut parser = Parser::new(tokens);
                let imported_cf = parser.parse()?;

                // An imported file could be a list of directives inside a site block, or a standalone snippet/site.
                // If it has site blocks, take directives of the first site block, or top-level directives.
                let mut dirs = Vec::new();
                for site in imported_cf.site_blocks {
                    dirs.extend(site.directives);
                }
                self.expand_directive_list(&dirs)
            } else {
                Err(ParseError::Import(format!(
                    "Snippet or file not found for import: '{}'",
                    target
                )))
            }
        };

        self.import_stack.remove(target);
        result
    }
}

fn substitute_snippet_args(directives: &[DirectiveNode], args: &[String]) -> Vec<DirectiveNode> {
    directives
        .iter()
        .map(|dir| {
            let mut new_dir = dir.clone();
            new_dir.args = dir.args.iter().map(|arg| replace_args(arg, args)).collect();
            if let Some(ref matcher) = dir.matcher {
                new_dir.matcher = Some(replace_args(matcher, args));
            }
            if let Some(ref block) = dir.block {
                new_dir.block = Some(substitute_snippet_args(block, args));
            }
            new_dir
        })
        .collect()
}

fn replace_args(input: &str, args: &[String]) -> String {
    let mut out = input.to_string();
    for (i, arg) in args.iter().enumerate() {
        let placeholder = format!("{{args.{}}}", i);
        out = out.replace(&placeholder, arg);
    }
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
