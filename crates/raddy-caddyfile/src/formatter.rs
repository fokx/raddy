use crate::ast::*;
use crate::error::ParseResult;
use crate::parse_caddyfile;

/// Formats a Caddyfile string into canonical Caddyfile syntax.
pub fn format_caddyfile_str(input: &str) -> ParseResult<String> {
    let ast = parse_caddyfile(input)?;
    Ok(format_caddyfile(&ast))
}

/// Formats a parsed `Caddyfile` AST into a canonically formatted string.
pub fn format_caddyfile(caddyfile: &Caddyfile) -> String {
    let mut out = String::new();
    let mut needs_spacing = false;

    // 1. Global options block
    if let Some(ref global) = caddyfile.global_options {
        out.push_str("{\n");
        for opt in &global.options {
            format_directive(opt, 1, &mut out);
        }
        out.push_str("}\n");
        needs_spacing = true;
    }

    // 2. Snippets
    let mut sorted_snippets: Vec<_> = caddyfile.snippets.iter().collect();
    sorted_snippets.sort_by_key(|(name, _)| *name);
    for (name, snippet) in sorted_snippets {
        if needs_spacing {
            out.push('\n');
        }
        out.push_str(&format!("({}) {{\n", name));
        for dir in &snippet.directives {
            format_directive(dir, 1, &mut out);
        }
        out.push_str("}\n");
        needs_spacing = true;
    }

    // 3. Named routes
    let mut sorted_routes: Vec<_> = caddyfile.named_routes.iter().collect();
    sorted_routes.sort_by_key(|(name, _)| *name);
    for (name, route) in sorted_routes {
        if needs_spacing {
            out.push('\n');
        }
        out.push_str(&format!("&({}) {{\n", name));
        for dir in &route.directives {
            format_directive(dir, 1, &mut out);
        }
        out.push_str("}\n");
        needs_spacing = true;
    }

    // 4. Site blocks
    for site in &caddyfile.site_blocks {
        if needs_spacing {
            out.push('\n');
        }

        let addrs = site.addresses.join(", ");
        if site.directives.is_empty() {
            out.push_str(&format!("{} {{\n}}\n", addrs));
        } else {
            out.push_str(&format!("{} {{\n", addrs));
            for dir in &site.directives {
                format_directive(dir, 1, &mut out);
            }
            out.push_str("}\n");
        }
        needs_spacing = true;
    }

    out
}

fn format_directive(dir: &DirectiveNode, indent: usize, out: &mut String) {
    let indent_str = "\t".repeat(indent);
    out.push_str(&indent_str);
    out.push_str(&dir.name);

    if let Some(ref m) = dir.matcher {
        out.push(' ');
        out.push_str(m);
    }

    for arg in &dir.args {
        out.push(' ');
        if arg.contains(' ') || arg.contains('\t') || arg.contains('"') || arg.is_empty() {
            out.push('"');
            out.push_str(&arg.replace('\\', "\\\\").replace('"', "\\\""));
            out.push('"');
        } else {
            out.push_str(arg);
        }
    }

    if let Some(ref sub_block) = dir.block {
        out.push_str(" {\n");
        for sub_dir in sub_block {
            format_directive(sub_dir, indent + 1, out);
        }
        out.push_str(&indent_str);
        out.push_str("}\n");
    } else {
        out.push('\n');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_caddyfile() {
        let input = r#"
        localhost:8080 {
            root * /var/www
            file_server
            reverse_proxy /api/* 127.0.0.1:9000 {
                lb_policy round_robin
            }
        }
        "#;

        let formatted = format_caddyfile_str(input).unwrap();
        assert!(formatted.contains("localhost:8080 {\n"));
        assert!(formatted.contains("\troot * /var/www\n"));
        assert!(formatted.contains("\tfile_server\n"));
        assert!(formatted.contains("\treverse_proxy /api/* 127.0.0.1:9000 {\n"));
        assert!(formatted.contains("\t\tlb_policy round_robin\n"));
    }
}
