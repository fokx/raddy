use crate::lexer::Span;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Caddyfile {
    pub global_options: Option<GlobalOptionsNode>,
    pub snippets: HashMap<String, SnippetNode>,
    pub named_routes: HashMap<String, NamedRouteNode>,
    pub site_blocks: Vec<SiteBlockNode>,
    pub imports: Vec<DirectiveNode>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GlobalOptionsNode {
    pub options: Vec<DirectiveNode>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SnippetNode {
    pub name: String,
    pub directives: Vec<DirectiveNode>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NamedRouteNode {
    pub name: String,
    pub directives: Vec<DirectiveNode>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SiteBlockNode {
    pub addresses: Vec<String>,
    pub directives: Vec<DirectiveNode>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DirectiveNode {
    pub name: String,
    pub matcher: Option<String>,
    pub args: Vec<String>,
    pub block: Option<Vec<DirectiveNode>>,
    pub span: Span,
}
