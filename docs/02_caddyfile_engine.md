# Chapter 2: Caddyfile Engine & Parser (`raddy-caddyfile`)

## 1. Caddyfile Grammar Specification

The Caddyfile is a human-friendly configuration format designed for intuitive website and reverse proxy administration.

```text
Caddyfile     = GlobalOptions? (SiteBlock | Snippet | NamedRoute)*
GlobalOptions = "{" GlobalDirective* "}"
SiteBlock     = Address+ "{" Directive* "}"
              | Address+ Directive
Snippet       = "(" name ")" "{" Directive* "}"
NamedRoute    = "&(" name ")" "{" Directive* "}"
Directive     = name Matcher? Arg* Block?
Block         = "{" Directive* "}"
Matcher       = "/" path | "@name" | "*" | (none)
Address       = [scheme://] host [:port] [/path]
```

---

## 2. Parsing Pipeline

The `raddy-caddyfile` crate translates raw Caddyfile text into the structured `raddy_core::config::Config` model through four stages:

```mermaid
flowchart LR
    Text["Caddyfile Text"] --> Lexer["Lexer
(tokenize)"]
    Lexer --> Dispenser["Token Dispenser
(cursor traversal)"]
    Dispenser --> Parser["Recursive-Descent Parser
(AST generation)"]
    Parser --> Preprocessor["Preprocessor
(snippets & imports)"]
    Preprocessor --> Adapter["Adapter Pipeline
(JSON Config emission)"]
```

### 1. Lexer (`raddy_caddyfile::lexer`)
- Character-by-character tokenization handling single and double quotes, backslash escapes, block comments (`#`), and heredocs (`<<EOF ... EOF`).
- Preserves token line numbers and character offsets for precise syntax error reporting.

### 2. Token Dispenser (`raddy_caddyfile::dispenser`)
- Cursor-based token stream traversal modeled after Caddy's Go `caddyfile.Dispenser`.
- Primitives: `next()`, `next_arg()`, `next_line()`, `next_block()`, `remaining_args()`.

### 3. AST Parser (`raddy_caddyfile::parser`, `raddy_caddyfile::ast`)
- Parses blocks, nested blocks, arguments, directives, and site declarations into an abstract syntax tree.

### 4. Preprocessor (`raddy_caddyfile::preprocessor`)
- **Import Expansion**: Evaluates `import` directives with file path resolution and wildcard glob matching (e.g. `import sites-enabled/*.conf`).
- **Snippet Argument Substitution**: Replaces `{args[0]}`, `{args[1]}`, and variadic `{args...}` within reusable snippet blocks.
- **Snippet Block Insertion**: Expands `{block}` placeholders with nested configuration blocks passed to snippets.

---

## 3. Adapter Pipeline (`raddy_caddyfile::adapter`)

The adapter converts the preprocessed AST into the internal `Config`:
1. **Global Options Extraction**: Reads `email`, `acme_ca`, `local_certs`, `http_port`, `https_port`, `auto_https`, `admin`, and global `servers` options.
2. **Site Address Normalization**: Normalizes schemes, ports, and wildcard hostnames.
3. **Directive Ordering**: Reorders directives into standard Caddy priority:
   ```text
   bind -> root -> handle_path -> handle -> basic_auth -> rewrite ->
   method -> vars -> try_files -> encode -> templates ->
   reverse_proxy -> forward_proxy -> file_server -> respond
   ```
4. **Named Matcher Synthesis**: Supports both multi-line named matcher blocks (`@api { ... }`) and single-line shorthands (`@api path /api/*`).
5. **Automatic Port 80 Redirects**: Synthesizes HTTP-to-HTTPS redirect servers when TLS is active.

---

## 4. Canonical Formatter (`raddy_caddyfile::formatter`)

The AST-based formatter normalizes Caddyfiles to canonical syntax (`raddy fmt`):
- Consistent 4-space indentation for directive blocks.
- Cleans trailing whitespace and collapses consecutive blank lines.
- Supports in-place file formatting with `--overwrite`.
