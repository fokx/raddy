use async_trait::async_trait;
use raddy_core::context::Context;
use raddy_core::error::Result;
use raddy_core::handler::Handler;
use raddy_core::placeholder::eval_placeholders;

/// Variable mapping handler.
pub struct MapHandler {
    pub source_template: String,
    pub dest_var: String,
    pub mappings: Vec<(String, String)>,
    pub default: Option<String>,
}

impl MapHandler {
    pub fn new(
        source_template: impl Into<String>,
        dest_var: impl Into<String>,
        mappings: Vec<(String, String)>,
        default: Option<String>,
    ) -> Self {
        let dest = dest_var.into();
        let clean_dest = dest
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .unwrap_or(&dest)
            .to_string();

        Self {
            source_template: source_template.into(),
            dest_var: clean_dest,
            mappings,
            default,
        }
    }

    fn matches_pattern(pattern: &str, value: &str) -> bool {
        if pattern == value {
            return true;
        }
        if let Some(prefix) = pattern.strip_suffix('*') {
            return value.starts_with(prefix);
        }
        if let Some(suffix) = pattern.strip_prefix('*') {
            return value.ends_with(suffix);
        }
        false
    }
}

#[async_trait]
impl Handler for MapHandler {
    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        let source_val = eval_placeholders(&self.source_template, ctx);

        let mut matched_val = None;
        for (pattern, val) in &self.mappings {
            if Self::matches_pattern(pattern, &source_val) {
                matched_val = Some(val.clone());
                break;
            }
        }

        let final_val = matched_val
            .or_else(|| self.default.clone())
            .unwrap_or_default();

        let evaluated_final = eval_placeholders(&final_val, ctx);
        ctx.vars.insert(self.dest_var.clone(), evaluated_final);

        Ok(())
    }
}
