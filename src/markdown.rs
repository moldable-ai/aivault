use serde_json::Value;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToMarkdownOptions {
    pub namespace: Option<String>,
    pub exclude_fields: Vec<String>,
    pub wrap_fields: Vec<String>,
}

pub fn to_markdown(data: &Value, options: &ToMarkdownOptions) -> String {
    let content = render_value(data, options, None, true);
    if content.is_empty() {
        return String::new();
    }

    let Some(namespace) = options
        .namespace
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    else {
        return content;
    };

    format!("<begin {namespace}>\n{content}\n</end {namespace}>\n")
}

fn render_value(
    data: &Value,
    options: &ToMarkdownOptions,
    key: Option<&str>,
    top_level: bool,
) -> String {
    match data {
        Value::Null => String::new(),
        Value::Bool(v) => v.to_string(),
        Value::Number(v) => v.to_string(),
        Value::String(v) => {
            if v.trim().is_empty() {
                "None".to_string()
            } else if !top_level {
                if let Some(key) = key {
                    if options.wrap_fields.iter().any(|f| f == key) {
                        return format!("<begin {key}>\n{v}\n</end {key}>");
                    }
                }
                v.to_string()
            } else {
                v.to_string()
            }
        }
        Value::Array(items) => {
            if items.is_empty() {
                return "None".to_string();
            }

            // Array of objects: render each item as its own section.
            if items.iter().all(|item| matches!(item, Value::Object(_))) {
                let mut blocks = Vec::new();
                for item in items {
                    blocks.push(render_object(item, options, false));
                }
                return blocks.join("\n\n");
            }

            // Array of primitives.
            let mut lines = Vec::new();
            for item in items {
                match item {
                    Value::Null => lines.push("  - None".to_string()),
                    Value::Bool(v) => lines.push(format!("  - {v}")),
                    Value::Number(v) => lines.push(format!("  - {v}")),
                    Value::String(v) => {
                        let v = if v.trim().is_empty() { "None" } else { v };
                        lines.push(format!("  - {v}"))
                    }
                    other => {
                        // Mixed/nested: wrap the whole thing.
                        let key = key.unwrap_or("items");
                        let nested = render_value(other, options, Some(key), false);
                        return format!("<begin {key}>\n{nested}\n</end {key}>");
                    }
                }
            }
            lines.join("\n")
        }
        Value::Object(_) => render_object(data, options, top_level),
    }
}

fn render_object(data: &Value, options: &ToMarkdownOptions, top_level: bool) -> String {
    let Value::Object(map) = data else {
        return String::new();
    };
    if map.is_empty() {
        return "None".to_string();
    }

    let mut out = String::new();
    for (key, value) in map {
        if options.exclude_fields.iter().any(|f| f == key) {
            continue;
        }

        let title = to_title_case(key);
        let rendered = match value {
            Value::Null => "None".to_string(),
            Value::Array(items) if items.is_empty() => "None".to_string(),
            Value::Object(obj) if obj.is_empty() => "None".to_string(),
            Value::String(v) if v.trim().is_empty() => "None".to_string(),
            Value::Array(items) if items.iter().all(|item| matches!(item, Value::Object(_))) => {
                let nested = render_value(value, options, Some(key), false);
                format!("<begin {key}>\n{nested}\n</end {key}>")
            }
            Value::Object(_) => {
                let nested = render_value(value, options, Some(key), false);
                format!("<begin {key}>\n{nested}\n</end {key}>")
            }
            other => render_value(other, options, Some(key), false),
        };

        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&format!("# {title}\n\n{rendered}\n"));
    }

    if out.trim().is_empty() {
        if top_level {
            String::new()
        } else {
            "None".to_string()
        }
    } else {
        out.trim_end().to_string()
    }
}

fn to_title_case(input: &str) -> String {
    let mut words = Vec::new();
    let mut current = String::new();
    for ch in input.chars() {
        if ch == '_' || ch == '-' {
            if !current.is_empty() {
                words.push(current.clone());
                current.clear();
            }
            continue;
        }
        current.push(ch);
    }
    if !current.is_empty() {
        words.push(current);
    }

    words
        .into_iter()
        .filter(|w| !w.is_empty())
        .map(|word| {
            let mut chars = word.chars();
            let Some(first) = chars.next() else {
                return word;
            };
            let mut out = String::new();
            out.push(first.to_ascii_uppercase());
            out.push_str(chars.as_str());
            out
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn to_markdown_wraps_namespace_top_level() {
        let input = json!({"title":"Main"});
        let md = to_markdown(
            &input,
            &ToMarkdownOptions {
                namespace: Some("data".to_string()),
                ..Default::default()
            },
        );
        assert!(md.starts_with("<begin data>"));
        assert!(md.contains("# Title"));
        assert!(md.contains("Main"));
        assert!(md.trim_end().ends_with("</end data>"));
    }

    #[test]
    fn to_markdown_excludes_fields() {
        let input = json!({"title":"Main","secret":"nope"});
        let md = to_markdown(
            &input,
            &ToMarkdownOptions {
                exclude_fields: vec!["secret".to_string()],
                ..Default::default()
            },
        );
        assert!(md.contains("# Title"));
        assert!(!md.contains("secret"));
        assert!(!md.contains("nope"));
    }

    #[test]
    fn to_markdown_wrap_fields_preserves_markdown_content() {
        let input = json!({"description":"## Header\n\n- Item"});
        let md = to_markdown(
            &input,
            &ToMarkdownOptions {
                wrap_fields: vec!["description".to_string()],
                ..Default::default()
            },
        );
        assert!(md.contains("# Description"));
        assert!(md.contains("<begin description>"));
        assert!(md.contains("## Header"));
        assert!(md.contains("</end description>"));
    }

    #[test]
    fn to_markdown_array_of_primitives_is_bulleted() {
        let input = json!({"tags":["important","urgent"]});
        let md = to_markdown(&input, &ToMarkdownOptions::default());
        assert!(md.contains("# Tags"));
        assert!(md.contains("  - important"));
        assert!(md.contains("  - urgent"));
    }

    #[test]
    fn to_markdown_nested_object_is_wrapped() {
        let input = json!({"meta":{"a":1}});
        let md = to_markdown(&input, &ToMarkdownOptions::default());
        assert!(md.contains("# Meta"));
        assert!(md.contains("<begin meta>"));
        assert!(md.contains("# A"));
        assert!(md.contains("1"));
        assert!(md.contains("</end meta>"));
    }

    #[test]
    fn to_markdown_null_and_empty_values_render_as_none() {
        let input = json!({"a":null,"b":"","c":[],"d":{}});
        let md = to_markdown(&input, &ToMarkdownOptions::default());
        assert!(md.contains("# A\n\nNone"));
        assert!(md.contains("# B\n\nNone"));
        assert!(md.contains("# C\n\nNone"));
        assert!(md.contains("# D\n\nNone"));
    }
}
