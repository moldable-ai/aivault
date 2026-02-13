use include_dir::{include_dir, Dir};

use crate::broker::{BrokerResult, ErrorCode, ProviderTemplate, Registry};

static REGISTRY_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/registry");

fn parse_provider_template(raw: &str, source: &str) -> BrokerResult<ProviderTemplate> {
    serde_json::from_str(raw).map_err(|err| crate::broker::BrokerError {
        error: ErrorCode::InvalidRequest,
        message: format!("invalid built-in registry provider '{}': {}", source, err),
    })
}

pub fn builtin_registry() -> BrokerResult<Registry> {
    let mut json_files: Vec<_> = REGISTRY_DIR
        .files()
        .filter(|file| file.path().extension().and_then(|ext| ext.to_str()) == Some("json"))
        .filter(|file| !file.path().starts_with("schemas"))
        .collect();
    json_files.sort_by(|a, b| a.path().cmp(b.path()));

    let mut templates = Vec::new();
    for file in json_files {
        let source = file.path().to_string_lossy().to_string();
        let raw = file
            .contents_utf8()
            .ok_or_else(|| crate::broker::BrokerError {
                error: ErrorCode::InvalidRequest,
                message: format!("invalid utf-8 in built-in registry provider '{}'", source),
            })?;
        templates.push(parse_provider_template(raw, &source)?);
    }
    Registry::from_templates(templates)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_registry_contains_initial_transcription_providers() {
        let registry = builtin_registry().expect("registry should load");

        let openai = registry.provider("openai").expect("openai provider");
        assert!(openai
            .capabilities
            .iter()
            .any(|cap| cap.id == "openai/transcription"));

        let deepgram = registry.provider("deepgram").expect("deepgram provider");
        assert!(deepgram
            .capabilities
            .iter()
            .any(|cap| cap.id == "deepgram/transcription"));

        let elevenlabs = registry
            .provider("elevenlabs")
            .expect("elevenlabs provider");
        assert!(elevenlabs
            .capabilities
            .iter()
            .any(|cap| cap.id == "elevenlabs/transcription"));
    }
}
