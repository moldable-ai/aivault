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

    #[test]
    fn builtin_registry_contains_all_openai_capabilities() {
        let registry = builtin_registry().expect("registry should load");
        let openai = registry.provider("openai").expect("openai provider");

        let expected_ids = [
            "openai/chat-completions",
            "openai/responses",
            "openai/embeddings",
            "openai/transcription",
            "openai/translation",
            "openai/speech",
            "openai/image-generation",
            "openai/moderation",
            "openai/models",
            "openai/files",
            "openai/fine-tuning",
            "openai/batch",
            "openai/vector-stores",
            "openai/assistants",
            "openai/uploads",
            "openai/realtime",
            "openai/videos",
        ];

        for expected in &expected_ids {
            assert!(
                openai.capabilities.iter().any(|cap| cap.id == *expected),
                "missing openai capability: {}",
                expected
            );
        }

        assert_eq!(
            openai.capabilities.len(),
            expected_ids.len(),
            "openai capability count mismatch"
        );
    }

    #[test]
    fn openai_capability_lookup_by_id() {
        let registry = builtin_registry().expect("registry should load");

        let chat = registry
            .capability("openai/chat-completions")
            .expect("chat-completions should be findable by id");
        assert_eq!(chat.provider, "openai");
        assert!(chat.allow.methods.contains(&"POST".to_string()));
        assert!(chat
            .allow
            .path_prefixes
            .contains(&"/v1/chat/completions".to_string()));

        let responses = registry
            .capability("openai/responses")
            .expect("responses should be findable by id");
        assert!(responses.allow.methods.contains(&"DELETE".to_string()));

        let images = registry
            .capability("openai/image-generation")
            .expect("image-generation should be findable by id");
        assert!(images
            .allow
            .path_prefixes
            .contains(&"/v1/images".to_string()));
    }
}
