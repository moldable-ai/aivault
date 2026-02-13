use chrono::Utc;

use super::helpers::*;
use super::*;

impl Broker {
    pub fn new(cfg: BrokerConfig, registry: Option<Registry>) -> Self {
        Self {
            cfg,
            registry,
            ..Self::default()
        }
    }

    pub fn default_with_registry(registry: Option<Registry>) -> Self {
        Self::new(BrokerConfig::default(), registry)
    }

    pub fn credentials(&self) -> Vec<Credential> {
        self.credentials.values().cloned().collect()
    }

    pub fn capabilities(&self) -> Vec<Capability> {
        self.capabilities.values().cloned().collect()
    }

    pub fn audit_records(&self) -> &[AuditRecord] {
        &self.audit
    }

    pub fn resolve_credential_for_capability(
        &self,
        capability_id: &str,
        request_credential: Option<&str>,
        token_credential: Option<&str>,
    ) -> BrokerResult<Credential> {
        let capability = self
            .capabilities
            .get(capability_id)
            .ok_or_else(|| BrokerError::new(ErrorCode::CapabilityNotFound, "capability not found"))?
            .clone();
        self.resolve_credential_for_request(&capability, request_credential, token_credential)
    }

    pub fn upsert_secret_material(
        &mut self,
        credential_id: &str,
        secret: SecretMaterial,
    ) -> BrokerResult<()> {
        let credential_id = credential_id.trim();
        if credential_id.is_empty() {
            return Err(BrokerError::new(
                ErrorCode::InvalidRequest,
                "credential id required",
            ));
        }
        if !self.credentials.contains_key(credential_id) {
            return Err(BrokerError::new(
                ErrorCode::CredentialNotFound,
                "credential not found",
            ));
        }
        self.secrets.insert(credential_id.to_string(), secret);
        Ok(())
    }

    pub fn build_caller_env(base_url: &str, token: &str) -> CallerEnv {
        CallerEnv {
            aivault_base_url: base_url.to_string(),
            aivault_token: token.to_string(),
        }
    }

    pub fn create_operator_secret(
        &mut self,
        auth: &RequestAuth,
        id: &str,
        value: &str,
    ) -> BrokerResult<()> {
        self.ensure_operator(auth)?;
        let id = id.trim();
        if id.is_empty() {
            return Err(BrokerError::new(
                ErrorCode::InvalidRequest,
                "secret id required",
            ));
        }
        self.operator_secrets.insert(
            id.to_string(),
            OperatorSecret {
                id: id.to_string(),
                value: value.to_string(),
            },
        );
        Ok(())
    }

    pub fn list_operator_secrets(&self, auth: &RequestAuth) -> BrokerResult<Vec<OperatorSecret>> {
        self.ensure_operator(auth)?;
        Ok(self.operator_secrets.values().cloned().collect())
    }

    pub fn create_credential(
        &mut self,
        auth: &RequestAuth,
        input: CredentialInput,
        secret: SecretMaterial,
    ) -> BrokerResult<Credential> {
        self.ensure_operator(auth)?;

        let id = input.id.trim();
        let provider = input.provider.trim();
        if id.is_empty() || provider.is_empty() {
            return Err(BrokerError::new(
                ErrorCode::InvalidRequest,
                "credential id/provider required",
            ));
        }
        if self.credentials.contains_key(id) {
            return Err(BrokerError::new(
                ErrorCode::InvalidRequest,
                "credential id already exists",
            ));
        }

        let provider_defaults = self
            .registry
            .as_ref()
            .and_then(|r| r.provider(provider).cloned());

        let requested_hosts = input.hosts.clone();
        let requested_hosts_present = requested_hosts.is_some();
        let auth_strategy = input
            .auth
            .or_else(|| provider_defaults.as_ref().map(|p| p.auth.clone()))
            .ok_or_else(|| {
                BrokerError::new(
                    ErrorCode::InvalidRequest,
                    "credential auth required when provider is not in registry",
                )
            })?;
        self.validate_auth_strategy(&auth_strategy)?;

        let hosts = requested_hosts
            .clone()
            .or_else(|| provider_defaults.as_ref().map(|p| p.hosts.clone()))
            .ok_or_else(|| {
                BrokerError::new(
                    ErrorCode::InvalidRequest,
                    "credential hosts required when provider is not in registry",
                )
            })?;

        let hosts = normalize_hosts(hosts)?;
        if let (Some(defaults), true) = (provider_defaults.as_ref(), requested_hosts_present) {
            // Registry providers may allow per-tenant host binding, but bound hosts must match
            // the registry's allowed host patterns (fail-closed).
            for host in &hosts {
                if !defaults.hosts.iter().any(|pattern| host_matches(pattern, host)) {
                    return Err(BrokerError::new(
                        ErrorCode::PolicyViolation,
                        "credential host is not allowed by registry provider host policy",
                    ));
                }
            }
        }
        self.validate_credential_hosts(&hosts)?;

        let credential = Credential {
            id: id.to_string(),
            provider: provider.to_string(),
            auth: auth_strategy,
            hosts,
        };

        self.secrets.insert(id.to_string(), secret);
        self.credentials.insert(id.to_string(), credential.clone());

        if let Some(defaults) = provider_defaults {
            for capability in &defaults.capabilities {
                self.create_or_replace_capability_from_registry(capability.clone())?;
            }
        }

        Ok(credential)
    }

    pub fn create_capability(
        &mut self,
        auth: &RequestAuth,
        capability: Capability,
    ) -> BrokerResult<()> {
        self.ensure_operator(auth)?;
        self.validate_capability(&capability, self.cfg.core_exact_hosts_only)?;
        if self.capabilities.contains_key(&capability.id) {
            return Err(BrokerError::new(
                ErrorCode::InvalidRequest,
                "capability id already exists",
            ));
        }
        self.capabilities.insert(capability.id.clone(), capability);
        Ok(())
    }

    pub fn set_capability_advanced_policy(
        &mut self,
        auth: &RequestAuth,
        capability_id: &str,
        policy: CapabilityAdvancedPolicy,
    ) -> BrokerResult<()> {
        self.ensure_operator(auth)?;
        if !self.capabilities.contains_key(capability_id) {
            return Err(BrokerError::new(
                ErrorCode::CapabilityNotFound,
                "capability not found",
            ));
        }
        self.advanced_policies
            .insert(capability_id.to_string(), policy);
        Ok(())
    }

    pub fn upsert_capability(
        &mut self,
        auth: &RequestAuth,
        capability: Capability,
    ) -> BrokerResult<()> {
        self.ensure_operator(auth)?;
        self.validate_capability(&capability, self.cfg.core_exact_hosts_only)?;
        self.capabilities.insert(capability.id.clone(), capability);
        Ok(())
    }

    pub fn mint_proxy_token(
        &mut self,
        auth: &RequestAuth,
        request: ProxyTokenMintRequest,
    ) -> BrokerResult<ProxyToken> {
        self.ensure_operator(auth)?;

        if request.ttl_ms <= 0 {
            return Err(BrokerError::new(
                ErrorCode::InvalidRequest,
                "ttlMs must be positive",
            ));
        }

        if let Some(credential_id) = request.credential.as_deref() {
            let credential = self.credentials.get(credential_id).ok_or_else(|| {
                BrokerError::new(ErrorCode::CredentialNotFound, "credential not found")
            })?;
            for capability_id in &request.capabilities {
                let capability = self.capabilities.get(capability_id).ok_or_else(|| {
                    BrokerError::new(ErrorCode::CapabilityNotFound, "capability not found")
                })?;
                if capability.provider != credential.provider {
                    return Err(BrokerError::new(
                        ErrorCode::PolicyViolation,
                        "capability provider does not match credential provider",
                    ));
                }
            }
        }

        let token = format!("avp_{}", uuid::Uuid::new_v4().simple());
        let expires_at_ms = Utc::now().timestamp_millis() + request.ttl_ms;
        let proxy_token = ProxyToken {
            token: token.clone(),
            capabilities: request.capabilities,
            credential: request.credential,
            expires_at_ms,
            context: request.context,
        };
        self.proxy_tokens.insert(token, proxy_token.clone());
        Ok(proxy_token)
    }

    pub fn parse_envelope(json: &str) -> BrokerResult<ProxyEnvelope> {
        serde_json::from_str::<ProxyEnvelope>(json).map_err(|e| {
            BrokerError::new(
                ErrorCode::InvalidRequest,
                format!("invalid envelope JSON: {}", e),
            )
        })
    }

    pub fn execute_envelope(
        &mut self,
        auth: &RequestAuth,
        envelope: ProxyEnvelope,
        client_ip: IpAddr,
    ) -> BrokerResult<PlannedRequest> {
        let proxy_token = self.ensure_proxy_token(auth)?.clone();
        self.ensure_client_allowed(client_ip)?;
        self.validate_envelope(&envelope)?;

        let capability = self
            .capabilities
            .get(&envelope.capability)
            .ok_or_else(|| BrokerError::new(ErrorCode::CapabilityNotFound, "capability not found"))?
            .clone();

        self.ensure_capability_allowed_by_token(&proxy_token, &capability.id)?;
        self.enforce_capability_rate_limit(&capability.id)?;

        let credential = self.resolve_credential_for_request(
            &capability,
            envelope.credential.as_deref(),
            proxy_token.credential.as_deref(),
        )?;

        let (normalized_path, mut query) = normalize_path_and_query(&envelope.request.path)?;
        let method = normalize_method(&envelope.request.method);
        ensure_method_allowed(&capability.allow.methods, &method)?;
        ensure_path_allowed(&capability.allow.path_prefixes, &normalized_path)?;

        let host = self.select_effective_host(&credential, &capability)?;
        let (upstream_host, upstream_port) = split_upstream_authority(&host)?;
        self.enforce_upstream_target_rules("https", &upstream_host, upstream_port)?;

        if let AuthStrategy::Query { param_name } = &credential.auth {
            if query.iter().any(|(k, _)| k == param_name) {
                return Err(BrokerError::new(
                    ErrorCode::PolicyViolation,
                    "query auth parameter is broker-managed",
                ));
            }
        }

        let body_mode = resolve_body_mode(&envelope.request)?;
        self.enforce_capability_request_size_limit(&capability.id, &body_mode)?;
        let mut headers = sanitize_headers(&envelope.request.headers, &credential.auth)?;
        apply_broker_managed_body_headers(&mut headers, &body_mode);
        let mut upstream_path = normalized_path;
        apply_auth(
            &credential.auth,
            self.secrets.get(&credential.id),
            &mut headers,
            &mut query,
            &mut upstream_path,
            true,
            &method,
        )?;

        let planned = PlannedRequest {
            capability: capability.id,
            credential: credential.id,
            host,
            scheme: "https".to_string(),
            method,
            path: upstream_path,
            headers,
            query,
            body_mode,
        };

        self.audit.push(AuditRecord {
            ts_ms: Utc::now().timestamp_millis(),
            capability: planned.capability.clone(),
            credential: planned.credential.clone(),
            host: planned.host.clone(),
            context: proxy_token.context.clone(),
        });

        Ok(planned)
    }

    pub fn execute_passthrough(
        &mut self,
        auth: &RequestAuth,
        method: &str,
        raw_path: &str,
        headers: Vec<Header>,
        client_ip: IpAddr,
    ) -> BrokerResult<PlannedPassthrough> {
        let proxy_token = self.ensure_proxy_token(auth)?.clone();
        self.ensure_client_allowed(client_ip)?;

        let (credential_id, upstream_path) = parse_passthrough_path(raw_path)?;
        let credential = self
            .credentials
            .get(credential_id)
            .ok_or_else(|| BrokerError::new(ErrorCode::CredentialNotFound, "credential not found"))?
            .clone();

        if let Some(scoped_credential) = proxy_token.credential.as_deref() {
            if scoped_credential != credential.id {
                return Err(BrokerError::new(
                    ErrorCode::PolicyViolation,
                    "token credential scope does not allow requested credential",
                ));
            }
        }

        let method = normalize_method(method);
        let (normalized_path, mut query) = normalize_path_and_query(upstream_path)?;

        let mut candidates: Vec<Capability> = self
            .capabilities
            .values()
            .filter(|cap| cap.provider == credential.provider)
            .cloned()
            .collect();

        candidates.retain(|cap| proxy_token.capabilities.iter().any(|id| id == &cap.id));
        candidates.retain(|cap| {
            method_allowed(&cap.allow.methods, &method)
                && path_allowed(&cap.allow.path_prefixes, &normalized_path)
        });

        if candidates.is_empty() {
            return Err(BrokerError::new(
                ErrorCode::CapabilityNotFound,
                "no passthrough capability matched method/path",
            ));
        }

        let mut sorted = candidates.clone();
        sorted.sort_by(|a, b| {
            let a_len = longest_prefix_len(&a.allow.path_prefixes, &normalized_path);
            let b_len = longest_prefix_len(&b.allow.path_prefixes, &normalized_path);
            b_len.cmp(&a_len).then_with(|| a.id.cmp(&b.id))
        });
        let best = sorted[0].clone();
        self.enforce_capability_rate_limit(&best.id)?;

        let host = self.select_effective_host(&credential, &best)?;
        let (upstream_host, upstream_port) = split_upstream_authority(&host)?;
        self.enforce_upstream_target_rules("https", &upstream_host, upstream_port)?;

        let mut headers = sanitize_headers(&headers, &credential.auth)?;
        let mut upstream_path = normalized_path;
        apply_auth(
            &credential.auth,
            self.secrets.get(&credential.id),
            &mut headers,
            &mut query,
            &mut upstream_path,
            false,
            &method,
        )?;

        let planned = PlannedRequest {
            capability: best.id.clone(),
            credential: credential.id.clone(),
            host: host.clone(),
            scheme: "https".to_string(),
            method,
            path: upstream_path,
            headers,
            query,
            body_mode: RequestBodyMode::Empty,
        };

        self.audit.push(AuditRecord {
            ts_ms: Utc::now().timestamp_millis(),
            capability: best.id.clone(),
            credential: credential.id,
            host,
            context: proxy_token.context.clone(),
        });

        let mut matched_capabilities: Vec<String> = sorted.into_iter().map(|cap| cap.id).collect();
        matched_capabilities.sort();

        Ok(PlannedPassthrough {
            planned,
            matched_capabilities,
            audit_capability: best.id,
        })
    }

    pub fn execute_ws_connect(
        &mut self,
        auth: &RequestAuth,
        frame: WsConnectFrame,
        client_ip: IpAddr,
    ) -> BrokerResult<PlannedRequest> {
        if frame.target_url.is_some() {
            return Err(BrokerError::new(
                ErrorCode::PolicyViolation,
                "targetUrl is not allowed",
            ));
        }

        let envelope = ProxyEnvelope {
            capability: frame.capability,
            credential: None,
            request: ProxyEnvelopeRequest {
                method: "GET".to_string(),
                path: frame.path,
                headers: Vec::new(),
                body: None,
                multipart: None,
                multipart_files: Vec::new(),
                body_file_path: None,
                url: None,
            },
        };

        let mut planned = self.execute_envelope(auth, envelope, client_ip)?;
        planned.scheme = "wss".to_string();
        let (upstream_host, upstream_port) = split_upstream_authority(&planned.host)?;
        self.enforce_upstream_target_rules("wss", &upstream_host, upstream_port)?;
        Ok(planned)
    }

    pub fn validate_redirect_hop(&self, current_host: &str, next_host: &str) -> BrokerResult<bool> {
        match self.cfg.redirect_mode {
            RedirectMode::Block => Err(BrokerError::new(
                ErrorCode::PolicyViolation,
                "redirects are blocked",
            )),
            RedirectMode::Revalidate => Ok(!eq_ignore_ascii_case(current_host, next_host)),
        }
    }

    pub fn forward_response(upstream: UpstreamResponse) -> ForwardedResponse {
        let headers = upstream
            .headers
            .into_iter()
            .filter(|h| !is_hop_by_hop_header(&h.name))
            .collect();
        ForwardedResponse {
            status: upstream.status,
            headers,
            body_chunks: upstream.body_chunks,
        }
    }

    pub fn forward_response_for_capability(
        &self,
        capability_id: &str,
        upstream: UpstreamResponse,
    ) -> BrokerResult<ForwardedResponse> {
        let mut forwarded = Self::forward_response(upstream);

        if let Some(policy) = self.advanced_policies.get(capability_id) {
            if let Some(max_bytes) = policy.max_response_body_bytes {
                let total: usize = forwarded.body_chunks.iter().map(|c| c.len()).sum();
                if total > max_bytes {
                    return Err(BrokerError::new(
                        ErrorCode::PolicyViolation,
                        "response body exceeds capability size limit",
                    ));
                }
            }

            if !policy.response_body_blocklist.is_empty() {
                let body = forwarded.body_chunks.concat();
                if let Ok(text) = String::from_utf8(body) {
                    let mut filtered = text;
                    for needle in policy
                        .response_body_blocklist
                        .iter()
                        .map(|v| v.trim())
                        .filter(|v| !v.is_empty())
                    {
                        filtered = filtered.replace(needle, "[REDACTED]");
                    }
                    forwarded.body_chunks = vec![filtered.into_bytes()];
                }
            }
        }

        Ok(forwarded)
    }

    pub fn conformance_levels(&self) -> HashMap<String, bool> {
        HashMap::from([
            ("Core".to_string(), true),
            ("Registry".to_string(), self.registry.is_some()),
            ("OAuth2".to_string(), true),
            ("WebSocket".to_string(), true),
            ("Signing".to_string(), true),
            ("mTLS".to_string(), true),
        ])
    }

    pub fn parse_auth_type(name: &str) -> BrokerResult<AuthStrategy> {
        match name.trim().to_ascii_lowercase().as_str() {
            "header" => Ok(AuthStrategy::Header {
                header_name: "authorization".to_string(),
                value_template: "Bearer {{secret}}".to_string(),
            }),
            "path" => Ok(AuthStrategy::Path {
                prefix_template: "/bot{{secret}}".to_string(),
            }),
            "query" => Ok(AuthStrategy::Query {
                param_name: "api_key".to_string(),
            }),
            "multi-header" | "multi_header" => Ok(AuthStrategy::MultiHeader(Vec::new())),
            "basic" => Ok(AuthStrategy::Basic),
            "oauth2" => Ok(AuthStrategy::OAuth2 {
                grant_type: "refresh_token".to_string(),
                token_endpoint: "https://example.com/token".to_string(),
                scopes: Vec::new(),
            }),
            "aws-sigv4" => Ok(AuthStrategy::AwsSigV4 {
                service: "s3".to_string(),
                region: "us-east-1".to_string(),
            }),
            "hmac" => Ok(AuthStrategy::Hmac {
                algorithm: "sha256".to_string(),
                header_name: "x-signature".to_string(),
                value_template: "sha256={{signature}}".to_string(),
            }),
            "mtls" => Ok(AuthStrategy::Mtls),
            other => Err(BrokerError::new(
                ErrorCode::PolicyViolation,
                format!("unknown auth.type '{}'", other),
            )),
        }
    }

    fn ensure_operator(&self, auth: &RequestAuth) -> BrokerResult<()> {
        if matches!(auth, RequestAuth::Operator(_)) {
            return Ok(());
        }
        Err(BrokerError::new(
            ErrorCode::OperatorAuthRequired,
            "operator token required",
        ))
    }

    fn ensure_proxy_token(&self, auth: &RequestAuth) -> BrokerResult<&ProxyToken> {
        let RequestAuth::Proxy(token) = auth else {
            return Err(BrokerError::new(
                ErrorCode::TokenInvalid,
                "proxy token required",
            ));
        };
        let stored = self
            .proxy_tokens
            .get(token)
            .ok_or_else(|| BrokerError::new(ErrorCode::TokenInvalid, "proxy token not found"))?;
        if stored.expires_at_ms <= Utc::now().timestamp_millis() {
            return Err(BrokerError::new(
                ErrorCode::TokenInvalid,
                "proxy token expired",
            ));
        }
        Ok(stored)
    }

    fn ensure_client_allowed(&self, client_ip: IpAddr) -> BrokerResult<()> {
        if self.cfg.allow_remote_clients || client_ip.is_loopback() {
            return Ok(());
        }
        Err(BrokerError::new(
            ErrorCode::PolicyViolation,
            "non-loopback clients are rejected by default",
        ))
    }

    fn ensure_capability_allowed_by_token(
        &self,
        token: &ProxyToken,
        capability_id: &str,
    ) -> BrokerResult<()> {
        if token.capabilities.iter().any(|id| id == capability_id) {
            return Ok(());
        }
        Err(BrokerError::new(
            ErrorCode::PolicyViolation,
            "token is not scoped to this capability",
        ))
    }

    fn resolve_credential_for_request(
        &self,
        capability: &Capability,
        request_credential: Option<&str>,
        token_credential: Option<&str>,
    ) -> BrokerResult<Credential> {
        if let Some(credential_id) = request_credential.map(str::trim).filter(|v| !v.is_empty()) {
            let credential = self.credentials.get(credential_id).ok_or_else(|| {
                BrokerError::new(ErrorCode::CredentialNotFound, "credential not found")
            })?;
            if credential.provider != capability.provider {
                return Err(BrokerError::new(
                    ErrorCode::PolicyViolation,
                    "credential provider does not match capability provider",
                ));
            }
            return Ok(credential.clone());
        }

        if let Some(credential_id) = token_credential.map(str::trim).filter(|v| !v.is_empty()) {
            let credential = self.credentials.get(credential_id).ok_or_else(|| {
                BrokerError::new(ErrorCode::CredentialNotFound, "credential not found")
            })?;
            if credential.provider != capability.provider {
                return Err(BrokerError::new(
                    ErrorCode::PolicyViolation,
                    "credential provider does not match capability provider",
                ));
            }
            return Ok(credential.clone());
        }

        let matching: Vec<_> = self
            .credentials
            .values()
            .filter(|credential| credential.provider == capability.provider)
            .cloned()
            .collect();

        match matching.as_slice() {
            [only] => Ok(only.clone()),
            [] => Err(BrokerError::new(
                ErrorCode::CredentialNotFound,
                "no credential for capability provider",
            )),
            _ => Err(BrokerError::new(
                ErrorCode::CredentialAmbiguous,
                "multiple credentials available; pass credential id",
            )),
        }
    }

    fn validate_envelope(&self, envelope: &ProxyEnvelope) -> BrokerResult<()> {
        if envelope.capability.trim().is_empty() {
            return Err(BrokerError::new(
                ErrorCode::InvalidRequest,
                "capability is required",
            ));
        }
        if envelope.request.method.trim().is_empty() {
            return Err(BrokerError::new(
                ErrorCode::InvalidRequest,
                "request.method is required",
            ));
        }
        if envelope.request.path.trim().is_empty() {
            return Err(BrokerError::new(
                ErrorCode::InvalidRequest,
                "request.path is required",
            ));
        }
        if envelope.request.url.is_some() {
            return Err(BrokerError::new(
                ErrorCode::PolicyViolation,
                "request.url is not allowed",
            ));
        }
        let body_modes = [
            envelope.request.body.is_some(),
            envelope.request.multipart.is_some() || !envelope.request.multipart_files.is_empty(),
            envelope.request.body_file_path.is_some(),
        ]
        .into_iter()
        .filter(|v| *v)
        .count();
        if body_modes > 1 {
            return Err(BrokerError::new(
                ErrorCode::PolicyViolation,
                "only one request body mode is allowed",
            ));
        }
        Ok(())
    }

    fn select_effective_host(
        &self,
        credential: &Credential,
        capability: &Capability,
    ) -> BrokerResult<String> {
        let allow_pattern = capability
            .allow
            .hosts
            .first()
            .map(|s| s.as_str())
            .unwrap_or_default();

        // Capability allow.hosts may be a wildcard pattern (registry templates); the effective
        // upstream authority is always the credential-bound host instance.
        let allowed: Vec<String> = credential
            .hosts
            .iter()
            .filter(|candidate| host_matches(allow_pattern, candidate))
            .cloned()
            .collect();

        if allowed.is_empty() {
            return Err(BrokerError::new(
                ErrorCode::PolicyViolation,
                "effective host intersection is empty",
            ));
        }

        if allowed.len() != 1 {
            return Err(BrokerError::new(
                ErrorCode::PolicyViolation,
                "core conformance requires exactly one effective host",
            ));
        }

        Ok(allowed[0].clone())
    }

    pub(super) fn enforce_upstream_target_rules(
        &self,
        scheme: &str,
        host: &str,
        port: Option<u16>,
    ) -> BrokerResult<()> {
        match scheme {
            "https" | "wss" => {}
            "http" | "ws" if self.cfg.allow_http_local_extension => {}
            _ => {
                return Err(BrokerError::new(
                    ErrorCode::PolicyViolation,
                    "scheme not allowed",
                ));
            }
        }

        if let Some(port) = port {
            let default_port = match scheme {
                "https" | "wss" => 443,
                "http" | "ws" => 80,
                _ => 0,
            };
            if port != default_port && !self.cfg.allow_non_default_ports_extension {
                return Err(BrokerError::new(
                    ErrorCode::PolicyViolation,
                    "non-default port not allowed",
                ));
            }
        }

        if is_ssrf_blocked_host(host) {
            return Err(BrokerError::new(
                ErrorCode::PolicyViolation,
                "upstream host blocked by SSRF guard",
            ));
        }

        Ok(())
    }

    fn validate_capability(&self, capability: &Capability, exact_hosts_only: bool) -> BrokerResult<()> {
        if capability.id.trim().is_empty() || capability.provider.trim().is_empty() {
            return Err(BrokerError::new(
                ErrorCode::InvalidRequest,
                "capability id/provider required",
            ));
        }

        if capability.allow.hosts.is_empty()
            || capability.allow.methods.is_empty()
            || capability.allow.path_prefixes.is_empty()
        {
            return Err(BrokerError::new(
                ErrorCode::PolicyViolation,
                "hosts, methods, and pathPrefixes are required",
            ));
        }

        if capability.allow.hosts.len() != 1 {
            return Err(BrokerError::new(
                ErrorCode::PolicyViolation,
                "core conformance requires allow.hosts length = 1",
            ));
        }

        for host in &capability.allow.hosts {
            validate_host_pattern(host, exact_hosts_only)?;
        }

        Ok(())
    }

    fn validate_credential_hosts(&self, hosts: &[String]) -> BrokerResult<()> {
        if hosts.is_empty() {
            return Err(BrokerError::new(
                ErrorCode::PolicyViolation,
                "credential hosts are required",
            ));
        }
        for host in hosts {
            validate_host_pattern(host, self.cfg.core_exact_hosts_only)?;
        }
        Ok(())
    }

    fn enforce_capability_rate_limit(&mut self, capability_id: &str) -> BrokerResult<()> {
        let Some(limit) = self
            .advanced_policies
            .get(capability_id)
            .and_then(|policy| policy.rate_limit_per_minute)
        else {
            return Ok(());
        };

        if limit == 0 {
            return Err(BrokerError::new(
                ErrorCode::PolicyViolation,
                "capability rate limit exceeded",
            ));
        }

        let now = Utc::now().timestamp_millis();
        let minute_bucket = now / 60_000;
        let entry = self
            .rate_windows
            .entry(capability_id.to_string())
            .or_insert((minute_bucket, 0));
        if entry.0 != minute_bucket {
            *entry = (minute_bucket, 0);
        }

        if entry.1 >= limit {
            return Err(BrokerError::new(
                ErrorCode::PolicyViolation,
                "capability rate limit exceeded",
            ));
        }

        entry.1 += 1;
        Ok(())
    }

    fn enforce_capability_request_size_limit(
        &self,
        capability_id: &str,
        body_mode: &RequestBodyMode,
    ) -> BrokerResult<()> {
        let Some(max_bytes) = self
            .advanced_policies
            .get(capability_id)
            .and_then(|policy| policy.max_request_body_bytes)
        else {
            return Ok(());
        };

        let size = estimated_body_size_bytes(body_mode)?;
        if size > max_bytes {
            return Err(BrokerError::new(
                ErrorCode::PolicyViolation,
                "request body exceeds capability size limit",
            ));
        }
        Ok(())
    }

    fn validate_auth_strategy(&self, auth: &AuthStrategy) -> BrokerResult<()> {
        if let AuthStrategy::OAuth2 { grant_type, .. } = auth {
            if !oauth_grant_is_supported(grant_type) {
                return Err(BrokerError::new(
                    ErrorCode::PolicyViolation,
                    "oauth2 consent/setup flow must happen outside broker",
                ));
            }
        }
        if let AuthStrategy::Path { prefix_template } = auth {
            let trimmed = prefix_template.trim();
            if trimmed.is_empty() || !trimmed.starts_with('/') {
                return Err(BrokerError::new(
                    ErrorCode::PolicyViolation,
                    "path auth prefixTemplate must start with '/'",
                ));
            }
            if trimmed.contains('?') || trimmed.contains('#') {
                return Err(BrokerError::new(
                    ErrorCode::PolicyViolation,
                    "path auth prefixTemplate cannot include query or fragment",
                ));
            }
            if trimmed.matches("{{secret}}").count() != 1 {
                return Err(BrokerError::new(
                    ErrorCode::PolicyViolation,
                    "path auth prefixTemplate must contain exactly one {{secret}}",
                ));
            }
        }
        if let AuthStrategy::MultiHeader(templates) = auth {
            if templates.is_empty() {
                return Err(BrokerError::new(
                    ErrorCode::PolicyViolation,
                    "multi-header auth must include at least one header template",
                ));
            }
            let mut seen = std::collections::HashSet::new();
            for t in templates {
                let name = t.header_name.trim().to_ascii_lowercase();
                if name.is_empty() {
                    return Err(BrokerError::new(
                        ErrorCode::PolicyViolation,
                        "multi-header auth requires non-empty headerName",
                    ));
                }
                if !seen.insert(name) {
                    return Err(BrokerError::new(
                        ErrorCode::PolicyViolation,
                        "multi-header auth cannot include duplicate header names",
                    ));
                }
                if t.value_template.trim().is_empty() {
                    return Err(BrokerError::new(
                        ErrorCode::PolicyViolation,
                        "multi-header auth requires non-empty valueTemplate",
                    ));
                }
            }
        }
        Ok(())
    }

    fn create_or_replace_capability_from_registry(
        &mut self,
        capability: Capability,
    ) -> BrokerResult<()> {
        // Registry templates may use wildcard host patterns for per-tenant SaaS providers.
        self.validate_capability(&capability, false)?;
        self.capabilities.insert(capability.id.clone(), capability);
        Ok(())
    }
}

fn split_upstream_authority(authority: &str) -> BrokerResult<(String, Option<u16>)> {
    let parsed = reqwest::Url::parse(&format!("https://{authority}/")).map_err(|_| {
        BrokerError::new(
            ErrorCode::PolicyViolation,
            "invalid host authority in capability or credential",
        )
    })?;
    let host = parsed
        .host_str()
        .ok_or_else(|| {
            BrokerError::new(
                ErrorCode::PolicyViolation,
                "invalid host authority in capability or credential",
            )
        })?
        .to_string();
    Ok((host, parsed.port()))
}
