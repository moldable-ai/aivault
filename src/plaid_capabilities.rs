use std::net::IpAddr;
use std::time::Instant;

use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::broker::{AllowPolicy, Capability, ProxyEnvelope};
use crate::broker_store::{BrokerStore, StoredCredential};
use crate::vault::{append_audit_event, SecretRef, SecretScope, VaultAuditEvent, VaultRuntime};

const PROVIDER: &str = "plaid";
const PLAID_HOST: &str = "production.plaid.com";
const PLAID_BASE_URL: &str = "https://production.plaid.com";
const DEFAULT_TRANSACTIONS_COUNT: u64 = 500;
const MAX_TRANSACTIONS_COUNT: u64 = 500;
const DEFAULT_MAX_PAGES: u64 = 4;
const MAX_MAX_PAGES: u64 = 20;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlaidCapabilityRequest {
    #[serde(default, alias = "public_token")]
    public_token: Option<String>,
    #[serde(default, alias = "item_id")]
    item_id: Option<String>,
    #[serde(default, alias = "credential_ref")]
    credential_ref: Option<String>,
    #[serde(default, alias = "institution_id")]
    institution_id: Option<String>,
    #[serde(default, alias = "institution_name")]
    institution_name: Option<String>,
    #[serde(default)]
    products: Vec<String>,
    #[serde(default, alias = "country_codes", alias = "countryCodes")]
    country_codes: Vec<String>,
    #[serde(
        default,
        alias = "additional_consented_products",
        alias = "additionalConsentedProducts"
    )]
    additional_consented_products: Vec<String>,
    #[serde(default, alias = "clientName", alias = "client_name")]
    client_name: Option<String>,
    #[serde(default)]
    language: Option<String>,
    #[serde(default, alias = "redirectUri", alias = "redirect_uri")]
    redirect_uri: Option<String>,
    #[serde(
        default,
        alias = "linkCustomizationName",
        alias = "link_customization_name"
    )]
    link_customization_name: Option<String>,
    #[serde(default)]
    user: Option<Value>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    count: Option<u64>,
    #[serde(default)]
    max_pages: Option<u64>,
    #[serde(default)]
    options: Option<Value>,
    #[serde(default)]
    metadata: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct PlaidAppSecret {
    client_id: String,
    secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlaidItemSecret {
    item_id: String,
    access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    institution_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    institution_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    products: Vec<String>,
    connected_at: String,
    updated_at: String,
}

#[derive(Debug, Deserialize)]
struct PublicTokenExchangeResponse {
    access_token: String,
    item_id: String,
    #[serde(default)]
    request_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PlaidItemRef {
    item_id: String,
    credential_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    institution_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    institution_name: Option<String>,
    connected_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PlaidCapabilityResponse<T: Serialize> {
    capability: String,
    credential: String,
    item_id: Option<String>,
    elapsed_ms: u128,
    result: T,
}

pub fn is_plaid_capability(id: &str) -> bool {
    matches!(
        id.trim(),
        "plaid/item-exchange-store"
            | "plaid/link-token-update"
            | "plaid/item-remove"
            | "plaid/accounts-sync"
            | "plaid/liabilities-sync"
            | "plaid/investments-sync"
            | "plaid/transactions-sync"
            | "plaid/transactions-recurring"
    )
}

pub fn builtin_capability(id: &str) -> Option<Capability> {
    builtin_capabilities()
        .into_iter()
        .find(|capability| capability.id == id)
}

pub fn builtin_capabilities() -> Vec<Capability> {
    [
        ("plaid/item-exchange-store", "/item/public_token/exchange"),
        ("plaid/link-token-update", "/link/token/create"),
        ("plaid/item-remove", "/item/remove"),
        ("plaid/accounts-sync", "/accounts/get"),
        ("plaid/liabilities-sync", "/liabilities/get"),
        ("plaid/investments-sync", "/investments/holdings/get"),
        ("plaid/transactions-sync", "/transactions/sync"),
        (
            "plaid/transactions-recurring",
            "/transactions/recurring/get",
        ),
    ]
    .into_iter()
    .map(|(id, path)| Capability {
        id: id.to_string(),
        provider: PROVIDER.to_string(),
        allow: AllowPolicy {
            hosts: vec![PLAID_HOST.to_string()],
            methods: vec!["POST".to_string()],
            path_prefixes: vec![path.to_string()],
        },
    })
    .collect()
}

pub fn run_plaid_capability(
    vault: &VaultRuntime,
    store: &BrokerStore,
    envelope: ProxyEnvelope,
    client_ip: IpAddr,
    workspace_id: Option<&str>,
    group_id: Option<&str>,
) -> Result<Value, String> {
    if !client_ip.is_loopback() {
        return Err("non-loopback clients are rejected by default".to_string());
    }
    if !envelope.request.method.eq_ignore_ascii_case("POST") {
        return Err("plaid capabilities require POST".to_string());
    }

    let capability = envelope.capability.trim().to_string();
    if builtin_capability(&capability).is_none() {
        return Err(format!("plaid capability '{}' not found", capability));
    }
    let workspace_id = workspace_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "plaid item capabilities require --workspace-id".to_string())?;
    let request = parse_request_body(&envelope)?;
    let stored = resolve_plaid_app_credential(store, workspace_id, group_id)?;
    ensure_plaid_host_allowed(stored)?;
    let app_secret = resolve_plaid_app_secret(vault, stored, workspace_id, group_id, &capability)?;

    match capability.as_str() {
        "plaid/item-exchange-store" => {
            run_item_exchange_store(vault, stored, app_secret, request, workspace_id, group_id)
        }
        "plaid/link-token-update" => {
            run_link_token_update(vault, stored, app_secret, request, workspace_id, group_id)
        }
        "plaid/item-remove" => {
            run_item_remove(vault, stored, app_secret, request, workspace_id, group_id)
        }
        "plaid/accounts-sync" => run_item_scoped_call(
            vault,
            stored,
            app_secret,
            request,
            workspace_id,
            group_id,
            &capability,
        ),
        "plaid/liabilities-sync" => run_item_scoped_call(
            vault,
            stored,
            app_secret,
            request,
            workspace_id,
            group_id,
            &capability,
        ),
        "plaid/investments-sync" => run_item_scoped_call(
            vault,
            stored,
            app_secret,
            request,
            workspace_id,
            group_id,
            &capability,
        ),
        "plaid/transactions-recurring" => run_item_scoped_call(
            vault,
            stored,
            app_secret,
            request,
            workspace_id,
            group_id,
            &capability,
        ),
        "plaid/transactions-sync" => {
            run_transactions_sync(vault, stored, app_secret, request, workspace_id, group_id)
        }
        _ => Err(format!("plaid capability '{}' not implemented", capability)),
    }
}

fn run_item_exchange_store(
    vault: &VaultRuntime,
    stored: &StoredCredential,
    app_secret: PlaidAppSecret,
    request: PlaidCapabilityRequest,
    workspace_id: &str,
    group_id: Option<&str>,
) -> Result<Value, String> {
    let public_token = required_string(request.public_token.as_deref(), "publicToken")?;
    let started = Instant::now();
    let response = plaid_post(
        "/item/public_token/exchange",
        &app_secret,
        &serde_json::json!({ "public_token": public_token }),
    )?;
    let exchange: PublicTokenExchangeResponse = serde_json::from_value(response)
        .map_err(|e| format!("invalid Plaid exchange response: {}", e))?;
    let connected_at = Utc::now().to_rfc3339();
    let institution_id = request
        .institution_id
        .or_else(|| metadata_string(&request.metadata, &["institution", "institution_id"]));
    let institution_name = request
        .institution_name
        .or_else(|| metadata_string(&request.metadata, &["institution", "name"]));
    let secret = PlaidItemSecret {
        item_id: exchange.item_id.clone(),
        access_token: exchange.access_token,
        institution_id: institution_id.clone(),
        institution_name: institution_name.clone(),
        products: request.products,
        connected_at: connected_at.clone(),
        updated_at: connected_at.clone(),
    };
    store_item_secret(vault, workspace_id, &secret)?;

    append_plaid_audit(
        vault,
        "plaid.item.exchange",
        Some(&exchange.item_id),
        workspace_id,
        group_id,
        Some(&stored.id),
        "stored Plaid Item access token in workspace vault secret",
    );

    let result = PlaidItemRef {
        item_id: exchange.item_id.clone(),
        credential_ref: credential_ref_for_item(&exchange.item_id),
        institution_id,
        institution_name,
        connected_at,
        request_id: exchange.request_id,
    };
    let payload = PlaidCapabilityResponse {
        capability: "plaid/item-exchange-store".to_string(),
        credential: stored.id.clone(),
        item_id: Some(exchange.item_id),
        elapsed_ms: started.elapsed().as_millis(),
        result,
    };
    response_envelope("plaid/item-exchange-store", &stored.id, &payload)
}

fn run_link_token_update(
    vault: &VaultRuntime,
    stored: &StoredCredential,
    app_secret: PlaidAppSecret,
    request: PlaidCapabilityRequest,
    workspace_id: &str,
    group_id: Option<&str>,
) -> Result<Value, String> {
    let item = resolve_item_secret(
        vault,
        &request,
        workspace_id,
        group_id,
        "plaid/link-token-update",
    )?;
    let started = Instant::now();
    let mut body = serde_json::json!({
        "access_token": item.access_token,
        "client_name": request.client_name.as_deref().unwrap_or("Moldable Money"),
        "country_codes": if request.country_codes.is_empty() {
            serde_json::json!(["US", "CA"])
        } else {
            serde_json::json!(request.country_codes)
        },
        "language": request.language.as_deref().unwrap_or("en"),
        "user": request.user.unwrap_or_else(|| serde_json::json!({
            "client_user_id": format!("moldable-money:{workspace_id}")
        })),
    });
    if let Some(redirect_uri) = request
        .redirect_uri
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        body["redirect_uri"] = Value::String(redirect_uri.to_string());
    }
    let additional_consented_products = if request.additional_consented_products.is_empty() {
        request.products
    } else {
        request.additional_consented_products
    };
    if !additional_consented_products.is_empty() {
        body["additional_consented_products"] = serde_json::json!(additional_consented_products);
    }
    if let Some(link_customization_name) = request
        .link_customization_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        body["link_customization_name"] = Value::String(link_customization_name.to_string());
    }
    let result = plaid_post("/link/token/create", &app_secret, &body)?;
    append_plaid_audit(
        vault,
        "plaid.item.link_token_update",
        Some(&item.item_id),
        workspace_id,
        group_id,
        Some(&stored.id),
        "created Plaid update-mode Link token without exposing Item access token",
    );
    let payload = PlaidCapabilityResponse {
        capability: "plaid/link-token-update".to_string(),
        credential: stored.id.clone(),
        item_id: Some(item.item_id),
        elapsed_ms: started.elapsed().as_millis(),
        result,
    };
    response_envelope("plaid/link-token-update", &stored.id, &payload)
}

fn run_item_remove(
    vault: &VaultRuntime,
    stored: &StoredCredential,
    app_secret: PlaidAppSecret,
    request: PlaidCapabilityRequest,
    workspace_id: &str,
    group_id: Option<&str>,
) -> Result<Value, String> {
    let item = resolve_item_secret(vault, &request, workspace_id, group_id, "plaid/item-remove")?;
    let started = Instant::now();
    let result = plaid_post(
        "/item/remove",
        &app_secret,
        &serde_json::json!({ "access_token": item.access_token }),
    )?;
    revoke_item_secret(vault, workspace_id, &item.item_id)?;
    append_plaid_audit(
        vault,
        "plaid.item.remove",
        Some(&item.item_id),
        workspace_id,
        group_id,
        Some(&stored.id),
        "removed Plaid Item and revoked stored Item access token",
    );
    let payload = PlaidCapabilityResponse {
        capability: "plaid/item-remove".to_string(),
        credential: stored.id.clone(),
        item_id: Some(item.item_id),
        elapsed_ms: started.elapsed().as_millis(),
        result,
    };
    response_envelope("plaid/item-remove", &stored.id, &payload)
}

fn run_item_scoped_call(
    vault: &VaultRuntime,
    stored: &StoredCredential,
    app_secret: PlaidAppSecret,
    request: PlaidCapabilityRequest,
    workspace_id: &str,
    group_id: Option<&str>,
    capability: &str,
) -> Result<Value, String> {
    let item = resolve_item_secret(vault, &request, workspace_id, group_id, capability)?;
    let path = match capability {
        "plaid/accounts-sync" => "/accounts/get",
        "plaid/liabilities-sync" => "/liabilities/get",
        "plaid/investments-sync" => "/investments/holdings/get",
        "plaid/transactions-recurring" => "/transactions/recurring/get",
        other => return Err(format!("unsupported Plaid item capability '{}'", other)),
    };
    let started = Instant::now();
    let mut body = serde_json::json!({ "access_token": item.access_token });
    if let Some(options) = request.options {
        body["options"] = options;
    }
    let result = plaid_post(path, &app_secret, &body)?;
    append_plaid_audit(
        vault,
        "plaid.item.invoke",
        Some(&item.item_id),
        workspace_id,
        group_id,
        Some(&stored.id),
        capability,
    );
    let payload = PlaidCapabilityResponse {
        capability: capability.to_string(),
        credential: stored.id.clone(),
        item_id: Some(item.item_id),
        elapsed_ms: started.elapsed().as_millis(),
        result,
    };
    response_envelope(capability, &stored.id, &payload)
}

fn run_transactions_sync(
    vault: &VaultRuntime,
    stored: &StoredCredential,
    app_secret: PlaidAppSecret,
    request: PlaidCapabilityRequest,
    workspace_id: &str,
    group_id: Option<&str>,
) -> Result<Value, String> {
    let item = resolve_item_secret(
        vault,
        &request,
        workspace_id,
        group_id,
        "plaid/transactions-sync",
    )?;
    let count = request
        .count
        .unwrap_or(DEFAULT_TRANSACTIONS_COUNT)
        .clamp(1, MAX_TRANSACTIONS_COUNT);
    let max_pages = request
        .max_pages
        .unwrap_or(DEFAULT_MAX_PAGES)
        .clamp(1, MAX_MAX_PAGES);
    let started = Instant::now();
    let mut cursor = request.cursor;
    let mut added = Vec::new();
    let mut modified = Vec::new();
    let mut removed = Vec::new();
    let mut next_cursor = None;
    let mut has_more = true;
    let mut pages = 0_u64;

    while has_more && pages < max_pages {
        let mut body = serde_json::json!({
            "access_token": item.access_token,
            "count": count,
        });
        if let Some(cursor_value) = cursor.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
            body["cursor"] = Value::String(cursor_value.to_string());
        }
        let page = plaid_post("/transactions/sync", &app_secret, &body)?;
        if let Some(values) = page.get("added").and_then(Value::as_array) {
            added.extend(values.iter().cloned());
        }
        if let Some(values) = page.get("modified").and_then(Value::as_array) {
            modified.extend(values.iter().cloned());
        }
        if let Some(values) = page.get("removed").and_then(Value::as_array) {
            removed.extend(values.iter().cloned());
        }
        next_cursor = page
            .get("next_cursor")
            .and_then(Value::as_str)
            .map(str::to_string);
        cursor = next_cursor.clone();
        has_more = page
            .get("has_more")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        pages += 1;
    }

    append_plaid_audit(
        vault,
        "plaid.item.invoke",
        Some(&item.item_id),
        workspace_id,
        group_id,
        Some(&stored.id),
        "plaid/transactions-sync",
    );
    let result = serde_json::json!({
        "item_id": item.item_id,
        "added": added,
        "modified": modified,
        "removed": removed,
        "next_cursor": next_cursor,
        "has_more": has_more,
        "pages": pages,
        "count": count,
    });
    let payload = PlaidCapabilityResponse {
        capability: "plaid/transactions-sync".to_string(),
        credential: stored.id.clone(),
        item_id: result
            .get("item_id")
            .and_then(Value::as_str)
            .map(str::to_string),
        elapsed_ms: started.elapsed().as_millis(),
        result,
    };
    response_envelope("plaid/transactions-sync", &stored.id, &payload)
}

fn plaid_post(path: &str, app_secret: &PlaidAppSecret, body: &Value) -> Result<Value, String> {
    let url = format!("{}{}", plaid_base_url(), path);
    let response = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(45))
        .build()
        .map_err(|e| e.to_string())?
        .post(&url)
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .header("PLAID-CLIENT-ID", app_secret.client_id.trim())
        .header("PLAID-SECRET", app_secret.secret.trim())
        .json(body)
        .send()
        .map_err(|e| format!("Plaid request failed: {}", e))?;
    let status = response.status();
    let text = response
        .text()
        .map_err(|e| format!("Plaid response read failed: {}", e))?;
    let value: Value = serde_json::from_str(&text)
        .map_err(|e| format!("Plaid returned non-JSON response (HTTP {}): {}", status, e))?;
    if !status.is_success() {
        return Err(format!(
            "Plaid returned HTTP {}: {}",
            status,
            redact_plaid_error(value)
        ));
    }
    Ok(value)
}

fn parse_request_body(envelope: &ProxyEnvelope) -> Result<PlaidCapabilityRequest, String> {
    let Some(body) = envelope.request.body.as_deref() else {
        return Ok(empty_plaid_request());
    };
    if body.trim().is_empty() {
        return Ok(empty_plaid_request());
    }
    serde_json::from_str(body).map_err(|e| format!("plaid request body must be JSON: {}", e))
}

fn empty_plaid_request() -> PlaidCapabilityRequest {
    PlaidCapabilityRequest {
        public_token: None,
        item_id: None,
        credential_ref: None,
        institution_id: None,
        institution_name: None,
        products: Vec::new(),
        country_codes: Vec::new(),
        additional_consented_products: Vec::new(),
        client_name: None,
        language: None,
        redirect_uri: None,
        link_customization_name: None,
        user: None,
        cursor: None,
        count: None,
        max_pages: None,
        options: None,
        metadata: None,
    }
}

fn resolve_plaid_app_credential<'a>(
    store: &'a BrokerStore,
    workspace_id: &str,
    group_id: Option<&str>,
) -> Result<&'a StoredCredential, String> {
    let matching: Vec<&StoredCredential> = store
        .credentials()
        .iter()
        .filter(|credential| credential.provider == PROVIDER)
        .filter(|credential| credential_matches_context(credential, Some(workspace_id), group_id))
        .collect();

    match matching.as_slice() {
        [only] => Ok(*only),
        [] => Err("no Plaid app credential found in this context; create PLAID_CLIENT_ID and PLAID_SECRET in aivault".to_string()),
        _ => Err("multiple Plaid app credentials available in this context".to_string()),
    }
}

fn resolve_plaid_app_secret(
    vault: &VaultRuntime,
    stored: &StoredCredential,
    workspace_id: &str,
    group_id: Option<&str>,
    capability: &str,
) -> Result<PlaidAppSecret, String> {
    let raw = resolve_secret_ref_for_context(
        vault,
        &stored.secret_ref,
        Some(workspace_id),
        group_id,
        Some(capability),
        Some(&stored.id),
    )?;
    let secret: PlaidAppSecret = serde_json::from_slice(&raw)
        .map_err(|_| "Plaid app credential must be JSON".to_string())?;
    if secret.client_id.trim().is_empty() || secret.secret.trim().is_empty() {
        return Err("Plaid app credential is missing client_id or secret".to_string());
    }
    Ok(secret)
}

fn store_item_secret(
    vault: &VaultRuntime,
    workspace_id: &str,
    item: &PlaidItemSecret,
) -> Result<(), String> {
    let name = item_secret_name(&item.item_id);
    let scope = SecretScope::Workspace {
        workspace_id: workspace_id.to_string(),
    };
    let value = serde_json::to_vec(item).map_err(|e| e.to_string())?;
    let existing = vault
        .list_secrets()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|meta| meta.name == name && meta.scope == scope && meta.revoked_at_ms.is_none());

    let meta = if let Some(existing) = existing {
        vault
            .set_secret_system_managed(&existing.secret_id, true)
            .map_err(|e| e.to_string())?;
        vault
            .rotate_secret_value(&existing.secret_id, &value)
            .map_err(|e| e.to_string())?
    } else {
        vault
            .create_system_secret(&name, &value, scope, Vec::new())
            .map_err(|e| e.to_string())?
    };
    vault
        .pin_secret_to_provider(&meta.secret_id, PROVIDER)
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn resolve_item_secret(
    vault: &VaultRuntime,
    request: &PlaidCapabilityRequest,
    workspace_id: &str,
    group_id: Option<&str>,
    capability: &str,
) -> Result<PlaidItemSecret, String> {
    let item_id = request_item_id(request)?;
    let name = item_secret_name(&item_id);
    let scope = SecretScope::Workspace {
        workspace_id: workspace_id.to_string(),
    };
    let meta = vault
        .list_secrets()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|meta| meta.name == name && meta.scope == scope && meta.revoked_at_ms.is_none())
        .ok_or_else(|| format!("Plaid Item '{}' is not stored in this workspace", item_id))?;
    let raw = resolve_secret_ref_for_context(
        vault,
        &SecretRef {
            secret_id: meta.secret_id,
        }
        .to_string(),
        Some(workspace_id),
        group_id,
        Some(capability),
        Some("plaid-item"),
    )?;
    serde_json::from_slice(&raw).map_err(|_| "stored Plaid Item secret is invalid".to_string())
}

fn revoke_item_secret(
    vault: &VaultRuntime,
    workspace_id: &str,
    item_id: &str,
) -> Result<(), String> {
    let name = item_secret_name(item_id);
    let scope = SecretScope::Workspace {
        workspace_id: workspace_id.to_string(),
    };
    let meta = vault
        .list_secrets()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|meta| meta.name == name && meta.scope == scope && meta.revoked_at_ms.is_none())
        .ok_or_else(|| format!("Plaid Item '{}' is not stored in this workspace", item_id))?;
    vault
        .revoke_secret(&meta.secret_id)
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn request_item_id(request: &PlaidCapabilityRequest) -> Result<String, String> {
    if let Some(item_id) = request
        .item_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Ok(item_id.to_string());
    }
    if let Some(credential_ref) = request
        .credential_ref
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return credential_ref
            .strip_prefix("plaid:item:")
            .map(str::to_string)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| "credentialRef must have form plaid:item:<item_id>".to_string());
    }
    Err("itemId or credentialRef is required".to_string())
}

fn item_secret_name(item_id: &str) -> String {
    format!("__aivault_plaid_item:{}", item_id.trim())
}

fn credential_ref_for_item(item_id: &str) -> String {
    format!("plaid:item:{}", item_id.trim())
}

fn credential_matches_context(
    credential: &StoredCredential,
    workspace_id: Option<&str>,
    group_id: Option<&str>,
) -> bool {
    let ws = workspace_id.map(str::trim).filter(|v| !v.is_empty());
    let group_id = group_id.map(str::trim).filter(|v| !v.is_empty());
    if group_id.is_some() && ws.is_none() {
        return false;
    }

    let cred_ws = credential
        .workspace_id
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let cred_group_id = credential
        .group_id
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());

    if let Some(cred_ws) = cred_ws {
        if ws != Some(cred_ws) {
            return false;
        }
        if let Some(cred_group_id) = cred_group_id {
            return group_id == Some(cred_group_id);
        }
        return true;
    }
    true
}

fn resolve_secret_ref_for_context(
    vault: &VaultRuntime,
    secret_ref: &str,
    workspace_id: Option<&str>,
    group_id: Option<&str>,
    capability: Option<&str>,
    consumer: Option<&str>,
) -> Result<Vec<u8>, String> {
    if let (Some(ws), Some(group_id)) = (workspace_id, group_id) {
        return vault
            .resolve_secret_ref_for_group(secret_ref, ws, group_id, capability, consumer)
            .map_err(|e| e.to_string());
    }
    vault
        .resolve_secret_ref(secret_ref, capability, consumer)
        .map_err(|e| e.to_string())
}

fn ensure_plaid_host_allowed(stored: &StoredCredential) -> Result<(), String> {
    if stored
        .hosts
        .iter()
        .any(|host| crate::broker::host_matches(host, PLAID_HOST))
    {
        return Ok(());
    }
    Err("Plaid credential host policy does not allow production.plaid.com".to_string())
}

fn response_envelope<T: Serialize>(
    capability: &str,
    credential: &str,
    payload: &T,
) -> Result<Value, String> {
    let body = serde_json::to_vec(payload).map_err(|e| e.to_string())?;
    let body_utf8 = String::from_utf8(body.clone()).ok();
    Ok(serde_json::json!({
        "planned": {
            "capability": capability,
            "credential": credential,
            "method": "POST",
            "url": "plaid://provider/"
        },
        "request": {
            "capability": capability,
            "credential": credential,
            "host": "plaid",
            "scheme": "plaid",
            "method": "POST",
            "path": "/"
        },
        "response": {
            "status": 200,
            "headers": [],
            "bodyUtf8": body_utf8,
            "bodyB64": base64::engine::general_purpose::STANDARD.encode(body)
        }
    }))
}

fn required_string(value: Option<&str>, label: &str) -> Result<String, String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("{} is required", label))
}

fn metadata_string(metadata: &Option<Value>, path: &[&str]) -> Option<String> {
    let mut cursor = metadata.as_ref()?;
    for key in path {
        cursor = cursor.get(*key)?;
    }
    cursor
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn redact_plaid_error(mut value: Value) -> Value {
    if let Some(obj) = value.as_object_mut() {
        obj.remove("access_token");
        obj.remove("public_token");
    }
    value
}

fn append_plaid_audit(
    vault: &VaultRuntime,
    kind: &str,
    item_id: Option<&str>,
    workspace_id: &str,
    group_id: Option<&str>,
    consumer: Option<&str>,
    note: &str,
) {
    append_audit_event(
        &vault.paths().audit_dir(),
        &VaultAuditEvent {
            ts_ms: Utc::now().timestamp_millis(),
            kind: kind.to_string(),
            secret_id: None,
            scope: Some(
                group_id
                    .map(|group| format!("group:{workspace_id}:{group}"))
                    .unwrap_or_else(|| format!("workspace:{workspace_id}")),
            ),
            actor: Some("aivault-cli".to_string()),
            capability: item_id.map(|id| format!("plaid:item:{id}")),
            consumer: consumer.map(str::to_string),
            note: Some(note.to_string()),
        },
    )
    .ok();
}

fn plaid_base_url() -> String {
    #[cfg(test)]
    {
        if let Ok(value) = std::env::var("AIVAULT_PLAID_BASE_URL") {
            return value.trim_end_matches('/').to_string();
        }
    }
    PLAID_BASE_URL.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_ref_round_trips_item_id() {
        let credential_ref = credential_ref_for_item("item-123");
        let request = PlaidCapabilityRequest {
            public_token: None,
            item_id: None,
            credential_ref: Some(credential_ref),
            institution_id: None,
            institution_name: None,
            products: Vec::new(),
            country_codes: Vec::new(),
            additional_consented_products: Vec::new(),
            client_name: None,
            language: None,
            redirect_uri: None,
            link_customization_name: None,
            user: None,
            cursor: None,
            count: None,
            max_pages: None,
            options: None,
            metadata: None,
        };

        assert_eq!(request_item_id(&request).unwrap(), "item-123");
    }

    #[test]
    fn builtin_capabilities_are_registered() {
        assert!(builtin_capability("plaid/item-exchange-store").is_some());
        assert!(builtin_capability("plaid/link-token-update").is_some());
        assert!(builtin_capability("plaid/item-remove").is_some());
        assert!(builtin_capability("plaid/accounts-sync").is_some());
        assert!(builtin_capability("plaid/liabilities-sync").is_some());
        assert!(builtin_capability("plaid/investments-sync").is_some());
        assert!(builtin_capability("plaid/transactions-sync").is_some());
        assert!(builtin_capability("plaid/transactions-recurring").is_some());
    }
}
