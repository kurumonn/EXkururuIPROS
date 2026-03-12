use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use reqwest::header::{ETAG, IF_NONE_MATCH};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use std::collections::HashMap;
use std::env;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
struct Config {
    workspace_slug: String,
    sensor_id: String,
    shared_secret: String,
    poll_interval_sec: u64,
    connect_timeout_sec: u64,
    read_timeout_sec: u64,
    backoff_base_sec: u64,
    backoff_max_sec: u64,
    heartbeat_sec: u64,
    ack_parallelism: usize,
    apply_mode: String,
    nft_family_table: String,
    nft_set: String,
    policy_url: String,
    pending_actions_url: String,
    ack_url_prefix: String,
}

impl Config {
    fn from_env() -> Result<Self> {
        let api_base = required_env("IPS_API_BASE")?
            .trim_end_matches('/')
            .to_string();
        let workspace_slug = required_env("IPS_WORKSPACE_SLUG")?;
        let sensor_id = required_env("IPS_SENSOR_ID")?;
        let pending_limit = env_u16("IPS_PENDING_LIMIT", 50, 1, 200);
        let policy_url = format!(
            "{}/api/v1/workspaces/{}/sensors/{}/policy/",
            api_base, workspace_slug, sensor_id
        );
        let pending_actions_url = format!(
            "{}/api/v1/workspaces/{}/sensors/{}/actions/pending/?limit={}",
            api_base, workspace_slug, sensor_id, pending_limit
        );
        let ack_url_prefix = format!(
            "{}/api/v1/workspaces/{}/sensors/{}/actions/",
            api_base, workspace_slug, sensor_id
        );
        Ok(Self {
            workspace_slug,
            sensor_id,
            shared_secret: required_env("IPS_SHARED_SECRET")?,
            poll_interval_sec: env_u64("IPS_POLICY_POLL_SEC", 5, 1, 300),
            connect_timeout_sec: env_u64("IPS_HTTP_CONNECT_TIMEOUT_SEC", 3, 1, 30),
            read_timeout_sec: env_u64("IPS_HTTP_READ_TIMEOUT_SEC", 8, 2, 120),
            backoff_base_sec: env_u64("IPS_BACKOFF_BASE_SEC", 2, 1, 60),
            backoff_max_sec: env_u64("IPS_BACKOFF_MAX_SEC", 30, 2, 600),
            heartbeat_sec: env_u64("IPS_HEARTBEAT_SEC", 60, 10, 3600),
            ack_parallelism: env_usize("IPS_ACK_PARALLELISM", 8, 1, 64),
            apply_mode: env::var("IPS_APPLY_MODE")
                .unwrap_or_else(|_| "dry-run".to_string())
                .trim()
                .to_lowercase(),
            nft_family_table: env::var("IPS_NFT_FAMILY_TABLE")
                .unwrap_or_else(|_| "inet ips".to_string())
                .trim()
                .to_string(),
            nft_set: env::var("IPS_NFT_SET")
                .unwrap_or_else(|_| "block_src".to_string())
                .trim()
                .to_string(),
            policy_url,
            pending_actions_url,
            ack_url_prefix,
        })
    }

    fn policy_url(&self) -> &str {
        &self.policy_url
    }

    fn pending_actions_url(&self) -> &str {
        &self.pending_actions_url
    }

    fn ack_url(&self, action_id: i64) -> String {
        format!("{}{action_id}/ack/", self.ack_url_prefix)
    }
}

#[derive(Debug, Deserialize)]
struct PolicyResponse {
    effective_policy: serde_json::Value,
    #[serde(default = "default_true")]
    waf_enabled: bool,
    #[serde(default)]
    waf_mode: String,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
struct PendingActionsResponse {
    actions: Vec<PendingAction>,
}

#[derive(Debug, Deserialize)]
struct PendingAction {
    id: i64,
    target_type: String,
    target_value: String,
    stage: String,
    ttl_seconds: u64,
}

#[derive(Debug, Serialize)]
struct AckPayload {
    status: String,
    meta: serde_json::Value,
}

#[derive(Debug, Clone)]
struct ApplyResult {
    status: String,
    meta: serde_json::Value,
}

fn required_env(key: &str) -> Result<String> {
    let value = env::var(key).with_context(|| format!("missing env: {key}"))?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        anyhow::bail!("empty env: {key}");
    }
    Ok(trimmed.to_string())
}

fn env_u64(key: &str, default: u64, min: u64, max: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
        .clamp(min, max)
}

fn env_u16(key: &str, default: u16, min: u16, max: u16) -> u16 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(default)
        .clamp(min, max)
}

fn env_usize(key: &str, default: usize, min: usize, max: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
        .clamp(min, max)
}

fn unix_timestamp_sec() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs() as i64
}

fn signed_headers(secret: &str, body: &[u8]) -> Result<(String, String)> {
    let ts = unix_timestamp_sec().to_string();
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).context("invalid HMAC secret")?;
    mac.update(ts.as_bytes());
    mac.update(b".");
    mac.update(body);
    let signature = hex::encode(mac.finalize().into_bytes());
    Ok((ts, signature))
}

fn compute_backoff_sleep_sec(cfg: &Config, consecutive_failures: u32) -> u64 {
    if consecutive_failures == 0 {
        return cfg.poll_interval_sec;
    }
    let exp = consecutive_failures.saturating_sub(1).min(10);
    let factor = 1u64 << exp;
    cfg.backoff_base_sec
        .saturating_mul(factor)
        .clamp(cfg.backoff_base_sec, cfg.backoff_max_sec)
}

fn is_safe_nft_ident(value: &str) -> bool {
    !value.is_empty()
        && value
            .as_bytes()
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
}

async fn fetch_policy(
    client: &reqwest::Client,
    cfg: &Config,
    etag_value: Option<&str>,
) -> Result<Option<(PolicyResponse, Option<String>)>> {
    let (ts, signature) = signed_headers(&cfg.shared_secret, b"")?;
    let mut req = client
        .get(cfg.policy_url())
        .header("X-IPS-Sensor-Id", &cfg.sensor_id)
        .header("X-IPS-Timestamp", ts)
        .header("X-IPS-Signature", signature);
    if let Some(etag) = etag_value {
        req = req.header(IF_NONE_MATCH, etag);
    }
    let resp = req.send().await.context("policy request failed")?;
    if resp.status().as_u16() == 304 {
        return Ok(None);
    }
    let resp = resp.error_for_status().context("policy response error")?;
    let etag = resp
        .headers()
        .get(ETAG)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string());
    let parsed = resp
        .json::<PolicyResponse>()
        .await
        .context("policy json decode failed")?;
    Ok(Some((parsed, etag)))
}

async fn fetch_pending_actions(
    client: &reqwest::Client,
    cfg: &Config,
) -> Result<Vec<PendingAction>> {
    let (ts, signature) = signed_headers(&cfg.shared_secret, b"")?;
    let resp = client
        .get(cfg.pending_actions_url())
        .header("X-IPS-Sensor-Id", &cfg.sensor_id)
        .header("X-IPS-Timestamp", ts)
        .header("X-IPS-Signature", signature)
        .send()
        .await
        .context("pending request failed")?
        .error_for_status()
        .context("pending response error")?;
    let parsed = resp
        .json::<PendingActionsResponse>()
        .await
        .context("pending json decode failed")?;
    Ok(parsed.actions)
}

async fn ack_action(
    client: &reqwest::Client,
    cfg: &Config,
    action_id: i64,
    payload: &AckPayload,
) -> Result<()> {
    let body = serde_json::to_vec(payload).context("serialize ack payload failed")?;
    let (ts, signature) = signed_headers(&cfg.shared_secret, &body)?;
    client
        .post(cfg.ack_url(action_id))
        .header("X-IPS-Sensor-Id", &cfg.sensor_id)
        .header("X-IPS-Timestamp", ts)
        .header("X-IPS-Signature", signature)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .context("ack request failed")?
        .error_for_status()
        .context("ack response error")?;
    Ok(())
}

async fn ack_actions_parallel(
    client: &reqwest::Client,
    cfg: &Config,
    payloads: Vec<(i64, AckPayload)>,
) -> Result<()> {
    if payloads.is_empty() {
        return Ok(());
    }
    let mut join_set = tokio::task::JoinSet::new();
    let mut iter = payloads.into_iter();
    let parallelism = cfg.ack_parallelism.max(1);

    loop {
        while join_set.len() < parallelism {
            let next = iter.next();
            if next.is_none() {
                break;
            }
            let (action_id, payload) = next.expect("checked is_some");
            let client_cloned = client.clone();
            let cfg_cloned = cfg.clone();
            join_set.spawn(async move {
                ack_action(&client_cloned, &cfg_cloned, action_id, &payload).await
            });
        }

        if join_set.is_empty() {
            break;
        }

        match join_set.join_next().await {
            Some(Ok(Ok(()))) => {}
            Some(Ok(Err(err))) => {
                join_set.abort_all();
                return Err(err);
            }
            Some(Err(err)) => {
                join_set.abort_all();
                anyhow::bail!("ack task join failed: {err}");
            }
            None => break,
        }
    }

    Ok(())
}

fn apply_action(cfg: &Config, action: &PendingAction) -> ApplyResult {
    ApplyResult {
        status: "applied".to_string(),
        meta: json!({
            "mode": cfg.apply_mode,
            "dry_run": true,
            "target_type": action.target_type,
            "target_value": action.target_value,
            "stage": action.stage,
            "ttl_seconds": action.ttl_seconds,
        }),
    }
}

fn apply_actions(cfg: &Config, actions: &[PendingAction]) -> Vec<(i64, ApplyResult)> {
    if actions.is_empty() {
        return Vec::new();
    }
    if cfg.apply_mode != "nft" {
        return actions
            .iter()
            .map(|action| (action.id, apply_action(cfg, action)))
            .collect();
    }

    let mut outputs: Vec<Option<ApplyResult>> = vec![None; actions.len()];
    let mut valid_inputs: Vec<(usize, String, u64)> = Vec::new();

    for (idx, action) in actions.iter().enumerate() {
        if action.target_type != "ip" {
            outputs[idx] = Some(ApplyResult {
                status: "failed".to_string(),
                meta: json!({"error": "only target_type=ip is supported in nft mode"}),
            });
            continue;
        }
        if action.target_value.parse::<std::net::IpAddr>().is_err() {
            outputs[idx] = Some(ApplyResult {
                status: "failed".to_string(),
                meta: json!({"error": "target_value is not a valid IP address"}),
            });
            continue;
        }
        valid_inputs.push((idx, action.target_value.clone(), action.ttl_seconds));
    }

    if !valid_inputs.is_empty() {
        let parts: Vec<&str> = cfg.nft_family_table.split_whitespace().collect();
        if parts.len() != 2 {
            for (idx, _, _) in &valid_inputs {
                outputs[*idx] = Some(ApplyResult {
                    status: "failed".to_string(),
                    meta: json!({"error": "IPS_NFT_FAMILY_TABLE must be '<family> <table>'"}),
                });
            }
        } else if !is_safe_nft_ident(parts[0])
            || !is_safe_nft_ident(parts[1])
            || !is_safe_nft_ident(&cfg.nft_set)
        {
            for (idx, _, _) in &valid_inputs {
                outputs[*idx] = Some(ApplyResult {
                    status: "failed".to_string(),
                    meta: json!({"error": "unsafe nft identifier in IPS_NFT_FAMILY_TABLE or IPS_NFT_SET"}),
                });
            }
        } else {
            let mut ttl_by_ip: HashMap<String, u64> = HashMap::new();
            for (_, ip, ttl) in &valid_inputs {
                ttl_by_ip
                    .entry(ip.clone())
                    .and_modify(|x| {
                        if *ttl > *x {
                            *x = *ttl;
                        }
                    })
                    .or_insert(*ttl);
            }

            let mut deduped: Vec<(String, u64)> = ttl_by_ip.into_iter().collect();
            deduped.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            let elements = deduped
                .iter()
                .map(|(ip, ttl)| format!("{ip} timeout {ttl}s"))
                .collect::<Vec<String>>()
                .join(", ");
            let script = format!(
                "add element {} {} {} {{ {} }}\n",
                parts[0], parts[1], cfg.nft_set, elements
            );

            let output = (|| -> std::io::Result<std::process::Output> {
                let mut child = Command::new("nft")
                    .args(["-f", "-"])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()?;
                if let Some(stdin) = child.stdin.as_mut() {
                    stdin.write_all(script.as_bytes())?;
                }
                child.wait_with_output()
            })();

            match output {
                Ok(cmd) if cmd.status.success() => {
                    for (idx, ip, ttl) in &valid_inputs {
                        outputs[*idx] = Some(ApplyResult {
                            status: "applied".to_string(),
                            meta: json!({
                                "mode": "nft",
                                "batched": true,
                                "target_type": "ip",
                                "target_value": ip,
                                "ttl_seconds": ttl,
                                "batch_size": deduped.len(),
                            }),
                        });
                    }
                }
                Ok(cmd) => {
                    let stderr = String::from_utf8_lossy(&cmd.stderr)
                        .chars()
                        .take(400)
                        .collect::<String>();
                    for (idx, _, _) in &valid_inputs {
                        outputs[*idx] = Some(ApplyResult {
                            status: "failed".to_string(),
                            meta: json!({"mode": "nft", "batched": true, "stderr": stderr}),
                        });
                    }
                }
                Err(err) => {
                    for (idx, _, _) in &valid_inputs {
                        outputs[*idx] = Some(ApplyResult {
                            status: "failed".to_string(),
                            meta: json!({"mode": "nft", "batched": true, "error": err.to_string()}),
                        });
                    }
                }
            }
        }
    }

    actions
        .iter()
        .enumerate()
        .map(|(idx, action)| {
            (
                action.id,
                outputs[idx].clone().unwrap_or_else(|| ApplyResult {
                    status: "failed".to_string(),
                    meta: json!({"error": "action apply failed"}),
                }),
            )
        })
        .collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = Config::from_env()?;
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(cfg.connect_timeout_sec))
        .timeout(Duration::from_secs(cfg.read_timeout_sec))
        .build()
        .context("failed to build http client")?;
    let mut etag_value: Option<String> = None;
    let mut consecutive_failures = 0u32;
    let mut last_heartbeat = Instant::now();
    let mut current_waf_enabled = true;
    let mut current_waf_mode = "block".to_string();

    println!(
        "kurutann-ips-sensor started sensor_id={} workspace={} mode={} ack_parallelism={}",
        cfg.sensor_id, cfg.workspace_slug, cfg.apply_mode, cfg.ack_parallelism
    );

    loop {
        let cycle = async {
            if let Some((policy, new_etag)) =
                fetch_policy(&client, &cfg, etag_value.as_deref()).await?
            {
                etag_value = new_etag;
                current_waf_enabled = policy.waf_enabled;
                if !policy.waf_mode.trim().is_empty() {
                    current_waf_mode = policy.waf_mode.trim().to_string();
                }
                println!(
                    "policy updated: {} waf_enabled={} waf_mode={}",
                    policy.effective_policy, current_waf_enabled, current_waf_mode
                );
            }
            if current_waf_enabled {
                let actions = fetch_pending_actions(&client, &cfg).await?;
                let applied = apply_actions(&cfg, &actions);
                let mut ack_payloads: Vec<(i64, AckPayload)> = Vec::with_capacity(applied.len());
                for (action_id, result) in applied {
                    ack_payloads.push((
                        action_id,
                        AckPayload {
                            status: result.status,
                            meta: result.meta,
                        },
                    ));
                }
                ack_actions_parallel(&client, &cfg, ack_payloads).await?;
            } else {
                println!("waf is disabled by server policy; skipping action apply");
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;

        match cycle {
            Ok(()) => {
                if consecutive_failures > 0 {
                    println!(
                        "sensor recovered after consecutive_failures={}",
                        consecutive_failures
                    );
                }
                consecutive_failures = 0;
            }
            Err(err) => {
                consecutive_failures = consecutive_failures.saturating_add(1);
                eprintln!("sensor loop error: {err:#}");
            }
        }

        if last_heartbeat.elapsed().as_secs() >= cfg.heartbeat_sec {
            println!(
                "sensor heartbeat sensor_id={} failures={} mode={} waf_enabled={} waf_mode={}",
                cfg.sensor_id,
                consecutive_failures,
                cfg.apply_mode,
                current_waf_enabled,
                current_waf_mode
            );
            last_heartbeat = Instant::now();
        }

        sleep(Duration::from_secs(compute_backoff_sleep_sec(
            &cfg,
            consecutive_failures,
        )))
        .await;
    }
}
