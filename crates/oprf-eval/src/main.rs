use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use oprf_eval::{pseudonymize, synthetic_alerts, Mode, ReverseMap, ThresholdKey};
use rand::{rngs::StdRng, Rng, SeedableRng};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeSet, HashSet},
    fs,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

#[derive(Parser)]
#[command(about = "Measurement-only threshold OPRF evaluation")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    OprfOnly {
        #[arg(long, default_value_t = 1000)]
        repetitions: usize,
    },
    Run {
        #[arg(long, default_value = "http://127.0.0.1:8080/v1/chat/completions")]
        llm_url: String,
        #[arg(long)]
        model: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        report: PathBuf,
        #[arg(long, default_value_t = 1000)]
        repetitions: usize,
    },
}
#[derive(Serialize)]
struct Measurement {
    repetitions: usize,
    mean_us: f64,
    stddev_us: f64,
    min_us: f64,
    max_us: f64,
    deterministic: bool,
    deterministic_test_token: String,
    cross_customer_external_ip: bool,
    cross_customer_file_hash: bool,
    cross_customer_private_ip: bool,
    external_ip_test_value: &'static str,
    file_hash_test_value: &'static str,
    private_ip_test_value: &'static str,
    frequency_tokens_generated: usize,
    frequency_distinct_tokens: usize,
    frequency_trials: usize,
    frequency_events: usize,
    frequency_confidence: f64,
    earliest_top1: usize,
    earliest_exact_top3: usize,
}
#[derive(Serialize, Deserialize, Clone)]
struct Answer {
    technique: String,
    severity: String,
    actions: Vec<String>,
    relationships: Vec<String>,
}
#[derive(Serialize, Deserialize)]
struct RawRecord {
    alert_id: String,
    mode: String,
    request: Value,
    response: String,
    parsed: Option<Answer>,
    error: Option<String>,
}

fn measure(repetitions: usize) -> Measurement {
    assert!(repetitions > 0);
    let key = ThresholdKey::default();
    let mut rng = StdRng::seed_from_u64(0xAD_A4);
    let mut samples = Vec::with_capacity(repetitions);
    for _ in 0..repetitions {
        let now = Instant::now();
        std::hint::black_box(key.token("user", "CONTOSO\\alice", &mut rng));
        samples.push(now.elapsed().as_secs_f64() * 1e6);
    }
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    let stddev =
        (samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / samples.len() as f64).sqrt();
    let token = |kind, raw, seed| key.token(kind, raw, &mut StdRng::seed_from_u64(seed));
    let names = ["alice", "bob", "carol", "dave", "erin", "frank"];
    let cumulative = [40, 65, 80, 90, 96, 100];
    let mut frequency_rng = StdRng::seed_from_u64(0xFEE1_5000);
    let mut frequency_tokens = HashSet::new();
    for _ in 0..5000 {
        let draw = frequency_rng.gen_range(0..100);
        let index = cumulative.iter().position(|bound| draw < *bound).unwrap();
        frequency_tokens.insert(key.token("user", names[index], &mut frequency_rng));
    }
    let (top1, top3) = oprf_eval::frequency_rank_recovery(500, 5000, 0xFEE1_DEAD, 0.95);
    let deterministic_test_token = token("user", "alice", 1);
    Measurement {
        repetitions,
        mean_us: mean,
        stddev_us: stddev,
        min_us: samples.iter().copied().fold(f64::INFINITY, f64::min),
        max_us: samples.iter().copied().fold(0., f64::max),
        deterministic: deterministic_test_token == token("user", "alice", 2),
        deterministic_test_token,
        cross_customer_external_ip: token("ip", "203.0.113.77", 3)
            == token("ip", "203.0.113.77", 4),
        cross_customer_file_hash: token(
            "file_hash",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            5,
        ) == token(
            "file_hash",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            6,
        ),
        cross_customer_private_ip: token("ip", "10.0.0.8", 7) == token("ip", "10.0.0.8", 8),
        external_ip_test_value: "203.0.113.77",
        file_hash_test_value: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        private_ip_test_value: "10.0.0.8",
        frequency_tokens_generated: 5000,
        frequency_distinct_tokens: frequency_tokens.len(),
        frequency_trials: 500,
        frequency_events: 5000,
        frequency_confidence: 0.95,
        earliest_top1: top1,
        earliest_exact_top3: top3,
    }
}
fn extract(raw: &str) -> Result<Answer> {
    let stripped = raw
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();
    if let Ok(v) = serde_json::from_str(stripped) {
        return Ok(v);
    }
    let start = stripped.find('{').context("no JSON object")?;
    let end = stripped.rfind('}').context("no JSON object end")?;
    Ok(serde_json::from_str(&stripped[start..=end])?)
}
fn ask(
    client: &Client,
    url: &str,
    model: &str,
    alert: &oprf_eval::Alert,
) -> Result<(Value, String, Answer)> {
    const PROMPT:&str="Analyze this synthetic Defender-like alert. Technique definitions: credential_dumping means access to LSASS memory or a credential minidump; lateral_movement means remote execution or authentication such as PsExec; phishing means a malicious message or Office attachment; data_exfiltration means copying data to external storage or a remote destination; privilege_escalation means bypass or elevation such as fodhelper; ransomware_preparation means deleting shadows or disabling recovery. Infer from the alert evidence. Return strict JSON only: {\"technique\": one of [\"credential_dumping\",\"lateral_movement\",\"phishing\",\"data_exfiltration\",\"privilege_escalation\",\"ransomware_preparation\"], \"severity\": one of [\"low\",\"medium\",\"high\",\"critical\"], \"actions\": array chosen only from [\"isolate_host\",\"disable_user\",\"block_ip\",\"quarantine_file\",\"collect_forensics\",\"reset_credentials\",\"monitor\"], \"relationships\": up to three short generic relationship types}. Never copy entity identifiers into relationships. Do not add fields or prose.";
    let request = json!({"model":model,"temperature":0,"max_tokens":400,"reasoning":{"effort":"none"},"messages":[{"role":"system","content":PROMPT},{"role":"user","content":serde_json::to_string(alert)?}],"response_format":{"type":"json_object"}});
    for attempt in 0..5 {
        let mut request_builder = client.post(url).json(&request);
        if let Ok(api_key) = std::env::var("OPENROUTER_API_KEY") {
            request_builder = request_builder.bearer_auth(api_key);
        }
        let response = request_builder.send()?;
        if response.status().as_u16() == 429 {
            thread::sleep(Duration::from_secs(2_u64.pow(attempt + 1)));
            continue;
        }
        let body = response.error_for_status()?.text()?;
        let envelope: Value = serde_json::from_str(&body)?;
        if let Some(content) = envelope
            .pointer("/choices/0/message/content")
            .and_then(Value::as_str)
        {
            return Ok((request, body, extract(content)?));
        }
        thread::sleep(Duration::from_secs(2_u64.pow(attempt + 1)));
    }
    bail!("LLM request exhausted five rate-limit/content retries")
}
fn main() -> Result<()> {
    match Cli::parse().command {
        Command::OprfOnly { repetitions } => {
            println!("{}", serde_json::to_string_pretty(&measure(repetitions))?)
        }
        Command::Run {
            llm_url,
            model,
            output,
            report,
            repetitions,
        } => {
            let measurement = measure(repetitions);
            let alerts = synthetic_alerts();
            let key = ThresholdKey::default();
            let client = Client::builder().build()?;
            let mut raw: Vec<RawRecord> = fs::read(&output)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .unwrap_or_default();
            let mut rows = Vec::new();
            let mut totals = [0usize; 2];
            let mut ground_truth_technique = [0usize; 3];
            for alert in alerts {
                let mut reverse_full = ReverseMap::default();
                let mut reverse_hybrid = ReverseMap::default();
                let full = pseudonymize(
                    &alert,
                    Mode::Full,
                    &key,
                    &mut StdRng::seed_from_u64(1000 + rows.len() as u64),
                    &mut reverse_full,
                );
                let hybrid = pseudonymize(
                    &alert,
                    Mode::Hybrid,
                    &key,
                    &mut StdRng::seed_from_u64(2000 + rows.len() as u64),
                    &mut reverse_hybrid,
                );
                let mut answers = Vec::new();
                for (name, item, reverse) in [
                    ("original", &alert, None),
                    ("full", &full, Some(&reverse_full)),
                    ("hybrid", &hybrid, Some(&reverse_hybrid)),
                ] {
                    let cached = raw
                        .iter()
                        .rev()
                        .find(|record| {
                            record.alert_id == alert.id
                                && record.mode == name
                                && record.error.is_none()
                        })
                        .and_then(|record| record.parsed.clone());
                    if let Some(answer) = cached {
                        answers.push(answer);
                        continue;
                    }
                    match ask(&client, &llm_url, &model, item) {
                        Ok((req, response, mut answer)) => {
                            if let Some(r) = reverse {
                                answer.technique = r.depseudonymize(&answer.technique);
                                answer.severity = r.depseudonymize(&answer.severity);
                                answer.actions = answer
                                    .actions
                                    .into_iter()
                                    .map(|x| r.depseudonymize(&x))
                                    .collect();
                                answer.relationships = answer
                                    .relationships
                                    .into_iter()
                                    .map(|x| r.depseudonymize(&x))
                                    .collect();
                            }
                            raw.push(RawRecord {
                                alert_id: alert.id.clone(),
                                mode: name.into(),
                                request: req,
                                response,
                                parsed: Some(answer.clone()),
                                error: None,
                            });
                            answers.push(answer);
                        }
                        Err(e) => {
                            raw.push(RawRecord {
                                alert_id: alert.id.clone(),
                                mode: name.into(),
                                request: Value::Null,
                                response: String::new(),
                                parsed: None,
                                error: Some(format!("{e:#}")),
                            });
                            fs::write(&output, serde_json::to_vec_pretty(&raw)?)?;
                            return Err(e.context(format!(
                                "LLM call {} {} (raw cache updated)",
                                alert.id, name
                            )));
                        }
                    }
                    fs::write(&output, serde_json::to_vec_pretty(&raw)?)?;
                }
                for (index, answer) in answers.iter().enumerate() {
                    ground_truth_technique[index] +=
                        usize::from(answer.technique == alert.technique);
                }
                for (index, label) in [(1, "full"), (2, "hybrid")] {
                    let a = &answers[0];
                    let b = &answers[index];
                    let technique = a.technique == b.technique;
                    let severity = a.severity == b.severity;
                    let actions: BTreeSet<_> = a.actions.iter().collect();
                    let bactions: BTreeSet<_> = b.actions.iter().collect();
                    let fewer = b.relationships.len() < a.relationships.len();
                    let hallucination =
                        a.technique == alert.technique && b.technique != alert.technique;
                    totals[index - 1] += usize::from(technique && severity && actions == bactions);
                    let note = if a.technique != alert.technique {
                        "A misses ground truth"
                    } else if hallucination {
                        "B diverges from ground truth"
                    } else if !severity || actions != bactions || fewer {
                        "reasoning detail changed"
                    } else {
                        "—"
                    };
                    rows.push(format!(
                        "| {} ({}) | {} / {} | {} | {} | {} | {} | {} | {} |",
                        alert.id,
                        label,
                        a.technique,
                        b.technique,
                        if technique { "yes" } else { "no" },
                        if severity { "yes" } else { "no" },
                        if actions == bactions { "yes" } else { "no" },
                        if fewer { "yes" } else { "no" },
                        if hallucination { "yes" } else { "no" },
                        note
                    ));
                }
            }
            let report_text=format!("## Test 4 — threshold OPRF pseudonymisation\n\n```json\n{}\n```\n\nHybrid explicitly leaks service/person account class, RFC1918/public IP class, known system/LOLBin process basenames, and file basenames; exact identities remain tokenized. Frequency results are event-count observations under one stated synthetic distribution, not a universal safe rotation threshold.\n\n| Alert (mode B) | Technique A / B | Match | Severity | Actions | Fewer relations | Hallucination | Note |\n|---|---|---|---|---|---|---|---|\n{}\n\nAggregate exact technique+severity+action matches: full {}/30; hybrid {}/30. Ground-truth technique accuracy: original {}/30; full {}/30; hybrid {}/30.\n",serde_json::to_string_pretty(&measurement)?,rows.join("\n"),totals[0],totals[1],ground_truth_technique[0],ground_truth_technique[1],ground_truth_technique[2]);
            fs::write(report, report_text)?;
        }
    }
    Ok(())
}
