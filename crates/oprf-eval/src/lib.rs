//! Measurement-only threshold OPRF and pseudonymisation experiment.
//! This is deliberately unaudited research code and must not protect real data.

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;

const KEY_SEED: &[u8] = b"ADAM Test 4 fixed measurement threshold key v1";

#[derive(Clone)]
pub struct ThresholdKey {
    shares: [Scalar; 2],
}

impl Default for ThresholdKey {
    fn default() -> Self {
        let key = Scalar::from_hash(Sha512::new().chain_update(KEY_SEED));
        let share0 = Scalar::from_hash(Sha512::new().chain_update(b"ADAM share zero v1"));
        Self {
            shares: [share0, key - share0],
        }
    }
}

impl ThresholdKey {
    /// Executes both holder evaluations separately, then aggregates and unblinds.
    pub fn token<R: RngCore>(&self, entity_type: &str, raw: &str, rng: &mut R) -> String {
        let point = RistrettoPoint::hash_from_bytes::<Sha512>(
            &[
                b"ADAM OPRF input v1\0",
                entity_type.as_bytes(),
                b"\0",
                raw.as_bytes(),
            ]
            .concat(),
        );
        let blind = loop {
            let mut wide = [0_u8; 64];
            rng.fill_bytes(&mut wide);
            let candidate = Scalar::from_bytes_mod_order_wide(&wide);
            if candidate != Scalar::ZERO {
                break candidate;
            }
        };
        let blinded = point * blind;
        let holder0 = blinded * self.shares[0];
        let holder1 = blinded * self.shares[1];
        let unblinded = (holder0 + holder1) * blind.invert();
        let digest = Sha256::digest(
            [
                b"ADAM token v1\0".as_slice(),
                entity_type.as_bytes(),
                b"\0",
                unblinded.compress().as_bytes(),
            ]
            .concat(),
        );
        format!("tok_{entity_type}_{}", hex::encode(&digest[..16]))
    }

    #[cfg(test)]
    fn incomplete_token<R: RngCore>(&self, entity_type: &str, raw: &str, rng: &mut R) -> String {
        let point = RistrettoPoint::hash_from_bytes::<Sha512>(raw.as_bytes());
        let mut wide = [0_u8; 64];
        rng.fill_bytes(&mut wide);
        let blind = Scalar::from_bytes_mod_order_wide(&wide);
        let value = point * blind * self.shares[0] * blind.invert();
        let digest = Sha256::digest(value.compress().as_bytes());
        format!("tok_{entity_type}_{}", hex::encode(digest))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Alert {
    pub id: String,
    pub timestamp: String,
    #[serde(skip)]
    pub technique: String,
    pub user: String,
    pub machine: String,
    pub process: String,
    pub parent_process: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub file_path: String,
    pub domain: String,
    pub file_hash: String,
    pub command_line: String,
    pub pid: u32,
    pub bytes: u64,
    pub relationships: Vec<String>,
}

pub const TECHNIQUES: [&str; 6] = [
    "credential_dumping",
    "lateral_movement",
    "phishing",
    "data_exfiltration",
    "privilege_escalation",
    "ransomware_preparation",
];

pub fn synthetic_alerts() -> Vec<Alert> {
    let processes = [
        "rundll32.exe",
        "psexec.exe",
        "outlook.exe",
        "rclone.exe",
        "fodhelper.exe",
        "vssadmin.exe",
    ];
    let parents = [
        "wininit.exe",
        "svchost.exe",
        "explorer.exe",
        "powershell.exe",
        "cmd.exe",
        "powershell.exe",
    ];
    let mut alerts = Vec::with_capacity(30);
    let mut metadata_rng = StdRng::seed_from_u64(0xADA4_0030);
    for (t, technique) in TECHNIQUES.iter().enumerate() {
        for variant in 0..5 {
            let service = variant % 2 == 0;
            let public = variant % 2 == 1;
            let process = if variant == 4 {
                "svchost.exe"
            } else {
                processes[t]
            };
            let file_path: String = if variant == 4 {
                "C:\\Windows\\System32\\svchost.exe".into()
            } else {
                match t {
                    0 => "C:\\Windows\\System32\\lsass.exe".into(),
                    2 => format!("C:\\Users\\analyst{variant}\\Downloads\\invoice.docm"),
                    3 => "C:\\Finance\\quarterly-results.zip".into(),
                    _ => format!("C:\\Users\\analyst{variant}\\Downloads\\payload{t}.exe"),
                }
            };
            let src_ip = if public { "198.51.100.42" } else { "10.0.0.8" };
            let dst_ip = if public {
                "203.0.113.77"
            } else {
                "192.168.1.20"
            };
            let domain = if t == 2 {
                "login-microsoft.example"
            } else {
                "corp.contoso.example"
            };
            let command_line = match t {
                0 => format!("{process} MiniDump target={file_path} full"),
                1 => format!("{process} remote_exec destination={dst_ip}"),
                2 => format!("{process} open_attachment={file_path} sender={domain}"),
                3 => format!("{process} copy source={file_path} destination={dst_ip}"),
                4 => format!("{process} elevation=/high"),
                5 => format!("{process} delete_shadows=/all,/quiet"),
                _ => unreachable!(),
            };
            alerts.push(Alert {
                id: format!("ALRT-{:016x}", metadata_rng.gen::<u64>()),
                timestamp: format!(
                    "2026-01-{:02}T12:{:02}:00Z",
                    metadata_rng.gen_range(1..=28),
                    metadata_rng.gen_range(0..60)
                ),
                technique: (*technique).into(),
                user: if service {
                    "NT AUTHORITY\\SYSTEM".into()
                } else {
                    format!("CONTOSO\\analyst{variant}")
                },
                machine: format!("WKSTN-{:02}", variant + 1),
                process: process.into(),
                parent_process: parents[t].into(),
                src_ip: src_ip.into(),
                dst_ip: dst_ip.into(),
                file_path,
                domain: domain.into(),
                file_hash: if variant < 2 {
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()
                } else {
                    format!("{:064x}", t * 10 + variant)
                },
                command_line,
                pid: metadata_rng.gen_range(1000..50_000),
                bytes: metadata_rng.gen_range(1_024..5_000_000),
                relationships: vec![
                    format!("{} spawned {}", parents[t], process),
                    format!("{} connected to destination", process),
                ],
            });
        }
    }
    alerts
}

#[derive(Default)]
pub struct ReverseMap(pub HashMap<String, String>);

impl ReverseMap {
    pub fn depseudonymize(&self, text: &str) -> String {
        let mut pairs: Vec<_> = self.0.iter().collect();
        pairs.sort_by_key(|(token, _)| std::cmp::Reverse(token.len()));
        pairs
            .into_iter()
            .fold(text.to_owned(), |s, (token, raw)| s.replace(token, raw))
    }
}

#[derive(Clone, Copy)]
pub enum Mode {
    Full,
    Hybrid,
}

fn basename(value: &str) -> &str {
    value.rsplit(['\\', '/']).next().unwrap_or(value)
}
fn known_process(value: &str) -> bool {
    matches!(
        basename(value).to_ascii_lowercase().as_str(),
        "lsass.exe"
            | "svchost.exe"
            | "rundll32.exe"
            | "psexec.exe"
            | "outlook.exe"
            | "rclone.exe"
            | "fodhelper.exe"
            | "vssadmin.exe"
            | "powershell.exe"
            | "cmd.exe"
            | "wininit.exe"
            | "explorer.exe"
    )
}
fn ip_class(ip: &str) -> &'static str {
    let private = ip.starts_with("10.")
        || ip.starts_with("192.168.")
        || ip.split('.').take(2).collect::<Vec<_>>().first() == Some(&"172")
            && ip
                .split('.')
                .nth(1)
                .and_then(|x| x.parse::<u8>().ok())
                .is_some_and(|x| (16..=31).contains(&x));
    if private {
        "RFC1918"
    } else {
        "PUBLIC"
    }
}

fn replace_entities(source: &str, replacements: &[(&str, &str)]) -> String {
    let mut replacements = replacements.to_vec();
    replacements.sort_by_key(|(raw, _)| std::cmp::Reverse(raw.len()));
    let mut result = String::with_capacity(source.len());
    let mut offset = 0;
    while offset < source.len() {
        if let Some((raw, replacement)) = replacements
            .iter()
            .find(|(raw, _)| !raw.is_empty() && source[offset..].starts_with(*raw))
        {
            result.push_str(replacement);
            offset += raw.len();
        } else {
            let character = source[offset..]
                .chars()
                .next()
                .expect("valid string offset");
            result.push(character);
            offset += character.len_utf8();
        }
    }
    result
}

pub fn pseudonymize<R: RngCore>(
    alert: &Alert,
    mode: Mode,
    key: &ThresholdKey,
    rng: &mut R,
    reverse: &mut ReverseMap,
) -> Alert {
    let mut token = |kind: &str, raw: &str| {
        let v = key.token(kind, raw, rng);
        reverse.0.insert(v.clone(), raw.into());
        v
    };
    let process = |raw: &str, token: &mut dyn FnMut(&str, &str) -> String| match mode {
        Mode::Hybrid if known_process(raw) => {
            format!("semantic_process:{}", basename(raw).to_ascii_lowercase())
        }
        Mode::Hybrid => format!("semantic_process:other:{}", token("process", raw)),
        Mode::Full => token("process", raw),
    };
    let ip = |raw: &str, token: &mut dyn FnMut(&str, &str) -> String| match mode {
        Mode::Hybrid => format!("ip_class:{}:{}", ip_class(raw), token("ip", raw)),
        Mode::Full => token("ip", raw),
    };
    let mut out = alert.clone();
    out.user = match mode {
        Mode::Hybrid => format!(
            "account_class:{}:{}",
            if alert.user == "NT AUTHORITY\\SYSTEM" {
                "SERVICE"
            } else {
                "PERSON"
            },
            token("user", &alert.user)
        ),
        Mode::Full => token("user", &alert.user),
    };
    out.machine = token("machine", &alert.machine);
    out.process = process(&alert.process, &mut token);
    out.parent_process = process(&alert.parent_process, &mut token);
    out.src_ip = ip(&alert.src_ip, &mut token);
    out.dst_ip = ip(&alert.dst_ip, &mut token);
    out.file_path = match mode {
        Mode::Hybrid => format!(
            "semantic_path:{}:{}",
            basename(&alert.file_path),
            token("file_path", &alert.file_path)
        ),
        Mode::Full => token("file_path", &alert.file_path),
    };
    out.domain = token("domain", &alert.domain);
    out.file_hash = token("file_hash", &alert.file_hash);
    let replacements = [
        (alert.user.as_str(), out.user.as_str()),
        (alert.machine.as_str(), out.machine.as_str()),
        (alert.process.as_str(), out.process.as_str()),
        (alert.parent_process.as_str(), out.parent_process.as_str()),
        (alert.src_ip.as_str(), out.src_ip.as_str()),
        (alert.dst_ip.as_str(), out.dst_ip.as_str()),
        (alert.file_path.as_str(), out.file_path.as_str()),
        (alert.domain.as_str(), out.domain.as_str()),
        (alert.file_hash.as_str(), out.file_hash.as_str()),
    ];
    out.command_line = replace_entities(&alert.command_line, &replacements);
    out.relationships = alert
        .relationships
        .iter()
        .map(|relationship| replace_entities(relationship, &replacements))
        .collect();
    out
}

/// Monte Carlo estimate of observations needed for rank inference at `confidence`.
/// Ties are failures, avoiding any ground-truth-favouring tie-break. The returned
/// points are the earliest sample sizes after which confidence remains at or above
/// the target through `events_per_trial`.
pub fn frequency_rank_recovery(
    trials: usize,
    events_per_trial: usize,
    seed: u64,
    confidence: f64,
) -> (usize, usize) {
    let cumulative = [40_u32, 65, 80, 90, 96, 100];
    let mut rng = StdRng::seed_from_u64(seed);
    let mut top1_successes = vec![0_usize; events_per_trial];
    let mut top3_successes = vec![0_usize; events_per_trial];
    for _ in 0..trials {
        let mut counts = [0_usize; 6];
        for event in 0..events_per_trial {
            let draw = rng.gen_range(0..100);
            let index = cumulative.iter().position(|bound| draw < *bound).unwrap();
            counts[index] += 1;
            if counts[0] > *counts[1..].iter().max().unwrap() {
                top1_successes[event] += 1;
            }
            if counts[0] > counts[1]
                && counts[1] > counts[2]
                && counts[2] > *counts[3..].iter().max().unwrap()
            {
                top3_successes[event] += 1;
            }
        }
    }
    let stable_threshold = |successes: &[usize]| {
        let required = (confidence * trials as f64).ceil() as usize;
        let mut stable = true;
        let mut earliest = events_per_trial;
        for (index, successes) in successes.iter().enumerate().rev() {
            stable &= *successes >= required;
            if stable {
                earliest = index + 1;
            }
        }
        earliest
    };
    (
        stable_threshold(&top1_successes),
        stable_threshold(&top3_successes),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};
    #[test]
    fn oprf_properties() {
        let key = ThresholdKey::default();
        let a = key.token("user", "alice", &mut StdRng::seed_from_u64(1));
        assert_eq!(a, key.token("user", "alice", &mut StdRng::seed_from_u64(2)));
        assert_eq!(a, key.token("user", "alice", &mut StdRng::seed_from_u64(3))); // another customer
        assert_ne!(
            a,
            key.token("machine", "alice", &mut StdRng::seed_from_u64(1))
        );
        assert_ne!(
            a,
            key.incomplete_token("user", "alice", &mut StdRng::seed_from_u64(1))
        );
    }
    #[test]
    fn corpus_and_pseudonymisation() {
        let alerts = synthetic_alerts();
        assert_eq!(alerts.len(), 30);
        assert!(!serde_json::to_string(&alerts[0])
            .unwrap()
            .contains("technique"));
        for technique in TECHNIQUES {
            assert_eq!(
                alerts.iter().filter(|a| a.technique == technique).count(),
                5
            );
        }
        let original = &alerts[0];
        let mut reverse = ReverseMap::default();
        let full = pseudonymize(
            original,
            Mode::Full,
            &ThresholdKey::default(),
            &mut StdRng::seed_from_u64(4),
            &mut reverse,
        );
        assert_eq!(full.id, original.id);
        assert_eq!(full.timestamp, original.timestamp);
        assert_eq!(full.pid, original.pid);
        assert_ne!(full.user, original.user);
        assert!(reverse.depseudonymize(&full.user).contains(&original.user));
        let hybrid = pseudonymize(
            original,
            Mode::Hybrid,
            &ThresholdKey::default(),
            &mut StdRng::seed_from_u64(5),
            &mut ReverseMap::default(),
        );
        assert!(hybrid.process.contains(&original.process));
        assert!(hybrid.src_ip.contains("RFC1918"));
        assert!(!hybrid.src_ip.contains("10.0.0.8"));

        for original in &alerts {
            let full = pseudonymize(
                original,
                Mode::Full,
                &ThresholdKey::default(),
                &mut StdRng::seed_from_u64(6),
                &mut ReverseMap::default(),
            );
            let serialized = serde_json::to_string(&full).unwrap();
            for raw in [
                &original.user,
                &original.machine,
                &original.process,
                &original.parent_process,
                &original.src_ip,
                &original.dst_ip,
                &original.file_path,
                &original.domain,
                &original.file_hash,
            ] {
                assert!(!serialized.contains(raw), "full mode leaked {raw}");
            }
        }
    }

    #[test]
    fn frequency_recovery_is_reproducible_and_bounded() {
        let result = frequency_rank_recovery(100, 5000, 7, 0.95);
        assert_eq!(result, frequency_rank_recovery(100, 5000, 7, 0.95));
        assert!(result.0 <= result.1);
        assert!(result.1 <= 5000);
    }
}
