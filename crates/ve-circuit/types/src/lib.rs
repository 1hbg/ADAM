//! Shared statement types and deterministic verification logic for the SP1 guest.

use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use rsa::{BigUint, Oaep, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SCHEMA_DESCRIPTOR: &[u8] = b"ADAM_ALERT_V1|serialization:bincode1|schema_version:u16=1|alert_id:bytes16,nonzero|timestamp:u64[1577836800,4102444800]|severity:u8[1,10]|category:u8[0,4]|user:ascii_string[1,32]|machine:ascii_string[1,64]|process:ascii_string[1,64]|ip:ascii_string[1,45]|file_path:ascii_string[1,128]";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdamAlert {
    pub schema_version: u16,
    pub alert_id: [u8; 16],
    pub timestamp: u64,
    pub severity: u8,
    pub category: u8,
    pub user: String,
    pub machine: String,
    pub process: String,
    pub ip: String,
    pub file_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Witness {
    pub alert: AdamAlert,
    pub schema_commitment: [u8; 32],
    pub sensor_public_key: Vec<u8>,
    pub sensor_signature: Vec<u8>,
    pub recipient_modulus: Vec<u8>,
    pub recipient_exponent: Vec<u8>,
    pub encryption_seed: [u8; 32],
    pub expected_ciphertext: Vec<u8>,
    pub org_secret: [u8; 32],
    pub campaign_id: [u8; 16],
    pub epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicValues {
    pub ciphertext: Vec<u8>,
    pub schema_commitment: [u8; 32],
    pub sensor_public_key: Vec<u8>,
    pub recipient_key_hash: [u8; 32],
    pub campaign_id: [u8; 16],
    pub epoch: u64,
    pub nullifier: [u8; 32],
}

pub fn schema_commitment() -> [u8; 32] {
    Sha256::digest(SCHEMA_DESCRIPTOR).into()
}

pub fn alert_bytes(alert: &AdamAlert) -> Result<Vec<u8>, &'static str> {
    bincode::serialize(alert).map_err(|_| "alert serialization failed")
}

fn check_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && value.is_ascii()
}

pub fn is_well_formed(alert: &AdamAlert) -> bool {
    alert.schema_version == 1
        && alert.alert_id.iter().any(|byte| *byte != 0)
        && (1_577_836_800..=4_102_444_800).contains(&alert.timestamp)
        && (1..=10).contains(&alert.severity)
        && alert.category <= 4
        && check_text(&alert.user, 32)
        && check_text(&alert.machine, 64)
        && check_text(&alert.process, 64)
        && check_text(&alert.ip, 45)
        && check_text(&alert.file_path, 128)
}

pub fn scoped_nullifier(org_secret: &[u8; 32], campaign_id: &[u8; 16], epoch: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ADAM_SCOPED_NULLIFIER_V1");
    hasher.update(org_secret);
    hasher.update(campaign_id);
    hasher.update(epoch.to_be_bytes());
    hasher.finalize().into()
}

fn recipient_key_hash(modulus: &[u8], exponent: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ADAM_RSA_RECIPIENT_V1");
    hasher.update((modulus.len() as u32).to_be_bytes());
    hasher.update(modulus);
    hasher.update(exponent);
    hasher.finalize().into()
}

pub fn evaluate(witness: &Witness) -> Result<PublicValues, &'static str> {
    if !is_well_formed(&witness.alert) {
        return Err("malformed ADAM alert");
    }
    if witness.schema_commitment != schema_commitment() {
        return Err("schema commitment mismatch");
    }

    let plaintext = alert_bytes(&witness.alert)?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&witness.sensor_public_key)
        .map_err(|_| "invalid sensor public key")?;
    let signature =
        Signature::from_slice(&witness.sensor_signature).map_err(|_| "invalid sensor signature")?;
    verifying_key
        .verify(&plaintext, &signature)
        .map_err(|_| "sensor signature verification failed")?;

    if witness.recipient_modulus.len() != 256 || witness.recipient_modulus[0] & 0x80 == 0 {
        return Err("recipient key is not 2048-bit RSA");
    }
    let recipient_key = RsaPublicKey::new(
        BigUint::from_bytes_be(&witness.recipient_modulus),
        BigUint::from_bytes_be(&witness.recipient_exponent),
    )
    .map_err(|_| "invalid recipient key")?;
    let mut rng = ChaCha20Rng::from_seed(witness.encryption_seed);
    let ciphertext = recipient_key
        .encrypt(&mut rng, Oaep::new::<Sha256>(), &plaintext)
        .map_err(|_| "RSA-OAEP encryption failed")?;
    if ciphertext != witness.expected_ciphertext {
        return Err("ciphertext does not encrypt the alert");
    }

    Ok(PublicValues {
        ciphertext,
        schema_commitment: witness.schema_commitment,
        sensor_public_key: witness.sensor_public_key.clone(),
        recipient_key_hash: recipient_key_hash(
            &witness.recipient_modulus,
            &witness.recipient_exponent,
        ),
        campaign_id: witness.campaign_id,
        epoch: witness.epoch,
        nullifier: scoped_nullifier(&witness.org_secret, &witness.campaign_id, witness.epoch),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{signature::Signer, SigningKey};
    use rand::{rngs::StdRng, SeedableRng};
    use rsa::{traits::PublicKeyParts, RsaPrivateKey};
    use std::sync::LazyLock;

    static VALID_WITNESS: LazyLock<Witness> = LazyLock::new(|| {
        let alert = AdamAlert {
            schema_version: 1,
            alert_id: *b"synthetic-alert!",
            timestamp: 1_783_512_000,
            severity: 8,
            category: 2,
            user: "USER_alice".into(),
            machine: "HOST-finance-07".into(),
            process: "powershell.exe".into(),
            ip: "203.0.113.42".into(),
            file_path: "C:\\Synthetic\\payload.ps1".into(),
        };
        let plaintext = alert_bytes(&alert).unwrap();
        let signing_key = SigningKey::from_bytes((&[3_u8; 32]).into()).unwrap();
        let signature: Signature = signing_key.sign(&plaintext);
        let mut key_rng = StdRng::seed_from_u64(0xADA0_0003);
        let recipient_private = RsaPrivateKey::new(&mut key_rng, 2048).unwrap();
        let recipient_public = RsaPublicKey::from(&recipient_private);
        let encryption_seed = [0x42; 32];
        let ciphertext = recipient_public
            .encrypt(
                &mut ChaCha20Rng::from_seed(encryption_seed),
                Oaep::new::<Sha256>(),
                &plaintext,
            )
            .unwrap();

        Witness {
            alert,
            schema_commitment: schema_commitment(),
            sensor_public_key: signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
            sensor_signature: signature.to_bytes().to_vec(),
            recipient_modulus: recipient_public.n().to_bytes_be(),
            recipient_exponent: recipient_public.e().to_bytes_be(),
            encryption_seed,
            expected_ciphertext: ciphertext,
            org_secret: [0xA5; 32],
            campaign_id: *b"campaign-2026-01",
            epoch: 42,
        }
    });

    #[test]
    fn schema_commitment_is_stable() {
        assert_eq!(
            hex::encode(schema_commitment()),
            "65457504f892774392eafa89c356ac5dd106367282ff1b775b9a8a165df9ce51"
        );
    }

    #[test]
    fn nullifier_is_scoped() {
        let secret = [7; 32];
        let campaign = [9; 16];
        assert_ne!(
            scoped_nullifier(&secret, &campaign, 1),
            scoped_nullifier(&secret, &campaign, 2)
        );
    }

    #[test]
    fn valid_statement_is_accepted() {
        assert!(evaluate(&VALID_WITNESS).is_ok());
    }

    #[test]
    fn malformed_alert_and_wrong_schema_are_rejected() {
        let mut malformed = VALID_WITNESS.clone();
        malformed.alert.severity = 0;
        assert_eq!(evaluate(&malformed), Err("malformed ADAM alert"));

        let mut wrong_schema = VALID_WITNESS.clone();
        wrong_schema.schema_commitment[0] ^= 1;
        assert_eq!(evaluate(&wrong_schema), Err("schema commitment mismatch"));
    }

    #[test]
    fn invalid_signature_is_rejected() {
        let mut witness = VALID_WITNESS.clone();
        witness.sensor_signature[0] ^= 1;
        assert_eq!(
            evaluate(&witness),
            Err("sensor signature verification failed")
        );
    }

    #[test]
    fn ciphertext_must_encrypt_the_signed_alert() {
        let mut witness = VALID_WITNESS.clone();
        witness.expected_ciphertext[0] ^= 1;
        assert_eq!(
            evaluate(&witness),
            Err("ciphertext does not encrypt the alert")
        );
    }

    #[test]
    fn recipient_key_must_be_2048_bits() {
        let mut witness = VALID_WITNESS.clone();
        witness.recipient_modulus[0] &= 0x7f;
        assert_eq!(evaluate(&witness), Err("recipient key is not 2048-bit RSA"));
    }

    #[test]
    fn changed_scope_cannot_reproduce_the_expected_nullifier() {
        let expected = evaluate(&VALID_WITNESS).unwrap();
        let mut wrong_scope = VALID_WITNESS.clone();
        wrong_scope.epoch += 1;
        assert_ne!(
            evaluate(&wrong_scope).unwrap().nullifier,
            expected.nullifier
        );
    }
}
