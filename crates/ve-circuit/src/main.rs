use anyhow::{ensure, Context, Result};
use clap::Parser;
use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use rand::{rngs::StdRng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rsa::{traits::PublicKeyParts, Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use sp1_sdk::{include_elf, prelude::*, ProverClient, SP1PublicValues};
use std::time::Instant;
use ve_circuit_types::{
    alert_bytes, evaluate, schema_commitment, AdamAlert, PublicValues, Witness,
};

const ELF: Elf = include_elf!("ve-circuit-program");

#[derive(Parser)]
#[command(about = "Measure the ADAM verifiable-encryption SP1 statement")]
struct Cli {
    #[arg(long, default_value_t = 10)]
    execute_repetitions: usize,
    #[arg(long, default_value_t = 3)]
    mock_repetitions: usize,
    #[arg(long, default_value_t = 1)]
    real_repetitions: usize,
}

fn fixture() -> Result<(Witness, PublicValues)> {
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
    let plaintext = alert_bytes(&alert).map_err(anyhow::Error::msg)?;
    ensure!(
        plaintext.len() <= 190,
        "alert is too large for RSA-2048 OAEP-SHA256"
    );

    let signing_key = SigningKey::from_bytes((&[3_u8; 32]).into())?;
    let signature: Signature = signing_key.sign(&plaintext);

    let mut key_rng = StdRng::seed_from_u64(0xADA0_0003);
    let recipient_private = RsaPrivateKey::new(&mut key_rng, 2048)?;
    let recipient_public = RsaPublicKey::from(&recipient_private);
    let encryption_seed = [0x42; 32];
    let mut encryption_rng = ChaCha20Rng::from_seed(encryption_seed);
    let ciphertext =
        recipient_public.encrypt(&mut encryption_rng, Oaep::new::<Sha256>(), &plaintext)?;
    let decrypted = recipient_private.decrypt(Oaep::new::<Sha256>(), &ciphertext)?;
    ensure!(decrypted == plaintext, "native RSA-OAEP round trip failed");

    let witness = Witness {
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
    };
    let expected = evaluate(&witness).map_err(anyhow::Error::msg)?;
    Ok((witness, expected))
}

fn stdin(witness: &Witness) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(witness);
    stdin
}

fn stats(samples: &[f64]) -> (f64, f64, f64, f64) {
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    let variance = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / samples.len() as f64;
    (
        mean,
        variance.sqrt(),
        samples.iter().copied().fold(f64::INFINITY, f64::min),
        samples.iter().copied().fold(f64::NEG_INFINITY, f64::max),
    )
}

fn check_public_values(mut values: SP1PublicValues, expected: &PublicValues) {
    let actual = values.read::<PublicValues>();
    assert_eq!(&actual, expected, "unexpected committed public values");
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    ensure!(
        cli.execute_repetitions > 0,
        "execute repetitions must be positive"
    );
    ensure!(
        cli.mock_repetitions > 0,
        "mock repetitions must be positive"
    );
    ensure!(
        cli.real_repetitions > 0,
        "real repetitions must be positive"
    );
    let (witness, expected) = fixture()?;

    let cpu = ProverClient::builder().cpu().build().await;
    let mut execute_ms = Vec::with_capacity(cli.execute_repetitions);
    let mut instructions = 0_u64;
    let mut syscalls = 0_u64;
    for _ in 0..cli.execute_repetitions {
        let started = Instant::now();
        let (public_values, report) = cpu.execute(ELF, stdin(&witness)).await?;
        execute_ms.push(started.elapsed().as_secs_f64() * 1000.0);
        instructions = report.total_instruction_count();
        syscalls = report.total_syscall_count();
        check_public_values(public_values, &expected);
    }
    let (mean, stddev, min, max) = stats(&execute_ms);
    println!(
        "execute repetitions={} mean_ms={mean:.3} stddev_ms={stddev:.3} min_ms={min:.3} max_ms={max:.3} cycles={instructions} syscalls={syscalls}",
        cli.execute_repetitions,
    );

    let mock = ProverClient::builder().mock().build().await;
    let mock_pk = mock.setup(ELF).await?;
    let mut mock_ms = Vec::with_capacity(cli.mock_repetitions);
    for _ in 0..cli.mock_repetitions {
        let started = Instant::now();
        let proof = mock.prove(&mock_pk, stdin(&witness)).compressed().await?;
        mock_ms.push(started.elapsed().as_secs_f64() * 1000.0);
        check_public_values(proof.public_values.clone(), &expected);
        mock.verify(&proof, mock_pk.verifying_key(), None)?;
    }
    let (mean, stddev, min, max) = stats(&mock_ms);
    println!(
        "mock repetitions={} mean_ms={mean:.3} stddev_ms={stddev:.3} min_ms={min:.3} max_ms={max:.3}",
        cli.mock_repetitions
    );

    let setup_started = Instant::now();
    let proving_key = cpu.setup(ELF).await?;
    let setup_ms = setup_started.elapsed().as_secs_f64() * 1000.0;
    let mut prove_ms = Vec::with_capacity(cli.real_repetitions);
    let mut verify_ms = Vec::with_capacity(cli.real_repetitions);
    let mut proof_bytes = 0_u64;
    let mut proof_bundle_bytes = 0_u64;
    for _ in 0..cli.real_repetitions {
        let started = Instant::now();
        let proof = cpu
            .prove(&proving_key, stdin(&witness))
            .compressed()
            .await?;
        prove_ms.push(started.elapsed().as_secs_f64() * 1000.0);
        check_public_values(proof.public_values.clone(), &expected);

        let verify_started = Instant::now();
        cpu.verify(&proof, proving_key.verifying_key(), None)?;
        verify_ms.push(verify_started.elapsed().as_secs_f64() * 1000.0);

        proof_bytes = bincode::serialize(&proof.proof)
            .context("serialize raw proof")?
            .len() as u64;
        proof_bundle_bytes = bincode::serialize(&proof)
            .context("serialize proof bundle")?
            .len() as u64;
    }
    let (prove_mean, prove_stddev, prove_min, prove_max) = stats(&prove_ms);
    let (verify_mean, verify_stddev, verify_min, verify_max) = stats(&verify_ms);
    println!(
        "real_compressed repetitions={} setup_ms={setup_ms:.3} prove_mean_ms={prove_mean:.3} prove_stddev_ms={prove_stddev:.3} prove_min_ms={prove_min:.3} prove_max_ms={prove_max:.3} verify_mean_ms={verify_mean:.3} verify_stddev_ms={verify_stddev:.3} verify_min_ms={verify_min:.3} verify_max_ms={verify_max:.3} raw_proof_bytes={proof_bytes} proof_bundle_bytes={proof_bundle_bytes} public_values_bytes={}",
        cli.real_repetitions,
        bincode::serialize(&expected)?.len()
    );
    Ok(())
}
