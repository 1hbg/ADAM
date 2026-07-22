#![no_main]

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let witness = sp1_zkvm::io::read::<ve_circuit_types::Witness>();
    let public = ve_circuit_types::evaluate(&witness).expect("invalid ADAM alert witness");
    sp1_zkvm::io::commit(&public);
}
