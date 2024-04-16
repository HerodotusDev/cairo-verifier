# Cairo Verifier

![Integrity](.github/readme.png)

[![Continuous Integration - tests](https://github.com/HerodotusDev/cairo-verifier/actions/workflows/tests.yml/badge.svg)](https://github.com/HerodotusDev/cairo-verifier/actions/workflows/tests.yml)

[![Continuous Integration - proof verification tests](https://github.com/HerodotusDev/cairo-verifier/actions/workflows/proof_verification_tests.yml/badge.svg)](https://github.com/HerodotusDev/cairo-verifier/actions/workflows/proof_verification_tests.yml)

## Building the Verifier

To build the Cairo Verifier, follow these steps:

1. Build the project by running the following command in your terminal:

```bash
scarb build
```

2. (Optional) Test the project to ensure everything works correctly:

```bash
scarb test
```

## Running the Verifier on Example Proof

### Local Proof Verification

For local proof verification, follow these steps:

1. Run the verifier locally on example proof using the following command:

By `default`, the verifier is configured for `layout_type`=`recursive` and `hash_type`=`keccak` for verifier unfriendly commitment layers.
```bash
scarb build &&
cargo run --release --bin runner -- target/dev/cairo_verifier.sierra.json < examples/proofs/recursive/example_proof.json
```

You can easily change configuration by specifying features in scarb build command

```bash
scarb build --no-default-features --features=<layout_type>,<hash_type>
```

`layout_type`: [`dex`, `recursive`, `recursive_with_poseidon`, `small`, `starknet`, `starknet_with_keccak`]  
`hash_type`: [`keccak`, `blake2s`]

All the example_proof's are using `hash_type`=`keccak`

### Starknet Proof Verification

To verify proofs on Starknet, proceed with the following steps:

1. Prepare calldata of example proof for sncast:

```bash
cargo run --release --bin snfoundry_proof_serializer < examples/proofs/<layout_type>/example_proof.json > examples/starknet/proof
```

2. Call the function with serialized `proof` on the Starknet contract:

In order to run this step, you need to have a Starknet account set up. For details, check [The Starknet Foundry Book](https://foundry-rs.github.io/starknet-foundry/starknet/account.html).

```bash
cd examples/starknet
./1-verify-proof.sh testnet <contract_address> proof
```

[List of deployed Verifier Contracts](deployed_contracts.md)

## Benchmarking

In order to launch benchmarking, just run this (it requires recursive layout configuration):

```bash
cargo run --release --bin benches -- target/dev/cairo_verifier.sierra.json
```

## Creating a Proof

### Stone Prover Instructions

For detailed instructions and examples, refer to the Stone Prover [documentation](https://github.com/starkware-libs/stone-prover?tab=readme-ov-file#creating-and-verifying-a-proof-of-a-cairozero-program).

### Stone Prover SDK Tool

For information on how to use the Stone Prover SDK tool, please refer to the [documentation](https://github.com/Moonsong-Labs/stone-prover-sdk).