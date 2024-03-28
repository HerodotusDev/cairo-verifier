# Cairo Verifier

![Cairo Verifier](https://github.com/HerodotusDev/cairo-verifier/assets/46165861/8692dfc1-f267-4c7e-9af0-4ceaeec84207)

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
./1-verify-proof.sh <contract_address> proof
```

[List of deployed Verifier Contracts](deployed_contracts.md)

## Creating a Proof

To create a proof, perform the following steps:

1. Install stone-prover (restart your shell after installation):

```bash
git clone https://github.com/starkware-libs/stone-prover.git
cd stone-prover
docker build --tag prover .
container_id=$(docker create prover)
docker cp -L ${container_id}:/bin/cpu_air_prover ../examples/prover
docker cp -L ${container_id}:/bin/cpu_air_verifier ../examples/prover
```

2. Install cairo-lang:

```bash
pip install cairo-lang==0.12.0
```

3. Compile a Cairo program, for example, the Fibonacci program:

```bash
cd examples/prover
cairo-compile fibonacci.cairo --output fibonacci_compiled.json --proof_mode
```

4. Run the Cairo program:

```bash
cairo-run \
    --program=fibonacci_compiled.json \
    --layout=recursive \
    --program_input=fibonacci_input.json \
    --air_public_input=fibonacci_public_input.json \
    --air_private_input=fibonacci_private_input.json \
    --trace_file=fibonacci_trace.bin \
    --memory_file=fibonacci_memory.bin \
    --print_output \
    --proof_mode
```

5. Prove the Cairo program:

```bash
./cpu_air_prover \
    --out_file=../proofs/recursive/fibonacci_proof.json \
    --private_input_file=fibonacci_private_input.json \
    --public_input_file=fibonacci_public_input.json \
    --prover_config_file=cpu_air_prover_config.json \
    --parameter_file=cpu_air_params.json \
    --generate_annotations
```

You can verify this proof locally or on the Starknet Cairo verifier contract by specifying the path examples/proofs/recursive/fibonacci_proof.json to the newly generated proof.

## Benchmarking

In order to launch benchmarking, just run this (it requires recursive layout configuration):

```bash
cargo run --release --bin benches -- target/dev/cairo_verifier.sierra.json
```