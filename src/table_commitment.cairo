use cairo_verifier::vector_commitment::vector_commitment::{
    VectorCommitmentConfig, VectorCommitment, VectorCommitmentWitness
};

// Commitment values for a table commitment protocol. Used to generate a commitment by "reading"
// these values from the channel.
#[derive(Drop, Copy)]
struct TableUnsentCommitment {
    vector: felt252,
}

// Commitment for a table (n_rows x n_columns) of field elements in montgomery form.
#[derive(Drop, Copy)]
struct TableCommitment {
    config: TableCommitmentConfig,
    vector_commitment: VectorCommitment,
}

#[derive(Drop, Copy, Serde)]
struct TableCommitmentConfig {
    n_columns: felt252,
    vector: VectorCommitmentConfig,
}

// Responses for queries to the table commitment.
// Each query corresponds to a full row of the table.
#[derive(Drop, Copy)]
struct TableDecommitment {
    // n_columns * n_queries values to decommit.
    values: Span<felt252>,
}

// Witness for a decommitment over queries.
#[derive(Drop, Copy)]
struct TableCommitmentWitness {
    vector: VectorCommitmentWitness,
}

fn table_commit(
    unsent_commitment: TableUnsentCommitment, config: TableCommitmentConfig
) -> TableCommitment {
    TableCommitment {
        config: TableCommitmentConfig {
            n_columns: 0,
            vector: VectorCommitmentConfig { height: 0, n_verifier_friendly_commitment_layers: 0, }
        },
        vector_commitment: VectorCommitment {
            config: VectorCommitmentConfig { height: 0, n_verifier_friendly_commitment_layers: 0, },
            commitment_hash: 0
        }
    }
}

// Decommits a TableCommitment at multiple indices.
// rows must be sorted and unique.
// Args:
// commitment - the table commitment.
// n_queries - number of queries to decommit.
// queries - the claimed indices.
// decommitment - the claimed values at those indices.
// witness - the decommitment witness.
fn table_decommit(
    commitment: TableCommitment,
    queries: Span<felt252>,
    decommitment: TableDecommitment,
    witness: TableCommitmentWitness,
) {}
