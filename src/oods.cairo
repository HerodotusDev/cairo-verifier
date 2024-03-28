use cairo_verifier::{
    common::array_extend::ArrayExtendTrait, table_commitment::table_commitment::TableDecommitment
};

#[cfg(feature: 'dex')]
use cairo_verifier::air::layouts::dex::{
    AIRComposition, AIROods, DexAIRCompositionImpl, DexAIROodsImpl,
    global_values::InteractionElements, public_input::PublicInput, traces::TracesDecommitment,
    constants::CONSTRAINT_DEGREE,
};

#[cfg(feature: 'recursive')]
use cairo_verifier::air::layouts::recursive::{
    AIRComposition, AIROods, RecursiveAIRCompositionImpl, RecursiveAIROodsImpl,
    global_values::InteractionElements, public_input::PublicInput, traces::TracesDecommitment,
    constants::CONSTRAINT_DEGREE,
};

#[cfg(feature: 'recursive_with_poseidon')]
use cairo_verifier::air::layouts::recursive_with_poseidon::{
    AIRComposition, AIROods, RecursiveWithPoseidonAIRCompositionImpl,
    RecursiveWithPoseidonAIROodsImpl, global_values::InteractionElements, public_input::PublicInput,
    traces::TracesDecommitment, constants::CONSTRAINT_DEGREE,
};

#[cfg(feature: 'small')]
use cairo_verifier::air::layouts::small::{
    AIRComposition, AIROods, SmallAIRCompositionImpl, SmallAIROodsImpl,
    global_values::InteractionElements, public_input::PublicInput, traces::TracesDecommitment,
    constants::CONSTRAINT_DEGREE,
};

#[cfg(feature: 'starknet')]
use cairo_verifier::air::layouts::starknet::{
    AIRComposition, AIROods, StarknetAIRCompositionImpl, StarknetAIROodsImpl,
    global_values::InteractionElements, public_input::PublicInput, traces::TracesDecommitment,
    constants::CONSTRAINT_DEGREE,
};

#[cfg(feature: 'starknet_with_keccak')]
use cairo_verifier::air::layouts::starknet_with_keccak::{
    AIRComposition, AIROods, StarknetWithKeccakAIRCompositionImpl, StarknetWithKeccakAIROodsImpl,
    global_values::InteractionElements, public_input::PublicInput, traces::TracesDecommitment,
    constants::CONSTRAINT_DEGREE,
};


#[derive(Drop)]
struct OodsEvaluationInfo {
    oods_values: Span<felt252>,
    oods_point: felt252,
    trace_generator: felt252,
    constraint_coefficients: Span<felt252>,
}

// Checks that the trace and the compostion agree at oods_point, assuming the prover provided us
// with the proper evaluations.
fn verify_oods(
    oods: Span<felt252>,
    interaction_elements: InteractionElements,
    public_input: @PublicInput,
    constraint_coefficients: Span<felt252>,
    oods_point: felt252,
    trace_domain_size: felt252,
    trace_generator: felt252
) {
    let composition_from_trace = AIRComposition::eval_composition_polynomial(
        interaction_elements,
        public_input,
        oods.slice(0, oods.len() - 2),
        constraint_coefficients,
        oods_point,
        trace_domain_size,
        trace_generator
    );

    // TODO support degree > 2?
    let claimed_composition = *oods[oods.len() - 2] + *oods[oods.len() - 1] * oods_point;

    assert(composition_from_trace == claimed_composition, 'Invalid OODS');
}

fn eval_oods_boundary_poly_at_points(
    n_original_columns: u32,
    n_interaction_columns: u32,
    eval_info: OodsEvaluationInfo,
    points: Span<felt252>,
    decommitment: TracesDecommitment,
    composition_decommitment: TableDecommitment,
) -> Array<felt252> {
    assert(
        decommitment.original.values.len() == points.len() * n_original_columns, 'Invalid value'
    );
    assert(
        decommitment.interaction.values.len() == points.len() * n_interaction_columns,
        'Invalid value'
    );
    assert(
        composition_decommitment.values.len() == points.len() * CONSTRAINT_DEGREE, 'Invalid value'
    );

    let mut evaluations = ArrayTrait::<felt252>::new();

    let mut i: u32 = 0;
    loop {
        if i == points.len() {
            break;
        }

        let mut column_values = ArrayTrait::<felt252>::new();

        column_values
            .extend(decommitment.original.values.slice(i * n_original_columns, n_original_columns));
        column_values
            .extend(
                decommitment
                    .interaction
                    .values
                    .slice(i * n_interaction_columns, n_interaction_columns)
            );
        column_values
            .extend(
                composition_decommitment.values.slice(i * CONSTRAINT_DEGREE, CONSTRAINT_DEGREE)
            );

        evaluations
            .append(
                AIROods::eval_oods_polynomial(
                    column_values.span(),
                    eval_info.oods_values,
                    eval_info.constraint_coefficients,
                    *points.at(i),
                    eval_info.oods_point,
                    eval_info.trace_generator,
                )
            );

        i += 1;
    };

    evaluations
}

#[cfg(feature: 'recursive')]
#[cfg(test)]
mod tests {
    use cairo_verifier::oods::verify_oods;
    use cairo_verifier::tests::stone_proof_fibonacci;

    #[test]
    #[available_gas(9999999999)]
    fn test_verify_oods() {
        let public_input = stone_proof_fibonacci::public_input::get();
        let interaction_elements = stone_proof_fibonacci::interaction_elements::get();
        let mask_values = stone_proof_fibonacci::stark::oods_values::get();
        let constraint_coefficients = stone_proof_fibonacci::constraint_coefficients::get();

        verify_oods(
            mask_values.span(),
            interaction_elements,
            @public_input,
            constraint_coefficients.span(),
            0x47148421d376a8ca07af1e4c89890bf29c90272f63b16103646397d907281a8,
            0x40000,
            0x4768803ef85256034f67453635f87997ff61841e411ee63ce7b0a8b9745a046
        );
    }
}

