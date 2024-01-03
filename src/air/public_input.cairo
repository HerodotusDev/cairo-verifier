use cairo_verifier::air::public_memory::{
    Page, PageTrait, ContinuousPageHeader, get_continuous_pages_product
};
use cairo_verifier::common::math::{pow, Felt252PartialOrd, Felt252Div};
use cairo_verifier::air::constants::{segments, MAX_ADDRESS, get_builtins, INITIAL_PC};

#[derive(Drop)]
struct SegmentInfo {
    // Start address of the memory segment.
    begin_addr: felt252,
    // Stop pointer of the segment - not necessarily the end of the segment.
    stop_ptr: felt252,
}

#[derive(Drop)]
struct PublicInput {
    log_n_steps: felt252,
    rc_min: felt252,
    rc_max: felt252,
    segments: Array<SegmentInfo>,
    padding_addr: felt252,
    padding_value: felt252,
    main_page: Page,
    continuous_page_headers: Span<ContinuousPageHeader>
}

#[generate_trait]
impl PublicInputImpl of PublicInputTrait {
    // Returns the ratio between the product of all public memory cells and z^|public_memory|.
    // This is the value that needs to be at the memory__multi_column_perm__perm__public_memory_prod
    // member expression.
    fn get_public_memory_product_ratio(
        self: @PublicInput, z: felt252, alpha: felt252, public_memory_column_size: felt252
    ) -> felt252 {
        let (pages_product, total_length) = self.get_public_memory_product(z, alpha);

        // Pad and divide
        let numerator = pow(z, public_memory_column_size);
        let padded = z - (*self.padding_addr + alpha * *self.padding_value);

        assert(total_length <= public_memory_column_size, 'Invalid length');
        let denominator_pad = pow(padded, public_memory_column_size - total_length);

        numerator / pages_product / denominator_pad
    }

    // Returns the product of all public memory cells.
    fn get_public_memory_product(
        self: @PublicInput, z: felt252, alpha: felt252
    ) -> (felt252, felt252) {
        let main_page_prod = self.main_page.get_product(z, alpha);

        let (continuous_pages_prod, continuous_pages_total_length) = get_continuous_pages_product(
            *self.continuous_page_headers,
        );

        let prod = main_page_prod * continuous_pages_prod;
        let total_length = (self.main_page.len()).into() + continuous_pages_total_length;

        (prod, total_length)
    }

    fn verify(self: @PublicInput) -> (felt252, felt252) {
        let public_segments = self.segments;

        let initial_pc = *public_segments.at(segments::PROGRAM).begin_addr;
        let final_pc = *public_segments.at(segments::PROGRAM).stop_ptr;
        let initial_ap = *public_segments.at(segments::EXECUTION).begin_addr;
        let initial_fp = initial_ap;
        let final_ap = *public_segments.at(segments::EXECUTION).stop_ptr;
        let output_start = *public_segments.at(segments::OUTPUT).begin_addr;
        let output_stop = *public_segments.at(segments::OUTPUT).stop_ptr;

        assert(initial_ap < MAX_ADDRESS, 'Invalid initial_ap');
        assert(final_ap < MAX_ADDRESS, 'Invalid final_ap');

        // TODO support more pages?
        assert((*self.continuous_page_headers).len() == 0, 'Invalid continuous_page_headers');

        let builtins = get_builtins();
        let memory = self.main_page;

        // 1. Program segment
        assert(initial_pc == INITIAL_PC, 'Invalid initial_pc');
        assert(final_pc == INITIAL_PC + 4, 'Invalid final_pc');

        let program_end_pc = initial_fp - 2;
        let program_len = program_end_pc - initial_pc;
        memory.extract_range(initial_pc, program_len);

        (0, 0)
    }
}
