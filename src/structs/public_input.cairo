#[derive(Drop, Serde)]
struct PublicInput {
    log_n_steps: felt252,
    range_check_min: felt252,
    range_check_max: felt252,
    layout: felt252,
    dynamic_params: Array<felt252>,
    n_segments: felt252,
    segments: Array<felt252>,
    padding_addr: felt252,
    padding_value: felt252,
    main_page_len: felt252,
    main_page: Array<felt252>,
    n_continuous_pages: felt252,
    continuous_page_headers: Array<felt252>,
}
