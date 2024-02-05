use cairo_verifier::{
    queries::queries::queries_to_points, domains::StarkDomains, tests::stone_proof_fibonacci
};

// test data from cairo0-verifier keccak-native run on stone-prover generated proof
#[test]
#[available_gas(9999999999)]
fn test_queries_to_points_0() {
    let stark_domains = stone_proof_fibonacci::stark::domains::get();

    let queries = stone_proof_fibonacci::queries::get().span();

    assert(
        queries_to_points(
            queries, @stark_domains
        ) == array![
            0x2db7913d585ab151bc2b66c288d0bc9b8c791083d1e4a347f418d499696385a,
            0x13de0c034702b2f857d20f1c4392d7308adf523675a6917ef9b24ffe481b3f3,
            0x79a18f6903e3f59a2fa62f2009dd31281ee4edf937ca2d9db9d53aa4136f44,
            0x7101334fb9526f5fd852697914640ed5a1fe8df743eb057b22621942911d330,
            0x7c6b8bb6c7d3e482aadaaa96b6899d8302963e19039896b77d14093d404ed4d,
            0x3b79da623a55f681ff504b9e358c66e4195d0ad90c1bd052f7b84f00023f628,
            0x2dd308f8d684d300811809255d1210ba974487fc02b9f5ae3a63c073bdfe9a8,
            0x23823ef38993551b68657d4607d1617ba0f4e323052cc14b3a5b18dc0bf5875,
            0x164e55f8fda082b5db06c0caedc2dd5a4c39ae8939cc61f7ee2f8255b5849c5,
            0x6638bb689428e37f36e1580ef4c46395758e96562940002b6f37ef33d10ac04,
            0x3abdf6cb714ba6c308c6eef1cc4d63e06928c17129867606802cfc44c961e80,
            0x4e2ad9b9530b45c3dacf36b44a8836844d301661dd9d54685606a917729716d,
            0x2b81aced85615991fd89e616e0ea8fb2f6841436a2565aeb19cbd785ecfca2a,
            0xe6b5ebff913e45d5a57ec627c03acd209d564935994b1058a5d828bfaeee3a,
            0x20d399aac1db0f8e99a1dd7e009f4d165ca411086bef0002edebf3395ef31be,
            0x5c0086656cb6c7208f87148b5d36a14b626ace2c9d4c67f5ae27106c3bde97,
            0x4ee93f199c1a2b9ed46dd9d0c1f51fd453a37698dd8074fe1eb197d4b42541b,
            0x27b6342139b5ab8f1ff29fea7f5602d3a438163f5547d2d341a5418ea90abe4,
        ],
        'Invalid value'
    );
}
