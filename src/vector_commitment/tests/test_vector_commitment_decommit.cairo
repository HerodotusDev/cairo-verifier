use cairo_verifier::vector_commitment::vector_commitment::{
    VectorCommitment, VectorCommitmentConfig, VectorCommitmentWitness, vector_commit, VectorQuery,
    vector_commitment_decommit,
};

#[cfg(feature: 'blake2s')]
#[test]
#[available_gas(9999999999)]
fn test_vector_commitment_decommit_1() {
    let commitment = VectorCommitment {
        config: VectorCommitmentConfig {
            height: 0x9, n_verifier_friendly_commitment_layers: 0x64,
        },
        commitment_hash: 0x1e9b0fa29ebe52b9c9a43a1d44e555ce42da3199370134d758735bfe9f40269
    };

    let queries = array![
        VectorQuery {
            index: 0x73, value: 0x12346ea425a6aebc8c323a401410cc325aabaf99b54e600a7271f146488aa2d
        },
        VectorQuery {
            index: 0xa5, value: 0x1aabe006a27bfa5f93bde192ff552adbef87058e62546c831ed14ce94866ac1
        },
        VectorQuery {
            index: 0xb0, value: 0x7205a2b5f5f403b8053b4e4ac65e2a484c007f6d118524fe28b7cdf2a56bb8a
        },
        VectorQuery {
            index: 0xf8, value: 0x5d49462d844a3f203c59d39fa005cbe153c78e6ac831987f19c0d6dfae38fad
        },
        VectorQuery {
            index: 0x115, value: 0x53d21587a9cb08d1b9402a4b8c2a9d37942b26963936200fea3122eaaf870b1
        },
        VectorQuery {
            index: 0x11c, value: 0x7c3355a75f6b36a95068b68d48e7539cd97531b7478e2cf7d2dc85b32bafc66
        },
        VectorQuery {
            index: 0x12f, value: 0xb6f3a522577229ac26f12df90daaf376afbd960ee4b0ab07f270bf9c5da56a
        },
        VectorQuery {
            index: 0x13c, value: 0x174cfc44eb57da0eda6ae9407db71c5144940f05ef51f858bc8e229d15703e2
        },
        VectorQuery {
            index: 0x153, value: 0x2220da78b33e155482bdf0534dc30fc17fe059a7b9e30f710ee2681a8151484
        },
        VectorQuery {
            index: 0x1f4, value: 0x566b71a4f84556a3816d911c5dfb45f75cc962d9829acd0dd56e81517cc73b8
        },
    ]
        .span();

    let witness = VectorCommitmentWitness {
        authentications: array![
            0x2e9de49846b184d454c30e3b4854167583093da20c5ddef5e3ba2885524d006,
            0xf3fb7305323c5fa68ad49a509a9c470e2396af41bfd2c9cf86228504436a3,
            0x9dc63f0ac48b17304af16748798567f21bb25f8cbeaa48a462a74b3e0c5d79,
            0x5d35649398cb24bc00458a32d01c61a8450c7a30cc5b95043f4e2b30df01360,
            0x4493f60ea79053f2a96439d50d6335fd35e13599190e1656b724eacac658e37,
            0x7f58b9c9c333dc5b31e3ee5e8a98d8cab0c84b3a886042b279dc2f2c408d92b,
            0x349a976371b7aef1b1992908fefa423b9e5d4d0be58092ff6e5ead51ecf1ca4,
            0x3ffacb144085ca3c572a314c6bb0e01b253827231285fba4084e3b624438ace,
            0x55d22158d5bfad58ddf2633f24a3fae4642afbcea1cb9155e8b54c2a432fbfd,
            0x63c1598794322bd8f1686e89c94dc60b0bb4f7940b5427af72187091e71ef63,
            0xebaa8e9ab29cfba43cdc1f2cacb9cbc08b2cb17317fed571718e5e66b42488,
            0xa31370f89d85108378244beeea13a2b2c379d16cde55c2fcd674f4296ddabe,
            0x4285440535fff0ba31e970a1948a09951ff740c91c6d6cf4635527877c55ff1,
            0x49eb1420843ac1a3178010c314906d28f6118e8b36620ce4469dffca27a047d,
            0x4e65200356931c3ea1e20e087b5bff96ba268239ed2e2f784def64f5760418d,
            0x103809d798aab5452c77f42bc4c8fcfcfa9e6efdfe24077e41928a52daf1dc8,
            0x4253b3498a013d4473d43686f9e509be7541daf00afae0d7216f7019bc75d8f,
            0x689297a643de6bd5955e314f94367af901eac67eeef51a52e40c0205cf8023,
            0x2ca9dcef95643af6ec5ee055d1a05720f2e3f5e6226de5b206c4a78482963b8,
            0x72fbddae565406f284bb4dd89623c29c821b6187dd7dfc292dbbddd4094077,
            0x30e5ea3c2280db52829548ae99a71faa030b4e4bb87679b427f76c594aaa05a,
            0x45ba1eda942e1085af97db6e189996903cfa09db90e52b4589e16df981f1601,
            0x8c36a69368bea30f8ecf7de3e461a03b0cdd004ae08a3d44281b093fc63f2,
            0x5c7194878dcb2d4ba69da97c1a878f96dd78d97612c882ba7179bafe92a6a90,
            0x20c37b922bb713f2b6772a9ae014715f418fe5da4d53fe9b00cc2fe851f233a,
            0x3a7e7c684904e82bf0be54290299b6d83f448bac5c6e9ea4d1cd1e844eccb70,
            0x1ebbb30dbcb3b4fd0da33cf84d456101bbe9147b1a65507901715b3490649c6,
            0x1409c71e0dcf4a620856775508ce1b4c7d55e4229ac5fd41a3f8ecee097eb39,
            0x18cdf340cc64b00bf134c9e55396f79eddfbda8e2090542380c5c4967ee790b,
            0x18add43c036948c8d7e767ae22056e1f5f1a9d1daad6b9a8f2e7da996f4a1c2,
            0x30e7224d1c98b75e019b60bbe320e358ef35b1adaf12aad044744e640c2a4d,
            0x25a8793c928ecacb2e84802830fa101fb3839455957921ed7bcb39549b1f80,
            0x65dd0f91032712c4a8b1b5c35cd6ebdb654efb5e56085a2eef0def4bde4d066,
            0x4a50e2b14315602b8c97c9d2304db828806c37b751203bb7dad534d7b45d21d,
            0x5afdcfcf55c58dbf5ad58b17f16514da8dac3e69501fb399c30333ab3050c3,
            0x20f5ecf9107f9d3e33f462948d955b70d5ec5573a679ae548998c41b5eec730,
            0x1f70d9f6c203312c6aabf4d191cd4cbc68f8c92bebf561cb8e20ce9fc07ef55,
            0x14e877449f7005ee874020d6759ce808345e20c3fae4a62e7f12c2c457f71ec,
            0x780b4537e060e0f1e88ca7337d5d43ef2d4bbb4b48e4899c55ea9a5e7120b5a,
            0x608a4544987ef3599043e9a8b4aa0598f8d71dee81e46104ca6ac186e2c8044,
            0x58cbd95dd12e8761a99011f0ae970fe73e03b7d7e43b614510ee7a6a2efe7d3,
            0x5c533c05cbf2af6d819bdf23272e567b7a49c2c2bd799201ed0e32ce9ff092b,
            0x342bb671b7d40601d4031045068abfbf2c578f7e4a380e180dbf2b0c8fef6,
            0x2da269eab1f7e247c0caf3bcac1bb0e5e7abacde34bc54a9de3e0a82a36cfff,
            0x117cc37e078928598470cfe43e1b6c66c6365d1cf601bc5daf1055a0f8210db,
            0x4640956c2daa074399825b0404260bee0898f9d24b1c807f5c43159e7a9b019,
            0x1da36b1fb01d0470d48c3eb4c92263eadb7b58c8829f2ee77e3287a6e39c902,
            0x78dac96e95e86f83b4a426bd0505d84b5ea967822d0fca9f3bd28331164d94b,
            0x1d50c82e363d8e7fa2641c9f2137b99832372d1879a2ee02b2c824a4cb620dd,
            0x2fd5a64db6093c9efda84ba327a43043e41310626073e58331c9f2f9f2db20f
        ]
            .span(),
    };

    vector_commitment_decommit(commitment, queries, witness);
}

#[cfg(feature: 'keccak')]
#[test]
#[available_gas(9999999999)]
fn test_vector_commitment_decommit() {
    let commitment = VectorCommitment {
        config: VectorCommitmentConfig {
            height: 0x9, n_verifier_friendly_commitment_layers: 0x64,
        },
        commitment_hash: 0x1e9b0fa29ebe52b9c9a43a1d44e555ce42da3199370134d758735bfe9f40269
    };

    let queries = array![
        VectorQuery {
            index: 0x73, value: 0x12346ea425a6aebc8c323a401410cc325aabaf99b54e600a7271f146488aa2d
        },
        VectorQuery {
            index: 0xa5, value: 0x1aabe006a27bfa5f93bde192ff552adbef87058e62546c831ed14ce94866ac1
        },
        VectorQuery {
            index: 0xb0, value: 0x7205a2b5f5f403b8053b4e4ac65e2a484c007f6d118524fe28b7cdf2a56bb8a
        },
        VectorQuery {
            index: 0xf8, value: 0x5d49462d844a3f203c59d39fa005cbe153c78e6ac831987f19c0d6dfae38fad
        },
        VectorQuery {
            index: 0x115, value: 0x53d21587a9cb08d1b9402a4b8c2a9d37942b26963936200fea3122eaaf870b1
        },
        VectorQuery {
            index: 0x11c, value: 0x7c3355a75f6b36a95068b68d48e7539cd97531b7478e2cf7d2dc85b32bafc66
        },
        VectorQuery {
            index: 0x12f, value: 0xb6f3a522577229ac26f12df90daaf376afbd960ee4b0ab07f270bf9c5da56a
        },
        VectorQuery {
            index: 0x13c, value: 0x174cfc44eb57da0eda6ae9407db71c5144940f05ef51f858bc8e229d15703e2
        },
        VectorQuery {
            index: 0x153, value: 0x2220da78b33e155482bdf0534dc30fc17fe059a7b9e30f710ee2681a8151484
        },
        VectorQuery {
            index: 0x1f4, value: 0x566b71a4f84556a3816d911c5dfb45f75cc962d9829acd0dd56e81517cc73b8
        },
    ]
        .span();

    let witness = VectorCommitmentWitness {
        authentications: array![
            0x2e9de49846b184d454c30e3b4854167583093da20c5ddef5e3ba2885524d006,
            0xf3fb7305323c5fa68ad49a509a9c470e2396af41bfd2c9cf86228504436a3,
            0x9dc63f0ac48b17304af16748798567f21bb25f8cbeaa48a462a74b3e0c5d79,
            0x5d35649398cb24bc00458a32d01c61a8450c7a30cc5b95043f4e2b30df01360,
            0x4493f60ea79053f2a96439d50d6335fd35e13599190e1656b724eacac658e37,
            0x7f58b9c9c333dc5b31e3ee5e8a98d8cab0c84b3a886042b279dc2f2c408d92b,
            0x349a976371b7aef1b1992908fefa423b9e5d4d0be58092ff6e5ead51ecf1ca4,
            0x3ffacb144085ca3c572a314c6bb0e01b253827231285fba4084e3b624438ace,
            0x55d22158d5bfad58ddf2633f24a3fae4642afbcea1cb9155e8b54c2a432fbfd,
            0x63c1598794322bd8f1686e89c94dc60b0bb4f7940b5427af72187091e71ef63,
            0xebaa8e9ab29cfba43cdc1f2cacb9cbc08b2cb17317fed571718e5e66b42488,
            0xa31370f89d85108378244beeea13a2b2c379d16cde55c2fcd674f4296ddabe,
            0x4285440535fff0ba31e970a1948a09951ff740c91c6d6cf4635527877c55ff1,
            0x49eb1420843ac1a3178010c314906d28f6118e8b36620ce4469dffca27a047d,
            0x4e65200356931c3ea1e20e087b5bff96ba268239ed2e2f784def64f5760418d,
            0x103809d798aab5452c77f42bc4c8fcfcfa9e6efdfe24077e41928a52daf1dc8,
            0x4253b3498a013d4473d43686f9e509be7541daf00afae0d7216f7019bc75d8f,
            0x689297a643de6bd5955e314f94367af901eac67eeef51a52e40c0205cf8023,
            0x2ca9dcef95643af6ec5ee055d1a05720f2e3f5e6226de5b206c4a78482963b8,
            0x72fbddae565406f284bb4dd89623c29c821b6187dd7dfc292dbbddd4094077,
            0x30e5ea3c2280db52829548ae99a71faa030b4e4bb87679b427f76c594aaa05a,
            0x45ba1eda942e1085af97db6e189996903cfa09db90e52b4589e16df981f1601,
            0x8c36a69368bea30f8ecf7de3e461a03b0cdd004ae08a3d44281b093fc63f2,
            0x5c7194878dcb2d4ba69da97c1a878f96dd78d97612c882ba7179bafe92a6a90,
            0x20c37b922bb713f2b6772a9ae014715f418fe5da4d53fe9b00cc2fe851f233a,
            0x3a7e7c684904e82bf0be54290299b6d83f448bac5c6e9ea4d1cd1e844eccb70,
            0x1ebbb30dbcb3b4fd0da33cf84d456101bbe9147b1a65507901715b3490649c6,
            0x1409c71e0dcf4a620856775508ce1b4c7d55e4229ac5fd41a3f8ecee097eb39,
            0x18cdf340cc64b00bf134c9e55396f79eddfbda8e2090542380c5c4967ee790b,
            0x18add43c036948c8d7e767ae22056e1f5f1a9d1daad6b9a8f2e7da996f4a1c2,
            0x30e7224d1c98b75e019b60bbe320e358ef35b1adaf12aad044744e640c2a4d,
            0x25a8793c928ecacb2e84802830fa101fb3839455957921ed7bcb39549b1f80,
            0x65dd0f91032712c4a8b1b5c35cd6ebdb654efb5e56085a2eef0def4bde4d066,
            0x4a50e2b14315602b8c97c9d2304db828806c37b751203bb7dad534d7b45d21d,
            0x5afdcfcf55c58dbf5ad58b17f16514da8dac3e69501fb399c30333ab3050c3,
            0x20f5ecf9107f9d3e33f462948d955b70d5ec5573a679ae548998c41b5eec730,
            0x1f70d9f6c203312c6aabf4d191cd4cbc68f8c92bebf561cb8e20ce9fc07ef55,
            0x14e877449f7005ee874020d6759ce808345e20c3fae4a62e7f12c2c457f71ec,
            0x780b4537e060e0f1e88ca7337d5d43ef2d4bbb4b48e4899c55ea9a5e7120b5a,
            0x608a4544987ef3599043e9a8b4aa0598f8d71dee81e46104ca6ac186e2c8044,
            0x58cbd95dd12e8761a99011f0ae970fe73e03b7d7e43b614510ee7a6a2efe7d3,
            0x5c533c05cbf2af6d819bdf23272e567b7a49c2c2bd799201ed0e32ce9ff092b,
            0x342bb671b7d40601d4031045068abfbf2c578f7e4a380e180dbf2b0c8fef6,
            0x2da269eab1f7e247c0caf3bcac1bb0e5e7abacde34bc54a9de3e0a82a36cfff,
            0x117cc37e078928598470cfe43e1b6c66c6365d1cf601bc5daf1055a0f8210db,
            0x4640956c2daa074399825b0404260bee0898f9d24b1c807f5c43159e7a9b019,
            0x1da36b1fb01d0470d48c3eb4c92263eadb7b58c8829f2ee77e3287a6e39c902,
            0x78dac96e95e86f83b4a426bd0505d84b5ea967822d0fca9f3bd28331164d94b,
            0x1d50c82e363d8e7fa2641c9f2137b99832372d1879a2ee02b2c824a4cb620dd,
            0x2fd5a64db6093c9efda84ba327a43043e41310626073e58331c9f2f9f2db20f
        ]
            .span(),
    };

    vector_commitment_decommit(commitment, queries, witness);
}

