use cairo_verifier::vector_commitment::vector_commitment::{
    VectorCommitment, VectorCommitmentConfig, VectorCommitmentWitness, vector_commit, VectorQuery,
    vector_commitment_decommit,
};

// test data from cairo0-verifier keccak-native run on stone-prover generated proof
#[test]
#[available_gas(9999999999)]
fn test_vector_commitment_decommit_0() {
    let commitment = VectorCommitment {
        config: VectorCommitmentConfig {
            height: 0xb, n_verifier_friendly_commitment_layers: 0x16,
        },
        commitment_hash: 0x3ce8c532eab6fcbf597abd8817cc406cc884f6000ab2d79c9a9ea3a12b4c038
    };

    //n_columns 0x4

    let queries = array![
        VectorQuery { index: 0x98, value: 0x67406d6bb8db3de41d8b7dd9896c85e6d69e951d },
        VectorQuery { index: 0xa7, value: 0xa04e05c094e8ff020674895a8e87f2e9cfe3bc5c },
        VectorQuery { index: 0xbc, value: 0x1e6d3c0ebe3b5b027d004491854b3f0d65ed3e0 },
        VectorQuery { index: 0xde, value: 0x32c5b2dbb1c4ddf042f28957e05374d52fd89f02 },
        VectorQuery { index: 0x1bc, value: 0x2c9bb403fe8e8bac0653f29385806918bd1fcf0e },
        VectorQuery { index: 0x1c1, value: 0xf56fb4a5d883041b083ed09e0e6716227514cab0 },
        VectorQuery { index: 0x1eb, value: 0x6a61fa5e145d3bb6bc886355e41f07f53deb8866 },
        VectorQuery { index: 0x27a, value: 0x2b42bc4742c6be2f729de5ee226f98a6f1ac7849 },
        VectorQuery { index: 0x300, value: 0x16c6e1dfe9a2861f9e104bddfc080a582e12bf37 },
        VectorQuery { index: 0x3dd, value: 0xbe093d1e5cde50c05c920259ff84bfabf4b3b0a0 },
        VectorQuery { index: 0x41a, value: 0xc7c4b092d8de1c9c0befaaf19ee51fdbe9999245 },
        VectorQuery { index: 0x43f, value: 0xaa42411d4938220290da0c5e6fbcf16cdef04847 },
        VectorQuery { index: 0x48a, value: 0x53cfb0631374186865337530371bc3129da3a418 },
        VectorQuery { index: 0x710, value: 0xbc77966ffc759fbdcf7ff1d5ff9275efb49e61b8 },
        VectorQuery { index: 0x72e, value: 0xaa3cc5a670b9f970f7dac6b7adb3f971456dfff6 },
        VectorQuery { index: 0x751, value: 0x19b79813c4376f363b27a623482a01775a4f7dcc },
        VectorQuery { index: 0x772, value: 0xbbaa216e8f9946749b0325ad463333f411c5ddd3 },
        VectorQuery { index: 0x78e, value: 0xd6ba0eee61fc3a2c0d901e56e5a2539e7c38d1d5 },
    ]
        .span();

    let witness = VectorCommitmentWitness {
        authentications: array![
            0xe676ff357a733da543bb3d81e3aa60ca9f1063e1,
            0xffc663afe730d87e8c5b65ff1c4e02bebfb45c5,
            0x9ee28fd2b364c452dfc86e0fb15db982895abb18,
            0x4b2aea8358aa2562fc75d90ff221cf7643da2d30,
            0xe6ca528ff25b6a8027f6f186a6823b22e407d0f4,
            0x2ffc0ca2d4c2a613decdcee120d7ce8bd31270b3,
            0x87525e0ba3a6d4f8ddf4a7cc48deb7546f12bd80,
            0x26d3a33a07adc85a684d7aa9fdf8b6f582b9acfa,
            0xc65fbd68d029050bd45eb8e111a6f31f87c0b451,
            0xb43296f2dc5b4c4d908b80789b193962be8db556,
            0x9465cacc05be1a69f3eb38424e448a73199774d6,
            0xb48f007b7760a3cc2056e5db6f3eca5c4aaa7c8e,
            0x54f3688454cf9b399bca2139a865ab970b02e0e,
            0xadcfc979b6dd3e142d5c1a6dd2f51d1f65651de1,
            0xaaebcd47fccc02841f65830056d1f2d0075a6d25,
            0xe45f1dd9110a7a0b3a6c157b841fd9aff4e66874,
            0xa3b8e22670e0876ec1f042c974359444c595f1a2,
            0x92693ffbfd0ad1f60d4f8843658f20c54fd11a5a,
            0x7281b36fcfc367c94e83bdb8ea3e08d0142cd0d2fe627b80c73acef7e6a49b9,
            0x3b5e95b9b0fadaf1031300d7c0d9f043706f4dc7f8baff7e2dd55a1a6c65b84,
            0x2cc6a33256646a68bed5dd10cb782b229736fc9028ad7addb3ec487c38e937c,
            0x296e424b9795e3f4f1e5c00d6285afbb4c797c6dd8624fd735824cb9fa8fb04,
            0x36931e8cf7d2e8cae2087d7532f93c12c8ffa20fe5c7a02c9aebd2c0657158,
            0x49c91ee3ddec4f62d4c5dd802317cfe81ba9009e7b46f66bb354019e284194a,
            0x63ed1d118d536eedd9a286f4fc633b7625f8af0a2bdf6acbeb4e7462dcd734e,
            0x4620a4b9fa50fbdd167b899ffa02e8965aa056d35086db2322d6a703c7ad15f,
            0x475db860a575eae6424c0bac0039cd8a9450ea558211e42db402a826c14c1dc,
            0x4c69f749f7b1a98b707ea255d786c43a944031f3bf9d2fdb4f5b1310c61bfa3,
            0x1552bebad7cd328047b44545dfdb3412953d8548b7a65bf15f0f1ccfc98fc0e,
            0x44557ef3c00fc68816781800bcf8ef54d988d70c8d22189bbd0415328c8eda0,
            0x4ac53f19aa2254dc7ce25d541953e31c2c143069760254162227ce3d975b61d,
            0x795b6fcf227eb5d19a4e01c5defc88ba05a65eebf23b9306a7513769d96d040,
            0xdbe8fb2afa68997d0ae59711090a255bfbb5f5ed6543a5655ad79577a7aeae,
            0x785cde61bda7ca4638d7759a0a742942eaedbf08d1269d36f373c3908964a7e,
            0x7f0d790427a3fe91985b625ab9138e5ad2a05af440c26201c516a6ff852f022,
            0x5cfc3623a36de637078f8daee039d624bf693db91f8fdb4ed81a41f59e09f3b,
            0x453ff600781c3bb90b791d0a7537f31add3a733ba5ea5bc9887d4bab9948a05,
            0x26befde2c0f7ad61a726b7138869d76f66ac68e809855fec10bb4e3fc846a0,
            0x7ae21aa0e4e1bd6e63527d34e9d493e6b1943d769c3d970e1a6113fb8cdc509,
            0x3c4bb6412da8c8cd9155cf27a22934afd270ce654486b15cd77813d1973fe7d,
            0x765c40ad58db8cf29235128173ed93490d2fee999353fa4d1401cf734bae9eb,
            0x6a8a36b56c2919a2c0f00485d929009d085c52583868aa96a87574e02ac19cb,
            0x7c606e8d4c7a82c9b97c733908dce06038ab72ce1d70026f1458b8b0840162b,
            0x94922071ef2d6c99fe9da993fa6b494e82a25dc10ab5d6bbbd71b28f58b9c1,
            0x53f5dd1bb156b3744de60903a5e1b89fd202dfd0b1c50279c04894f6ab2d13d,
            0x6768cb453416dfac3b0eebbb53efb0748e27bca54c0e870c58d9a8f869fa036,
            0x16c12fcd3cdafd2f4328fc1a2299de4035baa36fe3bf46701c98558166f9b4d,
            0x29cb2a1d86816e6e5ceacbd12c58088385d111cbec53ab677e38b56c3aeb350,
            0x8247a109564a0dbcc9f7bad00e0f4131bd1c024e0f3b76ebb6b6c66b317b6b,
            0x4751b9f7b400984dbf007960a0522b3696277bea06b4a950ef9b98fe0a8f08e,
            0x22907e920eec443995bc55de7ebafec33320ae4ecd0a3dd8635e95ae3ab52bd,
            0x7f92acf18e809b3d2a25deef9f176cfbcf1cee6dc48ac1bd1ccfb47f3d01a8b,
            0x304fb4d291aa6db2a08cb4fa70e7e3fce26d927048a78a725afcad00eebe671,
            0x7748c9d244881a114b8c225d3dc3c212377013fbe9bb4f681024c94c554350c,
            0x1e6e1c4a459327339e22e2ce13a7e5e8b55023617731712613898f011237ed1,
            0x51344e80e161f57469e4695e624b56c9989ce3fc4081a0a5e2c1e56ff5f4d22,
            0x2d8af710272d1e39b101419c80f691346cc93c4cb41d457dbd6697e09490505,
            0x69ad0f6fbd109ea3547b6606981197b802a920a319c61fa03ebee73c346e9ad,
            0x5c0469ac2a93eb97c7cda4f82253280bd681a611eec612eaff3f91b81844aff,
            0x2022f6794db246316b2d2e024e70008bd6ada94a1958b8e5d5cc039202d9400,
            0x23c4647f032d7703fda9ffbb4c2c983323c11ce80412b2b5e3b20efa4d3062d,
            0x37f277ff3e939433e79e156ce68004fe24741f8c1b9264d346919582117e3d3,
            0x4388f543724d6095d53ce54c2b8fec2df52ed0830cff0df933181fb8e377490,
            0x1f9646a1c35ccf8656ec727053aa7fc6a571ca0498bc22624f3e0dadc2e1bd,
            0xad4cd2d1f4c6da0c831c51b13b8bfe987f61d369f5fa64bfc8827f607c96c6,
            0x636027ef64d2f9ba05b3cf507f840c19f12645fb6a0db2a24b8cf1569191bb6,
            0x43c8814510c36a011f1b1994275a928b66812d7c3ef14d93c31463339137bbe,
            0x300b7133fc0cc085144a2a14e496700dbc4f8b583657ffdde33de02ef78191c,
            0x7ba0d828caa7cb414640e08a2fbd789a8d111ec7883ffab5fd538c120c5a5e6,
            0x8dde3adeb2e83b034a5ccc12638008362a24d66835262ad33caa211a6c9793,
            0x849bf4d63ae4007169c0bd9f5a2b7f572ee2bcd188e868f981b5f4f67bd47d,
            0x3ced5193d4bb228dfa19e7f7d46372d80393b242a72d48262e1a8594f623094,
            0x325ba92845f1d7350fa4491e3405fde9ebda7c1bbbf7e066a2c8c10a6c680c3,
            0x155b15335843b15e4b816ae7e6a340d452d6247552864ac53e39b56910519b4,
            0x482777b78954afd4c3ac5ebb92f93a82af11652f50935960d6ac75f75674140,
            0x6fe0d0ec0abe430cf7c7c32f15a7ae343796f6175e292fed589aea79b813616,
            0x5618be8b708e7ddca48c8b971916c5fd9a1ba6eb4252e614ef88c4f2e41775f,
            0x51365af55597548ba0f4543e4fccba8c6e1a7faf6b2e8c48af96dd16b48e8f1,
            0xb5cce5205193c3b87dafdf96fd0de0cdac974558aa47e18e515841b2740b1d,
            0x51a1cc3992db4da580a2a77277cd81e52376c266b8f8c585b879a2251d7439a,
            0x7ca03ac5453cdeff7d3fb2742680345af326e92935686f84462de6f37588dd1,
            0x3b26307ed64a35759b0b4792c1f74803627c6b31046ed9c8ff9cc9bfc5b2c0,
            0x27a8f5d9f84205f8439338257462f4efaf07924aded94b419ec98c0be0ace0,
            0x42223b23fa282ef6a087a92cc400d36ccc6e8d6d953e6d3144bd2f26505a6f,
            0x4ef7521d71a61c9fc42725fbf3e36361b53046b68694ce437f576d079ce86f5,
            0x35fe0ea431a96210926bbe2002d26c15133a0c2bb1d2c6ee31cec86af66922f,
            0x158bfc28d59e25bf7b7a0e9995d1fe201d708db865013aabd6f19fb371a734b,
            0x46b9fd1bf3be4660e16c85ae8854e2dd6a8d4203d4b19926e66b3a881553b96,
            0x4084cc05bc951721e44cbc69526393ece2f17d2c3ed28675d92bf6e33c1c047,
            0x4b8e7e93f3a6888142902582531d0659329a714727f26fa4bc87e4eafa1077,
            0x2e9e738a183faa18f7bdce422e9f49318226b3b32d1d8410a48b1cab0875c5,
            0x20f4db5c5abe20c948b151cc25bd4c2c001eb8a13711742dc665a21edf137fc,
            0x63b799bbf4ec3241fe16b4a154194ccd9e6377a785527ed9365e725521ae17c,
            0x365b2a7dcd62b7b0dcb2d10167cdd87c4ad1174dea6fac139d54a3256c0c1d8,
            0x3e0bfea95daf7c3a3244e35549f078e029e544b9fe65b4548ec28fe8212b9d,
            0x4a899f49847c782e0dbf581f89aa522e4114b42a741d5d78efbe49808ba91f3,
            0x593e1c4dc6e2ed44e0953cf736581eda4cc6873859f3e1614c629cc58d86689,
            0x12b4960751c2799461bc1fd9e8466c5cc1f2bb4e91aa2be4d7d1c87fb7e3d71,
            0x3e3c1fc87c1b07d5f40b728ea660c6320691a1b596edd70d7a2b48bf8e66d47,
            0x4a0eb250ff1e14199c95f1a942542e0ddb486317de03d033b6b03cf6a1f66e5,
            0x2a768272e178821889693ea00ffca5c5309a7ee33b078a675ff2b4f3dd82325,
            0x364195536f59b340f0f315fec7361229e4a61ae63e77d182dac9d54a2170296,
            0x204636737aef25c5f4c8aa332e67fc3618e83a896f134f10ed929677bba4f7b,
            0x75dfb1d1da06ef149195da6171b78ca57f21946e8920aef4da97c59581fc37b,
            0x74f11bef16a2c8923231df2090b074be1c0b017f7f1f12f919f332c9362f82a,
            0x109604ebb9ecedc292252882c8eb95d3ca041db27cf1d8a76ba6dfc2355a9c9,
        ]
            .span(),
    };

    vector_commitment_decommit(commitment, queries, witness);
}

// test data from cairo0-verifier keccak-native run on stone-prover generated proof
#[test]
#[available_gas(9999999999)]
fn test_vector_commitment_decommit_1() {
    let commitment = VectorCommitment {
        config: VectorCommitmentConfig {
            height: 0xf, n_verifier_friendly_commitment_layers: 0x16,
        },
        commitment_hash: 0x821aaa485d3fbdf7b0a06d773e565370f794c06bbcb4e23279a39544782c1e
    };

    //n_columns 0x8

    let queries = array![
        VectorQuery { index: 0x987, value: 0x52dd8c0a5ccccb7794f19f0ab5970fcd9f1ac0f3 },
        VectorQuery { index: 0xa7c, value: 0xe2d57dc4618b581f90656bc2d52e5d8dea486803 },
        VectorQuery { index: 0xbcf, value: 0x954ddc7bb2cee7d557ec4f9d59945b7fb6e48d05 },
        VectorQuery { index: 0xdee, value: 0x9345fc1125947d5ee81d4718c0f47192feb3482e },
        VectorQuery { index: 0x1bcc, value: 0x7220a5c1d0b8064cbd1209776fa4de6542d2df49 },
        VectorQuery { index: 0x1c1e, value: 0x3542844769c27f878f6e35bb2e67a88d4c03dd43 },
        VectorQuery { index: 0x1eb7, value: 0xb1c41a659a7c6152234cf2ca8cdb5efc72c9e9d2 },
        VectorQuery { index: 0x27a2, value: 0x81784f9cf7ed87bdbac6dcfbf44af72bca353464 },
        VectorQuery { index: 0x300e, value: 0x93092c78b03fd72c8b46bbe376e5bf462526cbea },
        VectorQuery { index: 0x3dd6, value: 0x82ac740a3abb9f578a927c22a2aa511518129cd0 },
        VectorQuery { index: 0x41af, value: 0x73623062ba1f6c257823894f018f5a27037eefe8 },
        VectorQuery { index: 0x43f0, value: 0xcde4b028895fd2c9255ef97b21953eae14fdf94 },
        VectorQuery { index: 0x48a0, value: 0x8d10a4ff032e5a941a7250cefa7a1bafb13fb26b },
        VectorQuery { index: 0x7107, value: 0x9e82d5b8e92ad12c4b58db86cb1d1296017214aa },
        VectorQuery { index: 0x72e1, value: 0xb9ab35b0d62e37527f06fe0160aa910a9ea30090 },
        VectorQuery { index: 0x751f, value: 0xefe7b0257f9a7adfb68657b1d304fa32c270fd9 },
        VectorQuery { index: 0x7724, value: 0xe445f9ed68e3f25b0643f9bad1a06347bc3a6aa },
        VectorQuery { index: 0x78e0, value: 0xd8805cdc4b3b0e8a5b4840c64644abbfef95c57d },
    ]
        .span();

    let witness = VectorCommitmentWitness {
        authentications: array![
            0xb0a447b02e1b4a1b347bc55447dccb3e5de98ca0,
            0x892a03c1eeacd2c6d25d95029ff19797bb4e68ac,
            0x913759543ddda4483ce45e3073010b5ff8f19aac,
            0x84d27e7eccaf23c0d3ada2039f5daef268b8c8cd,
            0x25028cc9c2166cbbe1db936b8d61affc8641e86e,
            0x6d2f6dc2e0c5431e352f4e7224a18aa78201c175,
            0xe288d8c704ab0701acd82c88b3195d899385327c,
            0xd7ef3f40010f78c71fb3a5921f3bf12e8883c7b6,
            0xaf5466d74a296db04371d9b4319072679df3ae0c,
            0x3051a95adc35959686a35d3b88a911edd58cbf6c,
            0x2d492c74ac266de638ef6b0e8c4848455d8d268a,
            0x1039f1e7ca1c7fffffacd29b21562c63ffcbf131,
            0x4c3efddc98969799b41705d51dfa826b961dce76,
            0xeffc79dc8be2710b95e310ba6de6633192496dd,
            0x52664ba11b6a455195c829272daae853c98ea947,
            0x1dd54c186b7741d34782a040e99f192cd2d7aabf,
            0xad697b5701f90e17580181ea8e5131d3ad1a269c,
            0xa5463255f189bd2fbedc84681a4742eb2d19e2a0,
            0x7506e7fc92336b65853b0484aad1fc5f346871678754ed345a58e7d7c043a56,
            0x2fd9031b3e0d9733f8c64007e8797e9f4800f0525898f2d58c62a7d94bd9c05,
            0x2b3b8b0dcad8cff9bd2251072e47aecea14e7ac89f22ef6f8675ce6fef9df5f,
            0x780dccbb5fb5f525844b2396d313010aff50dc35ebf0f5d08e829fdcd8bdf1f,
            0x45379e38fa5503a0089bbc345db8d480ecf9a6c5e480a3863f824332b9a804e,
            0x13a8aede766e3ad1b09e1d9a9f7e0595d369d3a0358f6d4266a1a9e200c0521,
            0x1eab3c03d38494f4ee5d7ab5484ec3e3f06f0dd1b7397ffc2a6814759bf9927,
            0x4d79f8be432eb782666b1b8f75c43f45a8615a090ceffe89b66908fee53d8c3,
            0x86e736d63446baf3ff05f5633014d329c43d3be06248179ccb34ba239e9250,
            0x27cf9130a84e1fe1497d8c0ae7522ba508087c647e135fcce81f985facd62d7,
            0x57665adbc7b286e2f5d5c2414ce78fea5ca4c142955a315301015b28d31d5e8,
            0x3cc5818ef7c15acd44b01e2a624cd3201438bdf540d755e57829ebd555e8de6,
            0x53e8751aa45335936ba48175bf08e665b15f3b1a3c226ac81b365d2c0e395c5,
            0x7b6376b914445b0952d894b76b89a04ff6dd17a7413229f7d27464d33160b93,
            0x84ce40f5a9bf3d3d28d0077189eca141e4aa6351a48dadd056f4bc72c1916b,
            0xdf52df2f23001f5dfc8c974ee998ed382a389ac6278d5d5186fc639204033,
            0xe482c57be8a9d338463fdaaf8774d09fc371e249740e6379468525400a751,
            0x7c661f2d67471f85d580eaca6bb27b296c0c9f512057e9ee2f646ceef9d15ff,
            0x681c2b863a73bb668163748af5c5f6a2b7f4db761f3b053380d0e0a5180a756,
            0x5fde89fb56662b09381cbbf08880a0fc0f9e59ceabff110d022390326f21416,
            0xa6f6b3b79466ac427cc1f4640ff83d183e4671a8380edfd8ceb012a83d9f07,
            0x6d2bc396eba151e9214a9d47d54a69f1df58b03c940a7646d963a05b1e30191,
            0x9147fed28ce017cb58cfa9278305307ee080540b7872e49851a38d1d216dec,
            0x7c50140f5b020c8354aa88854877d77a2a2eb9dac7461b14ed64c00f9f35e7a,
            0x2afcdf74e31c171d17196406083827422924d431289ffbeb9ebfacd47bafaa6,
            0x28b414010d49a3dfb9c613754e2246a1bdf14523e12edaa7a9eeaa39d6601ca,
            0x44391753cd6e36654d3c706417fa48b9e8b97ffdba1baa1a2d589ec48a9f662,
            0x71972b880e34b976de3cd6c7430f1f515cf96600ba564765f832124a036b660,
            0x2931db2901d6915ae12fba763c8524ec5a53613ae9b6bde8fc1a2343d6aa459,
            0x5bd9b692b3d7158dee8dcd479389bb37a2d62d0622c5ebc4f8b232d1555fdb0,
            0x36a37863614f66d0ad1ea5fc0ca34c84e9db5676c72cc965e5a57cec830ed8c,
            0x30962fba70ce97fed8a9785975a044e88cf8bce73706a2f92a0fd834e577036,
            0xcbac60936295ea56320fb86d2163f0dce9c1a7ed6a2d06b843527d39626404,
            0x6775d90fef7ef22aa96cc495d0835e64e6255f1e9145fadee95baa6ff9f168,
            0xe7f2260305cd693c71c9ff8c0ac26f730b21c4d92c03d380c011ea2ff58906,
            0x5dd0eedd817c5ac76b1491928c646609881022cc73b1799a9af82e51dff2ec6,
            0x3d6b5d86abba1de26e3643b315d848ddd831157f85d0baa1e01309bd1c76de,
            0x1a1dc9db2b65ecd4dde2cdaf57ee011f95de07828203211c98814e5d4bcb37c,
            0x653e0987d060480a1d0f1573fb76ef4ea7841b19f61e14e18bcbd0281758a79,
            0x7ea281d8498e5706f07e8f24ec9e73bf886677442dc36a04d61ba3c1b803116,
            0x6f7fde7fc38ffea543cb5e8c667d1e0da43c0aa9d62475f126ff33fc7a07b4b,
            0x3005b649b84d3c330d6c5ae7c05b45b9c09bb732ed58c314a3b80c27feb4c9b,
            0x1bbbb788ce8a0587a333838f7a36b7f3d0d78d0123d00524e0f83e39686d9fc,
            0x53ad82776d9626403051a40587cf690d04db746ce9a3a58c03851e1fb5e84b7,
            0x16e4c3fbf29b67b2e157dc0b6f0c9ada835b97033aa229814bb2fdb467fcc98,
            0x6621d4a5e7b8d3d3bd007035e4d41f2dce4eca9f5bfdb9f089c3916355cf8b9,
            0xe9904de0d4b22c19dd206ab5de3d1a6bd8afe5d02b6cbef7ad5a17287b4ce9,
            0x5df75d05c531927f35bca621ef1b463c0160a7ec409d01482947c9f605a6a26,
            0x359d5c38e66975ceeb739a3a8f2d39a7ea4c01bc50d9ceb40f0d43a93fbd602,
            0x610fb1edb0059777e19cbaf20ad53baaa91af0cb7fe0ef5b3976dbefc91a64a,
            0x2f9c99dc5b29c06d84ee649e1eb35990a7ffcc8a8601da6fb680eceee011046,
            0x37be9614003c140e1255912924fd618d1eee244ab69d2673620734e8fd29d06,
            0x5db9a3f47da773370f5c18c838703538aa4ca987aa311a8986f72e730c4289f,
            0x29f90f26bf1c633482ab0e806200145d73fd0784be8f361a332b9233ed09c89,
            0x436ddc1e75b986e6ec69763376aba5db071587d6663ce9542a7385d1cdc6558,
            0x5a7dda65665b46c22f23299d244180e26806c0535a0d53f2abfeab1da88feb5,
            0x679d4517fec1b0b64f12aac4d359400ca93dd4bc4963ccd3821ffe5fa2c2f2e,
            0x845ead83d9c3300e39a1dc5560bf2689f56a6c89091a128c5941430aa61e3f,
            0x340eda7c96bcbf05c25d283772e530cbee6361e9022ad4d68a79e10f1243067,
            0x3f0b1548439276bb579b8a82a8b8ddff592e14ee264fca1ef830757690a4ea,
            0x40f25c75d8bc4982d37ca63774cda73461c96188571b1c96b6e345e0debfb4a,
            0x4eeeac24be93d35a1b895b4a7c09983fb5362ba74296cade9c28128c2c4aba9,
            0x5b6283a2ed987cdba929ac0bc7dd62fe8ead889af29c1b669467685616b999c,
            0x3d0c0ff4668ba4ed193eed13662b2b56ff121be67e4f36101a8db3a8db4ae9c,
            0x6ca1a8f5c122154cb64cbde2e8f76f0228190aed478e1967035472615d11a18,
            0x1dac45bb8d7447e5b156b0262c6678c6536d4b8473808f235a7b7063e524c3f,
            0x73ea9cdd32d515d67b583a575ab668d541b6583e0444af130488c7392ae73f5,
            0x265e7573031568729cf0b9a048e67ad2a042cd946f0eee9cc793503ec16e8bc,
            0x2ddec60be45cce4484af51a7f3bf86e83e120196d761dca978a6b8200d5ee2b,
            0x7b43c1ea945be57a2dcc25b548b9f8507f8f48e9c0c1cc496b9ebb91c32994c,
            0x674f25574f0aeb5020b15b3a740d998ea70ed8c784252e892498d02b837f60c,
            0x4d9b611b5a427dbcd4284e10e6e77a6c26ad8b271d601f4b6d479ccceef703b,
            0x1f910fb44aeaccf25dcadcde0989c21083deccec3082ba1007260c457054ae,
            0x2bc8a629bf5998654c5f8e30e40cf2e35e7856f6df46500e8fc5a72278d2556,
            0x4ca4dd29836c3e84b1d246682e24e32d7821072144dffd10ad8bb3d5c72959c,
            0x747f042aada6343a0e2f67c2abca9e414939379a4867c019a076214a2e2b7c0,
            0x7d34eb7d9ab2f38f42b0c377ad272b1db996bcd009af9f837ddf37c4d98f918,
            0x7cabcdefa8cd4bf15c94dd8c9dca629dfca1d728a2c1b9719a4f8ed3c7efbb8,
            0x6133e7870aa62a810658e0e6423fa5c94fe3a9bf883a0bbec22f477a92ffd32,
            0x5b0cd0d9e876e036db1a9d8232e8622525445122a662ffd8530cd24e8c9a768,
            0x7c5e1ff07b9b78ec333e8a6da9eefe8d6753f304a2ede230da38f17faf78afc,
            0x30e7a5b56a568020f9b48c489783019c45a22074fc08dc64e00261170d09485,
            0x62aaf59648624d703fcb6bc8d935e9de5c019d9315c33fd002a97ac7b2472e0,
            0x20ab951e5863d67ec5ab6ae434cb3513d9745d914bee01ab56012e4ab7e3975,
            0x656ed3296eebb67964b799bc8589dce7448a1087a54e130b39ed7a3555af457,
            0x3f44d393132b76cf30699b24d213246918b05e9f413c8371ac7d730b7f29303,
            0x19f1fdfa391696368931ead5f8e6b6fc67d7871b311636a16cf7213f95f978c,
            0x38b035861a027f689c6c5abc7953a5c81d2800cf40da041e19c1868775002b7,
            0x6011cc2b8920985eeb3ce5bb865abd570f766ee2bf0be0790cafc06fbad09cb,
            0x677207c9431bc1818646785d5f6c709261a7f472486020d1a1103580de852b0,
            0x68b25bcc8b31ed62b76850ebb82186f30e05a55dab1526c36074f764a851d83,
            0x6d93176f9ec8cad58f1a9e4920d8cbf11e2b786a0a5aa0ec8534a4012122016,
            0x11eeb71224093f8c65ff5a29751c1a1ccb7d330e25abcb6bc9c863826fbef78,
            0x4932c523d1a1e90c5e291f62aa389854b871407255c8204ed79a4a719f58b12,
            0x3710ba91a40e7b55ee81007c46cec52fdad193c1c11ed191c5c1dec4f8d91e7,
            0x888f15b9ed73a0fbc0cd291ec534d177eb68169e69b930fe752d3a2ca57b60,
            0x531e8c6b90a91f420f1423ad75d4fa30b3dd5e774e755f82e064ccbcf79f0e2,
            0x2a1582e60ebf2d72bb80df062bf1b6046ff8dab804c4e6a1d6e926f77d69f0e,
            0x258dd942e3c04e955f7682a5e4199dfb28831ef35a8d0963fb8d66c3d9e0653,
            0x37466b659d3c8bbabf606a8f2ae373013aee82978cb51fec221e631e9683a4e,
            0x3dec2efed3f80a611f53dcd1e00fb56f1b496144402e390ea0a5bc5a36a6ff3,
            0x70f511a3ecad9fd4a81b2bfba2877b2e60ee4b2771d1a2db02c212734d12852,
            0x93c7e4a639ab31d5b0dd6ba9a691facc5c77d0f386f124b97c8f7c2497cf33,
            0x316db6c5844d662d614810bb73de2bbe6331fd2e8da2312a869782e87a1e588,
            0x5873c6dc2317906755f9dd1440175b3943fef5001f387c07a69b3b521041268,
            0x560a783ff7e8cabf8fb67963c50928384dbcfd24f027084f79467ad4078e981,
            0x29c0fa0b9202ed7cd6947c40f123425ecf0cf33d1c3e33aa78942392a213ae5,
            0x64af7b21f1cd142ac2c5a61de120424125022379ffbd81d7899a66ed1fe2f4,
            0x14c1481da77da43d04347572ad9a7d95b816539b4b3b2c03f4e9a252ee016ed,
            0x1c4478c8e7197ae898d3d86cdd43eea29dc96674a85550ff37cfe9046a57908,
            0x4b25d9a0a19908f79f7a91e74a3631a9032d5ce668f3c2cac20b44f93268809,
            0x877ab7bc4de0c57540715263b5316d004260d117eb01b830b471abc0a8fff1,
            0x73b5678163f66dae5f10bc84b998e8dc85c5f497c7923e7095f1f47096c3d30,
            0x14be7aef1f6af50fbca1c715dc285d74aee672c8497c54d635aaf3878e46f00,
            0x2b462bdf0759cb5e6e39ef9cfd8260c1dd080b8100124135a64756c37cddd39,
            0x6027e11cc5cc5b920732987771178c6fe937d65186b4df909b5ab9924a6f2e3,
            0xef1cba1431b83f7493a7191168f84bae152fc9b7bd6be69fc1d936363de9a6,
            0x3e0415a510ce0f0e5902779f4827021fb14e86c14a91af7323c597df6841c3c,
            0xd7a263b6f44bc7ddae58504ff1e9db058f948f667630793ae20342f92a9b65,
            0x146198bc2ffbdec9104a02e73179591b68218957fde65e98c7738253d0b1920,
            0x55ec7c90cf13919859df147fe0fd47367c11bf03489cc8f81d9db5c82ae9196,
            0x3ee3e8a7fa3e39072b862e5b7e22b6d1062a8318fedec260a21c4a43c50350f,
            0x4f1346c1d2180130a75f03332ae60ddd156c5ff9210f883c9c788731d6e1ae3,
            0x6a68b147371ab00f54b8ecd0db21acc74c466faeec1e096951d1583ab40d66c,
            0x42c32032d56766be1e6bbea6e411d42cdc09c6160055424d6fc8c498e56deaa,
            0x1c2a1fafca032a66d72809d385f21e31fb9f782e8c205cfafa49bee4cc733fe,
            0x6856dc7be18fc7422553e56873ba21266bc1ac33deed8bb967ad59d1fd8b48,
            0x6ccc14356b42d548ed81d9e7e8221a7c47372ef9cd1a0e01970c2675d2f22bd,
            0x5bece8fc9b7d80d1cc6ca6803e3e3387f5c616812aba57f107fbe3b432588b1,
            0x7eca089f5e2b5a60dc0ab8acbddbdccf262db053a77bfeb92926134da205304,
            0x4cfc657b820bb806e45e6687f902da16916e972234ff7b2e7e48eb462184f5c,
            0x74210bbd1a12572a7c33284b95bf35fe562fc641f4093b875c4f38458cdde9e,
            0x5e676e97b599c1144c77d97cf6c6a1f429e6b6e5ece6b1d88d7f05b2168637f,
            0x69fb65a12bf893a6865f21031786ea19a508a3404b5d3dd7ca5b4608ac42b96,
            0x47daf513b912aa2c7261745da5203204e07becfa9b32162a81169b3ef2df45,
            0x1f4aa8e52d2287aaa05708a375942d87fdc02360299040a841917a92ef48b72,
            0x450f60c17186331d30b54e47b86653985f58619cf22c03decf543641b5326f3,
            0x14fe73c7018ec5e11274c86eecc8a2caa07c2e99150e62248051ed496774785,
            0x601b015c7c94d5308a912067f7f1053efaf241c49ddfe45ebc3e8e2ca6800a6,
            0x65df0f3cdaa9fab092b11ef17af479be566a040bc8d13d20ef016e0e51b271,
            0x508e3ee800ff3b30334419e2058af211292658040eb4d524a78810a3443dbc0,
            0x7e6853f820c12807064e549ab85cc771d156c72c00de8d2e45ca7465b48919a,
            0x62b7d217cbd75cb2c321730a3f5fb12c383bbd5f1ecbbe9631feda95adafd46,
            0x1ffeb177d5ba5b765816d0b8efa33ac7a9032c83194326fb298c8af0a2a1b3,
            0x2e1fb7e47b42ee71beac44c4b7efed9048f47f6dfb19f09bc9184aa5f0a8aaa,
            0x7bfb6b6d268e28ed4288f18209525eedb8103907251093ba43d73aa9902b121,
            0x3d0021701e0b2cef1165a6863634d6c2fb0c21f9bf037b6b33516c0e043cbb2,
            0x2fa6fd5fd8d69f9d97c4a4527fd4ecc1b1c1455650d756e8f5c91909667c002,
            0x169f5a97ea7061d1919aee999fc085fe71ff8d7d9f015e97b057f579b6d395b,
            0x5616d5704ab7a5a8a298413965555f8cdf6b8c66c6589034a68c8431cccfa8c,
            0x3b0fc82a6c0ef3dd46bb5aa9d2b2a447b0d751a686295108b5e08c4ee4041d4,
            0x5f16cb2372eddee9e5d94912c5d1065216700c379e3ce5185d87a341f47e30b,
            0x40582d40217f8bee3419dcd3580fe76a606a5f1962cf36da858c6eb8fb63dff,
            0x7d4367553bfa4e42f6dbb5aec103a19f9eb672c3463f362f23dea6f64221cb5,
            0x13c4332ef9a002c119674501497e1911260376d447769445b1fe7bb0ffc4e2b,
            0xa4e5df371b112b44a04096dc73274c0ab319db7696e10e20b4eabea4a4624a,
            0x35bd8a5d993b3233e3717a879f3b80a04262a7a776470523e83c2e28630cabf,
            0x62da0c4d1e8da86fc9d51649becaae663eaccd994889214ea2f7cddef854484,
            0x6cc281bd4f41e94f605a3d41068d8eb5031d07493c8dd25e3c6f1fa8053c22f,
            0x28a02fd182c26d2f66e3703ab43ce59b348ca197b8c923019a1a0ce19d90e31,
        ]
            .span(),
    };

    vector_commitment_decommit(commitment, queries, witness);
}
