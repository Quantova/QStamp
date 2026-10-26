// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const A = require('./address');
const { decode } = require('./bech32m');
const { tlsSettings } = require('./transport');
const { clean } = require('./client');
const { parseRoster } = require('./finality');

const ENDPOINTS_MAX = 8;
const RATE_MAX = 1000;
const SLACK_MAX = 1000000;
const ENTRY_KEYS = new Set(['url', 'operator', 'ca', 'cert', 'key', 'insecure']);

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const key of Object.keys(value)) deepFreeze(value[key]);
  }
  return value;
}

const NETWORKS = deepFreeze({
  testnet: {
    name: 'testnet',
    rpc: 'https://q-test-net-0001.quantova.org',
    rpcs: [
      { url: 'https://q-test-net-0001.quantova.org', operator: 'Quantova Inc' },
    ],
    chainId: 'Q-test-net-0001',
    genesis: 'd1d791858aaf18eb656430ca7fac092b09902a824620e88599e4226dc15e8ff0',
    contract: 'Q13TYHHY7GCAUJL2GXD07MY6SMPJJZUQK8HGPUJWS3F29XTF25MRFQZMQ4LH',
    genesisTime: 1793015325,
    blocks: { minPerSecond: 1, maxPerSecond: 10, stallSeconds: 86400, slack: 240 },
    finality: {
      genesis: 'd1d791858aaf18eb656430ca7fac092b09902a824620e88599e4226dc15e8ff0',
      checkpoint: { height: 49152, hash: 'c7cc9222189cd78253f0c620ca4604b467517de136856ce40fb7f4a1297d134b' },
      epochBlocks: 65536,
      rosters: {
        0: [
        { id: 1, stake: '2000', attest_pk: 'f703b9dc24c04acf154b240547167a41a1395ae1d1d0e0e327fc343e3d8b479f72332d219b5cf3f93ce4adfcb4444c3c36bdc7315649ceae4ba53497c479be6c0107ef55092942f03b369b752dcff81144e3516b8a6efbf93cd3e625be623fe813da78e05542a81b1d59d1032967ddbec1c0eb7f8b06560a8c9f31055f9dae560cb853c9a4a6550abd972e2200b5b791dd483b80ef157240ca94fc790bb89476e4abc97a43334daec12d61a3a41943e75faf33435e2bc91f162cdb5ff7abbb07f35560a543cc069d0a8ee82b65a83748d11cf1343396774bb57e2c65b99a3ac5bda5bb6c2571205f8a20f3d9b7c672d6814578b566c00c2192ee11b06be98f6128eb2fddbc7a2701fbf3ca84319a5e847a5e7e9ed8fc3d82eaa3e9a695b107e270e01264a775916e978ba930d8104ecdd9bce047103a8c24160af1c3cf4499e18b505cf9d24299fa722f0788f4c946772a736363adbbd19b5d7a565d721d93c1cd90e486690a327748c568fdc59c688a678fc83ce11f0a0acda90f3b6993275752bb7822bb664209dd76993d7e78bc4de6756b38456acf96d449144f54563b6e149bbefb2ad25a87110884e78c2daf49c35d74e1d033a212f21b09f695ba54879f4e23e59057d63347216b9838708765bc1bf887884b0fe9b470ce6826c601dbf584f1a38776f7a9296138ecba4e753659dded16de20726959d8bd9b85f0a16aab458c1d8840b6dffbd63b97b2fb9d8870261bb3c403753e7891ec5ccac1fe3c91137890bc189b54480c64da75978a652ca0a000ff28376632d57395d612c677f77b84b14bac697d2a48fc43eae8262d81dfb30d1f5a24618b55a24797cbacb300a54edceceab44c86f35aa6856f3eba9b36fe69811797ff6dd7344698b539c0e23b87822d71058936a52cdf9e85504c4b746ebe2010055755c797544160a9b23fc5bfab4d7581461342d088d4a1f0ba4577364619471bf6f7cb99fd21f62e3e489e28eab33c2bff089997dc02be4a18a1093d57932e35adf7b3ae9751c54577d626df64a99cd510a82e2a215da1f67892b61936ba4132eb83b8a7ff659975cb8bf1bfbd8dcb1c2c1a9c7958cc101f8b8036b6f1bf8e823683647d03a300f2f771207baf1d15e4fce474380edc17c2d6b7996f38cdc4af9fda3955edafca0724a0c4170a269f2a04df39ed83762cfbb45c02c81faee75ba4802e7369eb12de72cbe1fd9d37013cfdcdce1dafba04775bee607fbec2afe5342ebc699d8edeb71ead430d208c08e9689946ca908a1714a91f1483b8e9cd4c45dbf50f97b2be9f9a16217d196f54f2b84a1d7fe6b1b943b8146f8c75c8208b4fc81e3c298291100707011f0bd159939eb467f8dcb7c273e72d02fcc972548bd72de3ce90c2bada77dc08a7692f0305832fb55eb1b5d96579b4c8109322f371b106ebe8ccba2074409d69abb7ac912a84226e0ca43fd6e99642533da79a35cf1e477257e3ef636e3648af3362823737510b9b0995c2fd23ea2fb84ed8dd97d05d15afd248c6a10ce448ba33206dde12376ff0971335b6a9fbede7c346f17417adf4558fa4cd1dd5a70930b7c676554473c2b4389749c3006fe948de944cbec1f35813f4c5b2fa55a3aa3b4786b0e4840dbef470968bd4feafa0f6fa6e3b4d2469704497f5b4d54ec654d61c86a782ad28ea79e8daf71f034fd25a4dec5c04174caa3ac443667b5ea64a759af54fe5a70b35006ea8a7920be456c11f4ae36aabc113023e6daa4de97345e26b3f21f0a8847377ecf90c4f88707ecb67458f882cdb44a60a92ad1a7988e8c96fd7e18b02a3f854f0997682b58049ff359910f1a9793bcb446b857b5e3e599a050edefce80830ff1ae40bc85b6d98f1bb5e0ac0bf3b511bcdc48d785090549c0c71a970a8c46ea232bf6427741333c26db0423c224c3ae6d62db6a207d7afb026096063ee9b08cb3345d02625e49171c2b5420540de6b7e9741807ca656e8d7e377137e200d3f47f0c67f705d7b96f44e2747c20ead460995dbeb5108544d7495cc1850c8e03789ecf15872207661bca8566ac2627d3e5525f6508356c0976f31575b0707ce847610c122478448f6c3a1321ea1b74bf09e39e14001a33071471f06b68b3066a35ef3e157d0b0663a83ef6e3cbc9b124d7ffba901266f0e92a605b16118e34bbdac406a863b35a7c914905c5b30334da214523f5ebfe616f68a7bb37fdb48d8c69848760cb698e8dd1fa05d1e720820114942fe93b252a8143c5b4f392312149762ef07a1a95e256d9d4b62f93dcfb8948f491430ce1a2e4b01b7815716ef309eb4bb190d9a73910d3fe4e87394cd6477ac80dcbbee28cd80c4543b1c24505a74e390ce93187179b918d173e4e0b3a2589544371e1aed0879c9eec3c957cbeb25cf1544b8b5038ef92f1bf6c9164ecd298a91994517f11daa6244897a94713b9f5fd3ee44eeddb77334e9313e5563a86c28b372c0508788203f482377dc90224c77e9d472bfe8069a2729fc74bdf7eb180d8a7097de665ecd2b327f13707da396e2112202bf599a5770e2855828098e100abff3396b8c70f29b7f951135de6a4a31b431d18b4bfc4e0055d7ba7a36d7e7749ed810f6ae30c03737df300beb8162de158a2b8e70cb8a582b46d542f5bd779c2d3c6cd14de72ad85b7359534ec045ab8225c78eab9e2c3f857bd939bdb1b2f8b3fa158f54b53c7f4287257841b13865dedb2e997f2dede684a068c9b7f68e2f627e376f853e', root: '0cf9018163dae679ce597302aff05ca1720fffd6bcc5532f9bd72c18c329f6d0', root_slots: '65536' },
        { id: 2, stake: '2000', attest_pk: '077709d84b64538f3c24e76b3250e2d878651f08c1b76aab8ca19b25a1c2f8f542e8da5fcd8c03a9e4931b06a297ecfbe3c5ef231d677932c298acc9c95aa87701385f4f7e0652225918c9d82b65ee7a1e45773b0d5cd9b31d131a1b7fb401a951d0a1cfeefe420df1ac27b747ec0589e3955b7c21ed9d1a0b2707f41ca409835659a9f88fce9b5fb53ba215ac9c05f63d0f636e29c9e4a202dc9a2e428788c6d51bb310ff7cdde2a8ed9ca4a80013cee803507a05fc7397563441edaa3c4a5538c99142f7a5e88f2e2bf844159a9020b1e9b23c63e187c463d69d54cc41a52645a2f9180d747e42ffe3ed1b3f103e7ab74374d0368cb61be4c3afb5d87ea579e46da772137227935559be219a1e75cbea32413ded1efe659adf5833ecc2582fa582ba3f088299d6d64b529808930bf39b9989bbbe1298ae2ac26f0853bf992360e3be1e58ae38ed1e8d51c557ee02098dea7fad87e64fd61ac964833c02dc74009104503a577eca71a63ba31b54456d5c4f928999e86b1e36984b998bedfb72f586130f5d5263761700e39b8d82a66d0d45ed961b89db06c9533c27f85e02f580d9a9941914e897a9d2076244f3de7f568fae1a9f4f3f8be6af7e9010f21d8ef4b0771408670f9fb1e3769747001e0eac8b276b4f49fd740124e76758237c3c3a9526b10ddd813bf5164f8db0cfd5691c19297e8624c05f52570ed127028dc2b873d8da23fdd1e1069386bea0bf2f004adfd4bdb6b1c45203d23b1900f49650fab85c24c3a4c0415bc2cdb289471050bb7de946bc36adf79fa25a1df3d194467113f9ad22701de414cb45849fc3dc781923e343948c1c5b2f656857e0694e324ed0842244dc7dbc6530909d0c32d522d7ba855f96369ff4e7617ed79169e183992085f44882bb98f345072dcc6bc39be8144178312b58b11d7bed82e44a799a6ef6be82c0b4177c8b69351b045947abfebdabd49eabdf5d941eed712abd67128b176b4e4f0e8a62d61fc801e1c5cdcb9633c6877f27a93f5e1b17b7c817cdc96f55ac1dd83fb50f7b9d7309af9fd144d55b80b7e12257ae82b81f9b9cb8b0c8084e33830b1468aebaf7471a689cb8a9f59e3f8e72f0f8bf75a745c48388d288696941e9f3319ef25cbb026a3e99c1e75629255fd93739c6cc5e0a101ba8909124211a692b9baae43b9121eef087d4e33cc5473d0a1a0354f050f9909ac921f446a4c2b6bd7921a042184392b7b7339ae6c6684137d3821884291e4080f4e8ca5067b92bd09f02c9e5ad156143aa6ef49d8323b797a9ba46d60c1a856e1c7fc52b22289ad026c402b5f4bef6ed72f4ff6ed1fec0edcdfe5f8aeed1f0b277810f0127ae979e41357a16992e1320dd7b5ab4c23a65ece8e18d2652df4621b4df973d6965032de008eaeed5cf7b5c7690cd621c8aaba5a57aa4757e40b1e356f7205f4c3162c14428239d05d699b4897021bbbe533c826e04ce2544db5cefd591e7aaa980d6bb6939e93d6965cf4b0cc1e10f6a32d8d3567661ad72de9ba824a1e80eab04dfa5359453684ebebec8c8f4a18c7c7c8211078b841ee0af8744c5b8f0759d1592dce638ee3b40038af613b1e1886cf0c4eeb8288b11bc181bfca835392813e71955b0961217cb26502340d3580c1ca77f69c060ab44b2dbbd5e24df7708a1b054659d9f56c6c841532164d961f21841a894829b16266aeeb9da4efa2d693fdbfaca41aaa57a16c0dff8c8901eea87b64008f1b45442e001d93d03c22d1e4298f341b2cd42aec01de9a894e5ed2a21d4b71ff20a36b180451d14043770a6039da83c6fd7bde7335051eb4f586a479367b271145f08f032db07c2a49cb100a433c599de3c71cc345aaf67ee5a94d3147acff81c8b94954694a8b0ee1a1ebb3b070f945c4596f39aec8f77c6b1c7a1c276f9044eeaeab53b92830a09412d3f03cc2fded37e44bbfba7202df78c844807b429d6aa99f3330420bd93105f086b2b73c34b53765183b8414999f68fdd6167e8bcfd372b9b8a870982570daa3c24dc997244ba12deaa433e1373800180950e84db54980e8ada088e627ecfe987a831c02c349cf372f6c8cb514ecb1a24556c3eff92f8f7a0ee9a1d3c7147f1926d2c7b974db578d7cb14d334c2b9884a4ff811a20f418c92285a701cc7cb2acbb59e1ca0dc25f09c02fd9a533ae36e8d325f3fece002d550f39608482cf0fe671def50e6768c04f84ac14c408f7f1b22a103cb487f0a1f9da26dcb537c43af9f4c3ded8d40c621b8ad704bab8b78f0ee011fe52f0bc850cf5eec2841a6732352cdb1481b55d5b7167d6e3b6ae00ccb08a389fa3b2c72a4ecbb593fa3273a7a062c8238a957f2864165d18360954be27ae0f1543aff0cd8b2674d270abd6ad1d9c55776b5dd0a854ad09b2f33beca9f210c9e84336137f3e35707eede63b6ec979cc90af1eb4f668fdfbe540c539fec20ec02f6690cfde0a91cbc2dd0cc3c127048376848b092783e111ee54b7f535c8ccea8515c020b1499b9f915230937095a593703aa0aad8fa7147dfa6116e882ddd7b08cce825b3d9024362babfd195f84236b1275b91a7fdd593aa9751644898089a2f7717867e0e5fe0e7c136e843063c536603df4235873585f2ed80245d46d6c625a08fec14f107eb5f9adb022ed9e0119f31e17e97330d026dff3a6b324412442636a1fcb748886cd51808ee6ac8e84094c6c889f24fce19f76800a0978863580410405fdaeaaccd0eef8f48a6c2e', root: '3e572f8c1ad94197166165096272760234143cb33f7c2dd9a3ab91405fad7bd6', root_slots: '65536' },
        { id: 3, stake: '2000', attest_pk: '1fb99a65825571554f7e673b18354f330158a9246584acb2a94fe398106c57b2d10c460d798190b9e76dffcb8989af04d59acc8288c128d5653f121c1fbad15a7ba2514a0e163628331a2408a06d384f070a3d87d16d0007d079729702f7897e0726334bcd87834734a45ab285a913c3eb8d95387c98c68fd3226f699242298d2a9f512947eed1aaec8a7591b96d7ef6ee511ed8eb29b96b09b0948e1a5270e2875600547503494641e9c669d2da40f61a5842e73b695d9043eec8d4abde7087b7c5c7ebe7fad5e7f5e5316b5a20e59c842bd76949119c64b00e25ee3d552f54683f8f48d72727eb1d46d59cc28934b76a9763ec503a90399fba41313174a58fdd95560e5d525002ad73440cd7f35041f14b2cde4c99bd200ef2a77efcd4e2669fd652bed37d55189c5513dfecdd83d786647476d314a0e505c79c606a56880488f02e9bd03fe1c9a38e4bed7bae26d2c14d1d18b7d91ae30e7ec5bdfee6a14678d24ea50251e7c6e29689d8939fee68975cd87f2adb87c30540f069fc0ce6d046fad3281ea8ec70f6520961182778fd6ffdecd5ef1a23c543056cd7e8387a266e31e13225cce7a5bb086643e08943a4609f5b82cff7b305cbb64f3f403cad5065f9bb980de945500a1e2f17a78c94117f992b43d79e8fe3c89d1cea44fd1f0312f77c1d04da7058433caa4d43a583e71b0ff5e5d144d8bb9e0bd1ac4bb6fc179f030d4ec934c41e3ebf685a76376b3dfc98529ad62296a0a2c8b81ca2bdbc3029234fd36a541655d2d36b4cce1d75aeee44a33d292b046afe6bc7976708f7b667925d4f6eeee1a95878acef10dfda3cd211af0ea4c7ab5951604f0335e6fd585f86c55b620580f36f83fb3c209afbe15a6ea5980f31d8af77bb6293a826f2770eb04dbf9fa8a9b656580ab8f0a2ac4792039c83a63c648b98a7f99540e02b478270d224fa41f8aa4404d35edfb94250c20abbc4edd548e8ffcac6bb248c9765b2fd9d0bccf767e9604507018b5be4b1854c9490f4e3e4ca5f158cba8ae051e2bb9b5468bb4974221ddaf03c70c0aa77a1651e50a6b4f86b23d8031e997edb631b6403cec7d55263692d914b51d515a26fae17a858cada5b404e8962504dab90be113bd0b0bff48806733a7c3a241a156d80ce8075c4e020c06efeae387e772f1c9950b34c4bb17d80385d103ba304457c3a6f9e096c5900daf3ec93dc7b0d36d099408599d1f04ecee44048629e0c5078f0e2089f04cdeda580312916492f52c4683e8d16660fb1bf18bba3465008d5613aa8991e7651f5715d2e5704ce25e7cb07785ed854e1d1d45163168b6d6b55992f827fb5b617a3a7d899e926c42433ece9a90d362dc8010fa720c0fe01ad242c9482b503ce95bc7a256bd5d763d26597cd94c4bf09dc5970c81877db3a1a22b526af5b1c6274dd0a7aa50a8cdb8f525a9d2dbcbdb77d03ddea2e6bb0ac72838f1a73baf7e56f06c01c3e160fb054f75ef5ed92312d765818f6720cc2f134ab115f70a24e5cd87a28863b03e1473119f0b5754607d5777e92ae5c38725e2aa9a3c3cbd4fb17b807fb0bf4acf7a9fd9bb6fb052b639af9b961b2790a5556e41a6625a3e1e4bb9d3083fc9cc84eaade77719443b77a4f3ab3e3786cd9f15b46185e3fda91481b128053aa8d7df5b53c138f8c9b6e7096ad42ed2818edc8b7a2696a41f2d522b9e2c8f2bbce65c0ec842e87e3271aa0a50220e4a4394660cc6d7eca16f7692528b2930d491c3c03e3dcb439519beeb27cf3571ae614fa74d4fe3b8f900383c87bee980643078644fecee8015a997da217eeb3dcdc308842687630db2d28df62f106519f360fcc4ae7efd9a09686ac7fed84f41697439f655664acd6b8475d7d9aaea3683ad595fc7aeeda48e8c788ba909d07e20589192f3811ad36082f8ac28ae31d6c70bcbbdd4b8bf1e69ebdb68d9cfaa6455003eac53f2dc17ed5c0c883dc464afbc4a082414601c091b4884dcb3b92bc03979613e199f59189485efdcd712382a02be682f0a5f2c3df1f14248a7a0e2e0e3f0d5195fa305bb0fe2722021739e5813eccaef7391eae15ac0ae776e238f04340d62ec211f2c5637b1891820ddd0d4f00cd2f9840ddbaca82fc39f4b4512c629a59e72a30e7630186994d248506f5f9356ceaeb9cdbab0b9a0e07bb82d5c04bb8f95bc162f1b1ac0300c3ab00ab1c03d5e0f1e8bb3076a643f56239fb0de932d512ca9d893f103aca83b02e5fda148a0a2b6b399dba2e59e02209d413459346110fd550cd5017c835b76c0be9c9a6539958b048c315926a7fad6aab10873d29f37ccced843481d862c2791cbc665956128175c2a1ea68aba97a0ec92fd97371785d6cb7cdb13087d1556174a99613e62e4e5cb67b02b4d09f04ff4e0c2b3a837d360af0c78cc7ff575cd49693d5d02b614704897ff4cc6950fda81abecf7ce81bfcc0888c8055f2b8cdc123e6651f43dfa5c9e03be6e0488ea31e92f5d5061d54467b576e1e589599aa26e48c87dde1958c47538652193e804bc4ff0d2d9c42aa8651005475e73d7bde8c4c9dee2dca54bd2946cf54e41ddd2e85b700db864ae808f25af9ccdcfd7a881f643c6deb61745761047819b49063c841479af64fd58c0d6f0b5f428338a9b832a70fc2ae9e07f83c5784e3892dd072db91c84d2d732b8e4db889d1b65287dc5241d66986d3b4004b71e1786894a03dcb62841daa47f9953601e281dc9d623a0c19886119a86afcf93668e024', root: '091ea43c39b2cc1cce713beb42dc664582dac0417b3269a74d097440158ba6d9', root_slots: '65536' },
        { id: 4, stake: '2000', attest_pk: '305bac1a28e9cf78eeabf97bd86b0cbfd547f7ac58bda54c6571a5673d7cf8f268827fbba6087af7df5cdc5f132c85a5aa0697ed405ab32c785f503ee07828056f9c5daf5441acbc512a7f4cd69a811079077a24a900b716509c4fe27de2084401d2d29a72dba4237da2ed8dfe8e3ae662abc1ae1e50b7dc1219737456c044c92771b3486e5941c54075a7016c79a9caf2b70e995f8524b22e939ebc6948c8e2b3d81f2ff1935cd23e0ff9c11205bff2c661ae52a53ba333e958e4f7fd467a705f051de57cb0064c871ed76395e9bffa9fd3317542c7f6c365a83a539681f3f1b0ed03cab16f9eca3001f2918f9a43ee88a43b6d4b5aaf1d649a80c44135a494cb3412ac066ef2213be15388e711e048713d1ab3af89cbafc9428a0c408a55be5005faf5625866e9c6543ee75a6804dc5e18af9afbe8a627816fb85da0d9d655d537a1fdeb5868794aab8f700ef9d2e5523fa93b5b8f82806be7b2f6b956dd77a97a434b9323d4fd10c55827ce0b9fdf279ae355a351623ce463dc05dd5a188cd10aa6ca2aa552c5cfbc2d2b38ea95a513f3ae3e8938654df4dd0e47b304b7640e9b70ff9dd28da182f258c09a8029f4988f9e2463bf12a48959a772aebd8f22ff87d61d0e64fe438be103da091cb61259938bb987f924f5c8279369360fe89a2851d083018af47df8f5940797b9993eee803b2b976ce32af02e049d66656e9f0833fdba316783e1d951b9947c895256fdf70a6a9711216d00dbf564d5675899a3d3c5b1044f34e748e9e7313d11587efd807bf3e0c395113f45956f5af30fd98f777afd50c5a88b6f205d9d5ca89b3d70952afbec67ea52d813226258f97656c34fc9f6731dd125f2dfdce8b55430a43e958620d1579c166558763cf4229935748eb7ac28a9d4ddba305422559028d06c2732803cc23a101fde8b695731190b0a59d673cb260fef13f372a8bf8210aef5bc9af7834db24d25f75de13af83c755b9d825f1b034256fb5d28392a6460929214d0e92ae14f1d05f60fcbc279fb66d1024ae0b9816cedd63d677a084fde57c703455cb3056c73b640eda652aa25c660462a387902dae14017e1fb960d5bd83806829ea1e5be3b69fbdfae55ab4b47bb25ddd02f7684cae71f4e10d5e5f9877025c67c1f647505b1030bdd866457ddc7ad09ed470f2e3a00497baf7c480b4b339c890508168e5f791bcda498cc8abb5da866bee9d4e4fd10c28807130057de246b246bb8db93b50393f80919348c5891736f55fd09723fdd59f2317bb57bc9881dba7daf19896ecd1481e0425a88111e30d129254924c516423b180b15d0bab1bfb557eaf67a99de20db66279814f32306100397b5f8a9b53e3f355fe4f3ebca30575769865e7ce85f81ebbd6e2e3950791c14ea9ef41ce8c610f5295a0b8c9cefa338622a285df27a1840cb4566d6de6a7ec6cdd6161ea9c46d39c78249fcc8aeacd71dbbe5552e088580ad0f58f0e788372d236c498c912e01f2cb4e38434eedea220d7aa2487fbc15d4572e11d9196810b372d9a45ffde0fa9698666ad9cab7e8ead8ae38a9eb44244c228b891af9b636ebc18515966262f9b6dbcefcb8ed5bc8e7d377ed18fd2a11a0ee121d927dcb241c88e99586f9f419160e940dfcdc71ede36b83909390692a6f99e8bbbd7b0dfc75af66d954bf9bb6dc95844fc2a576d438ee84863f90b2a270a900b9b26faf87912e5ff79c0ca5400156ccc48f2528a6545f0384c504918b5bc2bf42694304b06099d7cf4dd8b3de4e688c035e80cef24061f9d2d63d850b15d1d10217e6e21d1ce93dafb63a4d613c2b321eba36590e899143ad081ec87fd87b47167507c1658858282e39c60b7aa3c25312efe647e10fe30673572331812ad17e562ea889adb33f5dbbcf37ab0800b49a7436cf6ff58aff0ef265ef30962130e651057bcd1d5249386808720af822a49932955f1fd67638b40bff83f4fbeefcf136790dc41801716574baa77891ab253c134e8290e66c16a66523c5acaa1e70293fb33932951fa7f95fe9d4aa7584e36472413a4a42690ffcaa493de0f2f8c21bacb90a87eeab32228a4e548dde93d7d3443e481c4628c87c4583b5b66e95f9f9f859d5ac49cc5cc190aecf7e6044344172847e86bf9092fc3386d76485a273cf322f59b774a93977fd355b7bba41d9474ec8adab37fcfa92047a5d7582dfce1677744b4078bcf403c59952bfc5f39604861d3267d0d3a4786ce2ac74224e98976002482f6d30e9f35004bcb122b5a274d86f50e21ee678111dbe71dfc9611c77470c8b4666e110bb26d01c37e65e3c881feb308283c651e56af97c477e0c6a62b7668c9c538eec9a9af5c002fd6ae9e5ba83fedf6d76f19b5e7128ebb54f1274b38c4d00424db2c7cdb8de2a3f46eb93c3f13c314ef5c123528d55d2575c365acddd845c3f66454a3ee875ba645db136a3acae5b19f2a4f31669475dec9546c0c81f4d16dbff53a5fd6463bea61a026711f4a779c8d51645c7de87f649146e76e8e8c0d1bcabe47c6399c2e8826bb5babed444a23d1bc64bd4b561aa64d6b6ef869f12dbcd5ac49942eaee60b30c5ea9b0151d2ff94b338ea81148a5dd50772f62ecade496276c0512b57dfa25d38988bf1601d4b7b021e0c4da9c54ca9750647ca44de24d746f3efdae28d65a6d5b96eba6ef69c231cc98d068b8ebea5f90682f1cb1d138be77b34db58032a366cd9a58d969495b4dfacbebbd20319680b6ec29df', root: 'caad6c6ec3405447a564bd3e897cfdb240e323f9902482370ce0d07f845a89ec', root_slots: '65536' },
        ],
      },
    },
  },
});

function network(name) {
  if (typeof name !== 'string' || !Object.prototype.hasOwnProperty.call(NETWORKS, name)) {
    throw new Error('unknown network ' + (typeof name === 'string' ? name.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, '?').slice(0, 64) : 'of type ' + typeof name));
  }
  return NETWORKS[name];
}

function officialEndpointsOf(net) {
  if (!net) return [];
  if (Array.isArray(net.rpcs) && net.rpcs.length > 0) {
    return net.rpcs.filter((e) => e && typeof e.url === 'string' && typeof e.operator === 'string' && e.operator.length > 0);
  }
  return typeof net.rpc === 'string' ? [{ url: net.rpc, operator: net.name }] : [];
}

function rosterPinned(finality) {
  return !!finality && !!finality.rosters && typeof finality.rosters === 'object' &&
    Object.keys(finality.rosters).some((k) => Array.isArray(finality.rosters[k]) && finality.rosters[k].length > 0);
}

function requiresFinality(net) {
  if (!net) return false;
  if (typeof net.requireFinality === 'boolean') return net.requireFinality;
  return rosterPinned(net.finality);
}

function loopbackHost(host) {
  if (A.isLoopbackName(host)) return true;
  return A.normaliseIp(host) !== null && A.classify(host) === 'loopback';
}

function hostIdentity(host) {
  const ip = A.normaliseIp(host);
  if (ip) return ['ip:' + ip];
  if (A.isLoopbackName(host)) return A.LOOPBACK_ADDRESSES.map((a) => 'ip:' + a);
  return ['host:' + host].concat(A.embeddedIps(host).map((a) => 'ip:' + a));
}

function checkBounds(net) {
  if (!Number.isSafeInteger(net.genesisTime) || net.genesisTime < 0) {
    throw new Error('the network must give genesisTime, the time of its first block in whole seconds since 1970, so that anchor times can be checked');
  }
  const b = net.blocks;
  const rate = (v) => typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= RATE_MAX;
  const whole = (v, max) => Number.isSafeInteger(v) && v >= 0 && v <= max;
  if (!b || typeof b !== 'object' || !rate(b.minPerSecond) || !rate(b.maxPerSecond) || b.maxPerSecond <= 0 ||
    b.minPerSecond > b.maxPerSecond || !whole(b.stallSeconds, Number.MAX_SAFE_INTEGER) || !whole(b.slack, SLACK_MAX)) {
    throw new Error('the network must give blocks with minPerSecond, maxPerSecond, stallSeconds and slack, the bounds that let an anchor height be checked against its time');
  }
}

function checkEndpoint(e, opts) {
  if (!e || typeof e !== 'object' || Array.isArray(e)) throw new Error('each network endpoint is an object with its url and the operator that runs it');
  for (const k of Object.keys(e)) {
    if (!ENTRY_KEYS.has(k)) throw new Error('a network endpoint holds only url, operator, ca, cert, key and insecure');
  }
  if (typeof e.operator !== 'string' || e.operator.trim().length === 0 || e.operator.length > 80) throw new Error('each network endpoint names the operator that runs it');
  let u;
  let host;
  try {
    u = new URL(e.url);
    host = A.hostOf(e.url);
  } catch (err) {
    throw new Error('a network endpoint must be an http or https url without credentials');
  }
  if ((u.protocol !== 'https:' && u.protocol !== 'http:') || u.username || u.password) {
    throw new Error('a network endpoint must be an http or https url without credentials');
  }
  if (e.insecure !== undefined && e.insecure !== true) throw new Error('insecure on a network endpoint is either left out or set to true');
  if (e.insecure === true && u.protocol !== 'http:') throw new Error('insecure applies only to a network endpoint reached over plain http');
  if (u.protocol === 'http:' && e.insecure !== true) {
    if (!loopbackHost(host)) {
      throw new Error('the network endpoint ' + clean(e.url, 120) + ' uses plain http, which is refused unless the endpoint is marked insecure for an air gapped network');
    }
    if (opts.allowLoopback !== true) {
      throw new Error('the network endpoint ' + clean(e.url, 120) + ' uses plain http on a loopback address, which is refused unless allowLoopback is true');
    }
  }
  if (u.protocol === 'http:' && (e.ca !== undefined || e.cert !== undefined || e.key !== undefined)) {
    throw new Error('the network endpoint ' + clean(e.url, 120) + ' gives TLS settings but uses plain http');
  }
  tlsSettings(e);
  return { host, operator: e.operator.trim().toLowerCase() };
}

function checkEndpoints(net, opts) {
  if (!Array.isArray(net.rpcs) || net.rpcs.length === 0 || net.rpcs.length > ENDPOINTS_MAX) {
    throw new Error('the network must list 1 to ' + ENDPOINTS_MAX + ' endpoints in rpcs, each with its url and the operator that runs it');
  }
  const owners = new Map();
  for (const e of net.rpcs) {
    const { host, operator } = checkEndpoint(e, opts);
    for (const id of hostIdentity(host)) {
      if (owners.has(id) && owners.get(id) !== operator) {
        throw new Error('the network lists the host ' + clean(host, 80) + ' under two operators, so one host could pass for two independent endpoints');
      }
      owners.set(id, operator);
    }
  }
}

function checkFinality(net) {
  if (net.requireFinality !== undefined && typeof net.requireFinality !== 'boolean') throw new Error('requireFinality is either true or false');
  const f = net.finality;
  if (f === undefined) return;
  if (!f || typeof f !== 'object' || Array.isArray(f)) throw new Error('the network finality is given as genesis, checkpoint, epochBlocks and rosters');
  if (f.genesis !== undefined && f.genesis !== null && f.genesis !== net.genesis) {
    throw new Error('the network finality is pinned to a genesis other than the genesis of the network, and a finality proof counts only on the genesis its rosters were pinned for');
  }
  const c = f.checkpoint;
  if (c !== undefined && c !== null && (!c || typeof c !== 'object' || Array.isArray(c) || !Number.isSafeInteger(c.height) || c.height < 0 ||
    typeof c.hash !== 'string' || !/^[0-9a-f]{64}$/.test(c.hash))) {
    throw new Error('the network checkpoint gives the height of a certified block and its header hash as 64 lowercase hexadecimal characters');
  }
  if (f.epochBlocks !== undefined && f.epochBlocks !== null && (!Number.isSafeInteger(f.epochBlocks) || f.epochBlocks < 1)) {
    throw new Error('the network epochBlocks is a positive whole number');
  }
  if (f.rosters !== undefined && (!f.rosters || typeof f.rosters !== 'object' || Array.isArray(f.rosters))) {
    throw new Error('the network rosters map each epoch to its validator roster');
  }
  const pinsRoster = Object.values(f.rosters || {}).some((r) => Array.isArray(r) && r.length > 0);
  if (pinsRoster && (c === undefined || c === null)) {
    throw new Error('the network pins validator rosters without a checkpoint, and the rosters are pinned together with the height and header hash of a certified block of the pinned genesis');
  }
  for (const [epoch, roster] of Object.entries(f.rosters || {})) {
    if (!/^(0|[1-9][0-9]{0,15})$/.test(epoch) || !Number.isSafeInteger(Number(epoch))) throw new Error('the network rosters are keyed by whole epoch numbers');
    if (!Array.isArray(roster)) throw new Error('the network roster of epoch ' + epoch + ' is not a list of validators');
    if (roster.length === 0) continue;
    try {
      parseRoster(roster);
    } catch (e) {
      throw new Error('the network roster of epoch ' + epoch + ' is refused, ' + e.message + ', and every validator names its id, stake, attest_pk, root and root_slots as get_validator_set serves them');
    }
  }
}

function checkNetwork(net, options) {
  const opts = options || {};
  if (!net || typeof net !== 'object') throw new Error('a network is given as an object');
  if (typeof net.name !== 'string' || net.name.length === 0 || net.name.length > 64) throw new Error('the network must give its name');
  if (typeof net.chainId !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(net.chainId)) throw new Error('the network chain id is malformed');
  if (typeof net.genesis !== 'string' || !/^[0-9a-f]{64}$/.test(net.genesis)) throw new Error('the network genesis must be 64 lowercase hexadecimal characters');
  try {
    if (typeof net.contract !== 'string') throw new Error('type');
    decode(net.contract, 'Q', 32);
  } catch (e) {
    throw new Error('the network contract is not a Quantova address');
  }
  checkBounds(net);
  checkEndpoints(net, opts);
  checkFinality(net);
  return net;
}

module.exports = { NETWORKS, network, officialEndpointsOf, deepFreeze, checkNetwork, requiresFinality, rosterPinned, hostIdentity };
