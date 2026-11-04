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
    singleEndpoint: true,
    rpc: 'https://q-testnet-1-1.quantova.org',
    rpcs: [
      { url: 'https://q-testnet-1-1.quantova.org', operator: 'Quantova Inc' },
    ],
    chainId: 'Q-testNet-1.1',
    genesis: 'eb6a54c9d4daf6a8609c0fd9c25e339a59cb269646fbf53679efa58a0d15c7c8',
    contract: 'Q1N2U8M3DE95EKVSJRGQ29PZNNL56J53FK76VFJL3KRLNLM32EZASQ2SQTL6',
    genesisTime: 1793761285,
    blocks: { minPerSecond: 1, maxPerSecond: 10, stallSeconds: 86400, slack: 240 },
    finality: {
      genesis: 'eb6a54c9d4daf6a8609c0fd9c25e339a59cb269646fbf53679efa58a0d15c7c8',
      checkpoint: { height: 0, hash: 'eb6a54c9d4daf6a8609c0fd9c25e339a59cb269646fbf53679efa58a0d15c7c8' },
      epochBlocks: 65536,
      rosters: {
        0: [{"id":1,"stake":"2000","attest_pk":"16944d4db2e1ca2d9a376c68474a1c2944d98acd645eb9ed184dfe6e1261373349e2ff5067ecea47cc8cc9faa4da3c3ecd7f2ffd6e318330d2e32e79f7a64aa0e26bfadd44ae00c9e846e4a4fc68e038f14af6a04425631f1e7d17a6f65ce23992804518c1c48dd57e3776ea51881e290533b27c728d54735aef1ffd1edf4b335e74454536b4dfd885d9c3d06892545ac6fc8f6809cac662f3fd143d581814a0775d5bb2c3cbe9b5b0498edf68bd97c8371f74cf4b60e7300c82100e3bed5b96f6eb02ff632432352c2d9529cb78556a5ff8ee997afe790fcb92e2be9a94b9a611dd4cee5abbb9ea588a5e932fdf4108b459e99ac546a699bc52e14d8c9034f2b535b75e51a74e85e0f2e38753d6ca01ac0b96657266d68fffdc8316dcf9054921f63d7a5e3506396ca360e934fa8950c7681ed9a1493c16e80838f1a39a628de9cd8588ea110d0a31cde360efaf1cc3fb2f659cb191deff645994be4441f6df9401111e7dd39cc449b1301c4aa5febfa09b31b7cfac123d0341c780771069ec0f30277e7a1ed8bd83641558d92dc2db699e34dd6d1208b3b30fa75b0b00f75579bc709255b40d095213f5282fd5c488402cc3ddf4f25f49413041e42bf4cf36946774369392e1fe904aabe48ff5e7679d0333f4db91bdf78fdf36de71e712dbcd98c6067050c2b2183b52aa094bc95fa726a8db58c73b520e067f29342bb1a39d61a40b54c5f1079f11a2376e4fa6a4e4e87c3e3b10258207f4d8c8f7c678d8dc56f915c3e78e35306e606ad77bb96bcdfb81ce2f22521faf2329a60435c4ebfcde7694d59356339a2ef12ab909c556e6424344de583c565d87e3f8957618e0e3933fdc6b91627f79e80c5f446ba51fd882b6b82760412483a6d0be89ada9c66654d62f8a8d72231a5b3aaa178b41a55a77e3dda1c1771bdad0641eaba0fd41f817d0e0ee7c2556e6537ba9ba877de33e5b7a17cb25b1bb4bd6fa0b1241eaaf9bd17af28ff3f09ed61a352e4cbbdf43b5fa27bd40bd25da6b9b05291bcf12911ec818ce2ed1de163c6db5c177815bd52d022c44b5d78c7753985d3d65250b1c6e29e1622c4ae56d1e55c35277efea133f9960456c5e50924de3debdd72d2375e572894ba01d9c61fcd3936f4fe864c6d8ea5c1daefbebe9a4b87538dd3dbe16402a2b68bf79482226f5b9b1280fa48a1ef18516baa1c76915c7992d97ec17575bbba60cf21322f78a4591947a8ccca2b13fb203610d301747051a6823aec686f42476ba7aa4d342d2d17d19ee4c7d46bb95833f25f67375b5293a6a7b75dc5d8c30d850db2b085c316e8f4b472c91a630ff7c2e6760d4c65eaab0ed003980212417e598e9f21316978ae3d0e9b11701cbbad6451da901154f825d28de44a203fb5a52dcf8412eb234ba033fcc995853cf48e9f5e9c072932b4a5545c2d2ac5a47bd1c289d482cf472ea8ec132ebc088008c0759cf6b2390d72d5a056ad6e5f2f15d43065bd38ba0c207a52b53a92cf5c5280a733ccb6ed30f61e466ea2545ab549d4ca17d51eb05ba2d3990c72d13f7f1de6b4bceec3fa01f4670036685aa450bbb0b4c9acd2393dcb1194ddfb8a401d7f9a7ea5c42ee22c513c6d6da03436dbc5333c0fbe1f1c4f88b17137be13d7916706a5a87ec4b2714a69d4267b7ad5f8e0df25fd83015458283d21021b88bd4dd601437d8dd077424270fc7991aff6660653a6e369aa002e3ea71696e434f75659ef1482a15a54b1b4519cbed77acc5d27918273451563b15a9df1fc685838da19d8faf4098210b40985332436080ceeceb078aba3d4d5c9ad8e824529a3880104092444307770e4ba85867ed6b1be0ccf945c6d9521e48dabe1f047c8418f2d22b076f1fc2f4b67c939ef625e8adc70ed5a96770cb88e5315e5d7ef61779ab987f0aed7045307fb0b13fa3b3b92804bdc067f2e527c4eda2ba790b64a57d194513d597187d48230a3581204c806da613c5507201dcf7f0650468fe4055a4d09c6479ab55b6829ee747f8fc152a5b14d104283342814e7fc245572488a49e0b8bb2d20fe9e8cf5f8e24969fe6a1baeabf592dc8c632bc4cbeb987ce0922d6b64b176f5ced014fd2d09b61372f37d1fd63539a2df89513a6715aacf2bc437af72e3198038d6fbbbcfb6ca126f1dfdccf3dd8fb25155a5ad323e0f3428676e0a3bb91b1eeb3c0f1c79f1939dd28f3e9122d714f018fb62aea6787313cf0cf34e4641660bfaf0386e9ce37db7cb0d730b251b3823fe684d445dc22b94dc2f9157e408ee65ad0b5bac7667aac57158a107f0d5a0c45c4e3c742c06d5182e2eb5fb6f62fc1baf708138c25944c93b87754b72a915dccdebe0e973008eb62c15527e028a978a7a97219b12e2ba31a137dd48ed6c345d75fd88234c0564127dd936dfda01806dbe2b60351b00e88eceb3a42afa7fdf8a202269bd651d3e03e10d51b135a0638d4baee447e7892410f67bfad0d447fd248706f1759551446bf483e8c173d9a6cd61ff814987575e3274450ec9b408df8e249ab739100fcff227e974495e071290266bc14c51edd84a2d18211de850678edcd7dffa7bcc817d8a4d6968252a58a1f3ca89d7245e789b16f54a9d800d34ce1cb51141d705e49c2ec53aa674c6ed1b721c3a77fa02a5d71e9f4e5ad229437ca8075dad0a1da7cf0cc15fb1ae2883fb9779a2f317b0249d07a4e47b9d48c38559a6b9168766abbae35f6708c57d7daecb2d43de14e16d5c59484a947","root":"3bffdd055a2b881ee13c64095a5a3e41a91bd0e9caf50d06b7ebf3319fea605b","root_slots":"65536"},{"id":2,"stake":"2000","attest_pk":"30deebb21039418a6b9d4939c4734ab8967cb08af209e44d0b6c0fda243258d6b5802ffc7c5932146f5fd75cac2ed9d2932dd7fd82e9a6abe430958412238352c76bb3d6fc2a14a7279fe7a9e30f1929c76ea47014a3ba0f8f4fdde41843ce8543bdbb85a10fef0ce1a5f4ec1f54f2e06b8816b44c588df99efc515c96d3a29ecab62cbad9c1931b936b51b7dcaca62cd10bec4b7fe6eacb3791a456627f1e2ca7175829488d18ff82671176758525cb84139b67193429f2e7db7bcd93603cd273a943f74618bdb57f6071c4e745bd8a8af47c7b082b965ae6e70de59bf8e30412dff86142bd7743c6da2beca7c8ff68e580443711b5dea757bdbc71c4426117bd80e287a74964cbfbbdcd72a14b7921058ff75233b633d6beb8c209ea169cedc7324d5f6117977836ce709a199bae3bb11fc5a9c1cb274e60848cc9d31201d82670c88367c44f33ad7e3ecc48bb06018cb3886d8badf02df5e1a3131f5ecf32de4baf41113cc045c242e09a2fb136ace709734461962dcb3f478a8a86aae5c4c0ccc4eef6ff7090617feb484d5da4c067abb2d8aadefcf3efa180f002763274236afe79446f0336cb2876a7d00bed81b22277804bc5b222c72a6e8757f845f0a65758acbc1a517275af0f8a41c76aa5c3211f20fae1cc1fb1a45c4a2fdc0805f4d867083f606cba529c5e27f7ebb37117dda377b7391bfe45ec24d47066f12fc300820367ceaf1cfd3c6b1bedd8febba621aa0e2baecb1efb6dbd32a4b6a6bcfb25ef65d7ab12e778dc3a52393ecaa838164290b87d08a067f2fcea0119ff89b2e9fbc12311697e4e8dd509a0a5e8b0e773eeb1454ba888fc30cfc117644dc98b90d2e23dad36911ac02a39aabfa92e3571f8ade198d138f97f54ef745be1a479e8b03566d77a939942d84937382cad2d7f26b46f82f2bdf2260a58bd56b6d0e1b811c139cadfaa8c19c057782eaf3962ac297d0a255cbe34fe3f9bba2b9e6472e0103d19254d9bce7a63709dd8e8549a9b3fd48802b916901f7b6dec0b12f4ed74352eb2e93c08eced2094f2e94d4d0fa3600b435dac34f4110c3946f9fd06e14406c8321ee5a6d53ad8c9d25a24a71613c65a59cd597f99fbabd23c8a46c3aed3e0326157bd6cbb2cb9bf161886c0ebec238285426207c869e66024f92fc8ed470bdc893eeea4b08ec9fa5e092c15f98c71d8f8e662d38a10ad849a95eafab37bd31aca2aeab15c09d8ab7183eb3d092023c0baae29ebcb8a10a2add86113f1a6bfc99956b09c3511b9fc53e02333dbc3c58d6ca8894219a30ed4bd6a9d96ec6b076e2ceb243489b94d51b1fb80e50c1527c7ae5fc93201e680120138b7751e4da5dbd17e831fb637e9240f109ac466a91d113c91a4be7f6367e1c0c52a25087b4b3ca1d9e76a98c90a2019ab3b9ac92f39d599b67e763b1ecb2b0295680fc4e19589eb8c1a4a76ec0919ed80c51d4a63cfb9bf50cab5194818402816ce3e0f3370d7e696b5774eaf7ba089bfdc543b26e377580e3b63ff9245447176baaad8825c1f3b221806661006475733df189b744d73a41b1e577ea44a752f23c07f683711b2753acd33b783dcb99dfd00dc57bf1fa6d5f74706c25c7e2967221acea09a9624bd746c62adb39a060a54a3599d70b49bfd36bc29736d2eea625694d6b93e24ba6cd7b986526b522ffd1e6d6e814cc69c9cf96f5d7c7e3d242603a84501514bf829b84ed92b89b4b07b5d5b5788365eaa1eb84fece00d1fc04a3ce18e357825dde4070662c650b577773a04692602e58c0a194e6f4cf965e7eea3e9c81ba3500a09fb861c8170fd710375e4682060485826ca938339b1a33a3d9a26920fe9f31f23ec16b9f0d0561b757747343110ff81a902e2fd232aee8a96ec0c231bf58ab1675f6926ada97a9e8a58d568b5be16c3d56cdfb6dd482e9e3fbeedf24f3d57e696f931a5f33267f27ad3dbb18ec32e22f203fb1f6034b0ecc1b93a87d60ce839d25e8d6bb1212d373c5b1b01138733ef4b2b09c5da11a7aa0309f9ee255e2352510431ae88523c790824c06dae930afb487298953c81ebfe1a5a2b1a819c032ed4ee60508a1d714c485c4a9ff33389498dd05621b95d96b2b8de8827360d1f19be3d6ad6b5dc174e4d082d9fc2d8d1671c823db0f4228dec663430f33b3ad330a584aa3c40859aa8e0f1278603e684fcbce5acb52b670cc874a254f1c04c3970ced4b612334ac1328072a3d4cb265534023dcd67e0f8cdb099817004cf3914b16a8e44006c58664494543cab844b970d7e8c5b7640b6dc4055efdeb4be3d2c08f27456f5af60ddac0e288186b6565126b551f2df619d9527e2679d6d92df229c17e20a126a3dd538ff998e67a3828fde711c643e19448de1efbcf0b14b12ed895ccf37f20d8eca36c38762a49b84d1167b0e66931dd509611a2f6a2c0a8331dd7dbe79063a090d9afca61f6e42a1b7d679d11b5ba69c84d8997fa6dcb93daee9b49859f2e5955b0fdf8ae40a0115db94b8e91a2823cdc5f1f0e6d30c8545ff33172fee5359ab7e92e27727f1fc90f262a6cd1cf037806c7cc30af1b01b4db3fac651bc6e2f53862860af06862b059c2d19b64a01dbb7fe7afaa17967b1a1f04e6f43053dbeaf1385856e89fe88c47816970381bf7a920d0bbee4a4d2d8c943885fe222373344d0b265a98f5a056e4806e1518f4852fff492d8c58c5b916d96f3d2a80d3eef6504ddb93fa2466fedaf9de552f68b2f9fe7b0f60bae0b","root":"c188ebd97b87b852127b9c2e6d9b5dec46b41df6e7f7d34389804cf05e1c3097","root_slots":"65536"},{"id":3,"stake":"2000","attest_pk":"0731296b6765f98645a074d172e0038c8c7c07a518647f8657fada53dc8d2b175909da8512dfc691179498d33943eb1614289d77dd66febec92f9f68996e945da22f1aefb0a28592945385da1aec8cec7dd81df849a250314aad02144f8788d703572077cdffe52d3b7c7cee2232c8e89367584a288c165ba97d7e6e9dbc78ddfb5b6f329d4b4aad1768e7e8f134d0a872337eeed6ef7286a6e232b0dfd999e40253e58cea9d739b2aa4ede3f99c0dadcf7c9832534af4c634ed67bdf758c746a07b7a7921dc4928363176e5b4b6aba1cc4c5f2f0a343e3d2c8243c9ef8f59ca4311fb08b0c8b1a9727577846daacace84cff61f64daad6f46bf93d3a39fc3d1ccf38b920eda104989412c4406ba091e4c7a9e849c457d7745f4c635a1f3e8af362fb07e820ad5504b672a6a7bfb751f42308ba6f7598d358b6b8def605949d095e7355e795de40042c24e72f0bc0c4ea428ab12bf047516f3a2fc82c0580bc134ed00ece9e4f808bea40a9c7e66529013f3977193da5ee9e511ed87428a03f5ca74a7f1eca30f45797eedcd9610a594f286fed11cb9b3f641c8fdf3e0a4d7348643bdb13bff902663e54fe2f888f96ddfa8f530f70561623c0f8a69f48cbca416885081a6341808e6d333a1a644c4cf0566c43e2d18ccb4f613d89a7b2f452535bce930bd079e4d91c13970aade5fcf14f5740d56e596a456b6dead0ff470cc39597912c7c6575e538ac3f9552a79858c10c16f58c49b947e3cc8dd8d9b1eb99f74fa121b2141a50bea2d229cf680aae40fcbc559104213d54a8c75dfc2865b36ad685ba4161833f741dbd21f06b81a5198d3f28fb2ae03d04362dfc45603a6dafb1bc6b3e3b02595fe41fa976ee73f6ec89f536a3472cbc68c24441e363b70faa3abd5c025404c10e9f50d7a2449fef6435ffd1b9c9e65248d676b528b87ceffa8f8626a50b6ab30608dd9e28ec6aa051d6cffb95b603c967477a1307aeeb3f925e692b9f39ef39d48eef6f90504f2402360bb8dcbf6d43e2151ee4932a5096dffd6d4b37d42594a18c35bb6bdfdf309914d5f5a0036fd467fdc288c83aab3eb475e8a6533b511d7048fbbda6158da29bfe895e269ae693feb99ea0fa673f3fe559a783ae5ee09f85f21eb3d0bafb7723838a58c306c42219ebeb346d6e7f97528dd3b7c5ae65cdeaa91599a686ea5f1d97ec21478c5a7ed3108601ec4c0276515fbb8f7305745cbe97b9ead36583cb1ffc74d6b93945a2371cbfdf53f40252c1f00dff99f0334733f79455cccdeaa023772e51f5ebc914c17ae7d55a62366d19ae0de821c2066130e58868a2ff80b7b654aa9e70e7fb31a3167b61dfb3255ab3d30bfa78bc29f9a2881e12ef95ece96033e6dc14586ac41f7738352d642c354a258bee17b744826e39e63bdc07a9c51958f0a1b7dde05abbf7689f7ca9a8bdf992e4d589604fcad08b49adc39e54c84ed8ac684bf1f2637bb036579d2905b1c520fb5f397416411dbb7c55dc9e412db07a03b9b656cb11b5fb8c75425f73f80019a3f6aa654f4662dc5e5f7b83dd0e9d80c0dd07e87b6a2091b5fd07b9eeaf24d6ba9392ab17ac86ce45a48484f2db15401fd7e460c26381bea198dea9aeba97ae6a882cd3fa64a85ca2444a8b6f69baf1bc209caada9861811095013a0b92278f3b7d9eeb66ece1e48a56c5a132b5df9c969d77dbb8cf6250f386a00212933973fe5938de2e730c4e398b0991b783159822e023b70679342cbbb923204c401f7b2b15bf3c4e0cafa3fa7627c3bda501a1e1d6591d0e166897aa8a82c5a80196c3d50baf346f98757bc4aa22736c20d870803f53692af98b76597b12b418df60904943733781a9e83b35b9939e59400d18cf59709384e8e8142f70db70cca63a5975e33a655b44ac211b4352509ec3fc15e08b216701842305a6f9fa6737552d37c600a08a61bb08d51eb9115e04915fa0bee5b61a34dfb75d8124404ed43c7743dcbd0d7c49b4789971491ad61f2c40b6038fd56a470c48cb9f21a2b7f24d20894482a88f88ac949f9fe47727f5402c2e75ce7a7913e5d8d00dbd5d153a545b2e2e209d0693ac91d1f253d342759077cd8cec801ac8c1e49b283733c6368fe64cfe817c7d188deb7e0216a65a6045f473bc392b862161a758a8f5e9479415e718001e23c8315702264bb5d71553df2d1ea5dd737b215aed496738dfe1d52f2662839ff1431bc7442495aefc9e88496cd4c9d54bc6b810555e3c9edb2ae27a5cccc822d600ab05271c165878c5b273504135bc9002b14e708df815269e6e8e08b60523cf31a2e3cfd60d424ba587ff1f80b6bb98871de006d1492a428cca520720daabef4f6ed088a94ff75cb5907b40b51706d202c4fe716630cf02470df11a5c84b974392472915c166d2b565f19c91f99747de93d96efbc568fc58e219849d1a4272c7c122b6b43dc000873350150b91c58ea7149d3a14496b83aa3923a27d84365905318d1cdd4b214ff67cd6d0218f913d816fd961cfae79a9982b8844e6ab89e2ba22fc5f8a8cd667bda62fea61aee898242fb402ce3072586eb1782430dad0965076944ea7255a98e33a3f90375e707d7634da9784b206459b360bc4fd7d850223f35e73d8f1de4e8a3142178c337fd4f51bfeee009010aca55f34ff4c6f5db1c8fb6e481fe82f4e4c8f76e70b4a50b76c746c2a99921ef920a4009d36d11737c015c390d267374edf09feb5bf6a3f3d050ed206c272e898cd8650","root":"fb75cb75e0bd10210b647a94be79c703a87e53342497ba866a7fb52e9635d09f","root_slots":"65536"},{"id":4,"stake":"2000","attest_pk":"5437716b212e47d4c3432b700c8deb800a1d3b69667a7200074d2d5bce531ad83ec19d107b27194a1a32784f87bb49ef4718967f914f2d500505a2369f9e4bb36b66ce65e8fe3d98ad43692c3880e550995c02d3b9c6529449f6beacb97b02b8626cb42f2c77c56e47897646d0ee8847ee72d21cbf5e3112c2d3a35a0ce324adf4777ce133183d7948c4fbaffa3a5e48c72f469ff1567e7965126cff239bb8ddfcc855b438aeba2f871b8c84aaa2ebd46483d43d50795b7d468a7b1c94d476ef39858a359093e044cb0aef5ed711f3c7294eaa20dd69ad0b672f33c839fab3f3952b5e2e5a54713e599a60ca9d30d3f172b735842593ef3c3e51daf1e0a5791541513dc3fe400a1301db868a334136d6503fabfd45b00788d937caba3febafe3e47dc50f649cf98ce829e8b347904f06d2b1dc29b174c7477758d3e3d6883afb24aab06e18ea542487e795e7a6284d1ea2ada77c08f1f3de2b5ce7c35c6669e9f16ae0e1e918415b87d679151c2eb70cf7575760b8db2c7fc71d0196a9b7e67ccae7b123177a114f737e269365901ac8bc3b520b41cd2d862b30c1b44cad3b56c2ea5247f0be4fbd235e50c3eadb1eb6a93d14e8fbc41affa9625507f3ef432d27f5437130250894cb36b26c040efbfcb7911d04bee8fe62a57c6cf54892adc83656de677159ad57edb79b9926edcfc385b1addd1e4f2d9af87a53f6ed35c11259ad463d255ee09ed9adf81e8d3ea4c13d1e14eef89c94cfc11d3a9e9017869e311141245d674b5721ba6a7766156a7f0a5bda988c88b726757cf71c8c8357f1e1faec1f647ae1270cf3689bfc7ce522d9e8c191593c15f26d1fde5dd4fed10cfaf3fb33f2e87f6666ae240321bedf3f2016ae730197ac365111a6c8da61b3d74ecd64754f92c7cf50b6554054972f413b4c31af4cb5faa9aa7e9d524a69dff9466e67138b5bf1f5c1d60bed2a77b2db7d079660295dd6973909d1eeba062498a7e60b0691280feeabab8f1914105f323378ac02b7766c4d7e663fa6e7417a4af05631fe2f754b6dc76412b98d466a9e9940cfd5b342c7a02e27ff08beb84b714ff7a83d001e981a51c73a07e1e663f39f623321d1f440604676eb4282e596ed53661695dbf5cf6289513e4ef7d39dfc6914ce77b74795ff60832825c6e2f988c99573ee1f8d99194eb4c1adc03e1336a09c888e69ad0f545e82fd99d3abe0dce6059798f91bd83bdffe94b36ef2858fd8ac38755c3c26baba566bd6a308a5db267a01d8e216d252e310dbbf380e7d7839578de0dcc9e3c4e112d9e1489ca000325c1fb6ccbe94792d07ecc220b842b30f487dec9667c708f4ed496a8dd14fd4b9b9a059bf64917509f78f3e913bb03f8bf52311f7eca46db83aa159781e727d6ba2624cdd86ab558127c6c9a1287c458224a052abf9937351bbf8b45e15514b02d202559db7c9418ec8a2b6d9204e21b80011463fe03ef9e4b4885a962a8027c6e5fa62c32b7018d761f969f3c650a14e9c46ddc658fb8b65f40ce6adc8946017c631c1fd9a42f6bee673d344578c119ceecabd19b27dff1b17c8aa796012cf9a434c323e43a57578cf53a1c2a6423055d6eee2818728b898997cc728cb677023544e57789a2331db08d9b56b103ab7173c506f2dffbd386ce25abc6cf83b83cab5bff4fd7d9d9bf0e92ac8709c7d33ef956d2c10c61d7186543546c9131562e77b43cedfa4f148486d0d2a69f13b7717504b43acc8106c593e3a40361a0ec6383c46d7739a68f79c69a03a27277ba2d97905570ea41bc369f9fce0a563cd1f020ae5dc56d9cbc6f0ac0911925bf5e4e679b43df478ac90764f86c27945d157a93f66fc288f50f01d79c3d9bd232fd6b495f2de2b2dcf48dcfa56d8e2ee75e03c7296a74cfdb86756a33a3da0cdb082ab907da645c8557f0cb4b6e6970f0eb3afe26514ab8a5edd034612159eb3ddcc1be0fdd2e0f8c8d20aae6575ee170417b3b56af0dd0921fbc588b2accbcef7965b8d20db8b15cd29c9f5511160b69b9fbe9a69e2d1e45a8f4975516ae8c2e7058546f4f25adeb02a8fbbb522d2e6a4e817d4fee0b2325691a3d694619c0a5c018094040a0a86c36318205cb70da3a608d82cf7715f98f3d1b521d2631a4c42ea0872e06d610419d1cec279b11ec5ee74d9130e73669fd9cde583526df26e75e69bbd010e82a51972b97ee98dbbf2cdbd117fccf4f15f71bbc97388efe9ef0e85bce9d19a71f05947010a0625eec44847b82064e915007a003562b7da7feec75dbba0971db06f4b9cbdac02886b22981109caaed9ef70fbd9eca980b58480ef8b1bd8d50f97a41db6c9c7775888508d0f4e42696845419cafd0d2241a1907cbb6d69f6188dc6d1f90cc9396cb6d987cf228579630e96799093d4947a9be1ff4abea1db03a1a9aaf6fba25678ab2149cf58b5f86780498647fc4c85b802af048a4147453cac1fe530b6bffa56ea0eaf45c3b7d30761597a92c04a6c1b7edadea5751448793dce0ca593632c4df56b5e45ae9770c8ef34afd1b690983ac4fdf21340d8873c66104258bc7c5b58ca4b7d1ab7608f10fddec5b6c1a175b1857cfcb62d390e94f6ee69173648711a4cfbe7638347d374298f41b78d1ea169d7b87c518c1b6ae4f2f149b7ba55052118fbbfbe4ae3b7d70e7b34186c2e9ecb3960c2a1af4dbcb3864cb5e4fc355c16edfe6ba9e331eba490e6ba1324ecfbd8c1ded33621474ee74ef1264acb0840eb2f05e12a5","root":"e38b240826375e145375d0ab02ab96a156600c0aae290cd1870d8a07b6365fb0","root_slots":"65536"}],
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

function singleEndpointNetwork(net) {
  if (!net) return false;
  if (net.singleEndpoint === true) return true;
  const operators = new Set(officialEndpointsOf(net).map((e) => e.operator.trim().toLowerCase()));
  return operators.size < 2;
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
  if (net.singleEndpoint !== undefined && typeof net.singleEndpoint !== 'boolean') throw new Error('singleEndpoint is either true or false');
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

module.exports = { NETWORKS, network, officialEndpointsOf, deepFreeze, checkNetwork, requiresFinality, singleEndpointNetwork, rosterPinned, hostIdentity };
