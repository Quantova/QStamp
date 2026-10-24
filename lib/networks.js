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
    rpc: 'https://q-test-net-01.quantova.org',
    rpcs: [
      { url: 'https://q-test-net-01.quantova.org', operator: 'Quantova Inc' },
    ],
    chainId: 'Q-test-net-01',
    genesis: '5f18d6fbd39e55152cbb3f7986d50cc52e436fe577d5a47307e092a761f6a4c9',
    contract: 'Q1PVRQ8DQ6YYUEDH68QEM3PWT6JC9U9TP95V2QHU2PFDF2ZVNH5NQQRNM92J',
    genesisTime: 1792814502,
    blocks: { minPerSecond: 1, maxPerSecond: 10, stallSeconds: 86400, slack: 240 },
    finality: {
      genesis: '5f18d6fbd39e55152cbb3f7986d50cc52e436fe577d5a47307e092a761f6a4c9',
      checkpoint: { height: 12316, hash: 'e27f1382aa1bc05b26dab66ebba84b8ea4be7e2d6b54eea82069a0e2d9a46b73' },
      epochBlocks: 65536,
      rosters: {
        0: [
        { id: 1, stake: '2000', attest_pk: 'c1c35ae3d1c3df42179499bf7a62be8eeb62137940c3cfab9b7d17cd7d08447f7fe81c8778d8c8368916c7d5199cc5cd3abfa3b6afc36524291b567e0575ed596842c8e64b50d24b3cada01cdd16de14655002451bc3fa97d993e0e33cf42c6d075b765728ae8808883f43112e1ad58c388d1481756ca81c5a59daab415fd52b66dea137731346110295da721031b93ca9c1e27f6714c0e45d54cc5992c81e12ec52c8a03d6697700b334d7946d372c682650d03fe68868b7ad219d4793197d94971a95937bb428e832b53582a6918f20768c298fc47078f5562df57a9c3370994b31f53436d65d18e88acfc567dd6d117b7f850045b345ffb5e98a86949ea22cb81f79b372197882e8b9b5266f585bd8bc3e88fbc581b79bbe45715b1f141ae3594aafc64796d806a201b0d09fbdfa1d597cd968fb18799e3bfd916266b959744ed11b5ea095c6aa81e51075424eec7e613d5ec648b839a150020772ac085ab2b2864f8c81b2cb1afb039e1a632741b61f12ffbbe30633ecbded5cd2579c7e9e114e28295af8db31e471c19b95094098a4a4ae11b7f56d9da34bf7ae3059de0cf9cd2ce12c0b5f8243d935a8e64f97e53652aec34f5a670478e2446bdbca11d08ae822c0ce6752c1382c1e28450254bb22198f0108182f8a69b8a2a555126dccbc46d8b2d190167eb460ed3e1523a0988fb1a3d520e8294fb7066c9e1ebe7b2f9808143c1b55d001cfa066e25b5739a92f9c6c055a5280ac86d0b1461d00dd7a3bdeefc680cd50a5523dfd3462f6b85749047fc0a0a4cd8f82141a78974ad32fb36ff7cf99aee12ae73a82af8e9fa3ba18ac3cbf80dd74f05a8fd7cbe7fb3666f875342fff0af8e7d72027e5fc05ac6808db562240bfd4d0a8026f6009215ba708913c063253dfc88c4836cbff345fadb962d26240565ad32b0448e73fba3263ff8b635ce6e0be149a6725ce42a655fbb1a82aa71415999171840d081e261f0f1f79fc096e1c8085b885e90b9fd4dff233787cc2cc77d7073d8f604b502ece4ab653496c881b60360929f67ccbbfc1835a9aa297f53fc486572c56484024df6db2ee8edd1fa24d58225d3d637332b28479b7c9e4b996a1115e23f80e79091d66c17a9bbaeb4d44eaf2994e24ee5fbed15cea13edb0d80e5044e09185405ebe5fde5f8d3cad9e99ed768453160a290cf23a4df3698139183769ceef6aee316b620a273049c18f6829d0873be343a0c1cce73def0d6a41234395ad5318945d44dd30d36be11777622ec0647114e2e05766fa34af4f0e142ecd28c494363d3078f2cc052837048489cf198bd805ade962994e1b747bdc7449de1d0d8e3a7ced1df626b4529c9e0057dbe46269deb6fdc3f3b74c5d56ac221334bc3eb6205e58e37cbfff4ca2040a8693a71c3b1adbf25833181617baa4d5b8caa6d21bd8ec641c7b42e00d22862fbc907badfd23e359a84093425a6d549f0ac30cc2df01774d07dce587a5c6175cc33bb76def137143b3306819815d13f303679dcb3e784bcf1a07add570c360368011715ea7d75303f3139eefb20a03ad39be25ae5c13481807c9e4f9e6f7b383d09347228c4dd39e82594edf3358e0dd4feaca41215c7c7dba11f9416aeaf8ca0799b1b5926bc633a8a8684472358786320ddfa9a4a25364d1c2cebc85f5ae166f901a5fade8e186634ebbdc82c6eb49c10804ef4787959476831f8d64c607957a48ed13cccfa402159a08e271ff4c010e2ac7707737382f0f3d6c2b4b149113a96d54ff42a546d7ad6d03d22fcf168036c80fdd4bcf2dd7fe8411c3c55e9b8e457fa5a50df4e21d845550dbdccafb7d628e63d46764454c3c34023bccb4b29867ba6d512dd5023fc47cbbdc817883f33de172cada5c94d905158119f265eb826b6db8013d42fde1a1bb77750f0e933d993649d8aff989d7c7cc9c8aa540355f831fb8d72ede3cd70baab864cedd527072cb8b16953ddea49a1fe79bce31fa50046fd79117a11c561edb51f932afc35e4dd19efcd68dec828ad416def8577b855a918b001942c2343750f3ed411115c9fbbcd20007fb2ff65167a17c64c05a8e2781ace6bbf3a22e807a2af364482c776783c87f797ae816a473c995ac691d523901edc82ffa145a23682a1a0dcf739d36201e62de7a3adfa611f624113f50a40b304e6940b2cc3cdce37b86a5d559e01a973b84a65a94f7c80d07d8fbdf5c0c711a20ba2d63fa3eda9b6358adbae672ada996206924f68fee05fc829df892a30984cc6789c740634fb8404a563462fae69730cac24d73cac6c1c3d05cdb2f7bbc9daeede6183f5e28faa0849ba38fdedf59c8b43ad443469467cf9a257b31aba972f0bfb6cbd48efbc6ce36e9e3a55a3a69cb701272a45c19748d17454d1da45d4678107c3431018a79b390743506b7b08d7bcab44abae085c990a66520c7a1dac7164aa7d9d301fedd106c84f0dd84a4a4834bbf2768edf05c1d5460fdb625b26fe3c3436288d8d5ed426dd96d1ef04a6774a7e7b90ccdda89a88926093e476ca6c3927442b9995cae358d9b29c3249653c7aadd8f0b51b2c63e8266d0fcb45767a779d84369060480665d220a589247467f2517ea4e12f5065d8f192e53177572295119c0f9bf41955be124649b795f226e0970948aff3ad632dc823e462d8a0092241ef488d5969ae187df7bb2aeb116d065fe8d8aa5b8d48ecc2ef536964fe0063ef0841d6d36ea61471bb759c1ddf4f92e3103a186703', root: 'ab84d6c588acd2b54f2332842ce8271e3af11d377b01bc0e027167da44f142f5', root_slots: '65536' },
        { id: 2, stake: '2000', attest_pk: '6244fdddeefdcdcdf639a8014f74c50b9b0f9f4f043c8117ad08b9e7fc07bb5596c45e1cee7b6439915d8a8fac32aefe514a60a1e6161f1b73add441153041f45c8f09d659a3d545fe977178a8ea430071eb8c7c6c2f76e4606b3018aff51d97d26c410c5294827b6e82a5a44f122002e2b3d99c242d3a6086cc85bce38c0351641f3efad04d6f3967104fcf4e2a35fb09080da449a41acffc018579d4738f5bb7f565759ab05782fc44fa09233b7f935c76b638043345395c8afc47851cdb0d8473b2958039db950eb05549318a0e3ffd96276f88db68b260d7da9cbd9336b7a089adf805ed30d0588ba3312aef241e53d9133bb034c29c27b7e729f3f7f74e5bcee7e153c1dc1a4612bf9d7baeca48343458c9c99b0df3411ebefeb9197f7c6310b20f3f9e44545646bbb4d44d09693af83ac63616a36f923a7c91245dc35205aa675b2f881a9a5c9a2d3d685826c346a11c7fb6a9dda627487a2cb4627fe7389fd02ef7af697385dd0660524a7ff35eee195062eb61e0e4e6238127ffe7fbbfea753f7994337967bccb0992dca7274285b50cdae10f24509a15d46978dd9f59965279dbe26300984107943611ebc730f5e106c53afeed37761ecf470c8a0ff11bc40650546130eb8b61e38b9c29af83474c368067935a07b92ad50eb8ea2c0e6ebb5014cb3a1a7ae308ab350fdf0a92a9e68d0de1175b50608fac20241da43de1583fbaee14ce1c7538c631723200f56cf7bdcd8875ad8c7a9d4556f9d4f377fae0d745edadece98fbdf8706f9fa732a8e11ddfb4b5cf6f060bbe4b59fab36ec5c3aa5986b0f851604a6f1c653b4e47aa2af233d322a39fe65b68d0f46a1438c426f03dcff64e5fc43cd4ffb45bd2bd1b2dce8faada7ba3c055a857ddbbdfa22888805e2297470c79f94cb2871d914dab6e8a4afa38d01c04ffcef6fa5e932f2a2b6018847e6db663c43889c79566e876db2e71ae74bf8e538357d3b681d0d3235ada99d18da8b97b9cd3456ba878ccbb0784c2c6142df22a7b970ff2e8055198ffc76eab77c8156cd61b755cb45827be04979e6de15b11cf58b97af370673cb095c888a44dbbf8e9f6f1816cac1c57bf73833483825fc19dd47fa0e1f1f8dda537546558519123fb2e87fd3067107cd503f93e95ad03708cdaef39d2cf6b8bb3924b0eb898eab48b1ce1087e905f94d4dc4512f9bc5162aa245a0d9a10bbf41ad963b6ba4a9669a90abac3b07fd75d659703b4d579620e7deb28d31b80cf86c71781dadba8527699febe285c5243389a205cfa325b75381693bf4408e9d7ef55ee80e35878d67abc5a7c5dbb4dda3763b8b02a0a8b9ba93cb5ab4ed90aae110487fbb44757d7d0f040c3ca864ecf1e35430cd8216b11d3a41a327ee4b5ca349f33e138054692214bbf720afc8bb78749c25b59411e3f17cf4088d3a987ac6e45255745e313cac73e909c37f0e7fd8036fb98592884b85826873f6fbe9b04c2f72d02bfa1bcf498ab85cdf787c5c4e653a2ecf65f23743f67d040acf3e321bc6382b4cf5b29b906b39f8b8709ba002f389510f244bdb9631c572fdcc61596b84f1154b5fe4901d72ad93e03b16d761112fc58aab63e334d6dc9cc8e7967ea1cba5979f90bcc52b2c201a615044aa2da85b6d6487f3702afbc45fbd3a5260268cc4203ef454768ed36ca2e1048ce3d8b5a717310a450ec774bc2837eb35fe1a2b922c9506bdbe0668591ca2089bcadc805d098c9a6ede373e73d9d7bec306eae8e379bc831951b94bcccfe2402e2ba4bf1208e704554ea798f668d2f5f6472e3ef3adb2f5ed7e5f851ef93b2f7b898315c0046f33dfab56ed21f2541bb6bd85856a405c2bc8f7df33e3a2a439eb42801a1b1f12d8aee557c535263fab6bc54db84ca3a1e23cb3e1ea14680ff52ade0f1f9f32133a74d1fe67698a71db622628db21f28ef70cba51a41e505e2171ddf573ef08a1040b1b7411f488c5058e30f09805fc485fca574f888c0839264aa7c8515aa70e7cd260e568ce226a94f7cae766e237139f1dffcac26853a26cd72b75944dab7cf0297b1d886ffcd26edf438e6f4f62b33065afc71265c1077e3d083fcbb32906c6346ff536ffdf6c25866f0a8775510e7fd33ca0aab2abe7b880d74e778794603c691b44ca7a285a669dc817a6fad0c315aad77a789808a598372bdfbccb7acc603503c348a25b95001eca0e915bf67e961ae5af305cbed6b5bd37ea027be6437537efb063b932256860f006575559ce59714163531c02a86dd10f92a86d80b997440f44218f4274af058d3a186313428406fd3ad44d25dac9962a3a0ebdff780be5c526da6b7d9b2a66d4793c6b9f223176a7b0a5c9049f9fe1e9c178b4b98ccb34bd067c772d41ae7f5b4c2b78b9114738f53c3eaa17deec656bb35c78de9b81a1965b3a6a451cdb1f0fb851fc888ce9bc828a0f1523856c0ab35ef00de7c2bcb3967cd6c0ebbfc93a7cafdad2f7182507eb526d943a987ad4459322138fbfcbbb30297c4cfe5b5e634280a3c7426b172c0e30e4f59ad55621b8f31add7853356c9e7303193781dc1adea7cb8621e3a00f178f73736d54f96d54dc172666a0cc2af39028a37ef4e15be4724b4ee99ef19be46af07fe5cb63cf194cacef7a0bd9ca518c6b3f0bcae5baf6cb0e69353e255d0b8bf80a4af7ac83fd5635281731c6048b2e449a93417911d6c53f5b50fd840fad0a09b356124e88c62c84c6b6c1deee215e6b9e6408314bea2', root: '9d54fb18c951803d14346b5ee3bb31a5886f11401128d38ae13c42c604f309c7', root_slots: '65536' },
        { id: 3, stake: '2000', attest_pk: '46bd26657b35efe6c4296e25392d917381dcbd1057d40900353458e3562796e92fc9209fc80cc52606f7231c04223b0823054e76a2d4158b05aefb379edf83b461a38b44fee4556c1f1ba4cdfc8260e833f2629f3f017d12558cf11c602f42c04dfd33011e3e787e4bc587298ad0bc35d6f92b3dda088dd92fa01246ad2ddd75a90cf4bfb6db3f0dde917b380ae2b5f82e14db9b760f5157853c3386dcca827986ae1df9c8e2ad865f71326116fc568585267369a823d0c78fcdf5029511670244fd3cda6ba21ce5b9be218ae5178444f8f5161d9b3451f1fcae43785dfb87a22f933ed84644f43f0f3ba4e2927c3fd4ec6a4d7047a82398a7d6a2395195cd38a3ffb6d52f004616d14df42ba3bf478d5ecaa797950f4c04b97ef7e8850fa8b3f578f979f5764d174a33809188ae1dcf16349e16613338c7a4f8aa045f10da9c15192fadc3af4d1915b85d0a59036d372102f82e5ce75c239ea3a65460a098c729271103fff9e7a73ba92b76a94068c00622d09a75659324b13d854d9800e921624457c26a016f01299b4e0c974b04352d2d79e7f88b7d4be92fbdf1bc58054ef46a3201aa23d1d58c6baefb436793b6193e434758e52b7f51ca9cc1c36baed9a2bf872391b9cf8bffd1be9042e0731b196d20469dfebbf321ff6decc8b0b36f87128653d88806dd21644829b5fa16ac7949d70c76c38afc76178bec82a09757f1e5b9082e21355341ff87d12d795746fe8aa41fa2d98d3c7947c52fbe11869ee668ccebaa64cb24f5c089123365444f70f728829ae7a15b894859cf700a0f2f536924958d217df2a60ab79a4080c2c592b72a34f3fe49450e7130a502a48f540aedf2f169d686d0a170491842b6866bf4b670ac6dc5259df2718b24e228fd90c2ea3d4c88e61b370db2b44a753eb3d2d0c814902a6fba27eb6ff37fc5246fb9755b31412ebe4607bf7328335620a2247adb9ef0892e7bb10c5b267c0fed2ec487011a0125f3dd11dfd33f2d4cfae6822a8b57a31db49c58ef782c4403250bb7231d40e89115b37c024c315ec80f75ddaa8292be0a45bc21a43bd9caf065401a4e866f6cfaf36a6f4c22f252c39bccc44485fe106b9f04f22770a0516e928324618ce7d6c4e889e86716dc1bf7eaa973b3df4eada89021b5ca6374934376f0e07ecfc9168928a5ebd79e41e7e2a2272309b0dd355f994967742d7af595a525725d84e93e017885c4d2ec2eb608b9a92d5abc6edd22678f243b3cb0fb1955e867f54f5495973da73b98cb83f0e2720415d7fb25517ae5586cb8f948fcfc0cdcc66cdeb5897b1201eddfd454782d28388e6afd79e89ff34a3073bbda44fe3cf864059b66e509729ee941aa5ea03b3e5fa76eb630d26ed5f3c7ac0adf63b5d313837f6f0944ff9a1bc6f87f3e581797ccebaa958a37af704415f06d821dd2e53775f36ed72018a46361347632fd7bd324e6463ea5c6e1ee9eee29ca4a8ed828d6a48f4e99bbf249c31132d1cbad7a162b835af58955afde8dcd929774328fbbaf9cc60e0ffaef3d288d72a12a311c3fa155892890b939435b8eb463bf7b2c53090f45445ff904ba2fa9ca83f20c3603cad7033696c1e0b1356a6d6cc1ae3d74099609118ca8d1187b14da7076a9362d5eba5a000512023d15dd77b184360b6313e5cae5b715658283f3a88394aeaa9990aa36158e6ee10a140aa0b7a963a704d7b6e60981d65ee23e45c7b35c645e7c9658e530922028e3e4ef4f21c31874e218fadeaeb8684ffdd25f50e19a3eea2b494b3ce6b1e5df30b8adc1ea86f272eb380b5b2f89697b299a15453e6ebd107f00d73d6af891a2f127408253b6ff6c0543d6490a08165ea3be06bcae3a4df03e9545ed08f25c702cbdbaf1b3f20669509e44993aec7c5ffc005e814060c343980b20c24f222b6ea3e33063c6aec253ca811ba4d175c191fcc95de60a9c80700ec800f2dd473c834a17418dc44a7b12f68a65b92935ee52a7a77c1f7653e2c38584d02e9f296fbd276e295b583f021f053539ab3b93972974f0e01c6cfc8a3ac25057da8bd04801a677e03fc8d6d11f08fb09cb40f945e16fafa9b117cbbc2ae6e57bdfe353807a885d7bdb2a5830e8ba9f13b3e1c321c579ad7138b787e193965dadf53ce171839bc04911cd170632489c7de2bb5d0fc9deda3e21b70b86687572ae535706d87e1c2b3c6d41fd4969f63eab5f4c2ec466826fc2618a6ca18bedf39f5e84e18f5449abba58e478b624d46434303b71ac608f74ba6e14f57237fb720b2b4509f0629a18890151d6b7918425ce541a14143a2d5831db4d502c9074c53872bc78bd21a8435f93ea06d6db39755ba36ecddc851c06cc022ff56279113102fa4e397058463008f8fcf89e282721876784b0a6459ff84df0f612543b021cf2f9adaef9d03402bf1513c8ab7e49244295aea74a743be2970d26be822f27659925ffb30ac437afd5fa6638b0ae0f254ca2eebb1bf3c7060452a886f8998c53f237010970f36e5275caa05ee0fc290b62c8c1b8cfaf90e1728ef88033bafb0115c52de599590911c58f023be122943bd7e5866b1eb91305dd8440cd3f2d0ae30a6c4493318571d3ca34dee72c433202299ff5861a7892801f1c68301414aeec37a1e7c8f23970bc26989f7a1505dd1294114e40a67f5d4f97edab56bd04de1fd3458e07f67663f05b02fa4e2531bef62809e2e5e4d44db47e4918e8080d656f9c93bada1cd7f62ae401e54c4ae8c6287c', root: 'e7a17d798fc9e918ef0253c7573f0aeebf7cef85db0bf873c7a44979dfb6eb54', root_slots: '65536' },
        { id: 4, stake: '2000', attest_pk: 'b48da3cdf75fff26fb6cd140b818dd3427454ed2406d104f20f4468a051401e327aa6bf515e81151fb3fef23161d6ddee85abf38132581283ed7cef7447fa8a8451e065732f9091be35ece9104f61e78011e63deb443fb7b5242a57b5c12789f8092a07df993bcbf49e8ca0e5b7b353a9271606cfc3c98ba874545760859760e6c4ec36a2c1617346b42db859c7bd5a7157908022982b0ac5236a077b912abcffd351d08597e358d69a218b8172f625eb5d91b5583d5c68882233015911e161e7052db157442793b6e57f67dbe95519ac807243001751d5f587e6bec874b192aba38ec8049fa97d520e8ee18c27619bca99dd9b52e524d846f58d1c76d1fa87e230e0c11b8211e1309e428683bb530448daece55411de0ac02b9c12571b93ddbd418511b3017441440b5ddb5af1288da252571b53597b8b123f858eadab855aa10702dafb64171d9293c2221a03992e0eaf03cf95218fcd41754b2f3c486ff44a413f4b3e830f2b06ce9bc532dfa9901584a6498f16a30e1136754d4bd08318d82d14c8ab1e04338a6e8c41a832e7d521958d0691756e32787b3bd12e6ada4ca910e88881de8f23e13d074385590c60453ca92de4a7acc8805ecfac6843c540536f56701e70d7e67f621436ebfa91d5e5153462de78bbece284cfe6ed99e080194d03c5113d43f9a17abe3296face0b8ee371dadfa86d49e11ee2f7138e888960bc00fdf262c4f747f72793c1f8bdb95adb75ad3509bc4d3e3b62004b489fef82fb60f723947b8c9d72554b5dd1517655222db0cc5890af223502022f46a86906ea67213d87b1173412b9724ba2ee3686ad32fdfb1c443fe91e94917bee18a9e2a49d326d2f05290c4f51706e39b9bfa4fad2d98873ddd18d9b92b5107870e4d47e19f82605b16a1a52c607bbebf37587b5a25863040be53badf7db4824d5eacf7568755699b5431104cab68dab1f2b0b676ccde15232324335188669a5af742d5c115c926244f17baa275edbba73d4d8fcbfb59e984e1112050c983f223e18569898fa508bbe4f335ed309e940e1008708b5e8816f4a8c699a96a563574e99175ef23625912dc9d1d80a109c57580fd0a30efd9d26af4fab90ed768f3f9da78ffb59e1dc2e04ae72b5ca042b9248e5da85b7e5b41c6a04dddb9aedc8ea6496ded81d135bc7a435e96962aefd5d98f3498516a91f78ebc5093786d340d172d1d6a0b780046d5b9a68c74c94fd2a782661037ec277950b6d4df051ffca18bdfde11f4fd20d8e22bf494e23ddc21191706e1b095c91cac0b2788d7c66cb264f4ee2aed7c3e88c1a589de453fe081bba5a77cbc69e189b2ded6316ff7ba85d5839c5e3e9e1f3c83efc31829b5af9a301708dd753779ec608478c4bec0ea58a41fedada4260f377346dbb3943ea008139d71860d04011ed4b7fdd4e65131c641add8f4d28d35feaacd1a866acf63131f41375b67e69732366239bbe098d1fbe354e93819e24dc1a16386e007235d7f553d45ee5b1472fe601b4db95c487670382f5e46d9f9b0826a868788143ef57850a797d01e209483330d6868729de9e61e71797715630328c6dc8042f13cf101d234449764e615ce62cd0cafc68102c4597639206eb72aca9e55e92a68025c29584818f6bf9d3dc0def157e45d0edc961fe0ae819bd55a4280595e4eab5f70e0ca4fe54e9f544cb844015e844b8bec46a1fdd80e10117c10486d8409fbd49ea1a0c3a538323c5337c3583bcd6b54a0b016f8561807d4fb1965429dbe178dad35fd75a4c4261e3a0f3b6474a8df74bec71c2e5000970134f7391d9ca4b6594cf3eb7b7c934abcb51ecf1c66c0038f3b5f02fc85ed4941adc9895a6681fd2e33af277a244ae1a0727fa646bd20ac711ba1567aea888a86be678bb7465c5ffb8d87df41e1908a98ef839db2c84c25de834614aa746b3b3cb7f13adb92e55ffa3d874dffb3aaffca6eb97efa493238e0069ea9863233b86d06e9c5aab1da2614005f33b97d1a95500268cfc46f8f005a49ee28baf9135784e0fb4b14c6a0a9a977c2ffc0d16eb54836b4b2e6c6661d40778bc4f80a88e5441a4a958c46d1da0c6f3131e7e5c74507e1fa3a7f50f4f227247167b34904f0a2afec59ed221fee8716dc6aa02946f0218cef95f53ad545d3bae38dd465d6680cca05050dcc14b452ef1f78a58138dbf004d1ef515d43b1b3c8e951fcf9cce6257f114fe27dbf011dab0eade7182bdf8d9890f8ecf630f3a4d8b983000d6eab966d0f2eb1f6a28d150322901d921b24108c7fd0e075c8bf86c0571c42c2586c11c8f7c0aeb3b0afc7f01bfedc8ca46e0839b388d580c54770c40c815a7b298571880478c5704f1e149bea3d707bbaea9d96c7b4d47a08268836afd57bfc42d66b94c8ec0d6f1023d2cc0879a69e4673bdcc8cdd9e4e46ce22f0091ce5e0b063dc24a55e1b2ebfb8905868885f4ca3be553d9c90a6ac6fe146f21e7e4dba808ca6d2ba7ce9d017e728dee905ad78bf9a55070882be50b7f908f6df1128d7d6014aac186ede2d9591007615303d6adbbd6ca14567e4bbb375f9f0ee05cdc1fab2355175d1f18d0c40922b72525156f99c2309c891ef3fabc772cdc5306c201f0850a14046f6922e493431401284cd907611f62d65f02cb57fd53a89ecfa5b503852398c1952c44405504d54b22f298e393ee6cbb5890d99fe9e6edbb5ad5a78bf737ed90a6fe4bbd5d22160ec06be2a680dddfd1dcf7a7abbad2ea8185d87', root: '1528eaf0f52f2166aa5c34be011f6f405d237236001cd3be13290cb1f4920e7d', root_slots: '65536' },
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
