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
    rpc: 'https://q-testnet-1.quantova.org',
    rpcs: [
      { url: 'https://q-testnet-1.quantova.org', operator: 'Quantova Inc' },
    ],
    chainId: 'Q-TestNet-1',
    genesis: 'de409ca7204b36f68f4a8a32e8476df0ee079919600af499c0c8dd3cc69161ad',
    contract: 'Q1N2U8M3DE95EKVSJRGQ29PZNNL56J53FK76VFJL3KRLNLM32EZASQ2SQTL6',
    genesisTime: 1793182901,
    blocks: { minPerSecond: 1, maxPerSecond: 10, stallSeconds: 86400, slack: 240 },
    finality: {
      genesis: 'de409ca7204b36f68f4a8a32e8476df0ee079919600af499c0c8dd3cc69161ad',
      checkpoint: { height: 18000, hash: 'bb6e4fc3798b9d248dedcf025d972e3ce4c556cc1d8c9eba5be03fc2bd09628f' },
      epochBlocks: 65536,
      rosters: {
        0: [{"id":1,"stake":"2000","attest_pk":"e5f8a495a806b6fe6b8c1576972b20cabbdea9f9420cce4d9551e460928b7ddc1fa675507356da7457cb4f454a8b889d24eb4442086b3bc44c22723d920415657a4034130c59dd939709f275034af6c7c407d567dacc0b15c7a5eec7aebe6936162e172d340f87679c77e7b26b08c9baf13d4d5195e147eac8b5e6e317704a15ba3f344bf8dd7c2025b76120f90a715e34f24e7bb33b0acfdd03951a3b583d24f426a8b74194169f88e581c7cada0fddabde28da5ac2f03ca59f9fa23a722614a4b7f5420ea775d2dd1822e3555958e580400864bff6f5de40aa38202776560746e92edd2fda2a431976e3f084a031a252b04e7dea653dffa19f102cc867649eaaeb83c34f0f36b6b41f9f4764c2e599ba28c953dc0c4ecb9012872760668b71c95dcf42f844d6c8b19d63ba3b2cbb64f6a60a1df7e05468420c8eeb05570245a8d3e0158b73799adad7f4316d3a1cabfd47a9d3acd670f675108783a5d9ce0abffb7fe651548a0e49108871644f90c18af0e97254536dd00c575199d6f537bd67e952f1547bb6ff837afb012ea8f516d73f81f6be02f3b2de4108d0056b19199fa1bb6ff069d909c0477a459aa4c084d5bd8d8c365e02b3e5dd454fcceeb13d57e6f7f7db5a50e956f6bcdf5b6de09775e27f3a6f026cce107458a2a08fc3db24bfef7799bf7a86baee2a1fc417cfb37ff8325fd67d0790b01dc94a13e15867d50b4ba6d805071d3b067503cba574a1227dded9fa8c1f5e1070a5153a59a4f68e4090de310b367452c005c0b37eab9566e1969d300ad3e6f0024270f7c9ee523ba164df4b2621ec53cbfb763fd387b87b870d744192acb51353ad4733c2eae779f9366b4658407e41d8edfbe8ff595ed1466f20e85f99fa298599096ed35a89239a4ad6b5c0c3b63ce0208b95cf72ce6be56fec434022789f2b80c98470e42ab4eec465700d6c101add73d9c3a91e4ec2095ed86c815c8beae82a4edf5f8fe80cc632e11a62b35cd4289d6014fe56238d41be903320b357bca6acc8a7b0c4e04e006a814219c12183481706f6e2c962c650d3b37d2ca1c5539fd2debb3d981f3083fce8d36c53b0828006d5ede5b4cc7b6599a7f8ae41125be6f1b6cbd730e62d38c15ad75454e9b5bc584a86f4254b7f0c627935caf03f0718d72898ee8c01c7ccbd4a79d661f93d78cfc4ea06adafe41e72e5bc77c54a6f3d883a9c94145935b126e619cb6d21725ed829c9de5efda7dc78ba0c0bc6c27aa4bfa7b64cbb943847e6460f20742dfd05e84f9b6749913cbf90de71869dd7b969b37660a863f441df300d79a2fa30b8407e88ad6347eecb98ad981672e01393b847a0f6b6b9e8cf12c6afe80cbf20e1d5f5da967f670e9c305b4c79c5f0268bc1e7ac6202eeca3400f79b8945ee2a473b0c9b801dd42ab46a44d33ccb0b9dbcad73e2b26a75e9d6eefc442875d741db6c1deed84149ffc1c9656eef29291b11c8c34086883e2f8aacac9bd7db7f036ef8d85f8dea237b0bc9d3eaaac58b19713dcd21f0cd0c6199eb2f898185d4fd6a901321a4285cb09960494c752c35c61166651c0f3f681eb53652fbe38b12292633d002f0fbbefe2d660486336da71357253cecbe9453d7a2987303e287510bfefad499549db2d2b5c1554622196073f11d2ba46333c285a70ae658f89132929fe60509070e817599bcc27ea5c5832b5d31ab756fb777cfc0143a73b3f380af91870972bf3b4be1e656b4bf46d84eb0d9845d3ec0f173c06429c1dba4dd300b7bf0ae7ab5fb85eb6505a632cc98967b43359f161f06b37e4e25212b9b0d362f3f2d1d50020e6d01d6bf057bfac53c486c084325a3fc7e1515d49ac5d20de21315769cd59a746637d9ff83003a949b02df8684cc12035bd84a7e76694cf80afb11e3f4695e763b72bbaaf8b760ab54c66445a574951e9188e8b85c7a12247c6c713c87784828152ef035582e3a2eb342a5fd5e40ddf001f07590fc5a1a683a7f7794069245785b4ab4f1b44990e85bcd1d1ebe180a30072e53354f8abc7a478361717b25750acc5b1af2e9e18a5f024be610b69b3b34353f952f8f24a8ab08e812bca497d20a4ce4661781162bc6a466b7997e3db0894aacdbfb9666180b6091d4ff42d3d3a9d6d9171ad9ab20af7ed805259801e7a7895a330123096e08296877ab5066c107f812373cd732ce4997cbec7e3d063ddda9310609a7d3cdf02b3b2ce2f7b50956dbd026054e10a73b9a49359c8eaf45af9cfd82038b8455634b5141029349a0b562876707be7f06b293646e1fcebb67c7a552f391ce0de2d26f98f966612ab3481736991faa3110ed7b93e2eded993daa191a69ea246bfbafb1e17ca4fe77b5cc07d89b5c77c75d4463be9a924fbd85dd796f6fe6d103495f1aec6d46dad7269b779a1af70b0f49f6015fb14645f4f9b712e4598d77d7add754d8328dc7e56c77ad60b68e4289a396effb06cda58a4d656ffbd58628d64ce2b0a31c1ec6ab10d20887a7d9051c2838e64dc6c45398dcde28817c60fe1f0cd078069816a1d7879013afbba5aed11bc2c20b8baa1b32398359fe558f782838dc1e3d5733626b45e315c1dfabcb4a5ce0483daa0c17317bbd5beb94487eff232d52a677177774db0764764b9e56263a5c21b476538446ee2fe89fd14e36a3a600970652b397e062865ced32021600b3b36e4e0a545efbf9a97ef7da63b98157a12df74b816c8e3537edb9fb33071f03bccb7be13006ce6c1588bd","root":"8f6e357ff3eb2e9d40253056730320f7f33959a9f661d0ba0a3623bb598c1813","root_slots":"65536"},{"id":2,"stake":"2000","attest_pk":"f71a16db2ace806c0fd69c1f02b629fb2e144705e58fa0095a11232d62e27210a9aed3e1d5fb470e31b91764864c9761470afc19bf7bacf32029e0935016ac018cd021023e68fdfe6d90abcc2867d3d31e939385c3162a9027918e1b7d0bc6076db88c3be9c39c588dccec0be825dc2b9da47675d58a93192767b30ece35d5e7f0826ffdb5e46833b060d5c14a7f67f24a8782cdec469f129a702be7def2d479e5ee8031ba09afe3853928c82059f09e3951dcfd25786d5148b0409658056d8a7209a4f788f6fbf52c1f18e08e5a8af0b264920c5755c18a7d5de58725421c1aa3a1efdab24a2efe71fc966257f5f04532b6a9d4efe41a977bc48d0d552a24dd835815d3f4e7dea85b099528c297a9bd0736679444a6c20b0e0adb9286e5d505f4e25853daa134e338e13290432b6f4862da8a519bf7966170071b480d5bcf0529729883722ac56e7199e3c797dd802f4093ee0397b78bcfea2ae3a95d0b3b781dc9e9aa928fb2b373ede136622720036a345c08b09333160f6cea41782058cb6bd37f30e1bdec818860ada6edebf001fb3fee81ddb45384d346797fba8f8a3f984bd83187d7f252f5c04381ac1cd63e5b2f41ff4733fd95a1d9320b28580baf65e09a58dfd7518e9348f9efcb3cf78a9bf1497dfd85b611140596721dc440d139996df88bc075b4a7dd8bb85e0464ecdd3e7fa4b5935fe7c3f49e511bae4f63b694ebaacd098c5eb7eb04adadb867ee117861720db9d9f2739706d5aeeaa9f8e2682cd8770305969acf2ab707e93f072dbc2abe557ab3c642454effbfa72047ea878ba611bbede2012a38360d678b39b0365e83432b5574efbd07c8cad586963c0b39379aab53fe026eca81d4749d688495eef627789b15d09748d88f4a81dde1346d3658b209474c13532c3eb2bfbbfce80c81c5f98d473e01175481cdd8bfd59c0ef1566fbae0e3ce0dbd34b5266ce49878df1f3338d1be574c1aa8a4847d34f801ee3f510d5615626d0aa6fcbc706ab942b6fda2fe04e767b705d62e85df26803311bcd143489c6093cd2215febcf95e3fb64b520e7c3a5bc24cac099b56e923b5f172a9f9d60dc3f3184aff457deb18365b4554837ab5c1b906761b49c485a703ec93bca3bfdeab7a32651dcefa736e663fc5aa77693cf416d90498bed96a223eefd5cb6a79e88d88bb4c357ddd6378cc3f1f468269b7ad5f6af7aee91d7cb940b53a5bc651228dd06f04000e14106f3d323fc5373920a7334d26f5a96e3a8131eae791793cc424179b2ac65cc8549286978067f6173c5628378d8a70209e48e803493b66f1085a1a3ec7af4a30eb24adf979ab0aaad72949a3d131109e7ddaf2d5029cecc8c5ced433c04d9a9c97b9aee0c4c8da32f1e4541ee5f2d70446d844807434c349ad6babae9ad3000f6878aad171ddd639f0ed25367e5ab405ede64c1947d9f3f8b69f99ebf99482e153618b564a31bc2558de3e2aa07fc8a62181699097453963062553e333edb56b252bcbf42cf5ebe24bc4ce83b27e8fb8de43c37b73772e8baa385d08ece97d857ac050e7429c693d9665eaa8abd56333622949f3a620396b6280b1b2ea11d7dd16b53fb39d68fa78b509754ceaf25a82fe211890c108f96ee3fa681991992dcbc0958c08fa8207458cb70c3e4c1ba144828a9ec592e20971d9449612ffe06b31fae118ec4b8d4876aefad3e968510057064707834a194f1c0e28e900e1ba0d5e87fd37c671ac4824527ac018af73d316cdb4ce0936ad0ae88c5c23e21732da2f583cc8d79b2e57053b1907d0a40a5e14d0c41772684c2f80ca24b4ca9dc520321e8b4c39b8abfcc86a0064c635d90b8a5dce1152a124ec6ea2b87be17077605f983dedd994c9e38148d00015a979d058570077570c304ab21561d4475f9fa8b6498abd0c30a56e0d984e47a949e54332c21b4523888d53b3ea7f3a152865a7f2c8b0e3060bb74216c22447a75b739b738a005461d1c748fc87852525357fc14ade68b7ed69115febfa5870249067d823c7fe1067bf31b764766ef0c3ea24c0ffd267170127f78a66bd12c15f70dc646b986a15b3ff28e39282437eef7ad06fd42a3e4c555e1477acd7bc331bcb363d397ce54ef2ee13592b29b66ed01c316299bb3e5fa5bcc1476d972c6bc15e5a3be6d231fac11283bdaa940b66bafd5d07d424de7a046c94df5f22453562fb2f2986964c60abe8082edda9e8dc80c9616a96e03412f4c205a0fed7ff7bcdcbcea27df78da6b2e40d914234e807ab81a6dbcf443d058f4848b7187b2da9cb4b66c446586fc0e07ffb323dd563bf2c5f6510ce92f0d041dd3c0bbfcad502b181432f164fe4255c581434df843087e5479b60a75a56634adc72ca96e3b702744e54f3c5d30d2cfde0ac1ebf4590a41d8c8ed570cb1335d2c567a748c92d97eadf3029e37b20312deee760fa9a535ede3414f3ce60398886210cf774700dff39544504287000f843358c626df4c4227c07c57d06637ec23c1af926399caeca2710c2af8e34ad080e8230b142249a3cb0ca127d1b7f8e2ccfb0b8d712d1138bb393269315166d404433b25cd7415d0ea3a8eb819cfafbb17685287d745837d04ccd67b24de95b8c86f96d7a16022cc99daff3bd1a624da5e547d9c9d65d5b332787fcbc1917b465441b3fd29110a13c004b097455f6e7f4c1e0d113c6614115e56424211e81894b005e2f79b089b4fec933ab8d1b19b88f7ceb39ffd6b93d0b12ce31af4f","root":"939e7095a0301f50468fd65cc2f6cbf5a3340e6cd59d363ed28d077bb253186b","root_slots":"65536"},{"id":3,"stake":"2000","attest_pk":"250a80f91e78682728e5487cc2deb22a8f42b02a6ad8406803be8198f9591dbb039f68943e1e51c8b4b1f847d64e3dc7d415a0ad52e17965315c2b9ec1b9a6f995d4348237c45c85506cdc43a9682dbbaa3a7c13adbdf8560ff574f470f92260377919c9185bda27baa08e3fb62eddf209abcd6095658a31e4352908702f4c660643e48a921e7662bbbdf99f3d6e55b30c2ad03f9319b9c237a7803df6be032c0324a59bbe38c2decdac3e52b76cdb4d4918d90ee274a30e628981067156fcc5c32a8370c63ac4e7f83b27edf740758de5322e5cf41d534282bf0a3b3a7d43212611689ef81c748a181722320c5ef474fa6f21b9e6e4de765a3d45a70fd6a620e86e15129b14a7b554ac9ba139e36364c85f6ac5e8f18441e806e1021f4312b7b650021a52d9c5ec1a83c0095c6e7786ade026891525d5c058ff4589582838ebfa69daaec2e70a49f5e04a9667bfad9f0c256a525db05f0f6eddced634e962172c306e3804f4ee633aff5151826a5a93845b994fba132d14ac4e194fd824e9514eff1dbd21fcb3b4618593c96ab254c8d9fce7cbbda8b1f3af04a926755d22bd33515c1c757b1abdfda506235f625a900a818cdd82e0b4c5c05579a25b18a75fbae15d75a5bef5d47f002097718ba023939a8f13643f9b3773d1d864942b95011440ac2837f2af067367c449933b35d28cbe7d708ba8b2b6d15a99252ba46a2420a03af997cb7eff122a4741a91f8c64dcebc45b312602053bbf95b2064e384da81c58914060173b9513100e1e0c47af0069161b7f817696f9c076b8ec5b16389473c930cf1bc32697dd41c69dfa2c31f7ee266dfb2ef42ad17a3327b6a96b1ae74da3f76dc0a2a24b334b7502c06f193a8d374945b6792960cd09c6ac7ddb046ce4e0b77f2a43c2db2ddf8a3e7aed0dba1c8c4d9433fb03fd381ead36d8ec09a43841c93528c96f478d6cbbac5eae8834e7e100ed73b2c968f6d6dad2d8156b6f7d514da53b106cbccaa0fdf1e50b71d4734553c08fd8d1d27e4d4c31c5986c25f9989182c071c6ddd53a2e9561da812d1bad0db96c913a70f67deddaf6a256a2bdb880cc2450c2428d4ee049eebb79ff9d4c551b60767f48429b6fd30105ff4b98b0aaf9cda830281f4ef81a9380a3f150b01ce5ae240671ee4051def0d272261e543ac25a48a39c6b5dd332379428e735b87138f3092da9afe87e2a07e98ffa43b92ab956677f98b33f7cc819547a9ac295c014e45f1c61944ec0acccfa661cc82e8027b74c7e3d3c2c189c4a2faa5f2630b1024faaefb0c06afd48fe27bce3d762e95f083e257188fbf63c1fb27d9ac149415389a8ccfdb31f61d8c19199d9534d2b7186c6f4a94fcd6b723a90a407bbe430ff114d11c01d40d86d22b0ee568c51ef79d6ac9f38a160c88e4d1e7e7e15e50ad49b057a21920f9c6074b60d26cafb1175b455df8b19705d591ce58b78787e3a77af76839631c2a60f3955989540cc21089cc84e569b2eefc4733009e0b380e0a4e2377142f5471ca9084234374e791a9dd50dd465636d094e2bad2c57e0f7fcbe223f6d1fb76571ea1ae958b843ef953289294b3a0805facb2d124cbd71a5b9fb5e9f85c94469d66c73739d90a7dff2b90544385b6fcf5c58b9beb4d70b6df2b2db615f4aa685cdc4e9109789f6a1556c33a1e76cba3a71703e9dc536d0a590a38bd54d00ce627a179a813cf240ce9e89f1cf47432189a2da9f73a2b66964ab1aa50a17e44275fbfc8a59dc9f0375710076d030d7459b9a717f54e78d69ca0cbff35c6bcc5d5b93a95667d9d54643825cb8dc196bb622b6a6349fe58ee1ef6718c3dab2127523f43a527b6a34c71c0ed70d88adf47dccdc0c27a6de5d5388c694b2901a3d60368e73b08cbfba465e919e8e1e02ac6e56d5b98bc26828c69854b9bb260352c43d03069d7ddce4541797689893b2d2325bb37908cf2b786de5f52caa1c8a50be1721201a57aa62df8a52cd510cc13a6d397af754cc8b8bb73d30839e1b50ed86a2db962284bb39ef5d3ed106c33bf8311ec683ecc20a0a6d0483b4ac3d0070e2bdcf09944ad630c4790f463b99009f4fb002a4b583ec75bb34b555ee842ecbd6e411b959c9d90b40f3e420fd6aced5ee5d2fe3bbef6919c36ca25aa2d2671f1dbaee37e0da0cc858532d7c53ae34fd686cf433d0c93571f364594b9723fd46ea3be868ba415bf56ba65b71b19a131b78e7112f085cc07a3788f1e71dbfc44fb5861f6a00f0e2566b4cf74822e43996c2844b3b3789609738ec22a990e0e5a603031e1cbdb273e3bedbc28336819d8073e17991a23fb98001af9e82354733d057af2e028950bc4f93ac1722b3f380a9ce0543f8dd4b5a4698f56e4edf639269f711e1004f9e4dc823a484139af2509808fbaaa58c5360a894340884110b27699d890937a0b70167b69354012600765c6e2c2e69d815c3226f0fdb330e3bd50e43d4f1766a74a8d9acf02072343813d236b4a2cf4895d910c7710ce2344905dcc78398a5c9434a3a82e17e09976e783798cb056e6250594e1c1a4c266f67fefae06631a7674e0a7042b59b5b872bf24256ca46ff58d1a4480539a95f12cd343583366139ab4d771dabb0a2683038ca668c805ba0e9838b791ceee37bac61be01122eb599c0e76840db2689200cbaa606acfba787f35b235373b8dd1ae2e162a4b9251819ea5866eb29b3c25bab12dba5914353e7a18f2cf480eaef1009af8f865c208dbae75dad","root":"dcd501f2ef4ab264087f912eeff9b8859f796da2dd1e397d69a52f643a2ea596","root_slots":"65536"},{"id":4,"stake":"2000","attest_pk":"6ad595c1744715daf646928ebe7c79ffc27906fcdd35c09d16e142cb49c0631af4e96035c3de879486fdd96bd2c77225a872c9c85d2102d465eae93a0a56da977a0c68c8a509f6a1d23ce589049c3f941f8baafcf56d20452008fc6a2821ddfc8e6575f514094f8bfc589cf5357eb4888137dc4b2c526479b6f1ecd67449c6603c8d32742a5c5b1fdeadea2b049d7e06faf3594c96338337f2be4c05756413ad1e440836dfd66701da16396a2b4cae405aecd45334ef0c585c4b7473f34374e10f95a7ddb2dedfafea6966a603daba0f3564a841338d4a897018f547c2c53fa8bcd298ea0598853940dcde16761e9076499cf29d4eb10ad447761ad24efc3caf30bbd2bf9c76bdb371caab254505023db6eb818ab3416b36843f0481c89b8dfd098472482eb526245a12dbe975081a25b0cbeee069c662b92a74da350d156fb1fe04d1043b98333a60076cc30d32780ba6ceb6a75251b8a58a45e698e009d1fe3b86b7c1367abaddbca8527c5eb69cb29c7b7bde2603b467e9ef8f3ce071c31facfa9c3f6ee88c542761986c82eaad293657a5a4e51a42ef3f7ae8bc47be18f50b6681ac186b4bc0a83e309b77d51c300f56ee94571c5121d7b1454df183ffbea4af8d5959563db68cf2d28d427ef1eb723bcd247f40b0479c50b54a1cf3f392712be3e8b82c06e17696b9c5f5fe8ef84bc3ea4c233107e53e96155bf837804d04403e3940fcd11bce5e4fbcc1fec685c9099d0ee418b218764a873ef152c1a7eeb344099d840a537eb38d68040844ef8d5b7a33c06b4f0d3bb324e2e69867f2cfc3826be117814b4a19a04770273ab2db32229f39d378edad9e5993ba824ab5e6af43fa91ba7ab04595e827cf77c6a86dea3c95da7716e98c0c778d462eeb36501b6164f87a1320407cac6a167066c65f4663faa8415095249609f9fc7f43c5c6818d4007f004e016990587073164c3d4bc8416ac5d2df9efd626c430ffdf2427eb58c144f4674d41b637737efa6a9153575491638d063b7119ab4a48892163fdc33dde11016c4f5d134bc316ef26f3ee5c09baed184b4dc2c52fa0cb8a1e14e49c2294a1eda14c3096089cd8ab550a95b9d505262a2a5ac34fb29461d987e559df1b1040705dab7384288d122c3505fcace387f1e04016365dbd54dabd77fdac2ac08f9c6640b4ec71c4d5397b61fc2e149a817541e6efd1677d947bcbe3d1c6b3cd1eefdf233f383f3a358c422132b7fb9c06c3ee8dce972ade09bd3691e731563c6c7f7a46c33a54dd59b891ee3370a660b6235e6e43b4b9e97dd73f2e3521eb46c24cb8b07676cda9b6b8d32b35a9dc2f048be727cf41f8528b5fb636b818177aecbe12cbb0fb59e34a04e85d17d93188d8be16178dcfa0f8f6ee976f1de951b8cccec2e3fa6f6fbaf5b69dfb6b5d0fa919c3d95b98fa655ead67c76bbe4d497000c8bc46ec7c8aa37427cf2e3bc1460bc6c8151852aa4031ce556333c66f2bbbe528ccf83f0be0a1bdc581342fb5a9302b3c66bdebe98b13694defc4f5e2c1a24a98661dfb8381ff1e6cce114bec08e35c832d7bd1e8b830af50cb27f767c4b80b69e6a7308dced92126e36e7f05e60ac34e0bf5211b7768fb411e483a071830e4af7f8da8f31c2d96ae109bcd5b4e545fe72d8e847e95893bdaac399c411edbd6d048df9363e59011755dd19d5977cd61ac8aa09ddf369c1f024fbb580cd9a1f6d8cc7d812dd4622ac65551b02762cc19e406ce4e71dd837028cc752082357951874888e1b748da7cf57cd9d1adc3425529c6b96669ff0b4a4ed1a64ff9c0f0825376e51d428aab5db7e8cc5f901230149bb1038db1a83389a7e52ace9996eaf86145efd9f3a363b14db5d8eeedc7d3d5727ac7158c07aebb0e50dca630166ca2530362254bf3e46a60b72a29ec08ce01fd494c6b35bd65e956a5331c01dc24e715c671ca8dc904f5b88b7bfb088405aeb94344ad32cf489a4fc2ec3a5aa7903c7997a912d3362a9498415f4eb3615d327512990993d9e9bbe66d0588463955f65f9716ecaafc869eba69444954bab01714a0ac49571bcd4694b412794ae26e933a3eef59ae8351592880e73053c422b31d9354b23db15142fcd643412ecc0f51766b801e88b9d03b3ce80128185647866fc8f660147b5f1ac1db47de3e108ff5fdea521a2de6b5f677d2e45e1ca6b60e0791af182d4d79c08563a58ed73300d3be919a3aa3c747b2606381ea036b39f4910d71f2da587367fe30400c15956cb09f425041e9c0f15701e87e92f109e8d453c47abdae052cd86626915cc42925f607d0af846ce9ef85ee01ffd03ed823d879d7a3b03566aa155f1e312f99ce75a54ee8661f926b6c0cd5e61e73c653c5c2b2e65748f7fc899175483ab629837a090883e26055ee777e84c78e3ffeef7ee612fd3906b18883418fb6c2f6c9329b001fe9947df7cc5d0b2eef0bb0c255327f662214089929a0adf43c0883b4ae00d47a620420d09aa54816692fec5fd82de7a6fd1dcff065ac8c42b86446279120c01ecf24f263925b782c82fd409440987f7337efea4f2a8d9f3b8c971be07de80fa0dd300381958d5a9cef3e8b45945d5ebf7fc39d5f0b49acd8298dbe6459cfaecc4f6b2645a7c09552f71d39af47e5e6b4b075c15c36069aff73c77560b874c29f01050829bdbc88fc05ede3cfa2640938e942f0415556b37aa6fbbfcffa1fc55f2b33b53a30edec73cd2a167427d33f29dc30bf42bf298469e564bb","root":"64fc11d86ad1eee8aa3a4b3af532778297708ab6a085038588e8f63912d108d1","root_slots":"65536"}],
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
