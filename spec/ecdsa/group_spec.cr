require "./../spec_helper"
require "./../support/group_spec_macros"

describe ECDSA::Group do
  describe "#create_key_pair" do
    [
      {
        group_name: :secp192k1,
        secret_key: BigInt.new("dcd569823be84b873876da9b72b7e3193a9a29260e86f265", base: 16),
        public_key_x: BigInt.new("cda40fbbcff416b2822815ae014f600b68cf24ce1174997c", base: 16),
        public_key_y: BigInt.new("84a30976a1570fc99fa712c2e147b32c0f6f091ea81b6258", base: 16)
      },
      {
        group_name: :secp192r1,
        secret_key: BigInt.new("3204a7135ba6c7743cdabfb66b14d1afe55455d2475bfd1f", base: 16),
        public_key_x: BigInt.new("b69001e5e8fcd3f58092ccc846dbed0d357a6b527356e079", base: 16),
        public_key_y: BigInt.new("e2f25c2d9e163403007fa83dd57657612b5080d1d20547ca", base: 16)
      },
      {
        group_name: :secp224k1,
        secret_key: BigInt.new("716624a401872d16935e4e555274ccae634a1db8d3141002bb7ead67", base: 16),
        public_key_x: BigInt.new("7fa62572db1096748b2a690f486c16d3c6234ad3c52420a9e357c3fd", base: 16),
        public_key_y: BigInt.new("393f9e2e18f497a0a85dd6699eb42024d8e47b67254fe8f93cad2cbd", base: 16)
      },
      {
        group_name: :secp224r1,
        secret_key: BigInt.new("12c542d8dd4be7d2a573ca10529670d899e07ebb4abedf49c0720752", base: 16),
        public_key_x: BigInt.new("6d027c2aa86d98eaf65df2cc9820353c667b86edd92875145a9898d0", base: 16),
        public_key_y: BigInt.new("e132eeda3307801263067077b645f2efa42444f9fac8b4969035a996", base: 16)
      },
      {
        group_name: :secp256k1,
        secret_key: BigInt.new("e8dd0f12092bcaa449e68fbe9be9744fcbf627a1744ee9d5243a3de6cf010a6a", base: 16),
        public_key_x: BigInt.new("5cbeadc173c0cebc228c11ec285e8b7a36e2279c423b37b72a84079959c4d1c6", base: 16),
        public_key_y: BigInt.new("8d6167c63e42f6af378f7c7306116f6948ddb8d81a3027851001d0d2ce389996", base: 16)
      },
      {
        group_name: :secp256r1,
        secret_key: BigInt.new("b8fe5b92a61d67abec34a3ea3ac39c26708ecbe6ce58313664e1dc2730e270bc", base: 16),
        public_key_x: BigInt.new("403e13e5d690508040111e36b9fd4f39296e0d146f0eeb20e3a4277c294d3974", base: 16),
        public_key_y: BigInt.new("c0a7bc58f1677e5895f275781370e5371e5e093fe7833984f1f235e76096a4e2", base: 16)
      },
      {
        group_name: :secp384r1,
        secret_key: BigInt.new("200c2adf8c8d5ba95cbd661306d189296bb2d4d6ff961944df8683a40588d3b62eaed9112b094302c1faaf7edf5755db", base: 16),
        public_key_x: BigInt.new("d17ecadf39df3c7d3da4578645277024a8f6ba36e2c2cb2b0d11db957245d0a84a721fdbd7cdff4da3496332a81af3de", base: 16),
        public_key_y: BigInt.new("4af088fccfc5d887c124c0bb7c77c671e8fdbca26cbe514c19a3e3fa1f5cf59f51681b5c454833df588dfd687e6061e1", base: 16)
      },
      {
        group_name: :secp521r1,
        secret_key: BigInt.new("17108f001ba001fb2b9b09d15eb5f26d01c6395bb09c3cc3e8f58f2625199ad88e4104b6e36e9f27c4a8d0b34dbd35d6ee594f71031cde3b5cbf3ac39d355bb918", base: 16),
        public_key_x: BigInt.new("143ff422e3c9f52dbff32116f668eefe9edb84a6fc3949b758b688bf944d07a2c80d82d5646b26400d837697940339d6c26c5d3651e114c552eed3e6f57f4c92b72", base: 16),
        public_key_y: BigInt.new("da75033ac832c32136337c4e74bafc2d17da927dca422bb6aa06ccabc48605f6a364574f568b973bfda35f796fc870ca90398d3ae848e44d5cc47c9fea6050b7e9", base: 16)
      }
    ].each do |spec|
      create_key_pair_spec(spec[:group_name], spec[:secret_key], spec[:public_key_x], spec[:public_key_y])
    end
  end

  describe "#sign" do
    [
      {
        group_name: :secp192k1,
        message: "d9eca2f810596c03807627c8367693bc0cadae048193b3629a519b8ac2b36079",
        secret_key: BigInt.new("4f732da0325b45cbab773152a650d4e95fe4f04b0bf61be3", base: 16),
        temp_key: BigInt.new("581230b0f08a953449420903932cfe7a8d9d5405c5a6475a", base: 16),
        s: BigInt.new("4cf6e86f0d5df82af20b01f864dba35f8399b6731f73c11c", base: 16),
        r: BigInt.new("888e691ae121dd1c57c133a5697f577ba77d13a44b48ccef", base: 16)
      },
      {
        group_name: :secp192r1,
        message: "f9d4de59e9b56bd7905c7b8962becd00730afad4d7fa77e130dc48e026975dbf",
        secret_key: BigInt.new("74bbdaa41b5e5b5010ea36e77a34e022f97b55738ab382f0", base: 16),
        temp_key: BigInt.new("f6b84e2a1d70fff17fa4f65121fa55753ddc7ae3cf31da6c", base: 16),
        s: BigInt.new("f14dcc8b7bf424dd322711c3c456af76c9e02e99a32fb9f2", base: 16),
        r: BigInt.new("bb0097754ab3c36c61f40a9a68f108620a8d34e1cffd77c3", base: 16)
      },
      {
        group_name: :secp224k1,
        message: "6f4fb44d54f849f9a06c5dd5e209198a5b0789324bcf4e384d5a79f0d0dd1cf7",
        secret_key: BigInt.new("eee066c8dd9abc00b70e900e7fb55f3f0e1151592002b484c155ea0c", base: 16),
        temp_key: BigInt.new("ade726156532694488047c9822c87b8dd0f0d5345561a707dce391b5", base: 16),
        s: BigInt.new("b2006ef66df82b84ead0c31decd9440e911596fe2a10262852e60902", base: 16),
        r: BigInt.new("8d282c049f1dfda705d5ebe0c456c6422528db483cc5eee69f56e0f5", base: 16)
      },
      {
        group_name: :secp224r1,
        message: "4a7368aeb97976c5ee445d848e4ece86a8df2a40c4ef9d6dc3f443014c71130d",
        secret_key: BigInt.new("99320180fd070d7a63bb9b026da8a677bca96f06fbd45987605d33ea", base: 16),
        temp_key: BigInt.new("7bce09e451493762e9b69353a1fa62384e92cb0495c1588d429021a0", base: 16),
        s: BigInt.new("f85f7097376bd2bea176bc10a4837c941ade3c7ffa2fece8f51a46d7", base: 16),
        r: BigInt.new("e91612781146ff41222a48942796d51ea334648128e5f6b50fc2fb2d", base: 16)
      },
      {
        group_name: :secp256k1,
        message: "747eadeb6c62ec0a15875deacb33611ef9e176fe7b2bf14ca88f7b40a18f7a7b",
        secret_key: BigInt.new("a75c71811e2d4c969682309760f75b98b56ad74fd6cabd4026f19b7c90b145fc", base: 16),
        temp_key: BigInt.new("530b6cea047239963332936bbb97440e5c833210d589d490151bdb659b593588", base: 16),
        s: BigInt.new("b2c2cf86eb16e0c77a55a37b440ddcad7ff8d9727c5a11eacbbf3f59236c191b", base: 16),
        r: BigInt.new("f2d2ada1f74c03e0639b756b16ec0780ef6964cb6bf80fdf2513e0271580d9b2", base: 16)
      },
      {
        group_name: :secp256r1,
        message: "e95308f56ad5a44fb3d6d23c742c950f377c0fb6a6a442b9faf59e25044bbe6a",
        secret_key: BigInt.new("f435dca1fa36bb61631ed6944a52556a831691e2b9fd2ee272246b645cceed5d", base: 16),
        temp_key: BigInt.new("17d5dafdfd34edf0c8612dfac60a325bab17f6085de2e283f1c65d2f1e7d0b8f", base: 16),
        s: BigInt.new("4f3df863a878dacce8ba5e7e2e41a124d93ffaf992c143c1af2dcb884b200daa", base: 16),
        r: BigInt.new("19800aafcea68de4efd6c4621b3657ddb5986ac86d79cbf4448c00733c0766d5", base: 16)
      },
      {
        group_name: :secp384r1,
        message: "03708f125404af33f67b5715ed6aed36ab99f22af39b1d03ec7352b88fbf12ee",
        secret_key: BigInt.new("e330ac596ff6b7b80f00ae7747b4e880da7821261f0f0aecd178572dc395e60f6f783547cc287d8d08385321543e13a9", base: 16),
        temp_key: BigInt.new("f168a66399d0da2a29bf6a996104ac7fa628c27169bbfe45ae5b522e527209dcacfc149fb102ab89c11bdaf4630fd6e7", base: 16),
        s: BigInt.new("10403cf132426c604d6796b81ee7828273ecbf3ca22a8dcd56f81675b50cf566f9806c770b2149450a209a4e4c83cd9e", base: 16),
        r: BigInt.new("f128c329c497e205d80cd4f791bcd536fbbb4a8175e4c59d7224cd1d3ce93ce193ebbbd909ffae1c3ca52b7a876130bc", base: 16)
      },
      {
        group_name: :secp521r1,
        message: "aeeb6ef8d300f6b1185b5775aaf24a3eaf1621eab42aee79aa747f98a2be85d8",
        secret_key: BigInt.new("114b2bedac830fe96626baf581e95a168365be9a2fcb0b09762784e7a20fb1ad59c40e0eff76ce93587eaca83c0b18f87db05c4aac2f719aa37eec1691c5233277f", base: 16),
        temp_key: BigInt.new("86c29d7401a3cbbfb30e6bc66dfd53b0976f7adbc88fe5b5cb283b4110fb01d58a17f1638351fb9867a32196956c5702e3b484840badd0e51362e8c730b4fb2767", base: 16),
        s: BigInt.new("1540b0cf1966c626f0617aecb19224e4764324930fe76a978e018087c57ae28c8265f8fa59fac43baa96bffe3256bbfd92b4d3a41180e20e2b25382648e09ef9612", base: 16),
        r: BigInt.new("15f453c06b7d9cefe2fe736ffd38040fcd493d6e11555d455aa9d452b01ef81845abf22d9cd9f809995c0e65e5582725e33d9be3ab7edc092d038458df08553548", base: 16)
      },
    ].each do |spec|
      sign_spec(spec[:group_name], spec[:message], spec[:secret_key], spec[:temp_key], spec[:s], spec[:r])
    end
  end

  describe "#verify" do
    [
      {
        group_name: :secp192k1,
        message: "dac37bb1c6cfd193c92815853203d65280c8bbf922951e2046a5eea0d51405a6",
        s: BigInt.new("ed8a02e9ff88a11e36b33b316e7c4f97febb122d739b345d", base: 16),
        r: BigInt.new("b2430045f1fd05c8daccdf7ba5a131fd301c2bb8ec40e97d", base: 16),
        public_key_x: BigInt.new("56f55975870d9c05d47517cbf6042da88874b57680936c89", base: 16),
        public_key_y: BigInt.new("2aa8897909b0bcd9a81827987cb7e7a9ca3e4d8763494630", base: 16),
        result: true
      },
      {
        group_name: :secp192r1,
        message: "5657121346f29487d1ebe24fe4c767e1c38cb0a168bc49a2f40c3fd41d50f14a",
        s: BigInt.new("71a99b9eb08598339eeb9fd1582096e0af162a6c87bf763e", base: 16),
        r: BigInt.new("b5610d49acdc0cb8eb5a6134a2b01474f7f13d7970ffeb1", base: 16),
        public_key_x: BigInt.new("fe95c030ddca55e431d47bc212bc2e00ccf4082e33d54cda", base: 16),
        public_key_y: BigInt.new("7595e8931f0c94f2293418d6bf5b142f6360e1934278d830", base: 16),
        result: true
      },
      {
        group_name: :secp224k1,
        message: "524d2f57b4ee5d5588e3432437bc3ab5e243435526f76738853449816be53aa4",
        s: BigInt.new("45b5d90c8361fa0085f6b191b5113618ec66b10de308c12ae64c0739", base: 16),
        r: BigInt.new("4e3cb9b654c8a7a0b9e4f9dc71b9c8f9f3af5f389c74e364bf9e7dbd", base: 16),
        public_key_x: BigInt.new("8f491ae291a810d1a485a53d31d49dfe66d9114ea44e57fc8a3badd9", base: 16),
        public_key_y: BigInt.new("efd317c0a295ff2e940218cc057421ffd3fddfea30cfbfc6f16c703c", base: 16),
        result: true
      },
      {
        group_name: :secp224r1,
        message: "e1a33445d685a46e0a4cd97b05da29da3f7f95950a2917456fdfac7c7296fdb5",
        s: BigInt.new("af0688a899d4fe5d6b4b590583e799cdc0e5d17bf089afd1027fe22a", base: 16),
        r: BigInt.new("9d001993b81908d65f39de74e133e6c3404c4d64da86437182f8c0c1", base: 16),
        public_key_x: BigInt.new("9210b3737c9b042f213fbef858817e6858c5153a77c7504b869d53ac", base: 16),
        public_key_y: BigInt.new("3ccc7fb72085b700dd863c9fbe179a478c433fdff2c8dee5bc659db3", base: 16),
        result: true
      },
      {
        group_name: :secp256k1,
        message: "90c3121e21c80451f9ace42a196efb3d8395f8b30be72aa1f4666fc60357aee8",
        s: BigInt.new("281fd8ed20082706f4c05b2dcab0e3c0ca3eb1c0889db7a70e481525e7531d62", base: 16),
        r: BigInt.new("5eda4a55b4a8f58ac333bfe77b03c9401fcf1f248c1b3baf1f235463f490500c", base: 16),
        public_key_x: BigInt.new("15d0994cb5ee40e60762cf1845bfc43509bf62921be1b4ad8fc262e790609351", base: 16),
        public_key_y: BigInt.new("b7e0265336da8a45e784084887b2fcb9a0480fe1acf83e53b67d3d7c21b5cbac", base: 16),
        result: true
      },
      {
        group_name: :secp256r1,
        message: "59092a2aa4a51ebf9ab213a7861606f75f2b0691f58738b178d1a424c312b0b0",
        s: BigInt.new("3cd837a04534ab71b2351dcb9bdbb05d89a654197ec044765c409414fea2e231", base: 16),
        r: BigInt.new("173e7f36b24896b0c1624b93cca8a4bcd5d9748c64fba0564312de2d391c3214", base: 16),
        public_key_x: BigInt.new("1e93717e66c27cdd94022647295e7c2bf8babe660ae44e45ec33dbad6c6afedc", base: 16),
        public_key_y: BigInt.new("fdc4cf24dd4afbd2c69ca178eefa7a197b1cda23fec4b8c2cc6ac99d09d9a84d", base: 16),
        result: true
      },
      {
        group_name: :secp384r1,
        message: "0218c73d295c1bd4b0aea3a424c34ac8caf9f5ddc9e25e0a57e16747a847709c",
        s: BigInt.new("aaf93b5d09c883a1297e2d8bee7813680dd64575452be636ec0e1d9c057a672b5b8807dacbf54f97b89b05ce7a023e7e", base: 16),
        r: BigInt.new("39ee52bc5ebf331315209a3f473ca20cf66d930257ec6bf0cacfe28b130c322d4817496285790af8959c17fc5e997b1e", base: 16),
        public_key_x: BigInt.new("88cbc7281a65265b39be3a19f10891785fd1bb3f07611077ded98428c0c82824278db03006b076d6ebb71dc0a4d6aa4d", base: 16),
        public_key_y: BigInt.new("45aada22613864c60f6b8b3d2078a2076651976f6fc9bd2a2d6346febfd5201063e67c41aed3a30354df739827a901b9", base: 16),
        result: true
      },
      {
        group_name: :secp521r1,
        message: "e4c6f9dfd6c6aa902466dea65376a43727f4946ca441f027ae2fcf863ff4a337",
        s: BigInt.new("108011f1b6cfe304e79664f460d788103f2f7992419859243aa0e9468150d18e71f22abde018f3f89238431ccf22a374aa524e78a1a6ddbab45320eb746d3f9363d", base: 16),
        r: BigInt.new("76d66237f0f37942cade2d54e528cc4125a7d0064d7ea6b92560d7307caefbb94fa4207512b450e13b4761248e333ed6af66ae361c7cc9e4b34afefa4c289d2099", base: 16),
        public_key_x: BigInt.new("149e36308744f5b94d76c84f9bb6bb4d329ac312cb5813a9a63a2b5e4362fbaab33ef7909df774289cacec1390bef1360e421763c3cc7f7e6c62224b06bd5a8b951", base: 16),
        public_key_y: BigInt.new("11f4353b42381e7e77afde7801299192c22fb3cbb5e823acd0bad4b553579a7a74ef925f66d4a098e5f4eb1e78167077a25e790b63b41e0f499f5a05f33e946980d", base: 16),
        result: true
      },
      {
        group_name: :secp256k1,
        message: "Some payload",
        s: BigInt.new("144"),
        r: BigInt.new("1050"),
        public_key_x: BigInt.new("75404758482970552478342687949548602789701733940509850780379145804275702033212"),
        public_key_y: BigInt.new("51231939447366605701190019263228486011330128519473004560491454193878655241557"),
        result: false
      }
    ].each do |spec|
      ECDSA.get_group( spec[:group_name] ).should eq( ECDSA.get_group( spec[:group_name] ) )

      verify_spec(spec[:group_name], spec[:message], spec[:s], spec[:r], spec[:public_key_x], spec[:public_key_y], spec[:result])
    end
  end
end
