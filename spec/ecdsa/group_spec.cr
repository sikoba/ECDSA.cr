require "./../spec_helper"
require "./../support/group_spec_macros"

describe ECDSA::Group do
  describe "#create_key_pair" do
    [
      {
        group_name:   :secp192k1,
        secret_key:   BigInt.new("dcd569823be84b873876da9b72b7e3193a9a29260e86f265", base: 16),
        public_key_x: BigInt.new("cda40fbbcff416b2822815ae014f600b68cf24ce1174997c", base: 16),
        public_key_y: BigInt.new("84a30976a1570fc99fa712c2e147b32c0f6f091ea81b6258", base: 16),
      },
      {
        group_name:   :secp192r1,
        secret_key:   BigInt.new("3204a7135ba6c7743cdabfb66b14d1afe55455d2475bfd1f", base: 16),
        public_key_x: BigInt.new("b69001e5e8fcd3f58092ccc846dbed0d357a6b527356e079", base: 16),
        public_key_y: BigInt.new("e2f25c2d9e163403007fa83dd57657612b5080d1d20547ca", base: 16),
      },
      {
        group_name:   :secp224k1,
        secret_key:   BigInt.new("716624a401872d16935e4e555274ccae634a1db8d3141002bb7ead67", base: 16),
        public_key_x: BigInt.new("7fa62572db1096748b2a690f486c16d3c6234ad3c52420a9e357c3fd", base: 16),
        public_key_y: BigInt.new("393f9e2e18f497a0a85dd6699eb42024d8e47b67254fe8f93cad2cbd", base: 16),
      },
      {
        group_name:   :secp224r1,
        secret_key:   BigInt.new("12c542d8dd4be7d2a573ca10529670d899e07ebb4abedf49c0720752", base: 16),
        public_key_x: BigInt.new("6d027c2aa86d98eaf65df2cc9820353c667b86edd92875145a9898d0", base: 16),
        public_key_y: BigInt.new("e132eeda3307801263067077b645f2efa42444f9fac8b4969035a996", base: 16),
      },
      {
        group_name:   :secp256k1,
        secret_key:   BigInt.new("e8dd0f12092bcaa449e68fbe9be9744fcbf627a1744ee9d5243a3de6cf010a6a", base: 16),
        public_key_x: BigInt.new("5cbeadc173c0cebc228c11ec285e8b7a36e2279c423b37b72a84079959c4d1c6", base: 16),
        public_key_y: BigInt.new("8d6167c63e42f6af378f7c7306116f6948ddb8d81a3027851001d0d2ce389996", base: 16),
      },
      {
        group_name:   :secp256r1,
        secret_key:   BigInt.new("b8fe5b92a61d67abec34a3ea3ac39c26708ecbe6ce58313664e1dc2730e270bc", base: 16),
        public_key_x: BigInt.new("403e13e5d690508040111e36b9fd4f39296e0d146f0eeb20e3a4277c294d3974", base: 16),
        public_key_y: BigInt.new("c0a7bc58f1677e5895f275781370e5371e5e093fe7833984f1f235e76096a4e2", base: 16),
      },
      {
        group_name:   :secp384r1,
        secret_key:   BigInt.new("200c2adf8c8d5ba95cbd661306d189296bb2d4d6ff961944df8683a40588d3b62eaed9112b094302c1faaf7edf5755db", base: 16),
        public_key_x: BigInt.new("d17ecadf39df3c7d3da4578645277024a8f6ba36e2c2cb2b0d11db957245d0a84a721fdbd7cdff4da3496332a81af3de", base: 16),
        public_key_y: BigInt.new("4af088fccfc5d887c124c0bb7c77c671e8fdbca26cbe514c19a3e3fa1f5cf59f51681b5c454833df588dfd687e6061e1", base: 16),
      },
      {
        group_name:   :secp521r1,
        secret_key:   BigInt.new("17108f001ba001fb2b9b09d15eb5f26d01c6395bb09c3cc3e8f58f2625199ad88e4104b6e36e9f27c4a8d0b34dbd35d6ee594f71031cde3b5cbf3ac39d355bb918", base: 16),
        public_key_x: BigInt.new("143ff422e3c9f52dbff32116f668eefe9edb84a6fc3949b758b688bf944d07a2c80d82d5646b26400d837697940339d6c26c5d3651e114c552eed3e6f57f4c92b72", base: 16),
        public_key_y: BigInt.new("da75033ac832c32136337c4e74bafc2d17da927dca422bb6aa06ccabc48605f6a364574f568b973bfda35f796fc870ca90398d3ae848e44d5cc47c9fea6050b7e9", base: 16),
      },
    ].each do |spec|
      create_key_pair_spec(spec[:group_name], spec[:secret_key], spec[:public_key_x], spec[:public_key_y])
    end
  end

  describe "#sign" do
    [
      {
        group_name: :secp192k1,
        message:    "d9eca2f810596c03807627c8367693bc0cadae048193b3629a519b8ac2b36079",
        secret_key: BigInt.new("4f732da0325b45cbab773152a650d4e95fe4f04b0bf61be3", base: 16),
        temp_key:   BigInt.new("581230b0f08a953449420903932cfe7a8d9d5405c5a6475a", base: 16),
        s:          BigInt.new("d47231834bfa2beb506d632fe994ffbfd0825036c11d33cb", base: 16),
        r:          BigInt.new("888e691ae121dd1c57c133a5697f577ba77d13a44b48ccef", base: 16),
      },
      {
        group_name: :secp192r1,
        message:    "f9d4de59e9b56bd7905c7b8962becd00730afad4d7fa77e130dc48e026975dbf",
        secret_key: BigInt.new("74bbdaa41b5e5b5010ea36e77a34e022f97b55738ab382f0", base: 16),
        temp_key:   BigInt.new("f6b84e2a1d70fff17fa4f65121fa55753ddc7ae3cf31da6c", base: 16),
        s:          BigInt.new("44fcb81622e39d85c632ec360b1e7cc2b37514af64f93b40", base: 16),
        r:          BigInt.new("bb0097754ab3c36c61f40a9a68f108620a8d34e1cffd77c3", base: 16),
      },
      {
        group_name: :secp224k1,
        message:    "6f4fb44d54f849f9a06c5dd5e209198a5b0789324bcf4e384d5a79f0d0dd1cf7",
        secret_key: BigInt.new("eee066c8dd9abc00b70e900e7fb55f3f0e1151592002b484c155ea0c", base: 16),
        temp_key:   BigInt.new("ade726156532694488047c9822c87b8dd0f0d5345561a707dce391b5", base: 16),
        s:          BigInt.new("86236e81d257f7f7d47d2aca6d4a989c678d759c18ceee490eae545a", base: 16),
        r:          BigInt.new("8d282c049f1dfda705d5ebe0c456c6422528db483cc5eee69f56e0f5", base: 16),
      },
      {
        group_name: :secp224r1,
        message:    "4a7368aeb97976c5ee445d848e4ece86a8df2a40c4ef9d6dc3f443014c71130d",
        secret_key: BigInt.new("99320180fd070d7a63bb9b026da8a677bca96f06fbd45987605d33ea", base: 16),
        temp_key:   BigInt.new("7bce09e451493762e9b69353a1fa62384e92cb0495c1588d429021a0", base: 16),
        s:          BigInt.new("5e5f49b9ed27c970d952f72ae6c70022735aaed677203a0db9b44d09", base: 16),
        r:          BigInt.new("e91612781146ff41222a48942796d51ea334648128e5f6b50fc2fb2d", base: 16),
      },
      {
        group_name: :secp256k1,
        message:    "747eadeb6c62ec0a15875deacb33611ef9e176fe7b2bf14ca88f7b40a18f7a7b",
        secret_key: BigInt.new("a75c71811e2d4c969682309760f75b98b56ad74fd6cabd4026f19b7c90b145fc", base: 16),
        temp_key:   BigInt.new("530b6cea047239963332936bbb97440e5c833210d589d490151bdb659b593588", base: 16),
        s:          BigInt.new("7cb116b26df721a4b4b9c0e22107ae4cbac6fb096369fb94f166bb3efcf8268e", base: 16),
        r:          BigInt.new("f2d2ada1f74c03e0639b756b16ec0780ef6964cb6bf80fdf2513e0271580d9b2", base: 16),
      },
      {
        group_name: :secp256r1,
        message:    "e95308f56ad5a44fb3d6d23c742c950f377c0fb6a6a442b9faf59e25044bbe6a",
        secret_key: BigInt.new("f435dca1fa36bb61631ed6944a52556a831691e2b9fd2ee272246b645cceed5d", base: 16),
        temp_key:   BigInt.new("17d5dafdfd34edf0c8612dfac60a325bab17f6085de2e283f1c65d2f1e7d0b8f", base: 16),
        s:          BigInt.new("559a4bcddf1cd4ac72d81ee7bfe1ea11dee540358ab871bebe9cb14beab3a7b2", base: 16),
        r:          BigInt.new("19800aafcea68de4efd6c4621b3657ddb5986ac86d79cbf4448c00733c0766d5", base: 16),
      },
      {
        group_name: :secp384r1,
        message:    "03708f125404af33f67b5715ed6aed36ab99f22af39b1d03ec7352b88fbf12ee",
        secret_key: BigInt.new("e330ac596ff6b7b80f00ae7747b4e880da7821261f0f0aecd178572dc395e60f6f783547cc287d8d08385321543e13a9", base: 16),
        temp_key:   BigInt.new("f168a66399d0da2a29bf6a996104ac7fa628c27169bbfe45ae5b522e527209dcacfc149fb102ab89c11bdaf4630fd6e7", base: 16),
        s:          BigInt.new("31f6499313bb74cb2e6dbd757071d3715164468f8268accc3fd3a2159d1b9656143b1802a8bb31ef6ee30928c902c897", base: 16),
        r:          BigInt.new("f128c329c497e205d80cd4f791bcd536fbbb4a8175e4c59d7224cd1d3ce93ce193ebbbd909ffae1c3ca52b7a876130bc", base: 16),
      },
      {
        group_name: :secp521r1,
        message:    "aeeb6ef8d300f6b1185b5775aaf24a3eaf1621eab42aee79aa747f98a2be85d8",
        secret_key: BigInt.new("114b2bedac830fe96626baf581e95a168365be9a2fcb0b09762784e7a20fb1ad59c40e0eff76ce93587eaca83c0b18f87db05c4aac2f719aa37eec1691c5233277f", base: 16),
        temp_key:   BigInt.new("86c29d7401a3cbbfb30e6bc66dfd53b0976f7adbc88fe5b5cb283b4110fb01d58a17f1638351fb9867a32196956c5702e3b484840badd0e51362e8c730b4fb2767", base: 16),
        s:          BigInt.new("bbd4f738cd82ee670e2dba0429cf38bc2144a82b03e4b6f34d4cedb6f4b8962090337127e56554ce24705d22725ea58a950ac47d8821e62262a83eb85e318268d4", base: 16),
        r:          BigInt.new("15f453c06b7d9cefe2fe736ffd38040fcd493d6e11555d455aa9d452b01ef81845abf22d9cd9f809995c0e65e5582725e33d9be3ab7edc092d038458df08553548", base: 16),
      },
    ].each do |spec|
      sign_spec(spec[:group_name], spec[:message], spec[:secret_key], spec[:temp_key], spec[:s], spec[:r])
    end
  end

  describe "#verify" do
    [
      {
        group_name:   :secp192k1,
        message:      "dac37bb1c6cfd193c92815853203d65280c8bbf922951e2046a5eea0d51405a6",
        s:            BigInt.new("400e3c414f7af0a06a863cb7dcfadb940627265db9fe004d", base: 16),
        r:            BigInt.new("b035cf7dba49b21bcf363b0f71e25fb343e861a593f1cc96", base: 16),
        public_key_x: BigInt.new("7d9da64a4f96a6ee8c56bce334120db43d1b546fc6ede5ad", base: 16),
        public_key_y: BigInt.new("4db2c0b3f4b0948f112da335a3fb1655ea61c96bacf6c03b", base: 16),
        result:       true,
      },
      # {
      #   group_name:   :secp192r1,
      #   message:      "5657121346f29487d1ebe24fe4c767e1c38cb0a168bc49a2f40c3fd41d50f14a",
      #   s:            BigInt.new("71a99b9eb08598339eeb9fd1582096e0af162a6c87bf763e", base: 16),
      #   r:            BigInt.new("b5610d49acdc0cb8eb5a6134a2b01474f7f13d7970ffeb1", base: 16),
      #   public_key_x: BigInt.new("fe95c030ddca55e431d47bc212bc2e00ccf4082e33d54cda", base: 16),
      #   public_key_y: BigInt.new("7595e8931f0c94f2293418d6bf5b142f6360e1934278d830", base: 16),
      #   result:       true,
      # },
      # {
      #   group_name:   :secp224k1,
      #   message:      "524d2f57b4ee5d5588e3432437bc3ab5e243435526f76738853449816be53aa4",
      #   s:            BigInt.new("9616996288dfcfd8465406f480c34980f5f3de9b2eeb6cb7b4aeddd8", base: 16),
      #   r:            BigInt.new("9193096de410e6c722a4f7085296a3fb0d7682d035d26e7dc6fa550f", base: 16),
      #   public_key_x: BigInt.new("300a49508125376e50a0366c36592f5b9fecf020ee9f2096fcf1c303", base: 16),
      #   public_key_y: BigInt.new("85e8a99b1523ed28023579d38e6194c7b02b73356e9f3745c7e12fab", base: 16),
      #   result:       true,
      # },
      {
        group_name:   :secp224r1,
        message:      "e1a33445d685a46e0a4cd97b05da29da3f7f95950a2917456fdfac7c7296fdb5",
        s:            BigInt.new("0487d1b35c113683b0ee970c06e87a85686d4ba8cb497a492bd370b7", base: 16),
        r:            BigInt.new("b35f292d97c94f958dfa09a10b5d5e8cb0218c24df486cd73b6bc63f", base: 16),
        public_key_x: BigInt.new("ae0ea3c8d3905f5c70166d9cd7bc36a0d6acef6f538f334766189758", base: 16),
        public_key_y: BigInt.new("593c00a19b7401ca8a4ccd2f59d7f22246e843d900a26d1baa6cd0be", base: 16),
        result:       true,
      },
      {
        group_name:   :secp256k1,
        message:      "90c3121e21c80451f9ace42a196efb3d8395f8b30be72aa1f4666fc60357aee8",
        s:            BigInt.new("e6bd923da000a418c0c887ccef0edc04ecfb4cbcd425e2261bb9896379926226", base: 16),
        r:            BigInt.new("305952dd186fe8f97e7c19f1b5a5f5450ad2f8a9bb9152284cafa494041e7cb1", base: 16),
        public_key_x: BigInt.new("4ee25da0896e541b858f5cd88618666a43f59605ac67f1240d274876ca0f1cc5", base: 16),
        public_key_y: BigInt.new("06940a0016937b70a57a1f6e07a9b8f07c5adee1272cfc5d0148b90c65e08ab8", base: 16),
        result:       true,
      },
      # {
      #   group_name:   :secp256r1,
      #   message:      "59092a2aa4a51ebf9ab213a7861606f75f2b0691f58738b178d1a424c312b0b0",
      #   s:            BigInt.new("3cd837a04534ab71b2351dcb9bdbb05d89a654197ec044765c409414fea2e231", base: 16),
      #   r:            BigInt.new("173e7f36b24896b0c1624b93cca8a4bcd5d9748c64fba0564312de2d391c3214", base: 16),
      #   public_key_x: BigInt.new("1e93717e66c27cdd94022647295e7c2bf8babe660ae44e45ec33dbad6c6afedc", base: 16),
      #   public_key_y: BigInt.new("fdc4cf24dd4afbd2c69ca178eefa7a197b1cda23fec4b8c2cc6ac99d09d9a84d", base: 16),
      #   result:       true,
      # },
      {
        group_name:   :secp384r1,
        message:      "0218c73d295c1bd4b0aea3a424c34ac8caf9f5ddc9e25e0a57e16747a847709c",
        s:            BigInt.new("9f0985dfef5e88402b281d0864ac7b10533b169398ce9ee0dc057da9fdc014efb9d159804f64d699c8333d7d05586bf8", base: 16),
        r:            BigInt.new("688440f866a9d3693199940f237c7a2bbd4043671bb01f63b76201b15732c54d5e7b581aef21c7b3f63e3a340840614e", base: 16),
        public_key_x: BigInt.new("875d2162edeeb33805bd9f99447df5bc5039f1369166aa8ba871cf8c5d87154e79f9a187cebe3b85fbe8a440ae2b2340", base: 16),
        public_key_y: BigInt.new("2e941de8d14f7b7976571fd974297d1a3c19b3f2ff3f9357499de240abfe11ea1b8a7b97748fa2643c48838139d3d55c", base: 16),
        result:       true,
      },
      {
        group_name:   :secp521r1,
        message:      "e4c6f9dfd6c6aa902466dea65376a43727f4946ca441f027ae2fcf863ff4a337",
        s:            BigInt.new("5975cd24e579d18b7e0fc832f1ab3a23355a38a58df3a8ae2c0dbdd142c22dfd4cd473352e97de1ce98d04737185c5e0a6904e88d59911aec01cb52333a08473db", base: 16),
        r:            BigInt.new("363dc30a432fee05598ed261ff64544454cabe4f17a6f8fc0573136a181cc67c5e59f141df0ecdde6bb13c82036da8fce83b2352f98d16d51954b9244ab95c55e6", base: 16),
        public_key_x: BigInt.new("00efdb20872edd8d2d4498c71e38c270166c1ccee138a7da97ea59d7899c8c62170f26cbb814aafd301ba30ac3be900b3788ac91c2a440312f12d501a5e1f82e431e", base: 16),
        public_key_y: BigInt.new("009186c143ac04b0d02893d5d7e7d1a94f00143fa34b637f5013e14a7be8863c990a4b0970a42e42a14bc6055c4e357daba44b82a31379696e15d162937312525bb8", base: 16),
        result:       true,
      },
      {
        group_name:   :secp256k1,
        message:      "Some payload",
        s:            BigInt.new("144"),
        r:            BigInt.new("1050"),
        public_key_x: BigInt.new("75404758482970552478342687949548602789701733940509850780379145804275702033212"),
        public_key_y: BigInt.new("51231939447366605701190019263228486011330128519473004560491454193878655241557"),
        result:       false,
      },
    ].each do |spec|
      ECDSA.get_group(spec[:group_name]).should eq(ECDSA.get_group(spec[:group_name]))

      verify_spec(spec[:group_name], spec[:message], spec[:s], spec[:r], spec[:public_key_x], spec[:public_key_y], spec[:result])
    end
  end
end
