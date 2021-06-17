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

end
