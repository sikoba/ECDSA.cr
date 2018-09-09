require "./spec_helper"

macro sign_and_verify_spec(group_name)
  it "#{ {{ group_name }} }" do
    %message   = Random::Secure.hex(256)
    %group     = ECDSA.get_group {{ group_name }}

    %key_pair  = %group.create_key_pair

    %signature = %group.sign(%key_pair[:secret_key], %message)
    %verify    = %group.verify(%key_pair[:public_key], %message, %signature)

    %verify.should eq true
  end
end

describe ECDSA do
  describe "Signing and verification" do
    [
      :secp192k1,
      :secp192r1,
      :secp224k1,
      :secp224r1,
      :secp256k1,
      :secp256r1,
      :secp384r1,
      :secp521r1
    ].each { |group| sign_and_verify_spec(group) }
  end
end
