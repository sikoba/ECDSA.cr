require "spec"
require "../src/ecdsa"

macro create_key_pair_spec(group_name, secret_key, public_key_x, public_key_y)
  it do
    group = ECDSA.get_group {{ group_name }}

    key_pair = group.create_key_pair {{ secret_key }}

    key_pair[:secret_key].should eq {{ secret_key }}
    key_pair[:public_key].should eq ECDSA::Point.new(group, {{ public_key_x }}, {{ public_key_y }})
  end
end

macro sign_spec(group_name, message, secret_key, temp_key, s, r)
  it do
    message     = {{ message }}
    group       = ECDSA.get_group {{ group_name }}
    secret_key  = {{ secret_key }}
    temp_key    = {{ temp_key }}

    signature = group.sign(secret_key, message, temp_key)

    signature.should eq ECDSA::Signature.new(
      s: {{ s }},
      r: {{ r }}
    )
  end
end

macro verify_spec(group_name, message, s, r, public_key_x, public_key_y, result)
  it "returns {{ result }}" do
    message   = {{ message }}
    group     = ECDSA.get_group {{ group_name }}
    signature = ECDSA::Signature.new(
      s: {{ s }},
      r: {{ r }}
    )
    public_key = ECDSA::Point.new(
      group: group,
      x: {{ public_key_x }},
      y: {{ public_key_y }}
    )

    group.verify(public_key, message, signature).should eq {{ result }}
  end
end