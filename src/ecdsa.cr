require "./ecdsa/*"
require "./ecdsa/exceptions/*"

require "big"
require "random"
require "digest/sha256"
require "./sha3/*"
require "./sha3/digest/*"

module ECDSA

  def self.get_group(c : Symbol, pre = true)
    raise "Group #{c} not found" unless CURVES.has_key?(c)
    h = CURVES[c]
    return Group.new(c, h[:p], h[:a], h[:b], h[:gx], h[:gy], h[:n], pre)
  end
  
  def self.eth_address(pub_key : Point) : String
    #
    # the point needs to be on secp256k1, we do not check for this
    #
    # Keccak256 is applied to the full public key without leading "04"
    # Note that we hash a slice of bytes and not a string, hence ".hexbytes"
    # cf "Input type" in https://emn178.github.io/online-tools/keccak_256.html
    #
    # The last 40 nibbles (last 20 bytes) of the hash are the Ethereum address 
    #
    hash = Digest::Keccak.hexdigest pub_key.hex_full.hexbytes
    address = hash[-40..-1]
    return eth_address_to_mixed_case(address)
  end

  def self.eth_address_to_mixed_case(address : String) : String
    #
    # implements Mixed-case checksum address encoding as per:
    #
    # https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md
    #
    # the address must be a 40-byte hex string (with or without leading 0x)
    #
    address_normalised = address.gsub(/^0x/,"").downcase
    hash = Digest::Keccak.hexdigest address_normalised

    a = address_normalised.chars
    (0..39).each do |i|
      a[i] = a[i].upcase if hash[i].to_i(16) >= 8
    end
    
    return "0x#{a.join}"
  end


  # Ethereum Signature Verification
  #
  # This function verifies if a data string has been signed by a given Ethereum address
  # Cf https://web3js.readthedocs.io/en/v1.2.11/web3-eth-personal.html#sign
  #
  # Note that Ethereum uses determnistic signatures as per RFC 6979
  # which means that the signature will always be the same
  #
  # We expect the signature to have length 130, consisting of:
  #
  # 0..63 : hex value of r
  # 64..127 : hex value of s
  # 128..129 : "1b"/"1c" (Metamask) or "00"/"01" (Ledger) for even/odd y value
  #
  # Signatures of length 132, starting with 0x, are also acceptable
  #
  # To obtain a signature, for example in the Firefox browser console (F12)
  # when web3 has been initialised and an account is connected, the command is:
  # > account = "0x.....";
  # > web3.eth.personal.sign("Hello, world!", account, "").then(console.log);

  def self.verify_ethereum_signature(data : String, signature : String, eth_account : String) : Bool
    g = ECDSA.get_group :secp256k1
    sig = signature.gsub(/^0x/, "")
    res = Digest::Keccak.hexdigest "\u0019Ethereum Signed Message:\n#{data.size}#{data}"
    h = BigInt.new(res, base: 16)
    r = BigInt.new(sig[0..63], base: 16)
    s = BigInt.new(sig[64..127], base: 16)
    even = sig[128..129] =~ /1b|00/ ? true : false
    public_key = g.recover_public_key(h, r, s, even)
    eth_recovered = ECDSA.eth_address(public_key)
    return true if eth_recovered.downcase == eth_account.downcase
    return false
  end

end