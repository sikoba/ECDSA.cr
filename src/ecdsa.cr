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
    return "0x#{hash[-40..-1]}"
  end

end