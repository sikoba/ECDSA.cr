require "./ecdsa/*"
require "./ecdsa/exceptions/*"

require "big"
require "random"
require "openssl"
require "openssl/pkcs5"
require "openssl/digest"
require "sha3"

module ECDSA
  def self.get_group(c : Symbol)
    raise "Group #{c} not found" unless CURVES.has_key?(c)
    h = CURVES[c]
    return Group.new(c.to_s, h[:p], h[:a], h[:b], h[:gx], h[:gy], h[:n])
  end
end