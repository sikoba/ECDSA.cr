module ECDSA
  class Signature
    getter r : BigInt
    getter s : BigInt
    getter even_y : Bool
    getter lowered_s : Bool

    def initialize(@r : BigInt, @s : BigInt, @even_y : Bool, @lowered_s : Bool)
    end

    def ==(other : Signature) : Bool
      s == other.s && r == other.r && v == other.v
    end

    def v() : Int32
      return 0 if even_y ^ lowered_s
      return 1
    end

    def stringify(i : Int32 = 27) : String
      #
      # this is an Ethereum-style signature
      #
      # note that EIP-155 specifies "CHAIN_ID * 2 + 35/36" instead of "27/28",
      # but the old version of the signature remains valid
      #
      return "0x#{r.to_s(16).rjust(64, '0')}#{s.to_s(16).rjust(64, '0')}#{(i + self.v).to_s(16)}"
    end
  end
end