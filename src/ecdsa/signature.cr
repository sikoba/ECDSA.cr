module ECDSA
  class Signature
    getter r : BigInt
    getter s : BigInt
    getter v : Int32

    def initialize(@r : BigInt, @s : BigInt, @v : Int32)
    end

    def ==(other : Signature) : Bool
      s == other.s && r == other.r && v == other.v
    end

    def stringify() : String
      #
      # this is an Ethereum-style signature 
      #
      return "0x#{r.to_s(16).rjust(64, '0')}#{s.to_s(16).rjust(64, '0')}#{(27+v).to_s(16)}"
    end
  end
end