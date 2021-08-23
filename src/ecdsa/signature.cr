module ECDSA
  class Signature
    getter r : BigInt
    getter s : BigInt

    def initialize(@r : BigInt, @s : BigInt)
    end

    def ==(other : Signature) : Bool
      s == other.s && r == other.r
    end

  end
end