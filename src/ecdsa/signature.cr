module ECDSA
  class Signature
    getter r : BigInt
    getter s : BigInt

    def initialize(@r : BigInt, @s : BigInt)
    end
  end
end