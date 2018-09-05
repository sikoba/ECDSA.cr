module ECDSA
  class Signature
    getter :r, :s

    def initialize(r : BigInt, s : BigInt)
      @r = r
      @s = s
    end
  end
end