module SKO::ECDSA
  class Group
    include SKO::Math

    getter name : String
    getter p  : BigInt
    getter a  : BigInt
    getter b  : BigInt
    getter gx : BigInt
    getter gy : BigInt
    getter n  : BigInt

    def initialize(@name : String,
                   @p : BigInt,
                   @a : BigInt,
                   @b : BigInt,
                   @gx : BigInt,
                   @gy : BigInt,
                   @n : BigInt)
    end

    def g
      Point.new(self, @gx, @gy, false)
    end

    def infinity
      Point.new(self, BigInt.new, BigInt.new, true)
    end

    def create_key_pair
      random_key = Random::Secure.hex(32)
      secret_key = BigInt.new(random_key, base: 16)

      secret_key_hex = secret_key.to_s(16)
      return create_key_pair if secret_key_hex.hexbytes? == nil || secret_key_hex.size != 64

      key_pair = create_key_pair(secret_key)

      x = key_pair[:public_key].x.to_s(16)
      y = key_pair[:public_key].y.to_s(16)

      if x.hexbytes? == nil || y.hexbytes? == nil
        return create_key_pair
      end

      if x.size != 64 || y.size != 64
        return create_key_pair
      end

      key_pair
    end

    def create_key_pair(secret_key : BigInt)
      public_key = g * secret_key
      {
        secret_key: secret_key,
        public_key: public_key,
      }
    end

    def inverse(n1 : BigInt, n2 : BigInt)
      SKO::Math.mod_inverse(n1, n2)
    end

    def sign(secret_key : BigInt, message : String) : Array(BigInt)

      # https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm

      r = BigInt.new(0)
      s = BigInt.new(0)

      # inputs (k should not be used twice)
      hash = BigInt.new(SKO::Math.hash(message), base: 16)
      k = SKO::Math.random(BigInt.new(1), n-1)

      # computing r
      curve_point = g * k
      r = curve_point.x
      return sign(secret_key, message) if r == 0

      # computing s
      s = (inverse(k, n) * (hash + secret_key * r)) % n
      return sign(secret_key, message) if s == 0

      [r, s]
    end

    def verify(public_key : Point, message : String, r : BigInt, s : BigInt) : Bool

      # some verifications of input params??

      hash = BigInt.new(SKO::Math.hash(message), base: 16)

      c = inverse(s, n)

      u1 = (hash * c) % n
      u2 = (r * c) % n
      xy = (g * u1) + (public_key * u2)

      v = xy.x % n
      v == r
    end
  end
end