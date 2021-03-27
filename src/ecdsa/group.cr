module ECDSA
  class Group
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
      
      pre = nil
      if ECDSA::PRECOMPUTED.key?(name)
        pre = Array(ECDSA::Point).new
        d = ECDSA::CURVES[name][:d]
        (0..d).each do |i|
          pre << Point.new(self, ECDSA::PRECOMPUTED[name][i][0], ECDSA::PRECOMPUTED[name][i][1])
        end
      end
        
    end

    def ==( other : ECDSA::Group )
      ( @name == other.name ) &&
      ( @p == other.p ) &&
      ( @a == other.a ) &&
      ( @b == other.b ) &&
      ( @gx == other.gx ) &&
      ( @gy == other.gy ) &&
      ( @n == other.n )
    end

    def g
      Point.new(self, @gx, @gy)
    end

    def infinity
      Point.new(self, true)
    end

    def create_key_pair
      secret_key = ECDSA::Math.random(BigInt.new(1), n - 1)
      create_key_pair(secret_key)
    end

    def create_key_pair(secret_key : BigInt) : NamedTuple(secret_key: BigInt, public_key: Point)
      {
        secret_key: secret_key,
        public_key: create_public_key(secret_key),
      }
    end

    def create_public_key(secret_key : BigInt) : Point
      g * secret_key
    end

    def sign(secret_key : BigInt, message : String) : Signature
      # inputs (k should not be used twice)
      temp_key_k = ECDSA::Math.random(BigInt.new(1), n-1)
      sign(secret_key, message, temp_key_k)
    end

    def sign(secret_key : BigInt, e : BigInt) : Signature
      # inputs (k should not be used twice)
      temp_key_k = ECDSA::Math.random(BigInt.new(1), n-1)
      sign(secret_key, e, temp_key_k)
    end

    def sign(secret_key : BigInt, e : BigInt, temp_key_k : BigInt) : Signature
      # computing r
      curve_point = g * temp_key_k
      r = curve_point.x % n
      return sign(secret_key, e) if r == 0

      # computing s
      s = (inverse(temp_key_k, n) * (e + secret_key * r)) % n
      return sign(secret_key, e) if s == 0

      Signature.new(r: r, s: s)
    end

    def sign(secret_key : BigInt, message : String, temp_key_k : BigInt) : Signature
      # https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
      hash = ECDSA::Math.hash(message)

      # leftmost part of hash
      e = ECDSA::Math.normalize_digest(hash, ECDSA::Math.bit_length(p))

      sign(secret_key, e, temp_key_k)
    end

    def verify(public_key : Point, message : String, signature : Signature)
      verify(public_key, message, signature.r, signature.s)
    end

    def verify(public_key : Point, e : BigInt, signature : Signature)
      verify(public_key, e, signature.r, signature.s)
    end

    def verify(public_key : Point, e : BigInt, r : BigInt, s : BigInt) : Bool
      raise SignatureNotInRange.new unless (1...n).covers?(r) && (1...n).covers?(s)
      raise PublicKeyIsInfinity.new if public_key.infinity
      raise PointNotInGroup.new unless public_key.group == self && public_key.is_in_group?
      raise "Did not result in infinity" if public_key * n != Point.new(self, true)

      c = inverse(s, n)

      u1 = (e * c) % n
      u2 = (r * c) % n
      xy = (g * u1) + (public_key * u2)

      v = xy.x % n
      v == r
    end

    def verify(public_key : Point, message : String, r : BigInt, s : BigInt) : Bool
      hash = ECDSA::Math.hash(message)
      # leftmost part of hash
      verify(public_key, ECDSA::Math.normalize_digest(hash, ECDSA::Math.bit_length(p)), r, s)
    end

    def inverse(n1 : BigInt, n2 : BigInt)
      ECDSA::Math.mod_inverse(n1, n2)
    end
  end
end

