module ECDSA
  class Group
    getter name : Symbol
    getter p : BigInt
    getter a : BigInt
    getter b : BigInt
    getter gx : BigInt
    getter gy : BigInt
    getter n : BigInt
    getter d : Int32
    getter use_pre : Bool
    getter cached : Hash(ECDSA::Point, Array(ECDSA::Point))

    def initialize(@name : Symbol,
                   @p : BigInt,
                   @a : BigInt,
                   @b : BigInt,
                   @gx : BigInt,
                   @gy : BigInt,
                   @n : BigInt,
                   @use_pre : Bool = true)
      @d = ECDSA::Math.bit_length(p)
      @cached = Hash(ECDSA::Point, Array(ECDSA::Point)).new

      if @use_pre
        if PRECOMPUTED.has_key?(@name)
          ary = Array(ECDSA::Point).new
          (0..@d - 1).each do |i|
            ary << Point.new(self, PRECOMPUTED[@name][i][0], PRECOMPUTED[@name][i][1])
          end
          @cached[self.g] = ary
        else
          @cached[self.g] = self.precompute_g
        end
      end
    end

    def precompute_g
      ary = Array(ECDSA::Point).new
      pt = self.g
      (0..@d - 1).each do |i|
        ary << pt
        pt = pt.slow_mul(2)
      end
      ary
    end

    def add_to_cache(pt : ECDSA::Point)
      return if @cached.has_key?(pt)

      ptc = pt
      # ptc = Point.new(self, pt.x, pt.y)

      ary = Array(ECDSA::Point).new
      (0..@d - 1).each do |i|
        ary << ptc
        ptc = ptc.slow_mul(2)
      end
      @cached[pt] = ary
    end

    def remove_from_cache(pt : ECDSA::Point)
      return unless @cached.has_key?(pt)
      return if pt == self.g
      @cached.delete(pt)
    end

    def ==(other : ECDSA::Group)
      (@name == other.name) &&
        (@p == other.p) &&
        (@a == other.a) &&
        (@b == other.b) &&
        (@gx == other.gx) &&
        (@gy == other.gy) &&
        (@n == other.n)
    end

    def g
      Point.new(self, @gx, @gy)
    end

    def infinity
      Point.new(self, true)
    end

    #
    # key generatiom
    #

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

    #
    # sign
    #

    def sign(secret_key : BigInt, message : String) : Signature
      temp_key_k = ECDSA::Math.random(BigInt.new(1), n - 1)
      sign(secret_key, message, temp_key_k)
    end

    def sign(secret_key : BigInt, e : BigInt) : Signature
      temp_key_k = ECDSA::Math.random(BigInt.new(1), n - 1)
      sign(secret_key, e, temp_key_k)
    end

    def sign(secret_key : BigInt, message : String, temp_key_k : BigInt) : Signature
      hash = Digest::SHA256.hexdigest(message)
      e = ECDSA::Math.normalize_digest(hash, ECDSA::Math.bit_length(p)) # leftmost part
      sign(secret_key, e, temp_key_k)
    end

    def sign_sha3_256(secret_key : BigInt, message : String) : Signature
      hash = ECDSA::Math.sha3_256(message)
      e = ECDSA::Math.normalize_digest(hash, ECDSA::Math.bit_length(p))
      temp_key_k = ECDSA::Math.random(BigInt.new(1), n - 1)
      sign(secret_key, e, temp_key_k)
    end

    def sign(secret_key : BigInt, e : BigInt, temp_key_k : BigInt) : Signature
      # https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm

      # computing r
      curve_point = g * temp_key_k
      r = curve_point.x % n
      return sign(secret_key, e) if r == 0

      # computing s
      s = (inverse(temp_key_k, n) * (e + secret_key * r)) % n
      return sign(secret_key, e) if s == 0

      Signature.new(r: r, s: s)
    end

    #
    # verify
    #

    def verify(public_key : Point, message : String, signature : Signature, check = true)
      verify(public_key, message, signature.r, signature.s, check)
    end

    def verify(public_key : Point, e : BigInt, signature : Signature, check = true)
      verify(public_key, e, signature.r, signature.s, check)
    end

    def verify(public_key : Point, message : String, r : BigInt, s : BigInt, check = true) : Bool
      hash = Digest::SHA256.hexdigest(message)
      verify(public_key, ECDSA::Math.normalize_digest(hash, ECDSA::Math.bit_length(p)), r, s, check)
    end

    def verify_sha3_256(public_key : Point, message : String, r : BigInt, s : BigInt, check = true) : Bool
      hash = ECDSA::Math.sha3_256(message)
      verify(public_key, ECDSA::Math.normalize_digest(hash, ECDSA::Math.bit_length(p)), r, s, check)
    end

    def verify_sha3_256_plain(public_key : Point, hash : String, signature : Signature)
      verify(public_key, ECDSA::Math.normalize_digest(hash, ECDSA::Math.bit_length(p)), signature.r, signature.s, check)
    end

    def verify(public_key : Point, e : BigInt, r : BigInt, s : BigInt, check = true) : Bool
      raise SignatureNotInRange.new unless (1...n).covers?(r) && (1...n).covers?(s)

      if (check)
        raise PublicKeyIsInfinity.new if public_key.infinity
        raise PointNotInGroup.new unless public_key.group == self && public_key.is_in_group?
        raise "Did not result in infinity" if public_key * n != Point.new(self, true)
      end

      c = inverse(s, n)

      u1 = (e * c) % n
      u2 = (r * c) % n
      xy = (g * u1) + (public_key * u2)

      v = xy.x % n
      v == r
    end

    #
    # inverse
    #

    def inverse(n1 : BigInt, n2 : BigInt)
      ECDSA::Math.mod_inverse(n1, n2)
    end
  end
end
