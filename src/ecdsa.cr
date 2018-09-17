require "./ecdsa/*"

require "big"
require "json"
require "base64"
require "random"
require "openssl"
require "openssl/pkcs5"
require "openssl/digest"
require "sha3"

###############################################################################
#
# ECDSA
#
###############################################################################

module SKO::Math

  def self.mod_inverse(a : BigInt, n : BigInt) : BigInt

    # https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Modular_integers

    t, newt = BigInt.new(0), BigInt.new(1)    
    r, newr = n, a % n
      
    while newr > 0
      quotient = r / newr
      t, newt = newt, t - quotient * newt
      r, newr = newr, r - quotient * newr
    end

    raise "inverse: #{a} is not invertible in Z:#{n}" if r > 1

    return t % n
  end

  def self.sha256(base : Bytes | String) : String
    hash = OpenSSL::Digest.new("SHA256")
    hash << base
    puts hash.inspect
    hash.hexdigest
  end

  def self.sha3_256(base : Bytes | String) : String
    hash = Digest::SHA3.new(256)
    hash.update(base)
    puts hash.inspect
    hash.hexdigest
  end

  def self.hash(base : Bytes | String) : String
    sha256(base)
  end
  
  def self.random(n1 : BigInt, n2 : BigInt) : BigInt
    r = BigInt.new(1)

    return n1 if n1 == n2
    n1, n2 = n2, n1 if n1 > n2
    
    # number of bits of (n1..n2) 
    bin_length = (n2-n1).to_s(2).bytesize
    puts "bin_length of range: #{bin_length}"
    
    # number of bytes required
    n_bytes = bin_length / 8
    n_bytes += 1 unless bin_length % 8 == 0
    puts "n_bytes required: #{n_bytes}"
    puts (n2-n1).to_s(2)
    
    # get random bytes, convert to binary and cut down size
    s = BigInt.new(Random::Secure.hex(n_bytes), base: 16).to_s(2)[0, bin_length]
    puts s
    r = n1 + BigInt.new(s, base: 2)
    r = random(n1, n2) if r > n2

    return r
  end
  
end

###############################################################################
#
# ECDSA
#
###############################################################################
  
module SKO::ECDSA

  CURVES = {
  
    # 192-bit

    :secp192k1 => {
        p:  BigInt.new("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFEE37", base: 16),
        a:  BigInt.new("00000000 00000000 00000000 00000000 00000000 00000000", base: 16),
        b:  BigInt.new("00000000 00000000 00000000 00000000 00000000 00000003", base: 16),
        gx: BigInt.new("DB4FF10E C057E9AE 26B07D02 80B7F434 1DA5D1B1 EAE06C7D", base: 16),
        gy: BigInt.new("9B2F2F6D 9C5628A7 844163D0 15BE8634 4082AA88 D95E2F9D", base: 16),
        n:  BigInt.new("FFFFFFFF FFFFFFFF FFFFFFFE 26F2FC17 0F69466A 74DEFD8D", base: 16),
        h:  BigInt.new("00000000 00000000 00000000 00000000 00000000 00000001", base: 16),
      },

    :secp192r1 => {
        p:  BigInt.new("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFFFF FFFFFFFF", base: 16),
        a:  BigInt.new("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFFFF FFFFFFFC", base: 16),
        b:  BigInt.new("64210519 E59C80E7 0FA7E9AB 72243049 FEB8DEEC C146B9B1", base: 16),
        gx: BigInt.new("188DA80E B03090F6 7CBF20EB 43A18800 F4FF0AFD 82FF1012", base: 16),
        gy: BigInt.new("07192B95 FFC8DA78 631011ED 6B24CDD5 73F977A1 1E794811", base: 16),
        n:  BigInt.new("FFFFFFFF FFFFFFFF FFFFFFFF 99DEF836 146BC9B1 B4D22831", base: 16),
        h:  BigInt.new("00000000 00000000 00000000 00000000 00000000 00000001", base: 16),
      },
      
    # 224-bit

    :secp224k1 => {
        p:  BigInt.new("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFE56D", base: 16),
        a:  BigInt.new("00000000 00000000 00000000 00000000 00000000 00000000 00000000", base: 16),
        b:  BigInt.new("00000000 00000000 00000000 00000000 00000000 00000000 00000005", base: 16),
        gx: BigInt.new("A1455B33 4DF099DF 30FC28A1 69A467E9 E47075A9 0F7E650E B6B7A45C", base: 16),
        gy: BigInt.new("7E089FED 7FBA3442 82CAFBD6 F7E319F7 C0B0BD59 E2CA4BDB 556D61A5", base: 16),
        n:  BigInt.new("00000000 00000000 00000000 0001DCE8 D2EC6184 CAF0A971 769FB1F7", base: 16),
        h:  BigInt.new("00000000 00000000 00000000 00000000 00000000 00000000 00000001", base: 16),
      },

    :secp224r1 => {
        p:  BigInt.new("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 00000000 00000001", base: 16),
        a:  BigInt.new("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFE", base: 16),
        b:  BigInt.new("B4050A85 0C04B3AB F5413256 5044B0B7 D7BFD8BA 270B3943 2355FFB4", base: 16),
        gx: BigInt.new("B70E0CBD 6BB4BF7F 321390B9 4A03C1D3 56C21122 343280D6 115C1D21", base: 16),
        gy: BigInt.new("BD376388 B5F723FB 4C22DFE6 CD4375A0 5A074764 44D58199 85007E34", base: 16),
        n:  BigInt.new("FFFFFFFF FFFFFFFF FFFFFFFF FFFF16A2 E0B8F03E 13DD2945 5C5C2A3D", base: 16),
        h:  BigInt.new("00000000 00000000 00000000 00000000 00000000 00000000 00000001", base: 16),
      },

    # 256-bit

    :secp256k1 => {
      p:  BigInt.new("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F", base: 16),
      a:  BigInt.new("00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000", base: 16),
      b:  BigInt.new("00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000007", base: 16),
      gx: BigInt.new("79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798", base: 16),
      gy: BigInt.new("483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8", base: 16),
      n:  BigInt.new("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141", base: 16),
      h:  BigInt.new("00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001", base: 16),
    },

    :secp256r1 => {
        p:  BigInt.new("FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFF", base: 16),
        a:  BigInt.new("FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFC", base: 16),
        b:  BigInt.new("5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6 3BCE3C3E 27D2604B", base: 16),
        gx: BigInt.new("6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0 F4A13945 D898C296", base: 16),
        gy: BigInt.new("4FE342E2 FE1A7F9B 8EE7EB4A 7C0F9E16 2BCE3357 6B315ECE CBB64068 37BF51F5", base: 16),
        n:  BigInt.new("FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551", base: 16),
        h:  BigInt.new("00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001", base: 16),
      },
      
    # 384-bit

    :secp384r1 => {
        p:  BigInt.new("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFFFF 00000000 00000000 FFFFFFFF", base: 16),
        a:  BigInt.new("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFFFF 00000000 00000000 FFFFFFFC", base: 16),
        b:  BigInt.new("B3312FA7 E23EE7E4 988E056B E3F82D19 181D9C6E FE814112 0314088F 5013875A C656398D 8A2ED19D 2A85C8ED D3EC2AEF", base: 16),
        gx: BigInt.new("AA87CA22 BE8B0537 8EB1C71E F320AD74 6E1D3B62 8BA79B98 59F741E0 82542A38 5502F25D BF55296C 3A545E38 72760AB7", base: 16),
        gy: BigInt.new("3617DE4A 96262C6F 5D9E98BF 9292DC29 F8F41DBD 289A147C E9DA3113 B5F0B8C0 0A60B1CE 1D7E819D 7A431D7C 90EA0E5F", base: 16),
        n:  BigInt.new("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF C7634D81 F4372DDF 581A0DB2 48B0A77A ECEC196A CCC52973", base: 16),
        h:  BigInt.new("00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001", base: 16),
      },

  }
  
  def self.get_group(c : Symbol)
    raise "Group #{c} not found" unless CURVES.has_key?(c)
    h = CURVES[c]  
    return Group.new(c, h[:p], h[:a], h[:b], h[:gx], h[:gy], h[:n])
  end
  
  # ----- Group -----------------------
  
  class Group
  
    include SKO::Math
  
    getter name : Symbol
    getter p  : BigInt
    getter a  : BigInt
    getter b  : BigInt
    getter gx : BigInt
    getter gy : BigInt
    getter n  : BigInt
    
    def initialize(@name : Symbol,
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
      k = BigInt.new(55555)

      # computing r
      cp = g * k
      r = cp.x
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
  
  # ----- Point -----------------------

  class Point
  
    getter group : Group
    getter x : BigInt
    getter y : BigInt
    getter infinity : Bool
  
    def initialize(@group : Group, @x : BigInt, @y : BigInt, @infinity : Bool)
       raise "Point #{x}, #{y} is not in group #{group}" unless is_in_group?
       @x = @x % @group.p
       @y = @y % @group.p
    end

    def p
      @group.p
    end
    
    def a
      @group.a
    end
    
    def b 
      @group.b
    end
    
    def is_in_group? : Bool
      return true if infinity
      (y**2 - x**3 - x*a - b) % p == 0
    end
    
    def check_group!(other : Point)
      raise "Mismatched groups" if other.group != group
    end
    
    def equals?(other : Point) : Bool
      return false unless group == other.group
      return true if infinity && other.infinity
      return true if x == other.x && y == other.y
      return false
    end
    
    def +(other : Point ) : Point
    
      check_group! other
      
      # cases 1 and 2

      return other if infinity
      return self if other.infinity
      
      # case 3: identical x coordinates, points distinct or y-ccordinate 0
      
      if x == other.x && (y + other.y) % p == 0
        return @group.infinity
      end
      
      # case 4:  different x coordinates
      if x != other.x
        lambda = (y - other.y) * @group.inverse(x - other.x, p) % p
        x_new = (lambda**2 - x - other.x) % p
        y_new = (lambda * (x - x_new) - y) % p
        return Point.new(@group, x_new, y_new, false)
      end
      
      # case 5: 
      return self.double if self.equals?(other)
      
      # we should never get here!
      raise "Point addition failed!"
      
    end
    
    def double : Point    
      lambda = (3 * x**2 + a) * @group.inverse(2*y, p) % p
      x_new = (lambda**2 - 2*x) % p
      y_new = (lambda*(x - x_new) - y) % p
      return Point.new(@group, x_new, y_new, false)
    end
    
    def *(i : BigInt) : Point
      res = @group.infinity
      v = self
      
      while i > 0
        res = res + v if i.odd? && !v.is_a?(Nil) && !res.is_a?(Nil)
        v = v.double
        i >>= 1
      end
      
      return res
    end
    
  end  
    
end 
    
