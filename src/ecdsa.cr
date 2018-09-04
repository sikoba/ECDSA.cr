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
        p:  BigInt.new("FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFEE37", base: 16),
        a:  BigInt.new("00000000_00000000_00000000_00000000_00000000_00000000", base: 16),
        b:  BigInt.new("00000000_00000000_00000000_00000000_00000000_00000003", base: 16),
        gx: BigInt.new("DB4FF10E_C057E9AE_26B07D02_80B7F434_1DA5D1B1_EAE06C7D", base: 16),
        gy: BigInt.new("9B2F2F6D_9C5628A7_844163D0_15BE8634_4082AA88_D95E2F9D", base: 16),
        n:  BigInt.new("FFFFFFFF_FFFFFFFF_FFFFFFFE_26F2FC17_0F69466A_74DEFD8D", base: 16),
        h:  BigInt.new("00000000_00000000_00000000_00000000_00000000_00000001", base: 16),
      },

    :secp192r1 => {
        p:  BigInt.new("FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFFFF_FFFFFFFF", base: 16),
        a:  BigInt.new("FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFFFF_FFFFFFFC", base: 16),
        b:  BigInt.new("64210519_E59C80E7_0FA7E9AB_72243049_FEB8DEEC_C146B9B1", base: 16),
        gx: BigInt.new("188DA80E_B03090F6_7CBF20EB_43A18800_F4FF0AFD_82FF1012", base: 16),
        gy: BigInt.new("07192B95_FFC8DA78_631011ED_6B24CDD5_73F977A1_1E794811", base: 16),
        n:  BigInt.new("FFFFFFFF_FFFFFFFF_FFFFFFFF_99DEF836_146BC9B1_B4D22831", base: 16),
        h:  BigInt.new("00000000_00000000_00000000_00000000_00000000_00000001", base: 16),
      },
      
    # 224-bit

    :secp224k1 => {
        p:  BigInt.new("FFFFFFFF_FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFE56D", base: 16),
        a:  BigInt.new("00000000_00000000_00000000_00000000_00000000_00000000_00000000", base: 16),
        b:  BigInt.new("00000000_00000000_00000000_00000000_00000000_00000000_00000005", base: 16),
        gx: BigInt.new("A1455B33_4DF099DF_30FC28A1_69A467E9_E47075A9_0F7E650E_B6B7A45C", base: 16),
        gy: BigInt.new("7E089FED_7FBA3442_82CAFBD6_F7E319F7_C0B0BD59_E2CA4BDB_556D61A5", base: 16),
        n:  BigInt.new("00000000_00000000_00000000_0001DCE8_D2EC6184_CAF0A971_769FB1F7", base: 16),
        h:  BigInt.new("00000000_00000000_00000000_00000000_00000000_00000000_00000001", base: 16),
      },

    :secp224r1 => {
        p:  BigInt.new("FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_00000000_00000001", base: 16),
        a:  BigInt.new("FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFE", base: 16),
        b:  BigInt.new("B4050A85_0C04B3AB F5413256 5044B0B7 D7BFD8BA 270B3943 2355FFB4", base: 16),
        gx: BigInt.new("B70E0CBD 6BB4BF7F 321390B9 4A03C1D3 56C21122 343280D6 115C1D21", base: 16),
        gy: BigInt.new("BD376388 B5F723FB 4C22DFE6 CD4375A0 5A074764 44D58199 85007E34", base: 16),
        n:  BigInt.new("FFFFFFFF FFFFFFFF FFFFFFFF FFFF16A2 E0B8F03E 13DD2945 5C5C2A3D", base: 16),
        h:  BigInt.new("00000000_00000000_00000000_00000000_00000000_00000000_00000001", base: 16),
      },

    # 256-bit

    :secp256k1 => {
      p:  BigInt.new("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F", base: 16),
      a:  BigInt.new("00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000", base: 16),
      b:  BigInt.new("00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000007", base: 16),
      gx: BigInt.new("79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798", base: 16),
      gy: BigInt.new("483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8", base: 16),
      n:  BigInt.new("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141", base: 16),
      h:  BigInt.new("00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000001", base: 16),
    },

    :secp256r1 => {
        p:  BigInt.new("FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFF", base: 16),
        a:  BigInt.new("FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFC", base: 16),
        b:  BigInt.new("5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6 3BCE3C3E 27D2604B", base: 16),
        gx: BigInt.new("6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0 F4A13945 D898C296", base: 16),
        gy: BigInt.new("4FE342E2 FE1A7F9B 8EE7EB4A 7C0F9E16 2BCE3357 6B315ECE CBB64068 37BF51F5", base: 16),
        n:  BigInt.new("FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551", base: 16),
        h:  BigInt.new("00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000001", base: 16),
      },
      
    # 384-bit

    :secp384r1 => {
        p:  BigInt.new("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFFFF 00000000 00000000 FFFFFFFF", base: 16),
        a:  BigInt.new("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFFFF 00000000 00000000 FFFFFFFC", base: 16),
        b:  BigInt.new("B3312FA7 E23EE7E4 988E056B E3F82D19 181D9C6E FE814112 0314088F 5013875A C656398D 8A2ED19D 2A85C8ED D3EC2AEF", base: 16),
        gx: BigInt.new("AA87CA22 BE8B0537 8EB1C71E F320AD74 6E1D3B62 8BA79B98 59F741E0 82542A38 5502F25D BF55296C 3A545E38 72760AB7", base: 16),
        gy: BigInt.new("3617DE4A 96262C6F 5D9E98BF 9292DC29 F8F41DBD 289A147C E9DA3113 B5F0B8C0 0A60B1CE 1D7E819D 7A431D7C 90EA0E5F", base: 16),
        n:  BigInt.new("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF C7634D81 F4372DDF 581A0DB2 48B0A77A ECEC196A CCC52973", base: 16),
        h:  BigInt.new("00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000001", base: 16),
      },

    # 512-bit

    :secp521r1 => {
        p:  BigInt.new("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF", base: 16),
        a:  BigInt.new("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFC", base: 16),
        b:  BigInt.new("953EB961 8E1C9A1F 929A21A0 B68540EE A2DA725B 99B315F3 B8B48991 8EF109E1 56193951 EC7E937B 1652C0BD 3BB1BF07 3573DF88 3D2C34F1 EF451FD4 6B503F00", base: 16),
        gx: BigInt.new("", base: 16),
        gy: BigInt.new("39296A78 9A3BC004 5C8A5FB4 2C7D1BD9 98F54449 579B4468 17AFBD17 273E662C 97EE7299 5EF42640 C550B901 3FAD0761 353C7086 A272C240 88BE9476 9FD16650", base: 16),
        n:  BigInt.new("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFA 51868783 BF2F966B 7FCC0148 F709A5D0 3BB5C9B8 899C47AE BB6FB71E 91386409", base: 16),
        h:  BigInt.new("00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000001", base: 16),
      },
      
    :secp224k1 => {
        p:  BigInt.new("", base: 16),
        a:  BigInt.new("", base: 16),
        b:  BigInt.new("", base: 16),
        gx: BigInt.new("", base: 16),
        gy: BigInt.new("", base: 16),
        n:  BigInt.new("", base: 16),
        h:  BigInt.new("", base: 16),
      },    

  }
  
  def self.get_group(c : Symbol)
    raise "Group #{c} not found" unless CURVES.has_key?(c)
    h = CURVES[c]  
    return Group.new(h[:name], h[:p], h[:a], h[:b], h[:gx], h[:gy], h[:n])
  end
  
  # ----- Group -----------------------
  
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
    
