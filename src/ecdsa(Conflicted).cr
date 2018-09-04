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
    :Secp256k1 => {
      name: "Secp256k1",
      p:  BigInt.new("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", base: 16),
      a:  BigInt.new("0000000000000000000000000000000000000000000000000000000000000000", base: 16),
      b:  BigInt.new("0000000000000000000000000000000000000000000000000000000000000007", base: 16),
      gx: BigInt.new("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", base: 16),
      gy: BigInt.new("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", base: 16),
      n:  BigInt.new("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", base: 16),
    }
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
    
