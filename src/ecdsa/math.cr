# https://github.com/crystal-lang/crystal/issues/8612
# https://carc.in/#/r/89qh

@[Link("gmp")]
lib LibGMP
  fun mpz_powm_sec = __gmpz_powm_sec(rop : MPZ*, base : MPZ*, exp : MPZ*, mod : MPZ*)
end 

module ECDSA
  module Math
    
    def self.powm(n : BigInt, e : BigInt, p : BigInt) : BigInt
      # This is an implementation of the basic binary method
      # This can be done much more efficiently, cf https://www.youtube.com/watch?v=3Bh7ztqBpmw
    
      a = e.to_s(2).split("").reverse
      d = a.size - 1
    
      # ref[i] = n**(2**i) % p
      # ref = Array(BigInt).new
      # ref << n
      # (1..d).each do |i|
        # ref << (ref[i-1] * ref[i-1]) % p
      # end
    
      # res = BigInt.new(1)
      # (0..d).each do |i|
        # res = (res * ref[i]) % p if a[i] == "1"
      # end 

      res = BigInt.new(1)
      pow = n
      (0..d).each do |i|
        res = (res * pow) % p if a[i] == "1"
        pow = (pow**2) % p
      end 
    
      return res
    end
    
    def self.powm_wrapped(n : BigInt, e : BigInt, p : BigInt) : BigInt
      res = BigInt.new()
      LibGMP.mpz_powm_sec(res, n, e, p)
      return res
    end

    def self.is_quadratic_residue(n : BigInt, p : BigInt) : Bool
      # Euler's criterion
      # https://en.wikipedia.org/wiki/Euler%27s_criterion

      # trivial case
      return true if n % p == 0
      
      # general case
      e = BigInt.new( (p-1).tdiv(2) )
      res = BigInt.new
      LibGMP.mpz_powm_sec(res, n, e, p)
      return true if res == 1
      return false
    end

    def self.square_root(n : BigInt, p : BigInt, even : Bool = true) : BigInt
      # https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm
      # https://github.com/jacksoninfosec/tonelli-shanks/blob/main/tonelli-shanks.py

      # case p|n
      return BigInt.new(0) if n % p == 0 

      # raise exception if there is no root
      raise Exception.new("square_root: #{n} does not have a square root in Z:#{p}") unless is_quadratic_residue(n, p)
      
      # case p % 4 = 3
      if (p % 4 == 3)
        e = BigInt.new( (p+1).tdiv(4) )
        root = BigInt.new
        LibGMP.mpz_powm_sec(root, n, e, p)

        if ( (root % 2 == 0 && even) || (root % 2 == 1 && !even) )
          return root
        else
          return p - root
        end
      end
      
      # case p % 4 = 1
      if (p % 4 == 1)
        raise Exception.new("square_root for p % 4 = 1 : not yet implemented : TODO")
      end

      return BigInt.new(0)

    end  
    
    def self.mod_inverse(a : BigInt, n : BigInt) : BigInt
      # https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Modular_integers

      t, newt = BigInt.new(0), BigInt.new(1)
      r, newr = n, a % n

      while newr > 0
        quotient = r // newr
        t, newt = newt, t - quotient * newt
        r, newr = newr, r - quotient * newr
      end

      raise NotInvertible.new("inverse: #{a} is not invertible in Z:#{n}") if r > 1

      return t % n
    end

    def self.mod_exp(a : BigInt, exp : BigInt, mod : BigInt)
      res = BigInt.new(1)
      while (exp > 0)
        if ((exp & 1) > 0)
          res = (res*a).modulo(mod)
        end
        exp >>= 1
        a = (a*a).modulo(mod)
      end
      return res
    end

    def self.mod_sqrt(a : BigInt, n : BigInt) : BigInt
      # CAUTION: This works ONLY if n is prime but we do not check - We also do not check if a is a quadratic residue
      # https://en.wikipedia.org/wiki/Quadratic_residue
      if n % 4 == 3
        return mod_exp(a, (n + 1) // 4, n)
      end
      raise Exception.new "Not implemented"
    end

    def self.sha3_256(base : Bytes | String) : String
      Digest::SHA3.hexdigest base
    end

    def self.hash(base : Bytes | String) : String
      sha3_256(base)
    end

    def self.bit_length(integer)
      length = 0
      while integer > 0
        length += 1
        integer >>= 1
      end
      length
    end

    def self.normalize_digest(hexdigest : String, bit_length : Int) : BigInt
      hexdigest_bit_size = hexdigest.size * 4 # each hex is 4 bit
      if hexdigest_bit_size > bit_length
        BigInt.new(hexdigest, base: 16) >> (hexdigest_bit_size - bit_length - 1)
      else
        BigInt.new(hexdigest, base: 16)
      end
    end

    def self.random(n1 : BigInt, n2 : BigInt) : BigInt
      r = BigInt.new(1)

      return n1 if n1 == n2
      n1, n2 = n2, n1 if n1 > n2

      # number of bits of (n1..n2)
      bin_length = (n2 - n1).to_s(2).bytesize
      # puts "bin_length of range: #{bin_length}"

      # number of bytes required
      n_bytes = bin_length // 8
      n_bytes += 1 unless bin_length % 8 == 0
      # puts "n_bytes required: #{n_bytes}"
      # puts (n2-n1).to_s(2)

      # get random bytes, convert to binary and cut down size
      s = BigInt.new(Random::Secure.hex(n_bytes), base: 16).to_s(2)[0, bin_length]
      # puts s
      r = n1 + BigInt.new(s, base: 2)
      r = random(n1, n2) if r > n2

      return r
    end
  end
end
