module ECDSA
  module Math
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
      res = BigInt.new(1);
      while (exp > 0)
        if ((exp & 1) > 0)
          res = (res*a).modulo(mod);
        end
        exp >>= 1;
        a = (a*a).modulo(mod)
      end
      return res;
    end
  
    
    def self.mod_sqrt(a : BigInt, n : BigInt) : BigInt
      # CAUTION: This works ONLY if n is prime but we do not check - We also do not check if a is a quadratic residue
      # https://en.wikipedia.org/wiki/Quadratic_residue
      if n % 4 == 3
        return mod_exp(a,(n+1) // 4, n)
      end
      raise Exception.new "Not implemented"
    end

    def self.sha256(base : Bytes | String) : String
      hash = OpenSSL::Digest.new("SHA256")
      hash << base
      hash.hexdigest
    end

    def self.sha3_256(base : Bytes | String) : String
      hash = Digest::SHA3.new(256)
      hash.update(base)
      hash.hexdigest
    end

    def self.hash(base : Bytes | String) : String
      sha256(base)
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
        BigInt.new(hexdigest, base: 16) >> (hexdigest_bit_size - bit_length)
      else
        BigInt.new(hexdigest, base: 16)
      end
    end

    def self.random(n1 : BigInt, n2 : BigInt) : BigInt
      r = BigInt.new(1)

      return n1 if n1 == n2
      n1, n2 = n2, n1 if n1 > n2

      # number of bits of (n1..n2)
      bin_length = (n2-n1).to_s(2).bytesize
      # puts "bin_length of range: #{bin_length}"

      # number of bytes required
      n_bytes = bin_length / 8
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