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