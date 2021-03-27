require "base64"

# Defines the padding to use based on the SHA-3 function domain.
private class Domain
  SHA3  = 6u8
  SHAKE = 1u8 # Keccak[3]
end

class Digest::SHA3
  def self.digest(string_or_bytes : String | Bytes) : Bytes
    context = self.new
    context.update(string_or_bytes)
    context.result
  end

  def self.hexdigest(string_or_slice : String | Bytes) : String
    digest(string_or_slice).hexstring
  end

  def self.base64digest(string_or_slice : String | Bytes) : String
    Base64.strict_encode(digest(string_or_slice).to_slice)
  end

  def hexdigest : String
    result.hexstring
  end

  HASH_SIZES = Int32.static_array(224, 256, 384, 512)

  DOMAIN = Domain::SHA3

  def initialize(hash_size = 512)
    unless HASH_SIZES.includes? hash_size
      raise "Invalid hash size: #{hash_size}. Must be one of #{HASH_SIZES.join(',')}"
    end

    @input = uninitialized Bytes
    @size = UInt32.new(hash_size / 8)
  end

  # Ruby-style method names
  def update(s : String)
    update(s.to_slice)
  end

  def update(s : Bytes)
    @input = s
    self
  end

  # Crystal-style method name
  def input(s)
    update(s)
  end

  def reset
    @input.clear
    self
  end

  def result
    state = Pointer(UInt64).malloc(25_u64)
    width = 200 - @size * 2

    padding_size  = width - @input.size % width
    buffer_size   = @input.size + padding_size

    # Initialize and fill buffer with the input string
    buffer = Pointer(UInt8).malloc(buffer_size)
    buffer.copy_from(@input.to_unsafe, @input.size)

    # Set the first padded bit
    # Regarding the assignment: https://github.com/crystal-lang/crystal/issues/3241
    buffer[@input.size] = {% begin %}{{@type.id}}::DOMAIN{% end %}

    # Zero-pad the buffer up to the message width
    (buffer + @input.size + 1).clear(padding_size)

    # Set the final bit of padding to 0x80
    buffer[buffer_size-1] = (buffer[buffer_size-1] | 0x80)

    state_size = width // 8
    (0..buffer_size-1).step(width) do |j|
      state_size.times do |i|
        state[i] ^= (buffer + j).as(UInt64*)[i]
      end

      keccak(state)
    end

    # Return the result
    state.as(UInt8*).to_slice(@size)
  end

  private def keccak(state : Pointer(UInt64))
    lanes = Pointer(UInt64).malloc(5_u64)

    macro_keccak
  end

  private def rotl64(x : UInt64, y : Int32)
    (x << y | x >> 64 - y)
  end


  private macro macro_keccak
    {% for round in (0..23) %}
      theta
      rho_pi
      chi
      iota({{round}})
    {% end %}
  end

  private macro theta
    lanes[0] = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20]
    lanes[1] = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21]
    lanes[2] = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22]
    lanes[3] = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23]
    lanes[4] = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24]

    {% for i in (0..4) %}
      t = lanes[{{(i + 4) % 5}}] ^ rotl64(lanes[{{(i + 1) % 5}}], 1)
      state[{{i     }}] ^= t
      state[{{i +  5}}] ^= t
      state[{{i + 10}}] ^= t
      state[{{i + 15}}] ^= t
      state[{{i + 20}}] ^= t
    {% end %}
  end

  private macro rho_pi
    # The reverse of their usual order so that this loop can be optimised a bit.
    {%
      rotc = [
        44, 20, 61, 39, 18, 62, 43, 25, 8,  56, 41, 27,
        14, 2,  55, 45, 36, 28, 21, 15, 10, 6,  3,  1
      ]
      piln = [
        1, 6,  9,  22, 14, 20, 2, 12, 13, 19, 23, 15,
        4, 24, 21, 8,  16, 5,  3, 18, 17, 11, 7,  10
      ]
    %}

    s1 = state[1]
    {% for i in (0..23) %}
      {% if i < 23 %}
        state[{{piln[i]}}] = rotl64(state[{{piln[i + 1]}}], {{rotc[i]}})
      {% else %}
        state[{{piln[i]}}] = rotl64(s1, {{rotc[i]}})
      {% end %}
    {% end %}
  end

  private macro chi
    # Loop for (0..24).step(5)
    {% for i in [0, 5, 10, 15, 20] %}
      state_i   = state[{{i    }}]
      state_i_1 = state[{{i + 1}}]

      state[{{i    }}] ^= (~state_i_1)        & state[{{i + 2}}]
      state[{{i + 1}}] ^= (~state[{{i + 2}}]) & state[{{i + 3}}]
      state[{{i + 2}}] ^= (~state[{{i + 3}}]) & state[{{i + 4}}]
      state[{{i + 3}}] ^= (~state[{{i + 4}}]) & state_i
      state[{{i + 4}}] ^= (~state_i)          & state_i_1
    {% end %}
  end

  private macro iota(round)
    {% rndc = [
      0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
      0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
      0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
      0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
      0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
      0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
      0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
      0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    ] %}
    state[0] ^= {{rndc[round]}}
  end
end

class Digest::Keccak3 < Digest::SHA3
  DOMAIN = Domain::SHAKE
end
