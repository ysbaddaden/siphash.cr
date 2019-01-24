# Copyright (c) 2012-2016 Jean-Philippe Aumasson <jeanphilippe.aumasson@gmail.com>
# Copyright (c) 2012-2014 Daniel J. Bernstein <djb@cr.yp.to>
# Copyright (c) 2017 Julien Portalier <julien@portalier.com>
#
# To the extent possible under law, the author(s) have dedicated all copyright
# and related and neighboring rights to this software to the public domain
# worldwide. This software is distributed without any warranty.
#
# You should have received a copy of the CC0 Public Domain Dedication along
# with this software. If not, see
# <http://creativecommons.org/publicdomain/zero/1.0/>.
#
# See also https://131002.net/siphash/

# SipHash is a family of pseudorandom functions optimized for short inputs.
#
# You may choose how many compression-rounds and finalization-rounds to execute.
# For example `SipHash(2, 4)` has been verified to be cryptographically secure,
# whereas `SipHash(1, 3)` is faster but not verified, and should only be used
# when the result is never disclosed (e.g. for table hashing).
#
# See <https://131002.net/siphash/> for more information.
#
# Example:
# ```
# key = uninitialized SipHash::Key
# SecureRandom.random_bytes(key.to_slice)
#
# hash = SipHash(2, 4).siphash("input data", key)
# ```
struct SipHash(CROUNDS, DROUNDS)
  # SipHash uses a 128-bit key.
  alias Key = StaticArray(UInt8, 16)

  def self.siphash(input : Int | Float, key : Key) : UInt64
    size = sizeof(typeof(input))
    bytes = pointerof(input).as(UInt8*).to_slice(size)
    siphash(bytes, key : Key)
  end

  def self.siphash(input : String, key : Key) : UInt64
    siphash(input.to_slice, key)
  end

  def self.siphash(input : Bytes, key : Key) : UInt64
    output = 0_u64
    siphash(input.to_unsafe, input.size, key.to_unsafe, pointerof(output).as(UInt8*), 8)
    output
  end

  def self.siphash(input : Bytes, output : Bytes, key : Key)
    siphash(input.to_unsafe, input.size, key.to_unsafe, output.to_unsafe, output.size)
  end

  # UNSAFE!
  private def self.siphash(input : UInt8*, inlen : Int32, key : UInt8*, output : UInt8*, outlen : Int32)
    raise ArgumentError.new("SipHash can only generate 8 or 16 bytes.") unless {8, 16}.includes?(outlen)

    v0 = 0x736f6d6570736575_u64
    v1 = 0x646f72616e646f6d_u64
    v2 = 0x6c7967656e657261_u64
    v3 = 0x7465646279746573_u64

    k0 = u8to64_le(key)
    k1 = u8to64_le(key + 8)

    stop = input + (inlen - (inlen % 8))
    left = inlen & 7
    b = inlen.to_u64! << 56

    v3 ^= k1
    v2 ^= k0
    v1 ^= k1
    v0 ^= k0

    if outlen == 16
      v1 ^= 0xee
    end

    until input == stop
      m = u8to64_le(input)
      v3 ^= m

      trace
      CROUNDS.times { sipround }

      v0 ^= m
      input += 8
    end

    case left
    when 7
      b |= input[6].to_u64! << 48
      b |= input[5].to_u64! << 40
      b |= input[4].to_u64! << 32
      b |= input[3].to_u64! << 24
      b |= input[2].to_u64! << 16
      b |= input[1].to_u64! << 8
      b |= input[0].to_u64!
    when 6
      b |= input[5].to_u64! << 40
      b |= input[4].to_u64! << 32
      b |= input[3].to_u64! << 24
      b |= input[2].to_u64! << 16
      b |= input[1].to_u64! << 8
      b |= input[0].to_u64!
    when 5
      b |= input[4].to_u64! << 32
      b |= input[3].to_u64! << 24
      b |= input[2].to_u64! << 16
      b |= input[1].to_u64! << 8
      b |= input[0].to_u64!
    when 4
      b |= input[3].to_u64! << 24
      b |= input[2].to_u64! << 16
      b |= input[1].to_u64! << 8
      b |= input[0].to_u64!
    when 3
      b |= input[2].to_u64! << 16
      b |= input[1].to_u64! << 8
      b |= input[0].to_u64!
    when 2
      b |= input[1].to_u64! << 8
      b |= input[0].to_u64!
    when 1
      b |= input[0].to_u64!
    end

    v3 ^= b

    trace
    CROUNDS.times { sipround }

    v0 ^= b

    if outlen == 16
      v2 ^= 0xee
    else
      v2 ^= 0xff
    end

    trace
    DROUNDS.times { sipround }

    b = v0 ^ v1 ^ v2 ^ v3
    u64to8_le(output, b)

    if outlen == 8
      return
    end

    v1 ^= 0xdd

    trace
    DROUNDS.times { sipround }

    b = v0 ^ v1 ^ v2 ^ v3
    u64to8_le(output + 8, b)
  end

  private def self.rotl(x, b) : UInt64
    (x << b) | x >> (64 &- b)
  end

  private def self.u32to8_le(p, v)
    p[0] = v.to_u8!
    p[1] = (v >> 8).to_u8!
    p[2] = (v >> 16).to_u8!
    p[3] = (v >> 24).to_u8!
  end

  private def self.u64to8_le(p, v)
    u32to8_le(p, v.to_u32!)
    u32to8_le(p + 4, (v >> 32).to_u32!)
  end

  private def self.u8to64_le(p)
    p[0].to_u64! | (p[1].to_u64! << 8) |
      (p[2].to_u64! << 16) | (p[3].to_u64! << 24) |
      (p[4].to_u64! << 32) | (p[5].to_u64! << 40) |
      (p[6].to_u64! << 48) | (p[7].to_u64! << 56)
  end

  private macro sipround
    v0 &+= v1
    v1 = rotl(v1, 13)
    v1 ^= v0
    v0 = rotl(v0, 32)
    v2 &+= v3
    v3 = rotl(v3, 16)
    v3 ^= v2
    v0 &+= v3
    v3 = rotl(v3, 21)
    v3 ^= v0
    v2 &+= v1
    v1 = rotl(v1, 17)
    v1 ^= v2
    v2 = rotl(v2, 32)
  end

  private macro trace
    {% if flag?(:DEBUG) %}
    printf("(%3d) v0 %08x %08x\n", inlen, (v0 >> 32).to_u32!, v0.to_u32!)
    printf("(%3d) v1 %08x %08x\n", inlen, (v1 >> 32).to_u32!, v1.to_u32!)
    printf("(%3d) v2 %08x %08x\n", inlen, (v2 >> 32).to_u32!, v2.to_u32!)
    printf("(%3d) v3 %08x %08x\n", inlen, (v3 >> 32).to_u32!, v3.to_u32!)
    {% end %}
  end
end
