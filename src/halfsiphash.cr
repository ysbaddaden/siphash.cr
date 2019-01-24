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

# An alternative `SipHash` pseudorandom function that uses a 64-bit key and
# generates 32-bit or 64-bit hashes, meant for 32-bit platforms. On 64-bit
# platform we advise to use `SipHash` instead.
#
# While `SipHash(2, 4)` has been analyzed and verified to be cryptographically
# secure, `HalfSipHash` has not, and isn't expected to be. Results from the
# hasher should never be disclosed (e.g. use for table hashing on 32-bit).
#
# See <https://131002.net/siphash/> for more information.
#
# Example:
# ```
# key = uninitialized HalfSipHash::Key
# SecureRandom.random_bytes(key.to_slice)
#
# hash = HalfSipHash(2, 4).siphash("input data", key)
# ```
struct HalfSipHash(CROUNDS, DROUNDS)
  # HalfSipHash uses a 64-bit key.
  alias Key = StaticArray(UInt8, 8)

  def self.siphash(input : Int | Float, key : Key) : UInt32
    bytes = pointerof(input).as(UInt8*).to_slice(sizeof(typeof(input)))
    siphash(bytes, key : Key)
  end

  def self.siphash(input : String, key : Key) : UInt32
    siphash(input.to_slice, key)
  end

  def self.siphash(input : Bytes, key : Key) : UInt32
    output = 0_u32
    siphash(input.to_unsafe, input.size, key.to_unsafe, pointerof(output).as(UInt8*), 4)
    output
  end

  def self.siphash(input : Bytes, output : Bytes, key : Key)
    siphash(input.to_unsafe, input.size, key.to_unsafe, output.to_unsafe, output.size)
  end

  # UNSAFE!
  private def self.siphash(input : UInt8*, inlen : Int32, key : UInt8*, output : UInt8*, outlen : Int32)
    raise ArgumentError.new("HalfSipHash can only generate 4 or 8 bytes.") unless {4, 8}.includes?(outlen)

    v0 = 0_u32
    v1 = 0_u32
    v2 = 0x6c796765_u32
    v3 = 0x74656462_u32

    k0 = u8to32_le(key)
    k1 = u8to32_le(key + 4)

    stop = input + (inlen - (inlen % 4))
    left = inlen & 3
    b = inlen.to_u32 << 24

    v3 ^= k1
    v2 ^= k0
    v1 ^= k1
    v0 ^= k0

    if outlen == 8
      v1 ^= 0xee
    end

    until input == stop
      m = u8to32_le(input)
      v3 ^= m

      trace
      CROUNDS.times { sipround }

      v0 ^= m
      input += 4
    end

    case left
    when 3
      b |= input[2].to_u32! << 16
      b |= input[1].to_u32! << 8
      b |= input[0].to_u32!
    when 2
      b |= input[1].to_u32! << 8
      b |= input[0].to_u32!
    when 1
      b |= input[0].to_u32!
    end

    v3 ^= b

    trace
    CROUNDS.times { sipround }

    v0 ^= b

    if outlen == 8
      v2 ^= 0xee
    else
      v2 ^= 0xff
    end

    trace
    DROUNDS.times { sipround }

    b = v1 ^ v3
    u32to8_le(output, b)

    if outlen == 4
      return
    end

    v1 ^= 0xdd

    trace
    DROUNDS.times { sipround }

    b = v1 ^ v3
    u32to8_le(output + 4, b)
  end

  private def self.rotl(x, b)
    (x << b) | x >> (32 &- b)
  end

  private def self.u32to8_le(p, v)
    p[0] = v.to_u8!
    p[1] = (v >> 8).to_u8!
    p[2] = (v >> 16).to_u8!
    p[3] = (v >> 24).to_u8!
  end

  private def self.u8to32_le(p)
    p[0].to_u32! |
      (p[1].to_u32! << 8) |
      (p[2].to_u32! << 16) |
      (p[3].to_u32! << 24)
  end

  private macro sipround
    v0 &+= v1
    v1 = rotl(v1, 5)
    v1 ^= v0
    v0 = rotl(v0, 16)
    v2 &+= v3
    v3 = rotl(v3, 8)
    v3 ^= v2
    v0 &+= v3
    v3 = rotl(v3, 7)
    v3 ^= v0
    v2 &+= v1
    v1 = rotl(v1, 13)
    v1 ^= v2
    v2 = rotl(v2, 16)
  end

  private macro trace
    {% if flag?(:DEBUG) %}
    printf("(%3d) v0 %08x\n", inlen, v0.to_u32!)
    printf("(%3d) v1 %08x\n", inlen, v1.to_u32!)
    printf("(%3d) v2 %08x\n", inlen, v2.to_u32!)
    printf("(%3d) v3 %08x\n", inlen, v3.to_u32!)
    {% end %}
  end
end
