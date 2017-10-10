require "./spec_helper"
require "../src/siphash64"

describe SipHash64(2, 4) do
  key = UInt8.static_array(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)

  it "generates official SipHash2-4 64-bit test vectors" do
    input = uninitialized UInt8[64]
    output = uninitialized UInt8[8]

    64.times do |i|
      input[i] = i.to_u8

      hasher = SipHash64(2, 4).new(key)
      hasher.update(input.to_slice[0, i])
      hasher.final(output.to_slice)

      output.should eq(VECTORS_SIP64[i])
    end
  end

  it "generates 64-bit hash in chunks" do
    input = StaticArray(UInt8, 64).new { |i| i.to_u8 }
    expected = uninitialized UInt8[8]
    got = uninitialized UInt8[8]

    hasher = SipHash64(2, 4).new(key)
    hasher.update(input.to_slice)
    hasher.final(expected.to_slice)

    h = SipHash64(2, 4).new(key)
    h.update(input.to_slice[0, 4])    # buffer 4 bytes
    h.update(input.to_slice[4, 6])    # complete to 8 bytes + buffer 2 bytes
    h.update(input.to_slice[10, 4])   # buffer 4 more bytes
    h.update(input.to_slice[14, 2])   # complete to 8 bytes + buffer 0 bytes
    h.update(input.to_slice[16, 48])  # push the rest
    h.final(got.to_slice)

    got.should eq(expected)
  end
end
