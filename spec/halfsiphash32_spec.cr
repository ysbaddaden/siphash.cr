require "./spec_helper"
require "../src/halfsiphash32"

describe HalfSipHash32(2, 4) do
  key = UInt8.static_array(0, 1, 2, 3, 4, 5, 6, 7)

  it "generates official HalfSipHash2-4 32-bit test vectors" do
    input = uninitialized UInt8[64]
    output = uninitialized UInt8[4]

    64.times do |i|
      input[i] = i.to_u8

      hasher = HalfSipHash32(2, 4).new(key)
      hasher.update(input.to_slice[0, i])
      hasher.final(output.to_slice)

      output.should eq(VECTORS_HSIP32[i])
    end
  end

  it "generates 32-bit hash in chunks" do
    input = StaticArray(UInt8, 64).new { |i| i.to_u8 }
    expected = uninitialized UInt8[4]
    got = uninitialized UInt8[4]

    hasher = HalfSipHash32(2, 4).new(key)
    hasher.update(input.to_slice)
    hasher.final(expected.to_slice)

    h = HalfSipHash32(2, 4).new(key)
    h.update(input.to_slice[0, 2])    # buffer 2 bytes
    h.update(input.to_slice[2, 6])    # complete to 4 bytes + buffer 2 bytes
    h.update(input.to_slice[8, 1])    # buffer 1 more byte
    h.update(input.to_slice[9, 1])    # complete to 4 bytes + buffer 0 bytes
    h.update(input.to_slice[10, 54])  # push the rest
    h.final(got.to_slice)

    got.should eq(expected)
  end
end
