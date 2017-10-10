require "./spec_helper"
require "../src/halfsiphash"

describe HalfSipHash(2, 4) do
  key = UInt8.static_array(0, 1, 2, 3, 4, 5, 6, 7)

  it "generates official HalfSipHash2-4 32-bit test vectors" do
    input = uninitialized UInt8[64]
    output = uninitialized UInt8[4]

    64.times do |i|
      input[i] = i.to_u8
      HalfSipHash(2, 4).siphash(input.to_slice[0, i], output.to_slice, key)
      output.should eq(VECTORS_HSIP32[i])
    end
  end

  it "generates official HalfSipHash2-4 64-bit test vectors" do
    input = uninitialized UInt8[64]
    output = uninitialized UInt8[8]

    64.times do |i|
      input[i] = i.to_u8
      HalfSipHash(2, 4).siphash(input.to_slice[0, i], output.to_slice, key)
      output.should eq(VECTORS_HSIP64[i])
    end
  end
end
