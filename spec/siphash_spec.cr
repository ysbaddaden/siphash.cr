require "./spec_helper"
require "../src/siphash"

describe SipHash(2, 4) do
  key = UInt8.static_array(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)

  it "generates official SipHash2-4 64-bit test vectors" do
    input = uninitialized UInt8[64]
    output = uninitialized UInt8[8]

    64.times do |i|
      input[i] = i.to_u8
      SipHash(2, 4).siphash(input.to_slice[0, i], output.to_slice, key)
      output.should eq(VECTORS_SIP64[i])
    end
  end

  it "generates official SipHash2-4 128-bit test vectors" do
    input = uninitialized UInt8[64]
    output = uninitialized UInt8[16]

    64.times do |i|
      input[i] = i.to_u8
      SipHash(2, 4).siphash(input.to_slice[0, i], output.to_slice, key)
      output.should eq(VECTORS_SIP128[i])
    end
  end
end
