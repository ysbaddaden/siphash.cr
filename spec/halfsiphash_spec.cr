require "../src/halfsiphash"
require "spec"

describe HalfSipHash24 do
  vectors_hsip32 = [
    UInt8.static_array(0xa9, 0x35, 0x9f, 0x5b),
    UInt8.static_array(0x27, 0x47, 0x5a, 0xb8),
    UInt8.static_array(0xfa, 0x62, 0xa6, 0x03),
    UInt8.static_array(0x8a, 0xfe, 0xe7, 0x04),
    UInt8.static_array(0x2a, 0x6e, 0x46, 0x89),
    UInt8.static_array(0xc5, 0xfa, 0xb6, 0x69),
    UInt8.static_array(0x58, 0x63, 0xfc, 0x23),
    UInt8.static_array(0x8b, 0xcf, 0x63, 0xc5),
    UInt8.static_array(0xd0, 0xb8, 0x84, 0x8f),
    UInt8.static_array(0xf8, 0x06, 0xe7, 0x79),
    UInt8.static_array(0x94, 0xb0, 0x79, 0x34),
    UInt8.static_array(0x08, 0x08, 0x30, 0x50),
    UInt8.static_array(0x57, 0xf0, 0x87, 0x2f),
    UInt8.static_array(0x77, 0xe6, 0x63, 0xff),
    UInt8.static_array(0xd6, 0xff, 0xf8, 0x7c),
    UInt8.static_array(0x74, 0xfe, 0x2b, 0x97),
    UInt8.static_array(0xd9, 0xb5, 0xac, 0x84),
    UInt8.static_array(0xc4, 0x74, 0x64, 0x5b),
    UInt8.static_array(0x46, 0x5b, 0x8d, 0x9b),
    UInt8.static_array(0x7b, 0xef, 0xe3, 0x87),
    UInt8.static_array(0xe3, 0x4d, 0x10, 0x45),
    UInt8.static_array(0x61, 0x3f, 0x62, 0xb3),
    UInt8.static_array(0x70, 0xf3, 0x67, 0xfe),
    UInt8.static_array(0xe6, 0xad, 0xb8, 0xbd),
    UInt8.static_array(0x27, 0x40, 0x0c, 0x63),
    UInt8.static_array(0x26, 0x78, 0x78, 0x75),
    UInt8.static_array(0x4f, 0x56, 0x7b, 0x5f),
    UInt8.static_array(0x3a, 0xb0, 0xe6, 0x69),
    UInt8.static_array(0xb0, 0x64, 0x40, 0x00),
    UInt8.static_array(0xff, 0x67, 0x0f, 0xb4),
    UInt8.static_array(0x50, 0x9e, 0x33, 0x8b),
    UInt8.static_array(0x5d, 0x58, 0x9f, 0x1a),
    UInt8.static_array(0xfe, 0xe7, 0x21, 0x12),
    UInt8.static_array(0x33, 0x75, 0x32, 0x59),
    UInt8.static_array(0x6a, 0x43, 0x4f, 0x8c),
    UInt8.static_array(0xfe, 0x28, 0xb7, 0x29),
    UInt8.static_array(0xe7, 0x5c, 0xc6, 0xec),
    UInt8.static_array(0x69, 0x7e, 0x8d, 0x54),
    UInt8.static_array(0x63, 0x68, 0x8b, 0x0f),
    UInt8.static_array(0x65, 0x0b, 0x62, 0xb4),
    UInt8.static_array(0xb6, 0xbc, 0x18, 0x40),
    UInt8.static_array(0x5d, 0x07, 0x45, 0x05),
    UInt8.static_array(0x24, 0x42, 0xfd, 0x2e),
    UInt8.static_array(0x7b, 0xb7, 0x86, 0x3a),
    UInt8.static_array(0x77, 0x05, 0xd5, 0x48),
    UInt8.static_array(0xd7, 0x52, 0x08, 0xb1),
    UInt8.static_array(0xb6, 0xd4, 0x99, 0xc8),
    UInt8.static_array(0x08, 0x92, 0x20, 0x2e),
    UInt8.static_array(0x69, 0xe1, 0x2c, 0xe3),
    UInt8.static_array(0x8d, 0xb5, 0x80, 0xe5),
    UInt8.static_array(0x36, 0x97, 0x64, 0xc6),
    UInt8.static_array(0x01, 0x6e, 0x02, 0x04),
    UInt8.static_array(0x3b, 0x85, 0xf3, 0xd4),
    UInt8.static_array(0xfe, 0xdb, 0x66, 0xbe),
    UInt8.static_array(0x1e, 0x69, 0x2a, 0x3a),
    UInt8.static_array(0xc6, 0x89, 0x84, 0xc0),
    UInt8.static_array(0xa5, 0xc5, 0xb9, 0x40),
    UInt8.static_array(0x9b, 0xe9, 0xe8, 0x8c),
    UInt8.static_array(0x7d, 0xbc, 0x81, 0x40),
    UInt8.static_array(0x7c, 0x07, 0x8e, 0xc5),
    UInt8.static_array(0xd4, 0xe7, 0x6c, 0x73),
    UInt8.static_array(0x42, 0x8f, 0xcb, 0xb9),
    UInt8.static_array(0xbd, 0x83, 0x99, 0x7a),
    UInt8.static_array(0x59, 0xea, 0x4a, 0x74),
  ]

  vectors_hsip64 = [
    UInt8.static_array(0x21, 0x8d, 0x1f, 0x59, 0xb9, 0xb8, 0x3c, 0xc8),
    UInt8.static_array(0xbe, 0x55, 0x24, 0x12, 0xf8, 0x38, 0x73, 0x15),
    UInt8.static_array(0x06, 0x4f, 0x39, 0xef, 0x7c, 0x50, 0xeb, 0x57),
    UInt8.static_array(0xce, 0x0f, 0x1a, 0x45, 0xf7, 0x06, 0x06, 0x79),
    UInt8.static_array(0xd5, 0xe7, 0x8a, 0x17, 0x5b, 0xe5, 0x2e, 0xa1),
    UInt8.static_array(0xcb, 0x9d, 0x7c, 0x3f, 0x2f, 0x3d, 0xb5, 0x80),
    UInt8.static_array(0xce, 0x3e, 0x91, 0x35, 0x8a, 0xa2, 0xbc, 0x25),
    UInt8.static_array(0xff, 0x20, 0x27, 0x28, 0xb0, 0x7b, 0xc6, 0x84),
    UInt8.static_array(0xed, 0xfe, 0xe8, 0x20, 0xbc, 0xe4, 0x85, 0x8c),
    UInt8.static_array(0x5b, 0x51, 0xcc, 0xcc, 0x13, 0x88, 0x83, 0x07),
    UInt8.static_array(0x95, 0xb0, 0x46, 0x9f, 0x06, 0xa6, 0xf2, 0xee),
    UInt8.static_array(0xae, 0x26, 0x33, 0x39, 0x94, 0xdd, 0xcd, 0x48),
    UInt8.static_array(0x7b, 0xc7, 0x1f, 0x9f, 0xae, 0xf5, 0xc7, 0x99),
    UInt8.static_array(0x5a, 0x23, 0x52, 0xd7, 0x5a, 0x0c, 0x37, 0x44),
    UInt8.static_array(0x3b, 0xb1, 0xa8, 0x70, 0xea, 0xe8, 0xe6, 0x58),
    UInt8.static_array(0x21, 0x7d, 0x0b, 0xcb, 0x4e, 0x81, 0xc9, 0x02),
    UInt8.static_array(0x73, 0x36, 0xaa, 0xd2, 0x5f, 0x7b, 0xf3, 0xb5),
    UInt8.static_array(0x37, 0xad, 0xc0, 0x64, 0x1c, 0x4c, 0x4f, 0x6a),
    UInt8.static_array(0xc9, 0xb2, 0xdb, 0x2b, 0x9a, 0x3e, 0x42, 0xf9),
    UInt8.static_array(0xf9, 0x10, 0xe4, 0x80, 0x20, 0xab, 0x36, 0x3c),
    UInt8.static_array(0x1b, 0xf5, 0x2b, 0x0a, 0x6f, 0xee, 0xa7, 0xdb),
    UInt8.static_array(0x00, 0x74, 0x1d, 0xc2, 0x69, 0xe8, 0xb3, 0xef),
    UInt8.static_array(0xe2, 0x01, 0x03, 0xfa, 0x1b, 0xa7, 0x76, 0xef),
    UInt8.static_array(0x4c, 0x22, 0x10, 0xe5, 0x4b, 0x68, 0x1d, 0x73),
    UInt8.static_array(0x70, 0x74, 0x10, 0x45, 0xae, 0x3f, 0xa6, 0xf1),
    UInt8.static_array(0x0c, 0x86, 0x40, 0x37, 0x39, 0x71, 0x40, 0x38),
    UInt8.static_array(0x0d, 0x89, 0x9e, 0xd8, 0x11, 0x29, 0x23, 0xf0),
    UInt8.static_array(0x22, 0x6b, 0xf5, 0xfa, 0xb8, 0x1e, 0xe1, 0xb8),
    UInt8.static_array(0x2d, 0x92, 0x5f, 0xfb, 0x1e, 0x00, 0x16, 0xb5),
    UInt8.static_array(0x36, 0x19, 0x58, 0xd5, 0x2c, 0xee, 0x10, 0xf1),
    UInt8.static_array(0x29, 0x1a, 0xaf, 0x86, 0x48, 0x98, 0x17, 0x9d),
    UInt8.static_array(0x86, 0x3c, 0x7f, 0x15, 0x5c, 0x34, 0x11, 0x7c),
    UInt8.static_array(0x28, 0x70, 0x9d, 0x46, 0xd8, 0x11, 0x62, 0x6c),
    UInt8.static_array(0x24, 0x84, 0x77, 0x68, 0x1d, 0x28, 0xf8, 0x9c),
    UInt8.static_array(0x83, 0x24, 0xe4, 0xd7, 0x52, 0x8f, 0x98, 0x30),
    UInt8.static_array(0xf9, 0xef, 0xd4, 0xe1, 0x3a, 0xea, 0x6b, 0xd8),
    UInt8.static_array(0x86, 0xd6, 0x7a, 0x40, 0xec, 0x42, 0x76, 0xdc),
    UInt8.static_array(0x3f, 0x62, 0x92, 0xec, 0xcc, 0xa9, 0x7e, 0x35),
    UInt8.static_array(0xcb, 0xd9, 0x2e, 0xe7, 0x24, 0xd4, 0x21, 0x09),
    UInt8.static_array(0x36, 0x8d, 0xf6, 0x80, 0x8d, 0x40, 0x3d, 0x79),
    UInt8.static_array(0x5b, 0x38, 0xc8, 0x1c, 0x67, 0xc8, 0xae, 0x4c),
    UInt8.static_array(0x95, 0xab, 0x71, 0x89, 0xd4, 0x39, 0xac, 0xb3),
    UInt8.static_array(0xa9, 0x1a, 0x52, 0xc0, 0x25, 0x32, 0x70, 0x24),
    UInt8.static_array(0x5b, 0x00, 0x87, 0xc6, 0x95, 0x28, 0xac, 0xea),
    UInt8.static_array(0x1e, 0x30, 0xf3, 0xad, 0x27, 0xdc, 0xb1, 0x5a),
    UInt8.static_array(0x69, 0x7f, 0x5c, 0x9a, 0x90, 0x32, 0x4e, 0xd4),
    UInt8.static_array(0x49, 0x5c, 0x0f, 0x99, 0x55, 0x57, 0xdc, 0x38),
    UInt8.static_array(0x94, 0x27, 0x20, 0x2a, 0x3c, 0x29, 0xf9, 0x4d),
    UInt8.static_array(0xa9, 0xea, 0xa8, 0xc0, 0x4b, 0xa9, 0x3e, 0x3e),
    UInt8.static_array(0xee, 0xa4, 0xc1, 0x73, 0x7d, 0x01, 0x12, 0x18),
    UInt8.static_array(0x91, 0x2d, 0x56, 0x8f, 0xd8, 0xf6, 0x5a, 0x49),
    UInt8.static_array(0x56, 0x91, 0x95, 0x96, 0xb0, 0xff, 0x5c, 0x97),
    UInt8.static_array(0x02, 0x44, 0x5a, 0x79, 0x98, 0xf5, 0x50, 0xe1),
    UInt8.static_array(0x86, 0xec, 0x46, 0x6c, 0xe7, 0x1d, 0x1f, 0xb2),
    UInt8.static_array(0x35, 0x95, 0x69, 0xe7, 0xd2, 0x89, 0xe3, 0xbc),
    UInt8.static_array(0x87, 0x1b, 0x05, 0xca, 0x62, 0xbb, 0x7c, 0x96),
    UInt8.static_array(0xa1, 0xa4, 0x92, 0xf9, 0x42, 0xf1, 0x5f, 0x1d),
    UInt8.static_array(0x12, 0xec, 0x26, 0x7f, 0xf6, 0x09, 0x5b, 0x6e),
    UInt8.static_array(0x5d, 0x1b, 0x5e, 0xa1, 0xb2, 0x31, 0xd8, 0x9d),
    UInt8.static_array(0xd8, 0xcf, 0xb4, 0x45, 0x3f, 0x92, 0xee, 0x54),
    UInt8.static_array(0xd6, 0x76, 0x28, 0x90, 0xbf, 0x26, 0xe4, 0x60),
    UInt8.static_array(0x31, 0x35, 0x63, 0xa4, 0xb7, 0xed, 0x5c, 0xf3),
    UInt8.static_array(0xf9, 0x0b, 0x3a, 0xb5, 0x72, 0xd4, 0x66, 0x93),
    UInt8.static_array(0x2e, 0xa6, 0x3c, 0x71, 0xbf, 0x32, 0x60, 0x87),
  ]

  key = UInt8.static_array(0, 1, 2, 3, 4, 5, 6, 7)

  it "generates official HalfSipHash2-4 64-bit test vectors" do
    input = uninitialized UInt8[64]
    output = uninitialized UInt8[4]

    64.times do |i|
      input[i] = i.to_u8
      HalfSipHash24.siphash(input.to_slice[0, i], output.to_slice, key)
      output.should eq(vectors_hsip32[i])
    end
  end

  it "generates official HalfSipHash2-4 128-bit test vectors" do
    input = uninitialized UInt8[64]
    output = uninitialized UInt8[8]

    64.times do |i|
      input[i] = i.to_u8
      HalfSipHash24.siphash(input.to_slice[0, i], output.to_slice, key)
      output.should eq(vectors_hsip64[i])
    end
  end
end