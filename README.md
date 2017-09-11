# SipHash

Crystal implementation of SipHash and HalfSipHash.

## Usage

```crystal
require "secure_random"
require "siphash"

key = SecureRandom.random_bytes(16)

# generate a 64-bit hash:
hash = SipHash(2, 4).siphash("some data", key)

# generate a 128-bit hash:
hash = Bytes.new(16)
SipHash(2, 4).siphash("some data", hash, key)
```

## License

Distributed under the Apache 2.0 license.

## Credits

Created by:
- Jean-Philippe Aumasson
- Daniel J. Bernstein

Ported by:
- Julien Portalier

