# SipHash

Crystal implementation of SipHash and HalfSipHash, a family of pseudorandom
functions optimized for short inputs.

See <https://131002.net/siphash/> for more information on the algorithms.


## SipHash

You may choose how many compression-rounds and finalization-rounds to execute.
Be wary about your use cases; `SipHash(2, 4)` has been verified to be
cryptographically secure for example, whereas `SipHash(1, 3)` is faster but not
verified, and should only be used when the result is never disclosed (e.g. for
table hashing).

```crystal
require "secure_random"
require "siphash"

key = uninitialized SipHash::Key
SecureRandom.random_bytes(key.to_slice)

# generate a 64-bit hash:
hash = SipHash(2, 4).siphash("some data", key)
# => UInt64

# generate a 128-bit hash:
hash = Bytes.new(16)
SipHash(2, 4).siphash("some data", hash, key)
```

You may alternatively hash a streaming input as you read it. This implies a
slight performance hit, and may only generate 64-bit hashes. This is still
useful when you don't know the complete input beforehand, or the input is
scaterred from different places.

```crystal
require "secure_random"
require "siphash/siphash64"

key = uninitialized SipHash64::Key
SecureRandom.random_bytes(key.to_slice)

hasher = SipHash64(2, 4).new(key)
hasher.update("some data")
hash = hasher.final # => UInt64
```


### HalfSipHash

An alternative `SipHash` pseudorandom function that uses a 64-bit key and
generates 32-bit or 64-bit hashes, meant for 32-bit platforms. On 64-bit
platform we advise to use `SipHash` instead.

While `SipHash(2, 4)` has been analyzed and verified to be cryptographically
secure, `HalfSipHash` has not, and isn't expected to be. Results from the
hasher should never be disclosed (e.g. use for table hashing on 32-bit).

```crystal
require "secure_random"
require "siphash/halfsiphash"

key = uninitialized HalfSipHash::Key
SecureRandom.random_bytes(key.to_slice)

# generate a 32-bit hash:
hash = HalfSipHash(2, 4).siphash("some data", key)
# => UInt32

# generate a 64-bit hash:
hash = Bytes.new(8)
HalfSipHash(2, 4).siphash("some data", hash, key)
```

A streaming version is also available, limited to 32-bit hashes:

```crystal
require "secure_random"
require "siphash/halfsiphash32"

key = uninitialized HalfSipHash32::Key
SecureRandom.random_bytes(key.to_slice)

hasher = HalfSipHash32(2, 4).new(key)
hasher.update("some data")
hash = hasher.final # => UInt32
```


## License

Distributed under the Apache 2.0 license.


## Credits

Created by:
- Jean-Philippe Aumasson
- Daniel J. Bernstein

Ported by:
- Julien Portalier

