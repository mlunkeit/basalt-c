# Basalt 🪨

**Basalt** is a lightweight, zero-dependency C library implementing fundamental cryptographic primitives and arbitrary-precision arithmetic from scratch. Built for education, high control, and deep architectural understanding.

> [!CAUTION]
> Do NOT use this in production. This library was built for educational purposes only. Make sure to **NEVER** use your
> own crypto.

---

## 🛠️ Features & Current Status

* **SHA-256, SHA-512:** Fully standard-compliant (FIPS PUB 180-4) implementation.
* **RIPEMD-160:** Functioning implementation 
* **Arbitrary-Precision Arithmetic (BigInt):** Basic 256-bit+ integer arithmetic (Addition, Subtraction, Multiplication).
* **Modular Arithmetic & Reduction:** Optimized Barrett reduction for fast modular operations.
* **Elliptic Curve Arithmetic (`secp256k1, secp256r1`):** Point addition, point doubling, and scalar multiplication ($k \cdot P$) using jacobian coordinates.
* **RFC 6979:** Deterministic Nonce Generation with HMAC-SHA256
* **ECDSA:** Signing and verification
* **PBKDF2:** RFC-2898 compliant password-based key derivation
* **BIP-32 & BIP-39:** Standard-compliant mnemonic generator and key derivation function
* **Base58:** Conversion from bytes to base58 and back.

### 🚧 Roadmap
* [ ] **Key serialization and deserialization:** Working with `xpub` and `xprv` formatted keys
* [ ] **Schnorr / BIP-340:** X-only public keys (32 bytes) & Schnorr signatures for Bitcoin/Taproot

---

## 🚀 Quick Start

### Prerequisites
* A C23-compliant C compiler (`gcc`, `clang`, or MSVC)
* `CMake` (or your preferred build runner)

### Building & Running Tests

```bash
# Clone the repository
git clone https://github.com/mlunkeit/basalt-c.git
cd Basalt

# Build project and test suite
cmake -B build
cmake --build build

# Run unit tests
cd build
./run_tests
```

## Examples

### Generating an ECDSA signature

```c++
#include <stdint.h>

#include <basalt/ecdsa.h>
#include <basalt/sha.h>

uint8_t message[12] = "Hello World!";

uint8_t hash[32]; // SHA-256 generates a 256-bit (32-byte) hash
if (basalt_sha256(hash, message, 12) != 0) {
    // handle error
}

// (private key generation is not ready yet)
basalt_ecdsa_private_key_t privkey = ...

basalt_ecdsa_signature_t sig;
if (basalt_ecdsa_sign(BASALT_CURVE_SECP256K1, &sig, &privkey, hash, 32) != 0) {
    // handle error
}
```

### Verifying an ECDSA signature

```c++
#include <stdint.h>

#include <basalt/ecdsa.h>
#include <basalt/sha.h>

uint8_t message[12] = "Hello World!";

uint8_t hash[32];
if (basalt_sha256(hash, message, 12) != 0) {
    // handle error
}

// retrieve the public key and the signature
basalt_ecdsa_public_key_t pubkey = ...
basalt_ecdsa_signature_t sig = ...

if (basalt_ecdsa_verify(BASALT_CURVE_SECP256K1, &pubkey, hash, 32, &sig) != 0) {
    // handle error
}
```