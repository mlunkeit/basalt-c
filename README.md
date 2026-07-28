# Basalt 🪨

**Basalt** is a lightweight, zero-dependency C library implementing fundamental cryptographic primitives and arbitrary-precision arithmetic from scratch. Built for education, high control, and deep architectural understanding.

> [!CAUTION]
> Do NOT use this in production. This library was built for educational purposes only. Make sure to **NEVER** use your
> own crypto.

---

## 🛠️ Features & Current Status

* **SHA-256, SHA-512:** Fully standard-compliant (FIPS PUB 180-4) implementation.
* **Arbitrary-Precision Arithmetic (BigInt):** Basic 256-bit+ integer arithmetic (Addition, Subtraction, Multiplication).
* **Modular Arithmetic & Reduction:** Optimized Barrett reduction for fast modular operations.
* **Elliptic Curve Arithmetic (`secp256k1, secp256r1`):** Point addition, point doubling, and scalar multiplication ($k \cdot P$) using jacobian coordinates.
* **RFC 6979:** Deterministic Nonce Generation with HMAC-SHA256
* **ECDSA:** Signing and verification

### 🚧 Roadmap
* [ ] **ECDSA:** Key generation (SEC1 33-byte compressed format)
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
mkdir build && cd build
cmake ..
make

# Run unit tests
./run_tests