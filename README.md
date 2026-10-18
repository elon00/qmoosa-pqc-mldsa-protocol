# @qmoosa/pqc-mldsa-protocol

**QMOOSA Post-Quantum Cryptography — NIST FIPS 204 ML-DSA Digital Signature Protocol Specification**

Part of the **QMOOSA-1000 Sovereign Web4 Infrastructure Portfolio** (Repository 056 / 1,000, Domain 2: Post-Quantum Cryptography & Zero-Knowledge Reality Gates, Batch 12).

---

## 1. Algorithmic Overview & Standard Specifications

This package implements formal type definitions, data structures, and mathematical validation rules for **Module-Lattice-Based Digital Signature Standard (ML-DSA)** as specified in **NIST FIPS 204 (Initial Release, August 2024)**, derived from the CRYSTALS-Dilithium proposal.

### Parameter Sets

| Parameter Set | Security Category | Matrix Dim ($k \times l$) | Public Key ($pk$) | Secret Key ($sk$) | Signature ($\sigma$) | Primary Use Case |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **ML-DSA-44** | Category 2 (AES-128) | $4 \times 4$ | 1,312 B | 2,560 B | 2,420 B | Lightweight edge devices |
| **ML-DSA-65** | Category 3 (AES-192) | $6 \times 5$ | 1,952 B | 4,032 B | 3,309 B | **Primary Web4 Standard** |
| **ML-DSA-87** | Category 5 (AES-256) | $8 \times 7$ | 2,592 B | 4,896 B | 4,627 B | Settlement roots & Governance |

---

## 2. Invariants & Reality Gates

1. **Exact Byte Length Invariants:** Strict rejection of malformed or non-compliant public keys, secret keys, or signatures.
2. **Deep Freeze Protection:** Runtime configuration structures are deeply frozen to prevent monkey-patching or prototype mutation.
3. **Constant-Time Comparison:** Cryptographic equality checks utilize timing-safe comparisons to eliminate side-channel leakage.

---

## 3. License & Certification Status

- **License:** MIT
- **Production Certification Status:** 0 / 1,000 (Local testnets & research only; locked from mainnet deployment until formal security audit sign-offs).
- **Cost Incurred:** $0.00
