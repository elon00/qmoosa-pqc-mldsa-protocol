/**
 * QMOOSA Post-Quantum Cryptography Specification
 * NIST FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)
 *
 * Parameter definitions, byte lengths, data structures, and mathematical validation
 * for ML-DSA-44, ML-DSA-65, and ML-DSA-87.
 */
import { timingSafeEqual } from 'node:crypto';
/**
 * ML-DSA-44: NIST Security Category 2 (matrix dimension 4x4)
 * Public key: 1312 bytes, Secret key: 2560 bytes, Signature: 2420 bytes
 */
export const ML_DSA_44 = Object.freeze({
    name: 'ML-DSA-44',
    nistCategory: 2,
    k: 4,
    l: 4,
    publicKeyBytes: 1312,
    secretKeyBytes: 2560,
    signatureBytes: 2420,
    description: 'NIST Security Category 2 (equivalent to SHA-256 / AES-128 collision resistance)'
});
/**
 * ML-DSA-65: NIST Security Category 3 (matrix dimension 6x5)
 * Primary recommendation for QMOOSA Web4 transaction authorization.
 * Public key: 1952 bytes, Secret key: 4032 bytes, Signature: 3309 bytes
 */
export const ML_DSA_65 = Object.freeze({
    name: 'ML-DSA-65',
    nistCategory: 3,
    k: 6,
    l: 5,
    publicKeyBytes: 1952,
    secretKeyBytes: 4032,
    signatureBytes: 3309,
    description: 'NIST Security Category 3 (equivalent to AES-192 / SHA-384, primary Web4 standard)'
});
/**
 * ML-DSA-87: NIST Security Category 5 (matrix dimension 8x7)
 * High-security standard for high-value settlement roots and governance anchors.
 * Public key: 2592 bytes, Secret key: 4896 bytes, Signature: 4627 bytes
 */
export const ML_DSA_87 = Object.freeze({
    name: 'ML-DSA-87',
    nistCategory: 5,
    k: 8,
    l: 7,
    publicKeyBytes: 2592,
    secretKeyBytes: 4896,
    signatureBytes: 4627,
    description: 'NIST Security Category 5 (equivalent to AES-256 / SHA-512 maximum security)'
});
export const ML_DSA_REGISTRY = new Map([
    [ML_DSA_44.name, ML_DSA_44],
    [ML_DSA_65.name, ML_DSA_65],
    [ML_DSA_87.name, ML_DSA_87]
]);
export function getMlDsaParameters(name) {
    const params = ML_DSA_REGISTRY.get(name);
    if (!params) {
        throw new Error(`UNSUPPORTED_ML_DSA_PARAMETER_SET: Parameter set "${name}" is not defined in FIPS 204`);
    }
    return params;
}
export function validatePublicKey(pk, params) {
    return pk instanceof Uint8Array && pk.length === params.publicKeyBytes;
}
export function validateSecretKey(sk, params) {
    return sk instanceof Uint8Array && sk.length === params.secretKeyBytes;
}
export function validateSignature(sig, params) {
    return sig instanceof Uint8Array && sig.length === params.signatureBytes;
}
/**
 * Constant-time comparison for byte buffers to prevent timing side channels.
 */
export function constantTimeEqual(a, b) {
    if (a.length !== b.length)
        return false;
    return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
