/**
 * QMOOSA Post-Quantum Cryptography Specification
 * NIST FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)
 *
 * Parameter definitions, byte lengths, data structures, and mathematical validation
 * for ML-DSA-44, ML-DSA-65, and ML-DSA-87.
 */
export type MlDsaParameterName = 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';
export interface MlDsaParameters {
    readonly name: MlDsaParameterName;
    readonly nistCategory: number;
    readonly k: number;
    readonly l: number;
    readonly publicKeyBytes: number;
    readonly secretKeyBytes: number;
    readonly signatureBytes: number;
    readonly description: string;
}
/**
 * ML-DSA-44: NIST Security Category 2 (matrix dimension 4x4)
 * Public key: 1312 bytes, Secret key: 2560 bytes, Signature: 2420 bytes
 */
export declare const ML_DSA_44: Readonly<MlDsaParameters>;
/**
 * ML-DSA-65: NIST Security Category 3 (matrix dimension 6x5)
 * Primary recommendation for QMOOSA Web4 transaction authorization.
 * Public key: 1952 bytes, Secret key: 4032 bytes, Signature: 3309 bytes
 */
export declare const ML_DSA_65: Readonly<MlDsaParameters>;
/**
 * ML-DSA-87: NIST Security Category 5 (matrix dimension 8x7)
 * High-security standard for high-value settlement roots and governance anchors.
 * Public key: 2592 bytes, Secret key: 4896 bytes, Signature: 4627 bytes
 */
export declare const ML_DSA_87: Readonly<MlDsaParameters>;
export declare const ML_DSA_REGISTRY: ReadonlyMap<MlDsaParameterName, Readonly<MlDsaParameters>>;
export declare function getMlDsaParameters(name: MlDsaParameterName): Readonly<MlDsaParameters>;
export interface MlDsaKeyPair {
    readonly publicKey: Uint8Array;
    readonly secretKey: Uint8Array;
    readonly parameterSet: MlDsaParameterName;
}
export interface MlDsaSignatureResult {
    readonly signature: Uint8Array;
    readonly parameterSet: MlDsaParameterName;
}
export interface Web4SignedTransactionEnvelope {
    readonly chainId: string;
    readonly nonce: number;
    readonly fromAddress: string;
    readonly toAddress: string;
    readonly value: string;
    readonly payloadHex: string;
    readonly contextString: string;
    readonly parameterSet: MlDsaParameterName;
    readonly publicKeyHex: string;
    readonly signatureHex: string;
    readonly timestamp: number;
}
export declare function validatePublicKey(pk: Uint8Array, params: MlDsaParameters): boolean;
export declare function validateSecretKey(sk: Uint8Array, params: MlDsaParameters): boolean;
export declare function validateSignature(sig: Uint8Array, params: MlDsaParameters): boolean;
/**
 * Constant-time comparison for byte buffers to prevent timing side channels.
 */
export declare function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean;
