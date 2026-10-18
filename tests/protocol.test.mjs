import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ML_DSA_44,
  ML_DSA_65,
  ML_DSA_87,
  ML_DSA_REGISTRY,
  getMlDsaParameters,
  validatePublicKey,
  validateSecretKey,
  validateSignature,
  constantTimeEqual
} from '../dist/index.js';

test('Protocol: Parameter Set Exact Byte Length Invariants per FIPS 204', () => {
  // ML-DSA-44: Category 2
  assert.equal(ML_DSA_44.k, 4);
  assert.equal(ML_DSA_44.l, 4);
  assert.equal(ML_DSA_44.publicKeyBytes, 1312);
  assert.equal(ML_DSA_44.secretKeyBytes, 2560);
  assert.equal(ML_DSA_44.signatureBytes, 2420);

  // ML-DSA-65: Category 3 (Primary)
  assert.equal(ML_DSA_65.k, 6);
  assert.equal(ML_DSA_65.l, 5);
  assert.equal(ML_DSA_65.publicKeyBytes, 1952);
  assert.equal(ML_DSA_65.secretKeyBytes, 4032);
  assert.equal(ML_DSA_65.signatureBytes, 3309);

  // ML-DSA-87: Category 5
  assert.equal(ML_DSA_87.k, 8);
  assert.equal(ML_DSA_87.l, 7);
  assert.equal(ML_DSA_87.publicKeyBytes, 2592);
  assert.equal(ML_DSA_87.secretKeyBytes, 4896);
  assert.equal(ML_DSA_87.signatureBytes, 4627);
});

test('Protocol: Deep Freeze Immutability Protection', () => {
  assert.ok(Object.isFrozen(ML_DSA_44));
  assert.ok(Object.isFrozen(ML_DSA_65));
  assert.ok(Object.isFrozen(ML_DSA_87));

  assert.throws(() => {
    // @ts-ignore
    ML_DSA_65.publicKeyBytes = 9999;
  });
});

test('Protocol: Registry Resolution & Negative Rejection', () => {
  assert.equal(getMlDsaParameters('ML-DSA-44').name, 'ML-DSA-44');
  assert.equal(getMlDsaParameters('ML-DSA-65').name, 'ML-DSA-65');
  assert.equal(getMlDsaParameters('ML-DSA-87').name, 'ML-DSA-87');

  // @ts-ignore
  assert.throws(() => getMlDsaParameters('ML-DSA-INVALID'), /UNSUPPORTED_ML_DSA_PARAMETER_SET/);
});

test('Protocol: Buffer Validation Helpers', () => {
  const pkValid = new Uint8Array(1952);
  const pkInvalid = new Uint8Array(100);
  assert.equal(validatePublicKey(pkValid, ML_DSA_65), true);
  assert.equal(validatePublicKey(pkInvalid, ML_DSA_65), false);

  const skValid = new Uint8Array(4032);
  const skInvalid = new Uint8Array(200);
  assert.equal(validateSecretKey(skValid, ML_DSA_65), true);
  assert.equal(validateSecretKey(skInvalid, ML_DSA_65), false);

  const sigValid = new Uint8Array(3309);
  const sigInvalid = new Uint8Array(300);
  assert.equal(validateSignature(sigValid, ML_DSA_65), true);
  assert.equal(validateSignature(sigInvalid, ML_DSA_65), false);
});

test('Protocol: Constant-Time Comparison Timing Safety', () => {
  const a = new Uint8Array([10, 20, 30, 40]);
  const b = new Uint8Array([10, 20, 30, 40]);
  const c = new Uint8Array([10, 20, 30, 41]);
  const d = new Uint8Array([10, 20, 30]);

  assert.equal(constantTimeEqual(a, b), true);
  assert.equal(constantTimeEqual(a, c), false);
  assert.equal(constantTimeEqual(a, d), false);
});
