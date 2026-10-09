/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {createHash} from 'node:crypto';

// keyType => hash algorithm for signing / verifying; not every keyType
// digests `verifyData` prior to signing (e.g., Ed25519 does not)
const HASH_ALGORITHMS = new Map([
  ['P-256', 'sha256'],
  ['P-384', 'sha384'],
  ['P-256K', 'sha256']
]);

export async function hash({keyType, data}) {
  const hashAlgorithm = HASH_ALGORITHMS.get(keyType);
  if(!hashAlgorithm) {
    // no hashing for the given keyType
    return {
      type: 'RAW', // matches AWS KMS casing for `MessageType`
      data
    };
  }
  return {
    type: 'DIGEST', // matches AWS KMS casing for `MessageType`
    data: createHash(hashAlgorithm).update(data).digest()
  };
}
