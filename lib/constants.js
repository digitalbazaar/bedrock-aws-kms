/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
export const AWS_MAX_INPUT_BYTE_LENGTH = 4096;
export const AWS_KEY_CONFIG = new Map([
  ['P-256', {
    KeySpec: 'ECC_NIST_P256',
    KeyUsage: 'SIGN_VERIFY',
    SigningAlgorithm: 'ECDSA_SHA_256'
  }],
  ['P-384', {
    KeySpec: 'ECC_NIST_P384',
    KeyUsage: 'SIGN_VERIFY',
    SigningAlgorithm: 'ECDSA_SHA_384'
  }],
  ['Ed25519', {
    KeySpec: 'ECC_NIST_EDWARDS25519',
    KeyUsage: 'SIGN_VERIFY',
    SigningAlgorithm: 'ED25519_SHA_512'
  }],
  ['HS256', {
    KeySpec: 'HMAC_256',
    KeyUsage: 'GENERATE_VERIFY_MAC',
    MacAlgorithm: 'HMAC_SHA_256',
    ExpectedMacByteLength: 32
  }],
  ['AES-256-GCM', {
    KeySpec: 'SYMMETRIC_DEFAULT',
    KeyUsage: 'ENCRYPT_DECRYPT',
    EncryptionAlgorithm: 'SYMMETRIC_DEFAULT'
  }]
]);

export const AWS_KMS_CREATE_GRANT_ACTION = 'kms:CreateGrant';
export const AWS_KMS_DECRYPT_ACTION = 'kms:Decrypt';
export const AWS_KMS_NITRO_PCR0_CONDITION = 'kms:RecipientAttestation:PCR0';
export const AWS_KMS_DEFAULT_NITRO_SID = 'Enable enclave data processing';

export const AWS_KMS_ADMIN_ACTIONS = [
  'kms:CancelKeyDeletion',
  'kms:CreateAlias',
  'kms:DeleteAlias',
  'kms:Describe*',
  'kms:DisableKey',
  'kms:DisableKeyRotation',
  'kms:EnableKey',
  'kms:EnableKeyRotation',
  'kms:Get*',
  'kms:List*',
  'kms:PutKeyPolicy',
  'kms:RevokeGrant',
  'kms:RotateKeyOnDemand',
  'kms:ScheduleKeyDeletion',
  'kms:TagResource',
  'kms:UntagResource',
  'kms:UpdateAlias',
  'kms:UpdateKeyDescription'
];

export const CURVE_TO_JOSE_ALGORITHM_NAME = new Map([
  ['P-256', 'ECDSA'],
  ['P-384', 'ECDSA']
]);

export const KEY_TYPES = {
  asymmetric: new Map([
    ['urn:webkms:multikey:P-256', {
      keyType: 'P-256',
      multicodecPublicKeyHeader: new Uint8Array([0x12, 0x00]),
      contextUrl: 'https://w3id.org/security/multikey/v1'
    }],
    ['urn:webkms:multikey:P-384', {
      keyType: 'P-384',
      multicodecPublicKeyHeader: new Uint8Array([0x12, 0x01]),
      contextUrl: 'https://w3id.org/security/multikey/v1'
    }],
    ['urn:webkms:multikey:Ed25519', {
      keyType: 'Ed25519',
      multicodecPublicKeyHeader: new Uint8Array([0xed, 0x01]),
      contextUrl: 'https://w3id.org/security/suites/multikey/v1'
    }]
  ]),
  keyAgreement: new Map(),
  symmetric: new Map([
    ['Sha256HmacKey2019', {
      keyType: 'HMAC_256',
      contextUrl: 'https://w3id.org/security/suites/hmac-2019/v1'
    }]
  ])
};
