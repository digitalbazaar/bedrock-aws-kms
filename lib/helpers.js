
/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import * as ecdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import {CURVE_TO_JOSE_ALGORITHM_NAME} from './constants.js';
import {webcrypto} from 'node:crypto';

const BYTE_LENGTH_P256_KEY = 32;
const BYTE_LENGTH_P384_KEY = 48;

export async function awsPublicKeyToMultikey({awsPublicKey, keyType}) {
  const algorithmName = CURVE_TO_JOSE_ALGORITHM_NAME.get(keyType);
  if(!algorithmName) {
    throw new Error(`Algorithm does not exist for key type: "${keyType}"`);
  }
  const algorithm = {name: algorithmName, namedCurve: keyType};
  const cryptoKey = await webcrypto.subtle.importKey(
    'spki', awsPublicKey, algorithm, true, ['verify']);

  const jwk = await webcrypto.subtle.exportKey('jwk', cryptoKey);

  if(algorithmName === 'ECDSA') {
    const multikey = await ecdsaMultikey.fromJwk({jwk});

    return multikey;
  }

  throw new Error(`"${algorithmName}" is not supported.`);
}

export function derToP1363({signature, keyType}) {
  if(!(signature instanceof Uint8Array)) {
    throw new Error('Input must be a Uint8Array.');
  }

  let pos = 0;

  function parseLength() {
    const initialPos = pos;
    let length = signature[pos++];

    // DER length octet (8 bits):
    //   - Short form: 1 octet. Bit 8 is "0" and bits 7-1 are the length.
    //   - Long form: 2-127 octets. Bit 8 of the first octet is "1" and bits 7-1
    //     give the number of length octets. The subsequent octets give the
    //     length.

    // Check if the first bit is "0" (short form)
    if(!(length & 0x80)) { // 0x80 -> 10000000 in binary
      return {length, bytesRead: pos - initialPos};
    }

    // If the first bit is "1" (long form):
    // The lower 7 bits give the number of length octets
    const numberOfBytes = length & 0x7F; // 0x7F -> 01111111 in binary
    length = 0;

    // Compute the length using the subsequent length octets
    // Assume numberOfBytes is 3 and the next bytes are 0x12, 0x34, and 0x56
    // Initially: length = 0
    //
    // Iteration 1:
    // length = (0 << 8) | 0x12 = 0x00 | 0x12 = 0x12
    //           00000000  | 00010010 = 00010010
    //
    // Iteration 2:
    // length = (0x12 << 8) | 0x34 = 0x1200 | 0x34 = 0x1234
    //           00010010 00000000  | 00110100 = 00010010 00110100
    //
    // Iteration 3:
    // length = (0x1234 << 8) | 0x56 = 0x123400 | 0x56 = 0x123456
    //       00010010 00110100 00000000  | 01010110 = 00010010 00110100 01010110
    for(let i = 0; i < numberOfBytes; i++) {
      length = (length << 8) | signature[pos++];
    }
    return {length, bytesRead: pos - initialPos};
  }

  function parseInteger() {
    if(signature[pos++] !== 0x02) { // Check for integer tag (0x02)
      throw new Error('Expected integer tag.');
    }
    const {length: intLength} = parseLength();
    // Prevent overrun
    if(pos + intLength > signature.length) {
      throw new Error('Integer length exceeds remaining signature length.');
    }
    const intValue = signature.slice(pos, pos + intLength);
    pos += intLength;
    return intValue;
  }

  // Check for sequence tag (0x30)
  if(signature[pos++] !== 0x30) {
    throw new Error('Expected sequence tag.');
  }

  const {length: sequenceLength, bytesRead} = parseLength();
  // 1 (sequence tag) + # of bytes to describe sequence length (bytesRead) +
  //   sequence length (sequenceLength) = signature size
  if(1 + bytesRead + sequenceLength !== signature.length) {
    throw new Error('Invalid size.');
  }

  // Parse r and s values
  let r = parseInteger();
  let s = parseInteger();

  // Remove leading zeros if present
  const expectedKeyLength = _getKeyLengthBytes(keyType);

  _ensureValidSignatureComponentSize({component: r, expectedKeyLength});
  _ensureValidSignatureComponentSize({component: s, expectedKeyLength});

  if(r.length > expectedKeyLength) {
    r = _removeLeadingZeros(r);
  }
  if(s.length > expectedKeyLength) {
    s = _removeLeadingZeros(s);
  }

  // Pad r and s to expectedKeyLength
  r = _padToLength(r, expectedKeyLength);
  s = _padToLength(s, expectedKeyLength);

  // Concatenate r and s
  const concatenated = new Uint8Array(expectedKeyLength * 2);
  concatenated.set(r, 0); // Set r at the beginning
  concatenated.set(s, expectedKeyLength); // Set s after r
  return concatenated;
}

function _removeLeadingZeros(value) {
  let startIndex = 0;
  while(startIndex < value.length && value[startIndex] === 0) {
    startIndex++;
  }
  return value.slice(startIndex);
}

function _getKeyLengthBytes(keyType) {
  if(keyType === 'P-256') {
    return BYTE_LENGTH_P256_KEY;
  }
  if(keyType === 'P-384') {
    return BYTE_LENGTH_P384_KEY;
  }

  throw new Error(`Unsupported operation key type: "${keyType}.`);
}

function _padToLength(value, length) {
  if(value.length < length) {
    const padded = new Uint8Array(length);
    padded.set(value, length - value.length);
    return padded;
  }
  return value;
}

export function p1363ToDer(signature) {
  function intToDer(int) {
    // Remove leading zeros
    while(int.length > 1 && int[0] === 0) {
      int = int.slice(1);
    }

    // Check if the first byte is >= 0x80 (128 in decimal)
    // If so, prepend a zero byte to ensure it's positive
    if(int[0] >= 0x80) {
      int = Uint8Array.from([0].concat(Array.from(int)));
    }

    // Return the DER encoding of the integer
    // Format: 0x02 (integer tag), length of the integer, integer bytes
    return Uint8Array.from([0x02, int.length].concat(Array.from(int)));
  }

  let n;
  // Determine the curve used by the length of the signature
  if(signature.length === BYTE_LENGTH_P256_KEY * 2) {
    // P-256 curve
    n = BYTE_LENGTH_P256_KEY;
  } else if(signature.length === BYTE_LENGTH_P384_KEY * 2) {
    // P-384 curve
    n = BYTE_LENGTH_P384_KEY;
  } else {
    throw new Error('Invalid signature length.');
  }

  // Split the P1363 signature into r and s components
  const r = signature.slice(0, n);
  const s = signature.slice(n);

  // Convert r and s components to DER format
  const rDer = intToDer(r);
  const sDer = intToDer(s);

  // Calculate the total length of the DER encoded sequence
  const derLength = rDer.length + sDer.length;
  // Determine the length encoding
  // Short form if length < 0x80 (128 in decimal)
  // Long form if length >= 0x80
  const derLengthBytes = derLength < 0x80 ? [derLength] : [0x81, derLength];

  // Construct the final DER encoded signature
  // Format: 0x30 (sequence tag), length, r component, s component
  return Uint8Array.from([0x30].concat(
    derLengthBytes, Array.from(rDer), Array.from(sDer)));
}

function _ensureValidSignatureComponentSize({component, expectedKeyLength}) {
  if(component.length >= 0 && component.length <= expectedKeyLength + 1) {
    return;
  }

  const msg = 'Invalid signature component size. ' +
    `Expected: "${expectedKeyLength}" Actual: "${component.length}"`;
  throw new Error(msg);
}
