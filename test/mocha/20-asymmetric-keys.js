/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import * as base64url from 'base64url-universal';
import * as brAwsKms from '@bedrock/aws-kms';
import * as ecdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import * as helpers from '@bedrock/aws-kms/lib/helpers.js';
import {
  Ed25519VerificationKey2020
} from '@digitalbazaar/ed25519-verification-key-2020';
import {webcrypto} from 'node:crypto';

describe('asymmetric keys', () => {
  const tests = [
    {type: 'urn:webkms:multikey:P-256', keyType: 'P-256'},
    {type: 'urn:webkms:multikey:P-384', keyType: 'P-384'}
    // {type: 'urn:webkms:multikey:Ed25519', keyType: 'Ed25519'},
  ];
  let kms;
  before(() => {
    kms = brAwsKms.getClient({name: 'test'});
  });

  for(const {keyType, type} of tests) {
    describe(type, () => {
      describe('generateKey API', () => {
        it('should generate a key', async () => {
          const result = await kms.generateKey({keyType});

          should.exist(result);
          result.should.be.an('object');
          should.exist(result.amazonResourceName);
          should.exist(result.publicKey);
        });
      }); // end generateKey API

      describe('sign/verify API', () => {
        it('successfully signs data', async () => {
          const {amazonResourceName, publicKey} = await kms.generateKey({
            keyType
          });

          const data = webcrypto.getRandomValues(new Uint8Array(32));

          let err;
          let result;
          try {
            result = await kms.sign({
              amazonResourceName, data, keyType
            });
          } catch(e) {
            err = e;
          }
          should.not.exist(err);
          should.exist(result);
          result.should.be.an('object');
          should.exist(result.signature);
          const {signature} = result;
          signature.should.be.a('Uint8Array');

          const p1663Signature = helpers.derToP1363({signature, keyType});
          const signatureValue = base64url.encode(p1663Signature);

          const key = await helpers.awsPublicKeyToMultikey({
            awsPublicKey: publicKey, keyType
          });

          let verifier;
          if(type === 'urn:webkms:multikey:Ed25519') {
            verifier = (await Ed25519VerificationKey2020.from(key)).verifier();
          } else {
            verifier = {
              async verify({data, signature}) {

                const derSignature = helpers.p1363ToDer(signature);
                const {verified: hsmVerified} = await kms.verify({
                  amazonResourceName, keyType, data, signature: derSignature
                });
                const verifier = (await ecdsaMultikey.from(key)).verifier();
                const jsLibVerified = await verifier.verify({
                  data, signature
                });

                return hsmVerified && jsLibVerified;
              }
            };
          }
          result = await verifier.verify({
            data,
            signature: base64url.decode(signatureValue)
          });
          result.should.be.a('boolean');
          result.should.be.true;
        });
      }); // end sign/verify API
    }); // end type
  }
});
