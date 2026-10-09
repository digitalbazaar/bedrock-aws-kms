/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import * as brAwsKms from '@bedrock/aws-kms';
import {webcrypto} from 'node:crypto';

describe('symmetric keys', () => {
  let kms;
  before(() => {
    kms = brAwsKms.getClient({name: 'test'});
  });

  describe('Sha256HmacKey2019', () => {
    const keyType = 'HS256';

    describe('generateKey API', () => {
      it('should generate a key for type Sha256HmacKey2019', async () => {
        const result = await kms.generateKey({keyType});

        should.exist(result);
        result.should.be.an('object');
        should.exist(result.amazonResourceName);
        should.not.exist(result.publicKey);
      });
    }); // end generateKey API

    describe('sign/verify API', () => {
      let amazonResourceName;
      before(async () => {
        ({amazonResourceName} = await kms.generateKey({keyType}));
      });
      it('successfully signs data', async () => {
        const data = webcrypto.getRandomValues(new Uint8Array(32));

        let err;
        let result;
        try {
          result = await kms.generateMac({amazonResourceName, data, keyType});
        } catch(e) {
          err = e;
        }

        should.not.exist(err);
        should.exist(result);
        should.exist(result.algorithm);
        should.exist(result.signature);

        const {signature} = result;
        try {
          result = await kms.verifyMac({
            amazonResourceName, keyType, data, signature
          });
        } catch(e) {
          err = e;
        }

        should.not.exist(err);
        should.exist(result);
        should.exist(result.algorithm);
        should.exist(result.verified);
        result.verified.should.be.true;
      });
      it('fails to sign data - input too large', async () => {
        const {amazonResourceName} = await kms.generateKey({keyType});

        const data = webcrypto.getRandomValues(new Uint8Array(4096));

        let err;
        let result;
        try {
          result = await kms.generateMac({amazonResourceName, data, keyType});
        } catch(e) {
          err = e;
        }

        should.not.exist(result);
        should.exist(err);
        err.name.should.equal('QuotaExceededError');
        err.details.httpStatusCode.should.equal(413);
        err.details.byteLength.should.equal(4096);
        err.details.maxByteLength.should.equal(4096);
      });
      it('fails to verify data - signature size mismatch', async () => {
        const {amazonResourceName} = await kms.generateKey({keyType});

        const data = webcrypto.getRandomValues(new Uint8Array(32));

        let err;
        let result;
        try {
          result = await kms.generateMac({amazonResourceName, data, keyType});
        } catch(e) {
          err = e;
        }

        should.not.exist(err);
        should.exist(result);
        should.exist(result.algorithm);
        should.exist(result.signature);

        const signature = webcrypto.getRandomValues(new Uint8Array(1000));

        err = undefined;
        result = undefined;
        try {
          result = await kms.verifyMac({
            amazonResourceName, keyType, data, signature
          });
        } catch(e) {
          err = e;
        }

        should.not.exist(result);
        should.exist(err);
        err.name.should.equal('DataError');
        err.details.httpStatusCode.should.equal(400);
        err.details.byteLength.should.equal(1000);
        err.details.expectedByteLength.should.equal(32);
      });
    }); // end sign API
  }); // end Sha256HmacKey2019
  describe('AES-256-GCM', () => {
    const keyType = 'AES-256-GCM';

    describe('generateKey API', () => {
      it('should generate a key for type AES-256-GCM', async () => {
        const result = await kms.generateKey({keyType});

        should.exist(result);
        result.should.be.an('object');
        should.exist(result.amazonResourceName);
        should.not.exist(result.publicKey);
      });
    }); // end generateKey API

    describe('encrypt/decrypt API', () => {
      let amazonResourceName;
      before(async () => {
        ({amazonResourceName} = await kms.generateKey({keyType}));
      });

      it('successfully encrypts and decrypts data', async () => {
        const data = webcrypto.getRandomValues(new Uint8Array(32));

        let err;
        let result;
        try {
          result = await kms.encrypt({amazonResourceName, data, keyType});
        } catch(e) {
          err = e;
        }

        should.not.exist(err);
        should.exist(result);
        should.exist(result.algorithm);
        should.exist(result.ciphertext);

        const {ciphertext} = result;
        err = undefined;
        result = undefined;
        try {
          result = await kms.decrypt({
            amazonResourceName, keyType, ciphertext
          });
        } catch(e) {
          err = e;
        }

        should.not.exist(err);
        should.exist(result);
        should.exist(result.algorithm);
        should.exist(result.plaintext);
        result.plaintext.should.deep.equal(data);
      });
      it('fails to encrypt data - input too large', async () => {
        const data = webcrypto.getRandomValues(new Uint8Array(4096));

        let err;
        let result;
        try {
          result = await kms.encrypt({amazonResourceName, data, keyType});
        } catch(e) {
          err = e;
        }

        should.not.exist(result);
        should.exist(err);
        err.name.should.equal('QuotaExceededError');
        err.details.httpStatusCode.should.equal(413);
        err.details.byteLength.should.equal(4096);
        err.details.maxByteLength.should.equal(4096);
      });
    }); // end encrypt API
  }); // end AES-256-GCM
}); // end symmetric keys
