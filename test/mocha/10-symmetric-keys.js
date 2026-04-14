/*!
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as brAwsKms from '@bedrock/aws-kms';
import {webcrypto} from 'node:crypto';

describe('symmetric keys', () => {
  const kms = brAwsKms.getClient({name: 'test'});

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
        const data = Buffer.alloc(32);
        webcrypto.getRandomValues(data);

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

        const data = Buffer.alloc(4096);
        webcrypto.getRandomValues(data);

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

        const data = Buffer.alloc(32);
        webcrypto.getRandomValues(data);

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

        const signature = Buffer.alloc(1000);
        webcrypto.getRandomValues(data);

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
}); // end symmetric keys
