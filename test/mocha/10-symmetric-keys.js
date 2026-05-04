/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
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
        const data = new Uint8Array(32);
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

        const data = new Uint8Array(4096);
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

        const data = new Uint8Array(32);
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

        const signature = new Uint8Array(1000);
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
        const data = new Uint8Array(32);
        webcrypto.getRandomValues(data);

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
        Buffer.compare(Buffer.from(result.plaintext), data).should.equal(0);
      });
      it('fails to encrypt data - input too large', async () => {
        const data = new Uint8Array(4096);
        webcrypto.getRandomValues(data);

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
      it('fails to decrypt data when Nitro Enclave attestation is required',
        async () => {
          const {amazonResourceName: arn} = await kms.generateKey({keyType});

          const secretKey = new Uint8Array(32);
          webcrypto.getRandomValues(secretKey);

          let err;
          let result;
          try {
            result = await kms.encrypt({
              amazonResourceName: arn, data: secretKey, keyType
            });
          } catch(e) {
            err = e;
          }

          should.not.exist(err);
          should.exist(result);
          should.exist(result.algorithm);
          should.exist(result.ciphertext);

          const {ciphertext} = result;
          const pcr0s = [
            // eslint-disable-next-line @stylistic/max-len
            '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
            // eslint-disable-next-line @stylistic/max-len
            'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'
          ];

          const {policy} = await kms.updateNitroEnclaveKeyPolicy({
            amazonResourceName: arn,
            principal: '*',
            pcr0s,
            actions: ['kms:Decrypt']
          });

          const statement = policy.Statement.find(
            s => s.Sid === 'Enable enclave data processing');

          should.exist(statement);
          statement.Action.should.deep.equal(['kms:Decrypt']);
          statement.Condition.should.deep.equal({
            StringEqualsIgnoreCase: {
              'kms:RecipientAttestation:PCR0': pcr0s
            }
          });

          err = undefined;
          result = undefined;
          try {
            result = await kms.decrypt({
              amazonResourceName: arn, keyType, ciphertext
            });
          } catch(e) {
            err = e;
          }

          const devMode = kms.endpoint.includes('localhost');
          if(devMode) {
            // skip test for access check since localstack does not support it
            return;
          }

          should.not.exist(result);
          should.exist(err);
          err.name.should.equal('AccessDeniedException');
        });
    }); // end encrypt API
  }); // end AES-256-GCM
}); // end symmetric keys
