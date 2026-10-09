/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import * as bedrock from '@bedrock/core';
import {AWS_KEY_CONFIG, AWS_MAX_INPUT_BYTE_LENGTH} from './constants.js';
import {
  CreateKeyCommand, DecryptCommand, EncryptCommand, GenerateMacCommand,
  GetPublicKeyCommand, KMSClient,
  SignCommand, VerifyCommand, VerifyMacCommand
} from '@aws-sdk/client-kms';
import {decryptWithKmsTool} from './kmsTool.js';
import {hash} from './hash.js';

const {config, util: {BedrockError}} = bedrock;

export class AwsKmsClient {
  /**
   * AWS auth configuration.
   *
   * @typedef {object} AwsCredentials
   * @property {string} accessKeyId - The AWS access key ID.
   * @property {string} secretAccessKey - The AWS secret access key.
   * @property {string} [sessionToken] - The AWS session token.
   */
  /**
   * @param {object} options - The options to use.
   * @param {string} options.name - The logical name for this client (used in
   *   error messages).
   * @param {AwsCredentials|Function} [options.credentials] - Static AWS
   *   credentials or an AWS SDK credential provider for this client.
   * @param {string|Function} [options.region] - The AWS region or region
   *   provider.
   * @param {string} [options.endpoint] - An optional custom endpoint URL.
   */
  constructor({name, credentials, region, endpoint}) {
    this.name = name;
    this.endpoint = endpoint;
    this.region = region;

    const kmsClientConfig = {};
    if(credentials) {
      kmsClientConfig.credentials = credentials;
    }
    if(endpoint) {
      kmsClientConfig.endpoint = endpoint;
    }
    if(region) {
      kmsClientConfig.region = region;
    }

    this._kmsClient = new KMSClient(kmsClientConfig);
  }

  /**
   * Generates a new key inside of AWS KMS.
   *
   * @param {object} options - The options to use.
   * @param {string} options.keyType - The abbreviated key type.
   *
   * @returns {Promise<object>} An object containing
   *   `{amazonResourceName, publicKey}`.
   */
  async generateKey({keyType}) {
    const awsKeyConfig = AWS_KEY_CONFIG.get(keyType);
    if(!awsKeyConfig) {
      throw new BedrockError(
        `Key type "${keyType}" is not supported.`,
        'NotSupportedError', {
          httpStatusCode: 400,
          public: true,
          keyType
        });
    }
    const {KeySpec, KeyUsage, SigningAlgorithm} = awsKeyConfig;
    const command = new CreateKeyCommand({
      KeySpec,
      KeyUsage,
      MultiRegion: false
    });

    const {$metadata, KeyMetadata} = await this._kmsClient.send(command);
    if($metadata.httpStatusCode !== 200) {
      throw new BedrockError(
        'Could not create key.',
        'OperationError', {
          httpStatusCode: 500,
          public: false
        });
    }
    const {Arn} = KeyMetadata;

    const isAsymmetricKey = !!SigningAlgorithm;
    let PublicKey;
    if(isAsymmetricKey) {
      const getKeyCommand = new GetPublicKeyCommand({KeyId: Arn});
      ({PublicKey} = await this._kmsClient.send(getKeyCommand));
    }

    return {amazonResourceName: Arn, publicKey: PublicKey};
  }

  /**
   * Encrypts data with the key identified by the Amazon Resource Name.
   *
   * @param {object} options - The options to use.
   * @param {string} options.amazonResourceName - The ARN of the KMS key.
   * @param {Uint8Array} options.data - The bytes to encrypt.
   * @param {string} options.keyType - The abbreviated key type.
   *
   * @returns {Promise<object>} An object containing `{ciphertext, algorithm}`.
   */
  async encrypt({amazonResourceName, data, keyType}) {
    const {EncryptionAlgorithm} = AWS_KEY_CONFIG.get(keyType) ?? {};
    if(!EncryptionAlgorithm) {
      throw new BedrockError(
        `Key type "${keyType}" is not supported.`,
        'NotSupportedError', {
          httpStatusCode: 400,
          public: true,
          keyType
        });
    }
    _ensureMessageUnderAWSByteLengthLimit(data);
    const input = {
      KeyId: amazonResourceName,
      Plaintext: data,
      EncryptionAlgorithm,
      DryRun: false
    };
    const command = new EncryptCommand(input);

    const {
      $metadata, CiphertextBlob, EncryptionAlgorithm: algorithm
    } = await this._kmsClient.send(command);
    if($metadata.httpStatusCode !== 200) {
      throw new BedrockError(
        'Could not encrypt data.',
        'OperationError', {
          httpStatusCode: 500,
          public: false
        });
    }

    return {ciphertext: CiphertextBlob, algorithm};
  }

  /**
   * Decrypts data with the key identified by the Amazon Resource Name.
   *
   * @param {object} options - The options to use.
   * @param {string} options.amazonResourceName - The ARN of the KMS key.
   * @param {Uint8Array} options.ciphertext - The encrypted bytes to decrypt.
   * @param {string} options.keyType - The abbreviated key type.
   *
   * @returns {Promise<object>} An object containing `{plaintext, algorithm}`.
   */
  async decrypt({amazonResourceName, ciphertext, keyType}) {
    const {EncryptionAlgorithm} = AWS_KEY_CONFIG.get(keyType) ?? {};
    if(!EncryptionAlgorithm) {
      throw new BedrockError(
        `Key type "${keyType}" is not supported.`,
        'NotSupportedError', {
          httpStatusCode: 400,
          public: true,
          keyType
        });
    }
    const input = {
      KeyId: amazonResourceName,
      CiphertextBlob: ciphertext,
      EncryptionAlgorithm,
      DryRun: false
    };
    const command = new DecryptCommand(input);

    const {
      $metadata, Plaintext, EncryptionAlgorithm: algorithm
    } = await this._kmsClient.send(command);
    if($metadata.httpStatusCode !== 200) {
      throw new BedrockError(
        'Could not decrypt data.',
        'OperationError', {
          httpStatusCode: 500,
          public: false
        });
    }

    return {plaintext: Plaintext, algorithm};
  }

  /**
   * Decrypts ciphertext using an AWS KMS request with Nitro Enclave
   * recipient attestation.
   *
   * Uses kmstool because KMS calls requiring attestation documents cannot
   * go through the standard AWS SDK decrypt path inside an enclave.
   *
   * @param {object} options - The options to use.
   * @param {Uint8Array} options.ciphertext - The encrypted bytes to decrypt.
   * @param {string} [options.keyId] - The expected KMS key; KMS rejects the
   *   request if the ciphertext was not produced under this key.
   *
   * @returns {Promise<object>} An object containing `{plaintext}`.
   */
  async decryptWithAttestation({ciphertext, keyId}) {
    const [credentials, region] = await Promise.all([
      this._kmsClient.config.credentials(),
      this._kmsClient.config.region()
    ]);

    const plaintext = await decryptWithKmsTool({
      region,
      credentials,
      ciphertext,
      keyId,
      kmsTool: config['aws-kms'].kmsTool
    });
    return {plaintext};
  }

  /**
   * Signs data with the key identified by the Amazon Resource Name.
   *
   * @param {object} options - The options to use.
   * @param {string} options.amazonResourceName - The ARN of the KMS key.
   * @param {Uint8Array} options.data - The bytes to be signed.
   * @param {string} options.keyType - The abbreviated key type.
   *
   * @returns {Promise<object>} An object containing `{signature, algorithm}`.
   */
  async sign({amazonResourceName, data, keyType}) {
    const {SigningAlgorithm} = AWS_KEY_CONFIG.get(keyType) ?? {};
    if(!SigningAlgorithm) {
      throw new BedrockError(
        `Key type "${keyType}" is not supported.`,
        'NotSupportedError', {
          httpStatusCode: 400,
          public: true,
          keyType
        });
    }
    const {data: Message, type: MessageType} = await hash({keyType, data});
    _ensureMessageUnderAWSByteLengthLimit(Message);
    const input = {
      KeyId: amazonResourceName,
      Message,
      MessageType,
      SigningAlgorithm,
      DryRun: false
    };
    const command = new SignCommand(input);

    const {
      $metadata, Signature, SigningAlgorithm: algorithm
    } = await this._kmsClient.send(command);
    if($metadata.httpStatusCode !== 200) {
      throw new BedrockError(
        'Could not sign data.',
        'OperationError', {
          httpStatusCode: 500,
          public: false
        });
    }

    return {signature: Signature, algorithm};
  }

  /**
   * Verifies data with the key identified by the Amazon Resource Name.
   *
   * @param {object} options - The options to use.
   * @param {string} options.amazonResourceName - The ARN of the KMS key.
   * @param {Uint8Array} options.data - The original data bytes to verify.
   * @param {string} options.keyType - The abbreviated key type.
   * @param {Uint8Array} options.signature - The signature bytes to verify.
   *
   * @returns {Promise<object>} An object containing `{verified, algorithm}`.
   */
  async verify({amazonResourceName, data, keyType, signature}) {
    const {SigningAlgorithm} = AWS_KEY_CONFIG.get(keyType) ?? {};
    if(!SigningAlgorithm) {
      throw new BedrockError(
        `Key type "${keyType}" is not supported.`,
        'NotSupportedError', {
          httpStatusCode: 400,
          public: true,
          keyType
        });
    }
    const {data: Message, type: MessageType} = await hash({keyType, data});
    _ensureMessageUnderAWSByteLengthLimit(Message);
    const input = {
      KeyId: amazonResourceName,
      Message,
      MessageType,
      Signature: signature,
      SigningAlgorithm,
      DryRun: false
    };
    const command = new VerifyCommand(input);

    const {
      $metadata, SignatureValid, SigningAlgorithm: algorithm
    } = await this._kmsClient.send(command);
    if($metadata.httpStatusCode !== 200) {
      throw new BedrockError(
        'Could not verify data.',
        'OperationError', {
          httpStatusCode: 500,
          public: false
        });
    }

    return {verified: SignatureValid, algorithm};
  }

  /**
   * Generates a MAC from data with the key identified by the Amazon Resource
   * Name.
   *
   * @param {object} options - The options to use.
   * @param {string} options.amazonResourceName - The ARN of the KMS key.
   * @param {Uint8Array} options.data - The bytes to generate a MAC from.
   * @param {string} options.keyType - The abbreviated key type.
   *
   * @returns {Promise<object>} An object containing `{signature, algorithm}`.
   */
  async generateMac({amazonResourceName, data, keyType}) {
    const {MacAlgorithm} = AWS_KEY_CONFIG.get(keyType) ?? {};
    if(!MacAlgorithm) {
      throw new BedrockError(
        `Key type "${keyType}" is not supported.`,
        'NotSupportedError', {
          httpStatusCode: 400,
          public: true,
          keyType
        });
    }
    _ensureMessageUnderAWSByteLengthLimit(data);
    const input = {
      KeyId: amazonResourceName,
      Message: data,
      MacAlgorithm,
      DryRun: false
    };
    const command = new GenerateMacCommand(input);

    const {
      $metadata, Mac, MacAlgorithm: algorithm
    } = await this._kmsClient.send(command);
    if($metadata.httpStatusCode !== 200) {
      throw new BedrockError(
        'Could not generate MAC.',
        'OperationError', {
          httpStatusCode: 500,
          public: false
        });
    }

    return {signature: Mac, algorithm};
  }

  /**
   * Verifies a MAC with the key identified by the Amazon Resource Name.
   *
   * @param {object} options - The options to use.
   * @param {string} options.amazonResourceName - The ARN of the KMS key.
   * @param {Uint8Array} options.data - The original data bytes to verify.
   * @param {string} options.keyType - The abbreviated key type.
   * @param {Uint8Array} options.signature - The MAC bytes to verify.
   *
   * @returns {Promise<object>} An object containing `{verified, algorithm}`.
   */
  async verifyMac({amazonResourceName, data, keyType, signature}) {
    const {
      MacAlgorithm, ExpectedMacByteLength
    } = AWS_KEY_CONFIG.get(keyType) ?? {};
    if(!MacAlgorithm) {
      throw new BedrockError(
        `Key type "${keyType}" is not supported.`,
        'NotSupportedError', {
          httpStatusCode: 400,
          public: true,
          keyType
        });
    }
    if(signature.byteLength !== ExpectedMacByteLength) {
      throw new BedrockError(
        'Signature does not equal expected byte length.',
        'DataError', {
          httpStatusCode: 400,
          public: true,
          byteLength: signature.byteLength,
          expectedByteLength: ExpectedMacByteLength
        });
    }
    _ensureMessageUnderAWSByteLengthLimit(data);
    const input = {
      KeyId: amazonResourceName,
      Message: data,
      Mac: signature,
      MacAlgorithm,
      DryRun: false
    };
    const command = new VerifyMacCommand(input);

    const {
      $metadata, MacValid, MacAlgorithm: algorithm
    } = await this._kmsClient.send(command);
    if($metadata.httpStatusCode !== 200) {
      throw new BedrockError(
        'Could not verify MAC.',
        'OperationError', {
          httpStatusCode: 500,
          public: false
        });
    }

    return {verified: MacValid, algorithm};
  }

}

function _ensureMessageUnderAWSByteLengthLimit(data) {
  if(data.byteLength >= AWS_MAX_INPUT_BYTE_LENGTH) {
    throw new BedrockError(
      'Message exceeds AWS maximum byte limit.',
      'QuotaExceededError', {
        httpStatusCode: 413,
        public: true,
        byteLength: data.byteLength,
        maxByteLength: AWS_MAX_INPUT_BYTE_LENGTH
      });
  }
}
