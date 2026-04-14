/*!
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {AWS_KEY_CONFIG, AWS_MAX_INPUT_BYTE_LENGTH} from './constants.js';
import {
  CreateKeyCommand, GenerateMacCommand, GetPublicKeyCommand, KMSClient,
  ListKeysCommand, SignCommand, VerifyCommand, VerifyMacCommand
} from '@aws-sdk/client-kms';
import {hash} from './hash.js';

const {util: {BedrockError}} = bedrock;

export class AwsKmsClient {
  /**
   * @param {object} options - The options to use.
   * @param {string} options.name - The logical name for this client (used in
   *   error messages).
   * @param {object} options.credentials - The AWS auth configuration for this
   *   client.
   * @param {string} options.credentials.accessKeyId - The AWS access key ID.
   * @param {string} options.credentials.secretAccessKey - The AWS secret access
   *   key.
   * @param {string} [options.region] - The AWS region.
   * @param {string} [options.endpoint] - An optional custom endpoint URL.
   */
  constructor({name, credentials, region, endpoint}) {
    this.name = name;

    const kmsClientConfig = {credentials};
    if(endpoint) {
      kmsClientConfig.endpoint = endpoint;
    }
    if(region) {
      kmsClientConfig.region = region;
    }

    this._kmsClient = new KMSClient(kmsClientConfig);
  }

  /**
   * Pings the AWS KMS service to validate that the client credentials and
   * connectivity are working. Throws a BedrockError on failure.
   *
   * @returns {Promise<void>}
   */
  async ping() {
    // ListKeys with a limit of 1 is the lightest-weight authenticated call
    // available — it proves both network reachability and credential validity.
    const command = new ListKeysCommand({Limit: 1});
    try {
      const {$metadata} = await this._kmsClient.send(command);
      if($metadata.httpStatusCode !== 200) {
        throw new BedrockError(
          `AWS KMS client "${this.name}" ping failed ` +
            `(HTTP ${$metadata.httpStatusCode}).`,
          'OperationError', {
            httpStatusCode: 500,
            public: false,
            clientName: this.name
          });
      }
    } catch(err) {
      if(err instanceof BedrockError) {
        throw err;
      }
      throw new BedrockError(
        `AWS KMS client "${this.name}" could not connect to AWS KMS.`,
        'OperationError', {
          httpStatusCode: 500,
          public: false,
          clientName: this.name,
          cause: err
        });
    }
  }

  /**
   * Generates a new key using AWS KMS.
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
   * Signs data with the key identified by the Amazon Resource Name.
   *
   * @param {object} options - The options to use.
   * @param {string} options.amazonResourceName - The ARN of the KMS key.
   * @param {Buffer} options.data - The bytes to be signed.
   * @param {string} options.keyType - The abbreviated key type.
   *
   * @returns {Promise<object>} An object containing `{signature, algorithm}`.
   */
  async sign({amazonResourceName, data, keyType}) {
    const {SigningAlgorithm} = AWS_KEY_CONFIG.get(keyType);
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
   * @param {Buffer} options.data - The original data bytes to verify.
   * @param {string} options.keyType - The abbreviated key type.
   * @param {Buffer} options.signature - The signature bytes to verify.
   *
   * @returns {Promise<object>} An object containing `{verified, algorithm}`.
   */
  async verify({amazonResourceName, data, keyType, signature}) {
    const {SigningAlgorithm} = AWS_KEY_CONFIG.get(keyType);
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
   * @param {Buffer} options.data - The bytes to generate a MAC from.
   * @param {string} options.keyType - The abbreviated key type.
   *
   * @returns {Promise<object>} An object containing `{signature, algorithm}`.
   */
  async generateMac({amazonResourceName, data, keyType}) {
    const {MacAlgorithm} = AWS_KEY_CONFIG.get(keyType);
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
   * @param {Buffer} options.data - The original data bytes to verify.
   * @param {string} options.keyType - The abbreviated key type.
   * @param {Buffer} options.signature - The MAC bytes to verify.
   *
   * @returns {Promise<object>} An object containing `{verified, algorithm}`.
   */
  async verifyMac({amazonResourceName, data, keyType, signature}) {
    const {MacAlgorithm, ExpectedMacByteLength} = AWS_KEY_CONFIG.get(keyType);
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
