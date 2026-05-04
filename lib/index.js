/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import * as bedrock from '@bedrock/core';
import {AwsKmsClient} from './AwsKmsClient.js';

import './config.js';

const {config, util: {BedrockError}} = bedrock;

// Map of client name => AwsKmsClient instance, populated on bedrock.init.
const CLIENTS = new Map();

bedrock.events.on('bedrock.init', async () => {
  const {clients} = config['bedrock-aws-kms'];

  const entries = Object.entries(clients);
  if(entries.length === 0) {
    throw new BedrockError(
      'No AWS KMS clients are configured.',
      'InvalidStateError', {
        httpStatusCode: 500,
        public: false
      });
  }

  for(const [clientName, clientConfig] of Object.entries(clients)) {
    const exists = CLIENTS.has(clientName);
    if(exists) {
      throw new BedrockError(
        'An exisiting config exists for the given client name.',
        'DuplicateError', {
          httpStatusCode: 409,
          public: true,
          clientName
        });
    }

    clientConfig.name = clientName;
    const client = new AwsKmsClient(clientConfig);
    await client.ping();
    CLIENTS.set(clientName, client);
  }
});

/**
 * Returns the named AwsKmsClient.
 *
 * @param {object} options - The options to use.
 * @param {string} options.name - The name of the client to retrieve.
 *
 * @returns {AwsKmsClient} - The configured AWS KMS client.
 */
export function getClient({name}) {
  const client = CLIENTS.get(name);
  if(!client) {
    throw new BedrockError(
      `AWS KMS client "${name}" is not configured.`,
      'NotFoundError', {
        httpStatusCode: 404,
        public: true,
        clientName: name
      });
  }
  return client;
}
