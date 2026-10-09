/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import * as bedrock from '@bedrock/core';
import {AwsKmsClient} from './AwsKmsClient.js';
import {getClientRegion} from './region.js';

import './config.js';

const {config, util: {BedrockError}} = bedrock;
const CLIENTS = new Map();

export {getDefaultRegion, getEc2InstanceTag} from './region.js';

/**
 * Returns the named AwsKmsClient, constructing it on first use.
 *
 * @param {object} options - The options to use.
 * @param {string} options.name - The name of the client to retrieve.
 *
 * @returns {AwsKmsClient} - The configured AWS KMS client.
 */
export function getClient({name}) {
  if(typeof name !== 'string' || name.length === 0) {
    throw new TypeError('"name" must be a non-empty string.');
  }

  const clientConfig = config['aws-kms'].clients[name];
  if(!clientConfig) {
    throw new BedrockError(
      `AWS KMS client "${name}" is not configured.`,
      'NotFoundError', {
        httpStatusCode: 404,
        public: true,
        clientName: name
      });
  }

  let client = CLIENTS.get(name);
  if(!client) {
    const region = getClientRegion({region: clientConfig.region});
    client = new AwsKmsClient({...clientConfig, name, region});
    CLIENTS.set(name, client);
  }
  return client;
}
