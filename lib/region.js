/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import * as bedrock from '@bedrock/core';
import {httpClient} from '@digitalbazaar/http-client';

const {config, util: {BedrockError}} = bedrock;

const IMDS_BASE_URL = 'http://169.254.169.254/latest';
const IMDS_TIMEOUT_MS = 5000;

let imdsRegion;

/**
 * Returns the default AWS region for the running application environment.
 *
 * `AWS_REGION` takes precedence over the EC2 placement region. This function
 * deliberately does not apply `config['aws-kms'].region`; that setting is a
 * KMS-specific override and must not change the region used by other AWS
 * services such as Secrets Manager.
 *
 * @returns {Promise<string>} The default AWS region.
 */
export async function getDefaultRegion() {
  if(process.env.AWS_REGION) {
    return _assertRegion({
      region: process.env.AWS_REGION, source: 'AWS_REGION'
    });
  }

  if(imdsRegion === undefined) {
    // concurrent calls share one IMDS lookup. Failed lookups can be retried
    imdsRegion = _getRegionFromImds().catch(e => {
      imdsRegion = undefined;
      throw e;
    });
  }
  return imdsRegion;
}

/**
 * Returns an EC2 instance tag from IMDSv2.
 *
 * @param {object} options - The options to use.
 * @param {string} options.name - The instance tag name.
 *
 * @returns {Promise<string>} The instance tag value.
 */
export async function getEc2InstanceTag({name}) {
  if(typeof name !== 'string' || name.length === 0) {
    throw new TypeError('"name" must be a non-empty string.');
  }

  const token = await _getImdsToken();
  return _getImdsMetadata({
    token,
    path: `meta-data/tags/instance/${encodeURIComponent(name)}`,
    stage: 'instance_tag'
  });
}

/**
 * Resolves the effective region for a named AWS KMS client.
 *
 * @param {object} options - The options to use.
 * @param {string|null|undefined} options.region - A per-client override.
 *
 * @returns {string|Function} The effective KMS region or a lazy provider for
 *   the default Region.
 */
export function getClientRegion({region}) {
  if(region !== null && region !== undefined) {
    return _assertRegion({region, source: 'client config'});
  }

  const configuredRegion = config['aws-kms'].region;
  if(configuredRegion !== null && configuredRegion !== undefined) {
    return _assertRegion({
      region: configuredRegion, source: 'aws-kms config'
    });
  }

  return getDefaultRegion;
}

async function _getRegionFromImds() {
  const token = await _getImdsToken();
  const region = await _getImdsMetadata({
    token,
    path: 'meta-data/placement/region'
  });
  return _assertRegion({region, source: 'IMDS'});
}

async function _getImdsToken() {
  let response;
  try {
    response = await httpClient.put(`${IMDS_BASE_URL}/api/token`, {
      headers: {
        'X-aws-ec2-metadata-token-ttl-seconds': '60'
      },
      parseBody: false,
      retry: 0,
      timeout: IMDS_TIMEOUT_MS
    });
  } catch(cause) {
    throw _metadataError({cause, stage: 'token'});
  }

  const token = (await response.text()).trim();
  if(!token) {
    throw new BedrockError(
      'EC2 instance metadata returned an empty token.',
      'InvalidStateError', {
        httpStatusCode: 500,
        public: false
      });
  }
  return token;
}

async function _getImdsMetadata({token, path, stage = path}) {
  try {
    const response = await httpClient.get(`${IMDS_BASE_URL}/${path}`, {
      headers: {
        'X-aws-ec2-metadata-token': token
      },
      parseBody: false,
      retry: 0,
      timeout: IMDS_TIMEOUT_MS
    });
    return (await response.text()).trim();
  } catch(cause) {
    throw _metadataError({cause, stage});
  }
}

function _metadataError({cause, stage}) {
  const status = cause.status ?? cause.response?.status;
  const notFound = status === 404;
  return new BedrockError(
    'Could not read EC2 instance metadata.',
    notFound ? 'NotFoundError' : 'NetworkError', {
      httpStatusCode: notFound ? 404 : 503,
      public: false,
      metadataStatusCode: status ?? null,
      stage,
      cause
    });
}

function _assertRegion({region, source}) {
  if(typeof region !== 'string' || region.length === 0) {
    throw new BedrockError(
      'The AWS region is invalid.',
      'InvalidStateError', {
        httpStatusCode: 500,
        public: false,
        source
      });
  }
  return region;
}
