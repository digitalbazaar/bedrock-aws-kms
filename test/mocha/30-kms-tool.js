/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {decryptWithKmsTool} from '@bedrock/aws-kms/lib/kmsTool.js';
import {fileURLToPath} from 'node:url';
import path from 'node:path';

const executable = fileURLToPath(
  new URL('../fixtures/kmstool.js', import.meta.url));
const options = {
  region: 'us-east-1',
  credentials: {
    accessKeyId: 'access-key',
    secretAccessKey: 'secret-key',
    sessionToken: 'session-token'
  },
  ciphertext: new TextEncoder().encode('ciphertext'),
  kmsTool: {
    path: executable,
    libraryPath: path.dirname(executable),
    proxyPort: 8000
  }
};

describe('kmstool adapter', () => {
  afterEach(() => {
    delete process.env.BEDROCK_AWS_KMS_TEST_MODE;
  });

  it('returns decoded plaintext', async () => {
    process.env.BEDROCK_AWS_KMS_TEST_MODE = 'success';
    const plaintext = await decryptWithKmsTool(options);

    plaintext.should.deep.equal(new TextEncoder().encode('test plaintext'));
  });

  it('classifies an access denial', async () => {
    const error = await _getError({mode: 'access'});

    error.name.should.equal('NotAllowedError');
    error.details.httpStatusCode.should.equal(403);
    error.details.kmsToolExitCode.should.equal(1);
  });

  it('classifies a proxy connection failure', async () => {
    const error = await _getError({mode: 'socket'});

    error.name.should.equal('NetworkError');
    error.details.httpStatusCode.should.equal(503);
  });

  it('preserves an unknown failure as an operation error', async () => {
    const error = await _getError({mode: 'failure'});

    error.name.should.equal('OperationError');
    error.details.httpStatusCode.should.equal(500);
    error.details.kmsToolStderr.should.equal('unexpected native failure');
  });

  it('redacts subprocess inputs from the stderr diagnostic', async () => {
    const error = await _getError({mode: 'sensitive'});
    const {kmsToolStderr} = error.details;

    kmsToolStderr.should.include('native failure:');
    kmsToolStderr.should.include('[REDACTED]');
    kmsToolStderr.should.not.include(options.credentials.accessKeyId);
    kmsToolStderr.should.not.include(options.credentials.secretAccessKey);
    kmsToolStderr.should.not.include(options.credentials.sessionToken);
    kmsToolStderr.should.not.include(
      Buffer.from(options.ciphertext).toString('base64'));
  });

  it('rejects successful output without plaintext', async () => {
    const error = await _getError({mode: 'no-plaintext'});

    error.name.should.equal('DataError');
  });

  it('requires temporary credentials', async () => {
    let error;
    try {
      await decryptWithKmsTool({
        ...options,
        credentials: {accessKeyId: 'access-key', secretAccessKey: 'secret-key'}
      });
    } catch(e) {
      error = e;
    }

    should.exist(error);
    error.name.should.equal('InvalidStateError');
    error.details.hasSessionToken.should.equal(false);
  });
});

async function _getError({mode}) {
  process.env.BEDROCK_AWS_KMS_TEST_MODE = mode;
  try {
    await decryptWithKmsTool(options);
  } catch(error) {
    return error;
  }
  throw new Error(`Expected kmstool mode "${mode}" to fail.`);
}
