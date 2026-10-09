/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import * as bedrock from '@bedrock/core';
import {Buffer} from 'node:buffer';
import {execFile as execFileCallback} from 'node:child_process';
import {promisify} from 'node:util';

const {util: {BedrockError}} = bedrock;

const DECRYPT_TIMEOUT_MS = 30000;
const STDERR_SUMMARY_MAX_LENGTH = 2048;
const execFile = promisify(execFileCallback);

export async function decryptWithKmsTool({
  region, credentials, ciphertext, keyId, kmsTool
}) {
  _validateKmsTool({kmsTool});
  _validateCredentials({credentials});
  if(!(ciphertext instanceof Uint8Array) || ciphertext.length === 0) {
    throw new BedrockError(
      'The KMS ciphertext is invalid.',
      'DataError', {
        httpStatusCode: 500,
        public: false
      });
  }
  if(keyId !== undefined &&
    (typeof keyId !== 'string' || keyId.length === 0)) {
    throw new BedrockError(
      'The expected KMS key ID is invalid.',
      'DataError', {
        httpStatusCode: 500,
        public: false
      });
  }

  // kmstool only accepts credentials as command arguments. Run it inside the
  // enclave where other workloads cannot inspect them. On a developer machine
  // they are visible to local process inspection until kmstool exits
  const ciphertextBase64 = Buffer.from(ciphertext).toString('base64');
  const args = [
    'decrypt',
    '--region', region,
    '--proxy-port', `${kmsTool.proxyPort}`,
    '--aws-access-key-id', credentials.accessKeyId,
    '--aws-secret-access-key', credentials.secretAccessKey,
    '--aws-session-token', credentials.sessionToken,
    '--ciphertext', ciphertextBase64
  ];
  if(keyId) {
    args.push('--key-id', keyId);
    args.push('--encryption-algorithm', 'SYMMETRIC_DEFAULT');
  }
  let stdout;
  try {
    ({stdout} = await execFile(kmsTool.path, args, {
      encoding: 'utf8',
      env: _kmsToolEnv({libraryPath: kmsTool.libraryPath}),
      killSignal: 'SIGTERM',
      timeout: DECRYPT_TIMEOUT_MS
    }));
  } catch(cause) {
    throw _processError({
      cause,
      file: kmsTool.path,
      proxyPort: kmsTool.proxyPort,
      sensitiveValues: [
        credentials.accessKeyId,
        credentials.secretAccessKey,
        credentials.sessionToken,
        ciphertextBase64
      ]
    });
  }
  const line = stdout.split('\n')
    .find(value => value.startsWith('PLAINTEXT:'));
  if(!line) {
    throw new BedrockError(
      'KMS decryption did not return plaintext.',
      'DataError', {
        httpStatusCode: 500,
        public: false,
        outputLineCount: stdout.split('\n').length
      });
  }
  return Buffer.from(line.slice('PLAINTEXT:'.length).trim(), 'base64');
}

function _validateCredentials({credentials}) {
  if(!credentials?.accessKeyId || !credentials?.secretAccessKey ||
    !credentials?.sessionToken) {
    throw new BedrockError(
      'Temporary AWS credentials are required for enclave KMS decryption.',
      'InvalidStateError', {
        httpStatusCode: 500,
        public: false,
        hasAccessKeyId: Boolean(credentials?.accessKeyId),
        hasSecretAccessKey: Boolean(credentials?.secretAccessKey),
        hasSessionToken: Boolean(credentials?.sessionToken)
      });
  }
}

function _validateKmsTool({kmsTool}) {
  if(!_isNonEmptyString(kmsTool?.path)) {
    throw new BedrockError(
      'The kmstool path is not configured.',
      'InvalidStateError', {
        httpStatusCode: 500,
        public: false,
        configKey: 'config.aws-kms.kmsTool.path'
      });
  }
  if(!_isNonEmptyString(kmsTool.libraryPath)) {
    throw new BedrockError(
      'The kmstool library path is not configured.',
      'InvalidStateError', {
        httpStatusCode: 500,
        public: false,
        configKey: 'config.aws-kms.kmsTool.libraryPath'
      });
  }
  if(!Number.isInteger(kmsTool.proxyPort) ||
    kmsTool.proxyPort < 1 || kmsTool.proxyPort > 65535) {
    throw new BedrockError(
      'The kmstool proxy port is invalid.',
      'InvalidStateError', {
        httpStatusCode: 500,
        public: false,
        configKey: 'config.aws-kms.kmsTool.proxyPort',
        proxyPort: kmsTool.proxyPort ?? null
      });
  }
}

function _isNonEmptyString(value) {
  return typeof value === 'string' && value.length > 0;
}

function _kmsToolEnv({libraryPath}) {
  const current = process.env.LD_LIBRARY_PATH;
  return {
    ...process.env,
    LD_LIBRARY_PATH: current ? `${libraryPath}:${current}` : libraryPath
  };
}

function _processError({cause, file, proxyPort, sensitiveValues = []}) {
  if(cause.killed) {
    return new BedrockError(
      'KMS decryption timed out.',
      'TimeoutError', {
        httpStatusCode: 504,
        public: false,
        timeoutMs: DECRYPT_TIMEOUT_MS,
        proxyPort
      });
  }

  if(!Number.isInteger(cause.code)) {
    const notFound = cause.code === 'ENOENT';
    return new BedrockError(
      notFound ? 'The kmstool executable was not found.' :
        'The kmstool process could not start.',
      notFound ? 'NotFoundError' : 'OperationError', {
        httpStatusCode: 500,
        public: false,
        executable: file,
        proxyPort
      });
  }

  const stderr = cause.stderr ?? '';
  const kmsToolStderr = _stderrSummary({stderr, sensitiveValues});
  // only explicit access denials should be retried during boot. KMS 400 errors
  // also include invalid ciphertext and incorrect keys, which cannot recover
  const accessDenied = /AccessDenied|not authorized/iu.test(stderr);
  const socketFailure =
    /AWS_IO_SOCKET_NOT_CONNECTED|No route to host|Could not connect/iu
      .test(stderr) ||
    /connection (?:refused|reset|timed out)/iu.test(stderr);
  return new BedrockError(
    accessDenied ? 'KMS denied the attested decrypt request.' :
      socketFailure ? 'Could not connect to the KMS proxy.' :
        'KMS decryption failed.',
    accessDenied ? 'NotAllowedError' :
      socketFailure ? 'NetworkError' : 'OperationError', {
      httpStatusCode: accessDenied ? 403 : socketFailure ? 503 : 500,
      public: false,
      proxyPort,
      kmsToolExitCode: cause.code,
      kmsToolSignal: cause.signal ?? null,
      kmsToolStderr
    });
}

function _stderrSummary({stderr, sensitiveValues}) {
  let summary = typeof stderr === 'string' ? stderr : String(stderr);
  for(const value of sensitiveValues) {
    if(typeof value === 'string' && value.length > 0) {
      summary = summary.replaceAll(value, '[REDACTED]');
    }
  }

  summary = summary.trim().replace(/\s+/gu, ' ');
  if(summary.length <= STDERR_SUMMARY_MAX_LENGTH) {
    return summary || null;
  }
  return summary.slice(0, STDERR_SUMMARY_MAX_LENGTH - 3) + '...';
}
