#!/usr/bin/env node
/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {Buffer} from 'node:buffer';

const mode = process.env.BEDROCK_AWS_KMS_TEST_MODE;

if(mode === 'success') {
  const plaintext = Buffer.from('test plaintext').toString('base64');
  process.stdout.write(`PLAINTEXT: ${plaintext}\n`);
} else if(mode === 'no-plaintext') {
  process.stdout.write('request completed\n');
} else if(mode === 'sensitive') {
  process.stderr.write(`native failure: ${process.argv.slice(2).join(' ')}\n`);
  process.exitCode = 1;
} else {
  const messages = {
    access: 'AccessDeniedException: request denied',
    socket: 'AWS_IO_SOCKET_NOT_CONNECTED: connection refused',
    failure: 'unexpected native failure'
  };
  process.stderr.write(`${messages[mode] ?? messages.failure}\n`);
  process.exitCode = 1;
}
