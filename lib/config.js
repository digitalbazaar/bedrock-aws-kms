/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {config} from '@bedrock/core';
import {fileURLToPath} from 'node:url';

const cfg = config['aws-kms'] = {};

cfg.region = null;
cfg.clients = {};

cfg.kmsTool = {
  path: fileURLToPath(
    new URL('../vendor/alpine-x64/kmstool_enclave_cli', import.meta.url)),
  libraryPath: fileURLToPath(
    new URL('../vendor/alpine-x64/lib', import.meta.url)),
  proxyPort: 8000
};
