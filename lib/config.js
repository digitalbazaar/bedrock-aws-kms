/*!
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */
import {config} from '@bedrock/core';
import '@bedrock/validation';

const cfg = config['bedrock-aws-kms'] = {};

/**
 * A map of client name to AWS auth configuration. Each entry will be
 * instantiated as a separate KMS client on startup and verified with a
 * connectivity ping before being made available.
 *
 * Example with multiple clients:
 * cfg.clients = {
 *   default: {
 *     credentials: {
 *       accessKeyId: '...',
 *       secretAccessKey: '...'
 *     },
 *     region: 'us-east-1'
 *   },
 *   app2: {
 *     credentials: {
 *       accessKeyId: '...',
 *       secretAccessKey: '...'
 *     },
 *     region: 'eu-west-1',
 *     endpoint: 'https://custom-kms-endpoint.example.com'
 *   }
 * };.
 */
cfg.clients = {
  test: {
    credentials: {
      accessKeyId: 'test',
      secretAccessKey: 'test'
    },
    endpoint: 'http://localhost:4566',
    region: 'us-east-1'
  }
};
