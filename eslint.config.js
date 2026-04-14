/*!
 * Copyright 2026 Digital Bazaar, Inc.
 *
 */
import {defineConfig} from 'eslint/config';
import importConfig from '@digitalbazaar/eslint-config/import';
import nodeConfig from '@digitalbazaar/eslint-config/node-recommended';

export default defineConfig([
  ...importConfig,
  ...nodeConfig
]);
