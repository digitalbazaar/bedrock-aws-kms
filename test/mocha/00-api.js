/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import * as brAwsKms from '@bedrock/aws-kms';
import {config} from '@bedrock/core';

describe('client API', () => {
  it('returns and caches a client synchronously', () => {
    const client = brAwsKms.getClient({name: 'test'});

    should.exist(client);
    should.not.exist(client.then);
    brAwsKms.getClient({name: 'test'}).should.equal(client);
  });

  it('does not resolve a default Region while getting a client', () => {
    config['aws-kms'].clients['lazy-region'] = {};
    const client = brAwsKms.getClient({name: 'lazy-region'});

    should.exist(client);
  });

  it('rejects an invalid client name', () => {
    (() => brAwsKms.getClient({name: ''})).should.throw(TypeError,
      '"name" must be a non-empty string.');
  });

  it('rejects an unconfigured client name', () => {
    let error;
    try {
      brAwsKms.getClient({name: 'unconfigured'});
    } catch(e) {
      error = e;
    }

    should.exist(error);
    error.name.should.equal('NotFoundError');
    error.details.clientName.should.equal('unconfigured');
  });

  it('reports an unsupported key type as a BedrockError', async () => {
    const client = brAwsKms.getClient({name: 'test'});
    let error;
    try {
      await client.encrypt({
        amazonResourceName: 'unused',
        data: new TextEncoder().encode('data'),
        keyType: 'unsupported'
      });
    } catch(e) {
      error = e;
    }

    should.exist(error);
    error.name.should.equal('NotSupportedError');
    error.details.keyType.should.equal('unsupported');
  });
});
