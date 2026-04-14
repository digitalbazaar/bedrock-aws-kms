# bedrock-aws-kms

## Create a Tagged Release
```sh
# update the changelog as with `pubnpm`
pubtag -b main major
```

## API Reference
<a name="getClient"></a>

## getClient(name) ⇒ <code>AwsKmsClient</code>
Returns the named AwsKmsClient.

**Kind**: global function  

| Param | Type | Description |
| --- | --- | --- |
| name | <code>string</code> | The name of the client to retrieve. |


## Developing for AWS Locally

1. Install [LocalStack](https://github.com/localstack/localstack)
2. Get auth token for LocalStack via [docs](https://docs.localstack.cloud/aws/getting-started/auth-token/)
3. Install [Docker](https://docs.docker.com/get-docker/)
4. Start LocalStack inside a Docker container by running:

```bash
 % export GATEWAY_LISTEN=0.0.0.0:4566
 % localstack start -d

     __                     _______ __             __
    / /   ____  _________ _/ / ___// /_____ ______/ /__
   / /   / __ \/ ___/ __ `/ /\__ \/ __/ __ `/ ___/ //_/
  / /___/ /_/ / /__/ /_/ / /___/ / /_/ /_/ / /__/ ,<
 /_____/\____/\___/\__,_/_//____/\__/\__,_/\___/_/|_|

- LocalStack CLI: 2026.3.0
- Profile: default
- App: https://app.localstack.cloud

[07:36:00] starting LocalStack in Docker localstack.py:532
           mode 🐳
2026-04-08T07:36:00.792  INFO --- [  MainThread] l.p.c.b.licensingv2        : Successfully activated cached license 6c464168-dbb8-4219-b21b-61ebf592df81:freemium from /Users/john/Library/Caches/localstack-cli/license.json 🔑✅
           preparing environment         bootstrap.py:1332
           configuring container         bootstrap.py:1341
2026-04-08T07:36:00.896  WARN --- [  MainThread] l.utils.bootstrap          : Non-prefixed environment variable GATEWAY_LISTEN is forwarded to the LocalStack container! Please use `LOCALSTACK_GATEWAY_LISTEN` instead of GATEWAY_LISTEN to explicitly mark this environment variable to be forwarded from the CLI to the LocalStack Runtime.
           starting container            bootstrap.py:1351
[07:36:01] detaching                     bootstrap.py:1355
```

4. You can query the status of respective services on LocalStack by running:

```bash
% localstack status services
┏━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┓
┃ Service                  ┃ Status      ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━┩
│ acm                      │ ✔ available │
│ apigateway               │ ✔ available │
│ cloudformation           │ ✔ available │
│ cloudwatch               │ ✔ available │
│ config                   │ ✔ available │
│ dynamodb                 │ ✔ available │
...
```
