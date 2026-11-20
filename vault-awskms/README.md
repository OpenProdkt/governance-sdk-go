# AWS KMS key backend for the vault package

`github.com/OpenProdkt/governance-sdk-go-awskms` implements `vault.KeyBackend` from `github.com/OpenProdkt/governance-sdk-go/governance/vault` with AWS KMS. It is a separate Go module so that the core SDK has no AWS dependency. It runs in your environment, uses the AWS configuration of that environment, and calls only the KMS endpoint that configuration selects.

## Usage

```go
backend, err := awskms.NewFromConfig(ctx) // default AWS configuration chain; a region must be set
if err != nil {
    return err
}
envelope, err := vault.Seal(ctx, backend, "alias/my-records", vault.KindInput, orgID, operationID, record)
```

`NewFromConfig` loads the default AWS configuration (environment variables, shared configuration, role or instance credentials). The package never accepts or stores credentials. To use your own client, pass anything that has `GenerateDataKey` and `Decrypt` with the AWS SDK for Go v2 signatures to `awskms.New`; `*kms.Client` does.

The key reference is a KMS key ARN, an alias ARN, or `alias/<name>`. Anything else is refused with an error that matches `vault.ErrInvalidInput`.

## Behavior

- `GenerateDataKey` requests an `AES_256` data key under the key reference and requires a 32-byte plaintext key and a wrapped key of 1 to 4096 bytes.
- The encryption context that `vault.Seal` and `vault.Open` attach (organization and operation identifiers, not secret) is passed to KMS on both calls. KMS binds it to the wrapped key, so unwrapping with a different context fails.
- `Decrypt` names the key reference as `KeyId`. When the reference is a key ARN, the key identifier in the response must equal it. For an alias the response carries the ARN of the key behind the alias, so it is not compared.
- A disabled key, a key that is unavailable or in an invalid state (for example, scheduled for deletion), and a key that does not exist are reported as `vault.ErrKeyDestroyed`. A wrapped key that KMS rejects is reported as `vault.ErrInvalidWrappedKey`. Other failures are plain errors.
- Errors name the operation and the service error code only. They never contain keys, wrapped keys, plaintext, request bodies, or the key reference.
- Buffers that hold a plaintext key are overwritten once the backend is done with them. Callers receive copies.

Use of a key is governed by AWS KMS and your IAM policy. The checks in this module reject malformed input and validate response shapes; they are not an access control.

## Test

```bash
go vet ./... && go test -count=1 -race ./...
```

The tests use a fake KMS client and need no network or credentials. This module has not been exercised against a live KMS endpoint in automated tests.
