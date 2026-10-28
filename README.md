# Go SDK

## Install

```bash
go get github.com/OpenProdkt/governance-sdk-go@v0.7.0
```

## Supports

The Go client currently covers:

- Auth: `RequestCode`, `VerifyCode`, `Register`, `Me`, `Settings`; internal-admin `Bootstrap`

`Bootstrap` uses the client's bearer credential and requires an internal admin token with the `org:bootstrap` scope. A tenant API key cannot bootstrap organizations.
- Governance: `Authorize`, `AuthorizeAndWait`, `HTTPMiddleware`, `PlaygroundCheck`, `ListDecisionExplorer`, `ListAuditEvents`, `Usage`
- Resources: `ListAssets`, `CreateAsset`, `UpdateAsset`, `DeleteAsset`, `IngestAssetDiscovery`, `ListAssetDiscoveries`, `DeleteAssetDiscovery`, `ListGroups`, `CreateGroup`, `UpdateGroup`, `DeleteGroup`, `ListPolicies`, `CreatePolicy`, `DeletePolicy`
- Operations: `ListAPIKeys`, `CreateAPIKey`, `RotateAPIKey`, `RevokeAPIKey`, `ListApprovals`, `RejectApproval` (requires a user JWT), `InviteMember`, `UploadEntitlementArtifact`

## Usage

```go
package main

import (
  "context"
  "fmt"
  "time"

  "github.com/OpenProdkt/governance-sdk-go/governance"
)

func main() {
  client := governance.NewClientWithDefaultAssetIdentity(
    "http://localhost:8080", "opk_live_xxx", 5*time.Second,
    governance.AssetIdentity{Application: "billing", Service: "invoice-api", Environment: "production"},
  )
  resp, err := client.Authorize(context.Background(), governance.AuthorizationRequest{
    OperationID: "invoice-123",
    Metadata: map[string]interface{}{"amount": 125},
  })
  if err != nil {
    panic(err)
  }
  fmt.Println(resp.Decision, resp.DecisionID)

  me, err := client.Me(context.Background())
  if err != nil {
    panic(err)
  }
  fmt.Println(me)
}
```

Framework adapters may set `AuthorizationRequest.PrincipalContext` with a bearer credential already validated by the host application. The SDK sends it only in the `Authorization` header; it is never copied into evaluation JSON or metadata.

`Client.HTTPMiddleware()` builds canonical HTTP transport context from `net/http` requests. Configure asset and metadata resolvers, a principal resolver backed by the host's authentication middleware, and an explicit header allowlist. The middleware reads `Idempotency-Key` when no operation-ID resolver is supplied and does not forward caller-supplied `X-OpenProdkt-*` headers.

`Client.UnaryClientInterceptor()` / `Client.StreamClientInterceptor()` and their server counterparts authorize gRPC calls using trusted asset and principal resolvers. Streaming calls are authorized once at establishment; stream messages are not inspected.

The interceptors map typed outcomes to canonical gRPC codes and attach bounded `google.rpc.ErrorInfo` containing only the outcome reason; raw PDP bodies and credentials are not included.

`Authorize` sends one `/v1/evaluate` request per operation attempt. Allow and lifecycle pass-through return normally; pending approval returns `PendingApprovalError` with the stable operation ID, PDP-issued approval ID/hash, asset reference, status URL, and expiry. Denial and terminal approval outcomes use typed errors with distinct outcome codes. Quota, collision, invalid input/configuration, and PDP failures remain distinguishable. `AuthorizeAndWait` returns normally only after the exact retry receives an allow with `approvalStatus=consumed`. Asset-discovery methods are separate administrative inventory APIs and are not part of `Authorize`.

`AuthorizeAndWaitWithOptions` and `WaitForApprovalWithOptions` accept bounded timeout, poll interval, exponential backoff, jitter, and a cancellable `context.Context`. Timeout/cancellation preserves the pending challenge; async callers may call `GetApprovalStatus` and later retry `Authorize` with the exact tuple. API keys that poll need the `approvals:read` scope; missing scope and not-found results are typed errors.

`VerifyApprovalWebhook()` verifies the versioned HMAC over the exact timestamp header, `.` and raw body bytes, and enforces a replay window. Use `VerifyApprovalWebhookWithSecrets()` or `NewApprovalWebhookHandler()` to accept current and previous secrets during rotation. The `net/http` handler bounds raw-body reads and reports duplicate dispatches; its callback must atomically deduplicate `EventID` with durable operation state. Supported events include pending, approved, rejected, expired, and revoked.

`AuthorizationRequest.Metadata` accepts maps or structs and serializes them through `encoding/json` before applying metadata validation and size limits. Values that cannot be encoded as a JSON object are rejected locally.

`VerifyApprovalWebhook()` checks `X-OpenProdkt-Signature` against the raw body and exact timestamp header with constant-time HMAC comparison, enforces a replay window, and returns a typed lifecycle event containing the outbox event ID. `DispatchApprovalWebhook()` delegates to an application callback, which must atomically deduplicate that ID with durable operation state; the SDK does not execute stored payloads.

```go
options := governance.GRPCAdapterOptions{
  ResolveAsset: func(_ context.Context, _ governance.GRPCRequestContext) (governance.GRPCAssetReference, error) {
    return governance.GRPCAssetReference{AssetKey: "billing.refund-api.production"}, nil
  },
  MetadataAllowlist: []string{"x-region"},
}
server := grpc.NewServer(
  grpc.UnaryInterceptor(client.UnaryServerInterceptor(options)),
  grpc.StreamInterceptor(client.StreamServerInterceptor(options)),
)
```

The client-side equivalents can be registered with `grpc.WithUnaryInterceptor()` and `grpc.WithStreamInterceptor()`.

Framework adapters may set `AuthorizationRequest.PrincipalContext` with the bearer credential they have already validated for the request. The SDK sends it only in the `Authorization` header, never in evaluation metadata or JSON.
