package governance

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/OpenProdkt/governance-sdk-go/governance/vault"
)

// GuardOptions observes one attempt; it never creates IDs, polls approvals or
// retries execution. Traceparent on the EvaluateRequest stays header-only.
type GuardOptions struct {
	ExecutionID       *string
	Attempt           *int
	UpstreamRequestID *string
	// Vault, when set, stores caller-supplied records of the call in the evidence vault.
	// Nil leaves the guard exactly as it is without a vault.
	Vault *GuardVault
}

// GuardVault configures evidence records for one guarded call. The guard never sees the
// call's arguments or result: it stores only what the caller supplies here.
//
// A record must be a JSON object that the vault can canonicalize. The vault refuses
// fractional numbers, so a caller that needs one carries its raw text in a string.
type GuardVault struct {
	// Writer stores the records. *vault.Writer satisfies it.
	Writer VaultWriter
	// OrganizationID is the organization the records are sealed for.
	OrganizationID string
	// Input is the record of the call's input. It is required and is stored before the
	// evaluation, and its reference is sent with the evaluation.
	Input any
	// Output, when set, receives the callback's value after the callback returned
	// without an error and without a panic, and returns the record to store. Returning
	// nil skips the write without a gap. When Output is nil, nothing is stored for the
	// result and no callback value is read.
	Output func(result any) any
	// ContinueWithoutVault lets the call go on when the input record cannot be stored; the
	// evaluation then carries a gap instead of a reference. The default is to stop: Guard
	// returns a *VaultWriteError before evaluating, calling the callback or reporting.
	ContinueWithoutVault bool
}

// GuardResult separates business completion from report delivery. A ReportingError
// must only trigger an identical report retry, never another Guard/business call.
type GuardResult[T any] struct {
	Value          T
	Report         OperationOutcomeRequest
	ReportingError error
}

// Guard evaluates once and calls execute at most once, only after ALLOW. Callback
// errors are returned unchanged; panics are reported unknown and re-panicked.
// No callback value or error text is serialized, hashed, logged or sent.
func Guard[T any](ctx context.Context, client *Client, request EvaluateRequest, principal *PrincipalContext, options GuardOptions, execute func(context.Context) (T, error)) (result GuardResult[T], err error) {
	if client == nil || execute == nil || principal == nil {
		return result, &InvalidAuthorizationInputError{Message: "client, callback and explicit principal are required"}
	}
	// Snapshot before application code can mutate caller-owned options/principal.
	reporter := *principal
	result.Report = OperationOutcomeRequest{OperationID: request.OperationID, ExecutionID: guardCopy(options.ExecutionID), Attempt: guardCopy(options.Attempt), UpstreamRequestID: guardCopy(options.UpstreamRequestID)}
	if err = validateOutcomeCorrelation(result.Report); err != nil {
		return result, err
	}
	var evidence *GuardVault
	if options.Vault != nil {
		snapshot := *options.Vault
		evidence = &snapshot
		if err = validateGuardVault(evidence, request); err != nil {
			return result, err
		}
		ref, werr := WriteVaultRecord(ctx, evidence.Writer, vault.KindInput, evidence.OrganizationID, request.OperationID, evidence.Input)
		var writeErr *VaultWriteError
		switch {
		case werr == nil:
			request.VaultRef = ref
		case errors.As(werr, &writeErr) && evidence.ContinueWithoutVault:
			request.VaultGap = &VaultGap{Reason: writeErr.Reason}
		default:
			return result, werr
		}
	}
	response, err := client.EvaluateProxy(ctx, request, &reporter)
	if err != nil {
		return result, err
	}
	if response.Decision != "allow" || (response.OperationID != "" && response.OperationID != request.OperationID) {
		return result, fmt.Errorf("guard requires matching ALLOW")
	}
	completed := false
	defer func() {
		p := recover()
		result.Report.Status = "succeeded"
		if !completed || err != nil || p != nil {
			result.Report.Status = "unknown"
		}
		if evidence != nil && evidence.Output != nil && completed && err == nil && p == nil {
			attachGuardOutput(ctx, evidence, request.OperationID, result.Value, &result.Report)
		}
		result.Report.CompletedAt = time.Now().UTC().Truncate(time.Microsecond)
		_, result.ReportingError = client.ReportOperationOutcome(ctx, result.Report, &reporter)
		if p != nil {
			panic(p)
		}
	}()
	result.Value, err = execute(ctx)
	completed = true
	return result, err
}

func validateGuardVault(v *GuardVault, request EvaluateRequest) error {
	switch {
	case v.Writer == nil, strings.TrimSpace(v.OrganizationID) == "", v.Input == nil:
		return &InvalidAuthorizationInputError{Message: "vault requires a writer, an organization id and an input record"}
	case strings.TrimSpace(request.OperationID) == "":
		return &InvalidAuthorizationInputError{Message: "operation_id is required"}
	case request.VaultRef != nil || request.VaultGap != nil:
		return &InvalidAuthorizationInputError{Message: "vault_ref and vault_gap are set by the guard when a vault is configured"}
	}
	return nil
}

// attachGuardOutput stores the caller's output record and puts its reference, or a gap
// when it could not be stored, on the report. The call already ran, so a failure here
// never changes its result.
func attachGuardOutput(ctx context.Context, v *GuardVault, operationID string, value any, report *OperationOutcomeRequest) {
	record, ok := guardOutputRecord(v.Output, value)
	if ok && record == nil {
		return
	}
	if !ok {
		report.VaultGap = &VaultGap{Reason: VaultGapWriteFailed}
		return
	}
	ref, err := WriteVaultRecord(ctx, v.Writer, vault.KindOutput, v.OrganizationID, operationID, record)
	if err != nil {
		reason := VaultGapWriteFailed
		var writeErr *VaultWriteError
		if errors.As(err, &writeErr) {
			reason = writeErr.Reason
		}
		report.VaultGap = &VaultGap{Reason: reason}
		return
	}
	report.VaultRef = ref
}

// guardOutputRecord runs the caller's function; ok is false when it panicked.
func guardOutputRecord(output func(any) any, value any) (record any, ok bool) {
	defer func() {
		if recover() != nil {
			record, ok = nil, false
		}
	}()
	return output(value), true
}

func guardCopy[T any](value *T) *T {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
