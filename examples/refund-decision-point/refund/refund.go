// Package refund shows how an application uses the governance Go SDK for a
// refund flow: an immediate allow or deny, a bounded synchronous wait, and an
// asynchronous resume through a status poll or a signed approval webhook.
package refund

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	governance "github.com/OpenProdkt/governance-sdk-go/governance"
)

// Refund is the application-side request. OperationID must be stable per
// business operation so retries map to the same governance operation.
type Refund struct {
	OperationID string
	AmountCents int64
	Currency    string
}

// Outcome is the application-level result of Create.
type Outcome string

const (
	// Executed means the refund side effect ran exactly once.
	Executed Outcome = "executed"
	// Denied means governance rejected the refund; the side effect did not run.
	Denied Outcome = "denied"
	// Pending means an approval is required and was not resolved within the wait budget.
	// The refund resumes when the approval webhook arrives.
	Pending Outcome = "pending"
)

type pendingRefund struct {
	refund      Refund
	payloadHash string
}

// Service authorizes refunds and runs the side effect only after an allow decision.
type Service struct {
	client  *governance.Client
	asset   governance.AssetIdentity
	execute func(context.Context, Refund) error

	mu       sync.Mutex
	executed map[string]bool
	pending  map[string]pendingRefund // keyed by approval ID
}

// New creates a Service. execute must be idempotent for a given OperationID because
// an approved retry that succeeds at the PDP is not repeated after a downstream failure.
func New(client *governance.Client, asset governance.AssetIdentity, execute func(context.Context, Refund) error) *Service {
	return &Service{
		client:   client,
		asset:    asset,
		execute:  execute,
		executed: map[string]bool{},
		pending:  map[string]pendingRefund{},
	}
}

func (s *Service) authorizationRequest(r Refund) governance.AuthorizationRequest {
	return governance.AuthorizationRequest{
		AssetIdentity: &s.asset,
		OperationID:   r.OperationID,
		Metadata: map[string]any{
			"amount_cents": r.AmountCents,
			"currency":     r.Currency,
		},
	}
}

// Create authorizes the refund. It waits up to wait for an approval; if none
// arrives, it returns Pending and the caller relies on the approval webhook.
func (s *Service) Create(ctx context.Context, r Refund, wait time.Duration) (Outcome, error) {
	if s.isExecuted(r.OperationID) {
		return Executed, nil
	}
	_, err := s.client.AuthorizeAndWaitWithOptions(ctx, s.authorizationRequest(r), governance.ApprovalWaitOptions{
		Timeout:           wait,
		PollInterval:      50 * time.Millisecond,
		MaxPollInterval:   50 * time.Millisecond,
		BackoffMultiplier: 1,
	})

	var pending *governance.PendingApprovalError
	var denied *governance.AuthorizationDeniedError
	var terminal *governance.ApprovalTerminalError
	switch {
	case err == nil:
		if err := s.run(ctx, r); err != nil {
			return "", err
		}
		return Executed, nil
	case errors.As(err, &pending):
		s.mu.Lock()
		s.pending[pending.ApprovalID] = pendingRefund{refund: r, payloadHash: pending.PayloadHash}
		s.mu.Unlock()
		return Pending, nil
	case errors.As(err, &denied), errors.As(err, &terminal):
		return Denied, nil
	default:
		return "", err
	}
}

// HandleApprovalWebhook verifies a signed approval webhook and resumes the matching
// refund. Duplicate deliveries are acknowledged without a second execution.
func (s *Service) HandleApprovalWebhook(ctx context.Context, rawBody []byte, headers http.Header, secret string, now time.Time) (bool, error) {
	result, err := governance.DispatchApprovalWebhook(ctx, rawBody, headers, secret,
		governance.WebhookVerificationOptions{Now: now},
		func(ctx context.Context, event governance.ApprovalWebhookEvent) (bool, error) {
			switch event.EventType {
			case governance.ApprovalWebhookApproved:
				return s.resume(ctx, event.ApprovalID())
			case governance.ApprovalWebhookRejected, governance.ApprovalWebhookExpired, governance.ApprovalWebhookRevoked:
				return s.discard(event.ApprovalID()), nil
			default:
				return true, nil
			}
		})
	if err != nil {
		return false, err
	}
	return !result.Duplicate, nil
}

// Poll reads the approval status once. Approved resumes the refund, rejected or
// expired discards it, and pending leaves it stored for the next poll.
func (s *Service) Poll(ctx context.Context, approvalID string) (Outcome, error) {
	s.mu.Lock()
	_, ok := s.pending[approvalID]
	s.mu.Unlock()
	if !ok {
		return "", errors.New("refund: unknown approval")
	}

	approval, err := s.client.GetApprovalStatus(ctx, approvalID)
	if err != nil {
		return "", err
	}
	switch approval.Status {
	case "pending":
		return Pending, nil
	case "approved":
		if _, err := s.resume(ctx, approvalID); err != nil {
			return "", err
		}
		return Executed, nil
	case "rejected", "expired", "revoked":
		s.discard(approvalID)
		return Denied, nil
	default:
		return "", errors.New("refund: approval is " + approval.Status + "; reconcile before retrying")
	}
}

// resume sends the stored approval tuple exactly once and runs the refund on allow.
func (s *Service) resume(ctx context.Context, approvalID string) (bool, error) {
	s.mu.Lock()
	item, ok := s.pending[approvalID]
	s.mu.Unlock()
	if !ok {
		return false, nil
	}

	req := s.authorizationRequest(item.refund)
	req.ApprovalID = approvalID
	req.PayloadHash = item.payloadHash
	if _, err := s.client.Authorize(ctx, req); err != nil {
		return false, err
	}
	if err := s.run(ctx, item.refund); err != nil {
		return false, err
	}

	s.mu.Lock()
	delete(s.pending, approvalID)
	s.mu.Unlock()
	return true, nil
}

func (s *Service) discard(approvalID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.pending[approvalID]
	delete(s.pending, approvalID)
	return ok
}

func (s *Service) run(ctx context.Context, r Refund) error {
	if err := s.execute(ctx, r); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.executed[r.OperationID] = true
	return nil
}

func (s *Service) isExecuted(operationID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.executed[operationID]
}
