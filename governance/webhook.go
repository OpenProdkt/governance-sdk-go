package governance

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const maxApprovalWebhookBodyBytes = 256 * 1024

type ApprovalWebhookEventType string

const (
	ApprovalWebhookPending  ApprovalWebhookEventType = "approval.pending"
	ApprovalWebhookApproved ApprovalWebhookEventType = "approval.approved"
	ApprovalWebhookRejected ApprovalWebhookEventType = "approval.rejected"
	ApprovalWebhookExpired  ApprovalWebhookEventType = "approval.expired"
	ApprovalWebhookRevoked  ApprovalWebhookEventType = "approval.revoked"
)

type ApprovalWebhookEvent struct {
	EventID        string                   `json:"eventId"`
	EventType      ApprovalWebhookEventType `json:"eventType"`
	OrganizationID string                   `json:"organizationId"`
	AggregateID    string                   `json:"aggregateId"`
	Data           map[string]any           `json:"data"`
}

func (e ApprovalWebhookEvent) ApprovalID() string {
	value, _ := e.Data["approvalId"].(string)
	return value
}

type WebhookVerificationOptions struct {
	Now          time.Time
	ReplayWindow time.Duration
	MaxBodyBytes int
}

type WebhookDispatchResult struct {
	Event     ApprovalWebhookEvent
	Duplicate bool
}

func VerifyApprovalWebhook(rawBody []byte, headers http.Header, secret string, options WebhookVerificationOptions) (ApprovalWebhookEvent, error) {
	return VerifyApprovalWebhookWithSecrets(rawBody, headers, []string{secret}, options)
}

func VerifyApprovalWebhookWithSecrets(rawBody []byte, headers http.Header, secrets []string, options WebhookVerificationOptions) (ApprovalWebhookEvent, error) {
	if len(rawBody) == 0 || len(rawBody) > webhookMaxBody(options.MaxBodyBytes) {
		return ApprovalWebhookEvent{}, fmt.Errorf("webhook body is empty or exceeds the size limit")
	}
	if len(secrets) == 0 {
		return ApprovalWebhookEvent{}, fmt.Errorf("webhook secret is required")
	}
	for _, secret := range secrets {
		if strings.TrimSpace(secret) == "" {
			return ApprovalWebhookEvent{}, fmt.Errorf("webhook secret is required")
		}
	}
	replayWindow := options.ReplayWindow
	if replayWindow == 0 {
		replayWindow = 5 * time.Minute
	}
	if replayWindow < 0 {
		return ApprovalWebhookEvent{}, fmt.Errorf("webhook replay window must be positive")
	}
	eventID := strings.TrimSpace(headers.Get("X-OpenProdkt-Event-Id"))
	timestamp := strings.TrimSpace(headers.Get("X-OpenProdkt-Timestamp"))
	signature := strings.TrimSpace(headers.Get("X-OpenProdkt-Signature"))
	if eventID == "" || timestamp == "" || signature == "" {
		return ApprovalWebhookEvent{}, fmt.Errorf("required OpenProdkt webhook headers are missing")
	}
	if len(eventID) > 255 || len(timestamp) > 64 {
		return ApprovalWebhookEvent{}, fmt.Errorf("webhook header exceeds the size limit")
	}
	signedAt, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		signedAt, err = time.Parse(time.RFC3339Nano, timestamp)
	}
	if err != nil {
		return ApprovalWebhookEvent{}, fmt.Errorf("webhook timestamp is invalid")
	}
	now := options.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if delta := now.Sub(signedAt); delta > replayWindow || delta < -replayWindow {
		return ApprovalWebhookEvent{}, fmt.Errorf("webhook timestamp is outside the replay window")
	}
	const signaturePrefix = "v1=sha256="
	if !strings.HasPrefix(signature, signaturePrefix) {
		return ApprovalWebhookEvent{}, fmt.Errorf("webhook signature version is unsupported")
	}
	signatureHex := strings.TrimPrefix(signature, signaturePrefix)
	if len(signatureHex) != sha256.Size*2 {
		return ApprovalWebhookEvent{}, fmt.Errorf("webhook signature is invalid")
	}
	providedMAC, err := hex.DecodeString(signatureHex)
	if err != nil || len(providedMAC) != sha256.Size {
		return ApprovalWebhookEvent{}, fmt.Errorf("webhook signature is invalid")
	}
	message := make([]byte, 0, len(timestamp)+1+len(rawBody))
	message = append(message, timestamp...)
	message = append(message, '.')
	message = append(message, rawBody...)
	validSignature := 0
	for _, secret := range secrets {
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write(message)
		validSignature |= subtle.ConstantTimeCompare(providedMAC, mac.Sum(nil))
	}
	if validSignature != 1 {
		return ApprovalWebhookEvent{}, fmt.Errorf("webhook signature is invalid")
	}
	var event ApprovalWebhookEvent
	if err := json.Unmarshal(rawBody, &event); err != nil {
		return ApprovalWebhookEvent{}, fmt.Errorf("webhook body is not valid JSON")
	}
	if event.EventID == "" || event.EventID != eventID {
		return ApprovalWebhookEvent{}, fmt.Errorf("webhook event ID header does not match body")
	}
	switch event.EventType {
	case ApprovalWebhookPending, ApprovalWebhookApproved, ApprovalWebhookRejected, ApprovalWebhookExpired, ApprovalWebhookRevoked:
	default:
		return ApprovalWebhookEvent{}, fmt.Errorf("webhook event type is unsupported")
	}
	if event.OrganizationID == "" || event.AggregateID == "" || event.Data == nil {
		return ApprovalWebhookEvent{}, fmt.Errorf("webhook organization, aggregate, and data are required")
	}
	if event.ApprovalID() == "" {
		return ApprovalWebhookEvent{}, fmt.Errorf("webhook approval ID is required")
	}
	return event, nil
}

func DispatchApprovalWebhook(ctx context.Context, rawBody []byte, headers http.Header, secret string, options WebhookVerificationOptions, dispatch func(context.Context, ApprovalWebhookEvent) (bool, error)) (WebhookDispatchResult, error) {
	return DispatchApprovalWebhookWithSecrets(ctx, rawBody, headers, []string{secret}, options, dispatch)
}

func DispatchApprovalWebhookWithSecrets(ctx context.Context, rawBody []byte, headers http.Header, secrets []string, options WebhookVerificationOptions, dispatch func(context.Context, ApprovalWebhookEvent) (bool, error)) (WebhookDispatchResult, error) {
	if dispatch == nil {
		return WebhookDispatchResult{}, fmt.Errorf("webhook dispatch callback is required")
	}
	event, err := VerifyApprovalWebhookWithSecrets(rawBody, headers, secrets, options)
	if err != nil {
		return WebhookDispatchResult{}, err
	}
	processed, err := dispatch(ctx, event)
	if err != nil {
		return WebhookDispatchResult{}, err
	}
	return WebhookDispatchResult{Event: event, Duplicate: !processed}, nil
}

func webhookMaxBody(configured int) int {
	if configured <= 0 || configured > maxApprovalWebhookBodyBytes {
		return maxApprovalWebhookBodyBytes
	}
	return configured
}
