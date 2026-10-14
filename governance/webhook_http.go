package governance

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
)

func NewApprovalWebhookHandler(
	secrets []string,
	options WebhookVerificationOptions,
	dispatch func(context.Context, ApprovalWebhookEvent) (bool, error),
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		maxBody := webhookMaxBody(options.MaxBodyBytes)
		body, err := io.ReadAll(io.LimitReader(r.Body, int64(maxBody)+1))
		if err != nil || len(body) > maxBody {
			http.Error(w, "invalid OpenProdkt webhook", http.StatusBadRequest)
			return
		}
		event, err := VerifyApprovalWebhookWithSecrets(body, r.Header, secrets, options)
		if err != nil {
			http.Error(w, "invalid OpenProdkt webhook", http.StatusBadRequest)
			return
		}
		if dispatch == nil {
			http.Error(w, "webhook processing unavailable", http.StatusServiceUnavailable)
			return
		}
		processed, err := dispatch(r.Context(), event)
		if err != nil {
			http.Error(w, "webhook processing unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"eventId": event.EventID, "duplicate": !processed})
	})
}
