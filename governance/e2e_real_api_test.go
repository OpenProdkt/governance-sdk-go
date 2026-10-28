package governance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestClientRealAPI(t *testing.T) {
	if os.Getenv("OPK_SDK_E2E") != "1" {
		t.Skip("OPK_SDK_E2E is not enabled")
	}
	baseURL := requiredE2EEnv(t, "E2E_API_BASE_URL")
	apiKey := requiredE2EEnv(t, "E2E_API_KEY")
	organizationID := requiredE2EEnv(t, "E2E_EXPECTED_ORGANIZATION_ID")
	runID := fmt.Sprintf("sdk-go-%d", time.Now().UnixNano())
	client := NewClient(baseURL, apiKey, 15*time.Second)
	ctx := context.Background()

	group, err := client.CreateGroup(ctx, CreateGroupRequest{Name: runID + "-group", Approvers: requiredE2EEnv(t, "E2E_EMAIL")})
	if err != nil {
		t.Fatal(err)
	}
	groupID := fmt.Sprint(group["id"])
	defer func() { _, _ = client.DeleteGroup(ctx, groupID) }()

	asset, err := client.CreateAsset(ctx, CreateAssetRequest{
		Name:        runID + "-asset",
		Environment: "local-e2e",
		Group:       fmt.Sprint(group["name"]),
		Definition: map[string]interface{}{
			"_fieldMetadata": map[string]interface{}{"metadata.environment": map[string]interface{}{"type": "string"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	assetID := fmt.Sprint(asset["id"])
	defer func() { _, _ = client.DeleteAsset(ctx, assetID) }()

	allowPolicy, err := client.CreatePolicy(ctx, CreatePolicyRequest{
		AssetID:  assetID,
		Name:     runID + "-allow",
		Decision: "allow",
		Condition: map[string]interface{}{
			"field": "metadata.environment", "operator": "=", "value": "development",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	allowPolicyID := fmt.Sprint(allowPolicy["id"])
	defer func() { _, _ = client.DeletePolicy(ctx, allowPolicyID) }()

	approvalPolicy, err := client.CreatePolicy(ctx, CreatePolicyRequest{
		AssetID:  assetID,
		Name:     runID + "-approval",
		Decision: "approval_required",
		Condition: map[string]interface{}{
			"field": "metadata.environment", "operator": "=", "value": "production",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	approvalPolicyID := fmt.Sprint(approvalPolicy["id"])
	defer func() { _, _ = client.DeletePolicy(ctx, approvalPolicyID) }()

	decision, err := client.Authorize(ctx, AuthorizationRequest{AssetID: assetID, OperationID: runID + "-allow", Metadata: map[string]interface{}{"environment": "development"}})
	if err != nil {
		t.Fatal(err)
	}
	if decision.OrganizationID != organizationID || decision.Decision != "allow" {
		t.Fatalf("unexpected decision: %+v", decision)
	}
	playground, err := client.PlaygroundCheck(ctx, DecisionRequest{AssetID: assetID, Metadata: map[string]interface{}{"environment": "development"}})
	if err != nil || playground.Decision != "allow" {
		t.Fatalf("unexpected playground decision: %+v err=%v", playground, err)
	}
	explorer, err := client.ListDecisionExplorer(ctx, DecisionQuery{Limit: 25})
	if err != nil {
		t.Fatal(err)
	}
	audit, err := client.ListAuditEvents(ctx, AuditQuery{Limit: 25})
	if err != nil {
		t.Fatal(err)
	}
	if !containsE2EJSON(explorer, decision.DecisionID) || !containsE2EJSON(audit, decision.DecisionID) {
		t.Fatalf("decision %s was not correlated in explorer/audit", decision.DecisionID)
	}

	_, err = client.Authorize(ctx, AuthorizationRequest{
		AssetID:     assetID,
		OperationID: runID + "-approval",
		Metadata:    map[string]interface{}{"environment": "production"},
	})
	var pending *PendingApprovalError
	if !errors.As(err, &pending) {
		t.Fatalf("expected PendingApprovalError, got %T: %v", err, err)
	}
	approvalDecision := pending.Response
	approvals, err := client.ListApprovals(ctx, ApprovalQuery{Status: "pending", Limit: 25})
	if err != nil {
		t.Fatal(err)
	}
	approvalID := approvalIDForDecision(t, approvals.Approvals, approvalDecision.DecisionID)
	if approvalID == "" {
		t.Fatalf("pending approval missing for decision %s", approvalDecision.DecisionID)
	}
	audit, err = client.ListAuditEvents(ctx, AuditQuery{Limit: 25})
	if err != nil || !containsE2EJSON(audit, approvalDecision.DecisionID) {
		t.Fatalf("approval decision %s was not correlated in audit", approvalDecision.DecisionID)
	}
}

func approvalIDForDecision(t *testing.T, approvals []Approval, decisionID string) string {
	t.Helper()
	for _, approval := range approvals {
		if approval.DecisionID == decisionID {
			return approval.ID
		}
	}
	t.Fatalf("approval not found for decision %s", decisionID)
	return ""
}

func requiredE2EEnv(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}

func containsE2EJSON(value any, expected string) bool {
	payload, _ := json.Marshal(value)
	return strings.Contains(string(payload), expected)
}
