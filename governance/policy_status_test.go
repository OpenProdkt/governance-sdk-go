package governance

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPolicyStatusContract(t *testing.T) {
	for _, status := range []PolicyStatus{"", PolicyDraft, PolicyPublished} {
		b, err := json.Marshal(CreatePolicyRequest{AssetID: "asset", Status: status})
		if err != nil {
			t.Fatal(err)
		}
		if status == "" && strings.Contains(string(b), `"status"`) {
			t.Fatal("legacy creation must omit status")
		}
		if status != "" && !strings.Contains(string(b), `"status":"`+string(status)+`"`) {
			t.Fatalf("lost status: %s", b)
		}
	}
	var revision PolicyRevision
	if err := json.Unmarshal([]byte(`{"status":"archived","isActive":false,"action":"archived"}`), &revision); err != nil || revision.Status != PolicyArchived || revision.IsActive || revision.Action != "archived" {
		t.Fatalf("revision status: %+v %v", revision, err)
	}
}
