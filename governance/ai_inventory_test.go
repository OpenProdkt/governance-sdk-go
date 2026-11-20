package governance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestAIInventoryAssetWireParity(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/phase2-inventory.json")
	if os.IsNotExist(err) {
		raw, err = os.ReadFile("../testdata/phase2-inventory.json")
	}
	if err != nil {
		t.Fatal(err)
	}
	var v struct{ Valid []AIInventory }
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(captured)
	}))
	defer srv.Close()
	client := NewClient(srv.URL, "asset-writer", time.Second)
	for _, inventory := range v.Valid {
		bytes, _ := json.Marshal(inventory)
		var expected any
		json.Unmarshal(bytes, &expected)
		for _, update := range []bool{false, true} {
			var err error
			if update {
				_, err = client.UpdateAsset(context.Background(), "ast_test", UpdateAssetRequest{Name: "asset", Environment: "sandbox", Group: "test", AIInventory: &inventory})
			} else {
				_, err = client.CreateAsset(context.Background(), CreateAssetRequest{Name: "asset", Environment: "sandbox", Group: "test", AIInventory: &inventory})
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(captured["ai_inventory"], expected) {
				t.Fatalf("inventory changed: %+v", captured)
			}
			if _, ok := captured["definition"]; ok {
				t.Fatal("inventory leaked into policy definition")
			}
		}
	}
}
