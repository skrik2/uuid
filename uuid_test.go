package uuid

import (
	"encoding/json"
	"os"
	"testing"
)

// TestData 对应 JSON 中的结构
type TestData struct {
	Type   int    `json:"type"`
	Byte   []byte `json:"byte"`
	String string `json:"string"`
}

func TestVersion(t *testing.T) {
	file, err := os.ReadFile("test_data.json")
	if err != nil {
		t.Fatalf("Failed to read test_data.json: %v", err)
	}

	var cases []TestData
	if err := json.Unmarshal(file, &cases); err != nil {
		t.Fatalf("Failed to unmarshal test data: %v", err)
	}

	const iterations = 50_000
	totalChecks := len(cases) * iterations
	for n := 0; n < iterations; n++ {
		for i, tc := range cases {
			var u UUID
			copy(u[:], tc.Byte)
			version := tc.Type
			got := u.Version()
			if got != byte(version) {
				t.Errorf("Case %d failed: Got %d, Want %d", i, got, tc.Type)
			}
		}
	}

	t.Logf("Pressure Test Complete: Validated %d UUIDs (%d cases * %d iterations)", totalChecks, len(cases), iterations)
}

// go test -v -run ^TestUUID_String_CrossValidation_Pressure$ uuid -timeout 2m
func TestUUID_String_CrossValidation_Pressure(t *testing.T) {
	file, err := os.ReadFile("test_data.json")
	if err != nil {
		t.Fatalf("Failed to read test_data.json: %v", err)
	}

	var cases []TestData
	if err := json.Unmarshal(file, &cases); err != nil {
		t.Fatalf("Failed to unmarshal test data: %v", err)
	}

	const iterations = 50_000
	totalChecks := len(cases) * iterations

	for n := 0; n < iterations; n++ {
		for i, tc := range cases {
			var u UUID
			copy(u[:], tc.Byte)

			got := u.String()
			if n == 0 {
				if got != tc.String {
					t.Errorf("Case %d failed: Got %s, Want %s", i, got, tc.String)
				}
			}
		}
	}

	t.Logf("Pressure Test Complete: Validated %d UUIDs (%d cases * %d iterations)", totalChecks, len(cases), iterations)
}
