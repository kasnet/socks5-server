package main

import "testing"

func TestParseAuthPreservesColonInPassword(t *testing.T) {
	credentials, err := parseAuth("alice:p@ss:word")
	if err != nil {
		t.Fatal(err)
	}
	if got := credentials["alice"]; got != "p@ss:word" {
		t.Fatalf("password was truncated: %q", got)
	}
}

func TestParseAuthRejectsMalformedValue(t *testing.T) {
	for _, value := range []string{"", "alice", ":password", "alice:"} {
		if _, err := parseAuth(value); err == nil {
			t.Fatalf("expected %q to be rejected", value)
		}
	}
}
