package cli

import (
	"bytes"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	root := NewRootCommand(VersionInfo{Version: "1.2.3", Date: "2026-06-08"})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := out.String(); got != "version=1.2.3 build_date=2026-06-08\n" {
		t.Fatalf("output = %q", got)
	}
}
