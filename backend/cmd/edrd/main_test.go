package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestConfigurationRejectsAmbiguityAndPrivateFileExposure(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EDR_SOC_UI_DIR", "")
	name := filepath.Join(dir, "config.json")
	base := configuration{
		AgentListen:     "127.0.0.1:9443",
		SOCListen:       "127.0.0.1:9444",
		RegistryDSNFile: filepath.Join(dir, "registry.dsn"),
		RuntimeDSNFile:  filepath.Join(dir, "runtime.dsn"),
		UIDir:           t.TempDir(),
	}
	encode := func(c configuration) string {
		t.Helper()
		body, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	valid := encode(base)
	sameIdentity, relativeUI, sameListener := base, base, base
	sameIdentity.RuntimeDSNFile = base.RegistryDSNFile
	relativeUI.UIDir = "relative"
	sameListener.SOCListen = base.AgentListen
	type configCase struct {
		name, body string
		mode       os.FileMode
		ok         bool
	}
	cases := []configCase{
		{"valid", valid, 0600, true}, {"trailing", valid + `{}`, 0600, false},
		{"unknown", `{"password":"private-test-value"}`, 0600, false},
		{"same identity", encode(sameIdentity), 0600, false},
		{"relative UI", encode(relativeUI), 0600, false},
		{"same listener", encode(sameListener), 0600, false},
	}
	// Unix mode bits do not describe Windows ACLs. Keep the permission
	// rejection where boundedFile enforces it; native Windows ACL acceptance
	// remains separate from these configuration parsing and path checks.
	if runtime.GOOS != "windows" {
		cases = append(cases, configCase{"public", valid, 0644, false})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(name, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(name, tc.mode); err != nil {
				t.Fatal(err)
			}
			_, err := loadConfig(name)
			if (err == nil) != tc.ok {
				t.Fatalf("configuration acceptance mismatch: %v", err)
			}
			if err != nil && strings.Contains(err.Error(), "private-test-value") {
				t.Fatal("private value leaked through diagnostics")
			}
		})
	}
}

func TestCredentialReadRejectsSymlinkAndSize(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "secret")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("ephemeral-test-bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := boundedFile(link, true, 100); err == nil {
		t.Fatal("symlink credential accepted")
	}
	if _, err := boundedFile(target, true, 5); err == nil {
		t.Fatal("oversized credential accepted")
	}
	if _, err := boundedFile("relative", true, 100); err == nil {
		t.Fatal("relative credential accepted")
	}
}
