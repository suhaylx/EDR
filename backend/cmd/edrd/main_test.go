package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigurationRejectsAmbiguityAndPrivateFileExposure(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "config.json")
	valid := `{"agent_listen":"127.0.0.1:9443","soc_listen":"127.0.0.1:9444","registry_dsn_file":"/private/registry","runtime_dsn_file":"/private/runtime","ui_dir":"/srv/ui"}`
	for _, tc := range []struct {
		name, body string
		mode       os.FileMode
		ok         bool
	}{
		{"valid", valid, 0600, true}, {"trailing", valid + `{}`, 0600, false},
		{"unknown", `{"password":"private-test-value"}`, 0600, false},
		{"public", valid, 0644, false},
		{"same identity", strings.Replace(valid, "/private/runtime", "/private/registry", 1), 0600, false},
		{"relative UI", strings.Replace(valid, "/srv/ui", "relative", 1), 0600, false},
		{"same listener", strings.Replace(valid, "9444", "9443", 1), 0600, false},
	} {
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
