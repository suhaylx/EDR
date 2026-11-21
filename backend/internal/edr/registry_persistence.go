package edr

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Original TuranSec laboratory rule. EID13 is a Registry value SET, not
// proof that a Run/RunOnce entry executed or contained a malicious command.
const registryAutorunRuleID = "TURAN-WIN-REG-AUTORUN-001"

// Restrict to complete, recognized Win32 Run/RunOnce VALUE paths.
// Substring matching would incorrectly include RunServices, RunOther, etc.
func registryAutorunValueKey(valuePath string) (string, bool) {
	p := windowsPath(valuePath)
	parts := strings.Split(p, `\`)
	if len(parts) < 7 {
		return "", false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, ":/") {
			return "", false
		}
	}
	start := 1
	switch parts[0] {
	case "hkcu", "hklm":
	case "hku":
		// HKU paths include a real user SID before the SOFTWARE branch.
		if len(parts) < 8 || !strings.HasPrefix(parts[1], "s-1-") {
			return "", false
		}
		start = 2
	default:
		return "", false
	}
	tail := parts[start:]
	if len(tail) < 6 || tail[0] != "software" {
		return "", false
	}
	tail = tail[1:]
	if len(tail) > 0 && tail[0] == "wow6432node" {
		tail = tail[1:]
	}
	if len(tail) != 5 || tail[0] != "microsoft" ||
		tail[1] != "windows" || tail[2] != "currentversion" ||
		(tail[3] != "run" && tail[3] != "runonce") ||
		tail[4] == "" {
		return "", false
	}
	return strings.Join(parts[:len(parts)-1], `\`), true
}

type registryScope struct {
	device, boot, process string
}

func registryEventScope(e Event) registryScope {
	return registryScope{
		device: e.DeviceID, boot: e.BootID,
		process: strings.ToLower(e.ProcessGUID),
	}
}

// DetectRegistryAutorunSet produces a provisional alert only for an EID13
// set_value by a process running from a likely writable directory. EID12
// key creation and EID14 value rename can enrich an EID13; neither alone
// establishes persistence, so neither alone can trigger this rule.
func DetectRegistryAutorunSet(events []Event) []Detection {
	ordered := append([]Event(nil), events...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Time.Equal(ordered[j].Time) {
			return ordered[i].ID < ordered[j].ID
		}
		return ordered[i].Time.Before(ordered[j].Time)
	})

	alerts := make([]Detection, 0)
	seen := make(map[string]bool)
	for _, set := range ordered {
		if !validSysmonSignal(set, "registry_value_set", 13) ||
			set.RegistryOperation != "set_value" ||
			!userWritableExecutable(set.Image) {
			continue
		}
		keyPath, ok := registryAutorunValueKey(set.RegistryTarget)
		if !ok {
			continue
		}
		scope := registryEventScope(set)
		// Deduplicate a repeated source record in the same boot and scope.
		// Sender-provided record IDs are untrusted and not durable proof.
		fingerprint := fmt.Sprintf("%q:%q:%q:%q:%q:%s",
			registryAutorunRuleID, scope.device, scope.boot,
			scope.process, windowsPath(set.RegistryTarget), set.SourceRecordID)
		if seen[fingerprint] {
			continue
		}
		seen[fingerprint] = true
		digest := sha256.Sum256([]byte(fingerprint))
		alert := Detection{
			ID: hex.EncodeToString(digest[:16]), RuleID: registryAutorunRuleID,
			Category: "registry_autorun_value_set",
			Severity: "medium", Confidence: "low",
			DeviceID: scope.device, BootID: scope.boot,
			ProcessGUID: set.ProcessGUID, ProcessImage: set.Image,
			RegistrySetEventID: set.ID,
			RegistryTarget: set.RegistryTarget, ObservedAt: set.Time,
			Explanation: "A process in a potentially writable directory reportedly set a Run/RunOnce Registry value. This is not proof that the entry ran or contains malware. Review signer, value data under access controls and authorized installer activity.",
		}
		var latestCreate, latestRename *Event
		for _, prior := range ordered {
			if prior.ID == set.ID || prior.SourceRecordID == set.SourceRecordID ||
				registryEventScope(prior) != scope ||
				!timeAfterWithin(prior.Time, set.Time, 10*time.Minute) {
				continue
			}
			switch {
			case validSysmonSignal(prior, "registry_object", 12) &&
				prior.RegistryOperation == "create_key" &&
				windowsPath(prior.RegistryTarget) == keyPath:
				if latestCreate == nil || prior.Time.After(latestCreate.Time) ||
					(prior.Time.Equal(latestCreate.Time) && prior.ID < latestCreate.ID) {
					copyEvent := prior
					latestCreate = &copyEvent
				}
			case validSysmonSignal(prior, "registry_rename", 14) &&
				prior.RegistryOperation == "rename_value" &&
				windowsPath(prior.RegistryNewName) == windowsPath(set.RegistryTarget):
				if latestRename == nil || prior.Time.After(latestRename.Time) ||
					(prior.Time.Equal(latestRename.Time) && prior.ID < latestRename.ID) {
					copyEvent := prior
					latestRename = &copyEvent
				}
			}
		}
		if latestCreate != nil {
			alert.RegistryCreateEventID = latestCreate.ID
		}
		if latestRename != nil {
			alert.RegistryRenameEventID = latestRename.ID
		}
		alerts = append(alerts, alert)
	}
	return alerts
}
