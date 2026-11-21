package edr

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Independent Sysmon events 19/20/21 describe WMI permanent subscription
// components. They do NOT demonstrate command execution or malicious intent.
const wmiSubscriptionRuleID = "TURAN-WIN-WMI-SUBSCRIPTION-001"

type wmiScope struct {
	device, boot string
}

type wmiIdentity struct {
	scope wmiScope
	name string
}

func wmiName(name string) string {
	return strings.ToLower(name)
}

func validWMIEvent(e Event, kind string, eventID int) bool {
	if e.Platform != "windows" || e.Source != "sysmon" ||
		e.Type != kind || e.SysmonEventID != eventID ||
		!validID(e.DeviceID) || e.BootID == "" || e.ID == "" ||
		e.SourceRecordID == "" || e.Time.IsZero() {
		return false
	}
	for _, v := range []string{e.BootID, e.ID, e.SourceRecordID} {
		if strings.TrimSpace(v) != v {
			return false
		}
	}
	return true
}

// DetectWMIPermanentSubscription requires a reported EID19 filter, EID20
// consumer and EID21 binding referencing both names, all from one device and
// reported boot, within 30 minutes. A binding alone does not prove its
// referenced objects were created in the observed window. Exact identities
// are required: no substring/path/broad "contains" correlation.
func DetectWMIPermanentSubscription(events []Event) []Detection {
	ordered := append([]Event(nil), events...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Time.Equal(ordered[j].Time) {
			return ordered[i].ID < ordered[j].ID
		}
		return ordered[i].Time.Before(ordered[j].Time)
	})

	filters := make(map[wmiIdentity][]Event)
	consumers := make(map[wmiIdentity][]Event)
	bindings := make([]Event, 0)
	for _, e := range ordered {
		scope := wmiScope{e.DeviceID, e.BootID}
		switch {
		case validWMIEvent(e, "wmi_filter", 19) && e.WMIFilterName != "":
			k := wmiIdentity{scope, wmiName(e.WMIFilterName)}
			filters[k] = append(filters[k], e)
		case validWMIEvent(e, "wmi_consumer", 20) && e.WMIConsumerName != "":
			k := wmiIdentity{scope, wmiName(e.WMIConsumerName)}
			consumers[k] = append(consumers[k], e)
		case validWMIEvent(e, "wmi_binding", 21) &&
			e.WMIFilterName != "" && e.WMIConsumerName != "":
			bindings = append(bindings, e)
		}
	}

	alerts := make([]Detection, 0)
	seen := make(map[string]bool)
	for _, binding := range bindings {
		scope := wmiScope{binding.DeviceID, binding.BootID}
		filterKey := wmiIdentity{scope, wmiName(binding.WMIFilterName)}
		consumerKey := wmiIdentity{scope, wmiName(binding.WMIConsumerName)}
		var matchedFilter, matchedConsumer *Event
		for _, filter := range filters[filterKey] {
			if filter.SourceRecordID == binding.SourceRecordID ||
				!timeAfterWithin(filter.Time, binding.Time, 30*time.Minute) {
				continue
			}
			candidate := filter
			matchedFilter = &candidate // ordered ascending: nearest valid prior
		}
		for _, consumer := range consumers[consumerKey] {
			if consumer.SourceRecordID == binding.SourceRecordID ||
				!timeAfterWithin(consumer.Time, binding.Time, 30*time.Minute) {
				continue
			}
			candidate := consumer
			matchedConsumer = &candidate
		}
		if matchedFilter == nil || matchedConsumer == nil ||
			matchedFilter.SourceRecordID == matchedConsumer.SourceRecordID ||
			matchedFilter.ID == matchedConsumer.ID ||
			binding.ID == matchedFilter.ID || binding.ID == matchedConsumer.ID {
			continue
		}
		// Sender source records may be replayed in the lab. Do not emit more
		// than one signal for a single reported binding in the same boot.
		fingerprint := fmt.Sprintf("%q:%q:%q:%q:%q:%q",
			wmiSubscriptionRuleID, scope.device, scope.boot,
			filterKey.name, consumerKey.name, binding.SourceRecordID)
		if seen[fingerprint] {
			continue
		}
		seen[fingerprint] = true
		sum := sha256.Sum256([]byte(fingerprint))
		alerts = append(alerts, Detection{
			ID: hex.EncodeToString(sum[:16]),
			RuleID: wmiSubscriptionRuleID,
			Category: "wmi_permanent_subscription_correlation",
			Severity: "medium", Confidence: "low",
			DeviceID: scope.device, BootID: scope.boot,
			WMIFilterEventID: matchedFilter.ID,
			WMIConsumerEventID: matchedConsumer.ID,
			WMIBindingEventID: binding.ID,
			WMIFilterName: binding.WMIFilterName,
			WMIConsumerName: binding.WMIConsumerName,
			ObservedAt: binding.Time,
			Explanation: "Sysmon reports a WMI filter, consumer and binding for one reported boot. This suggests a permanent event subscription but does not establish execution or malicious intent. Validate source, object definitions and authorized management tooling.",
		})
	}
	return alerts
}
