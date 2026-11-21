package edr

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Original TuranSec lab heuristic. DNS (EID22) is NOT network (EID3).
const processDNSNetworkRuleID = "TURAN-WIN-PROC-DNS-NET-001"

type signalProcessKey struct {
	device, boot, process string
}

func validSysmonSignal(e Event, kind string, eventID int) bool {
	return e.Platform == "windows" && e.Source == "sysmon" &&
		e.Type == kind && e.SysmonEventID == eventID &&
		e.DeviceID != "" && e.BootID != "" && e.ProcessGUID != "" &&
		e.ID != "" && strings.TrimSpace(e.ID) == e.ID &&
		e.SourceRecordID != "" && strings.TrimSpace(e.SourceRecordID) == e.SourceRecordID &&
		!e.Time.IsZero()
}

func userWritableExecutable(image string) bool {
	p := windowsPath(image)
	if !strings.HasSuffix(p, ".exe") || !strings.Contains(p, ":") {
		return false
	}
	for _, marker := range []string{
		"\\appdata\\", "\\downloads\\", "\\temp\\", "\\programdata\\",
	} {
		if strings.Contains(p, marker) {
			return true
		}
	}
	return false
}

func signalKey(e Event) signalProcessKey {
	return signalProcessKey{e.DeviceID, e.BootID, e.ProcessGUID}
}

func eligibleRemoteIP(raw string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(raw)
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, false
	}
	ip = ip.Unmap()
	return ip, ip.IsGlobalUnicast() && !ip.IsPrivate()
}

func timeAfterWithin(earlier, later time.Time, max time.Duration) bool {
	delta := later.Sub(earlier)
	return delta >= 0 && delta <= max
}

// DetectSuspiciousProcessDNSNetwork requires three independent, synthetic
// Sysmon observations: process start EID1, DNS lookup EID22, and connection
// EID3 to an IP reported in the DNS response. Sender provenance is unverified.
// No detection is proof of infection; the rule never performs response.
func DetectSuspiciousProcessDNSNetwork(events []Event) []Detection {
	ordered := append([]Event(nil), events...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Time.Equal(ordered[j].Time) {
			return ordered[i].ID < ordered[j].ID
		}
		return ordered[i].Time.Before(ordered[j].Time)
	})

	processes := make([]Event, 0)
	dnsByProcess := make(map[signalProcessKey]map[netip.Addr][]Event)
	networkByProcess := make(map[signalProcessKey][]Event)

	for _, e := range ordered {
		switch {
		case validSysmonSignal(e, "process_create", 1) &&
			userWritableExecutable(e.Image):
			processes = append(processes, e)
		case validSysmonSignal(e, "dns_query", 22) &&
			e.DNSQuery != "" && strings.Contains(e.DNSQuery, "."):
			key := signalKey(e)
			if dnsByProcess[key] == nil {
				dnsByProcess[key] = make(map[netip.Addr][]Event)
			}
			for _, raw := range e.DNSAnswers {
				if ip, ok := eligibleRemoteIP(raw); ok {
					dnsByProcess[key][ip] = append(dnsByProcess[key][ip], e)
				}
			}
		case validSysmonSignal(e, "network_connect", 3) &&
			e.DestinationPort > 0:
			if _, ok := eligibleRemoteIP(e.DestinationIP); ok {
				networkByProcess[signalKey(e)] = append(
					networkByProcess[signalKey(e)], e)
			}
		}
	}

	alerts := make([]Detection, 0)
	seen := make(map[signalProcessKey]bool)
	for _, process := range processes {
		key := signalKey(process)
		if seen[key] {
			continue
		}
		for _, network := range networkByProcess[key] {
			if !timeAfterWithin(process.Time, network.Time, 6*time.Minute) {
				continue
			}
			ip, _ := eligibleRemoteIP(network.DestinationIP)
			for _, dns := range dnsByProcess[key][ip] {
				if !timeAfterWithin(process.Time, dns.Time, 5*time.Minute) ||
					!timeAfterWithin(dns.Time, network.Time, 2*time.Minute) {
					continue
				}
				// One alert per reported process/boot, even if it makes
				// multiple connections; stable with shuffled input.
				seen[key] = true
				fingerprint := fmt.Sprintf("%s:%d:%s%d:%s%d:%s%d:%s",
					processDNSNetworkRuleID, len(key.device), key.device,
					len(key.boot), key.boot, len(key.process), key.process,
					len(process.ID), process.ID)
				sum := sha256.Sum256([]byte(fingerprint))
				alerts = append(alerts, Detection{
					ID: hex.EncodeToString(sum[:16]),
					RuleID: processDNSNetworkRuleID,
					Category: "process_dns_network_correlation",
					Severity: "medium", Confidence: "low",
					DeviceID: key.device, BootID: key.boot,
					ProcessGUID: key.process, ProcessImage: process.Image,
					ProcessCreateEventID: process.ID, DNSEventID: dns.ID,
					NetworkEventID: network.ID, DNSQuery: dns.DNSQuery,
					DestinationIP: network.DestinationIP, DestinationPort: network.DestinationPort,
					ObservedAt: network.Time,
					Explanation: "A process in a potentially writable path started, resolved a remote IP, and connected to it. Events are unauthenticated lab reports. Verify signer, prevalence and context; this is not proof of malware.",
				})
				break
			}
			if seen[key] {
				break
			}
		}
	}
	return alerts
}

// Combine provisional lab signals. Do not use for automated quarantine.
func DetectAllLabSignals(events []Event) []Detection {
	all := DetectSuspiciousDLLLoads(events)
	all = append(all, DetectSuspiciousProcessDNSNetwork(events)...)
	all = append(all, DetectProcessAccessRemoteThread(events)...)
	all = append(all, DetectRegistryAutorunSet(events)...)
	all = append(all, DetectWMIPermanentSubscription(events)...)
	return append(all, DetectProcessTampering(events)...)
}
