package edr

import ("testing"; "time")

// Windows paths supplied through the lab control plane must be unambiguous.
// No filesystem operations are performed in these synthetic validation tests.
func TestWindowsScanPathRejectsDeviceNamesStreamsAndNormalization(t *testing.T) {
	rejected := []string{
		`C:\Lab\sample.dll:payload`,
		`C:\Lab\sample.dll::$DATA`,
		`C:\CON`,
		`C:\Lab\nul.txt`,
		`C:\Lab\PRN.log`,
		`C:\Lab\COM1`,
		`C:\Lab\LPT9.txt`,
		`C:\Lab\CONIN$`,
		`C:\Lab\COM¹.txt`,
		`C:\Lab\trailing.`,
		`C:\Lab\trailing `,
		`C:\Lab\inva?lid.exe`,
		`C:\Lab\inva*lid.exe`,
		`C:\Lab\inva"lid.exe`,
		"C:\\Lab\\bad\x7f.exe",
		"C:\\Lab\\bad\x1f.exe",
		`C:\Lab\nested\\test.dll`,
	}
	for _, p := range rejected {
		t.Run(p, func(t *testing.T) {
			if scanPathAllowed("windows", p) {
				t.Fatalf("unsafe or ambiguous Windows scan path was accepted: %q", p)
			}
		})
	}
}

func TestWindowsScanPathAllowsOrdinaryLocalTargets(t *testing.T) {
	accepted := []string{
		`C:\Lab\sample.dll`,
		`D:\Windows\System32\kernel32.dll`,
		`C:\Users\Public\hello world.txt`,
		`C:\Lab\COM10.txt`,
		`C:\Lab\NULity.txt`,
		`C:\Users\Public\résumé.txt`,
	}
	for _, p := range accepted {
		if !scanPathAllowed("windows", p) {
			t.Errorf("safe local Windows scan path was rejected: %q", p)
		}
	}
}

func TestScanCreateRejectsDangerousWindowsTargetWithoutQueueing(t *testing.T) {
	s := NewStore()
	if _, err := s.CheckIn(Agent{ID: "win-test", Platform: "windows"}); err != nil {
		t.Fatal(err)
	}
	for i, p := range []string{`C:\Lab\sample.exe:stream`, `C:\Lab\AUX.txt`, `C:\Lab\trailing.`} {
		if _, err := s.CreateScan(ScanRequest{
			AgentID: "win-test", RequestID: "bad-" + string(rune('a'+i)), ScanType: "path", Path: p,
		}, time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)); err == nil {
			t.Errorf("accepted unsafe Windows path %q", p)
		}
	}
	if got := len(s.ScanJobs()); got != 0 {
		t.Fatalf("rejected paths created %d scan jobs", got)
	}
}
